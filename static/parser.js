/* Parser firewallových exportov:
 *   - `iptables-save` / `iptables-save -c` (aj ip6tables, iptables-nft)
 *   - `nft list ruleset` (aj konfig /etc/nftables.conf bez premenných a include)
 * Výstup je pre oba formáty rovnaký: { "<tabuľka>": { chains, order } }.
 * Funguje v prehliadači (globálne funkcie) aj v Node (module.exports). */

const KIND_OF_TARGET = {
  ACCEPT: 'accept',
  DROP: 'drop',
  REJECT: 'reject',
  RETURN: 'return',
  SNAT: 'snat', MASQUERADE: 'snat', NETMAP: 'snat',
  DNAT: 'dnat', REDIRECT: 'dnat', TPROXY: 'dnat',
  MARK: 'mark', CONNMARK: 'mark', SECMARK: 'mark', CONNSECMARK: 'mark',
  CLASSIFY: 'mark', DSCP: 'mark', TOS: 'mark', TTL: 'mark', PRIORITY: 'mark',
  LOG: 'log', NFLOG: 'log', ULOG: 'log',
};

function newChain(name) {
  return {
    name, policy: null, builtin: false, counters: null, rules: [], incoming: [],
    depth: 0, orphan: false, hook: null, prio: 0, meta: '', metaShort: '',
  };
}

/* ---------------------------------------------------------------- iptables */

function tokenize(line) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) {
    out.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, '$1') : m[2] !== undefined ? m[2] : m[3]);
  }
  return out;
}

function parseIptablesSave(text) {
  const tables = {};
  let cur = null;

  const getChain = (tbl, name) => {
    if (!tbl.chains[name]) { tbl.chains[name] = newChain(name); tbl.order.push(name); }
    return tbl.chains[name];
  };

  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line[0] === '#') continue;

    if (line[0] === '*') {
      const name = line.slice(1).trim();
      cur = tables[name] = { name, chains: {}, order: [] };
      continue;
    }
    if (line === 'COMMIT') { cur = null; continue; }
    if (!cur) continue;

    if (line[0] === ':') {
      const m = line.match(/^:(\S+)\s+(\S+)(?:\s+\[(\d+):(\d+)\])?/);
      if (!m) continue;
      const c = getChain(cur, m[1]);
      c.policy = m[2] === '-' ? null : m[2];
      c.builtin = c.policy !== null;
      if (m[3] !== undefined) c.counters = { pkts: +m[3], bytes: +m[4] };
      continue;
    }

    let counters = null;
    const cm = line.match(/^\[(\d+):(\d+)\]\s+/);
    if (cm) { counters = { pkts: +cm[1], bytes: +cm[2] }; line = line.slice(cm[0].length); }

    const am = line.match(/^-A\s+(\S+)\s*(.*)$/);
    if (!am) continue;
    const chain = getChain(cur, am[1]);
    const body = am[2];

    // cieľ: prvý výskyt -j / -g (alebo --jump / --goto)
    let match = body, target = null, args = '', isGoto = false;
    const tm = body.match(/(?:^|\s)(?:-(j|g)|--(jump|goto))\s+(\S+)\s*(.*)$/);
    if (tm) {
      match = body.slice(0, tm.index).trim();
      target = tm[3];
      args = tm[4].trim();
      isGoto = (tm[1] || tm[2]) === 'g' || tm[2] === 'goto';
    }
    chain.rules.push({
      chain: chain.name, idx: chain.rules.length, line: body,
      match, target, args, isGoto, counters, jumpTos: [], jumpTo: null,
    });
  }
  return finalize(tables);
}

/* --------------------------------------------------------------------- nft */

const PRIO_NAMES = { raw: -300, mangle: -150, dstnat: -100, filter: 0, security: 50, srcnat: 100, out: 100 };
function parsePrio(s) {
  const m = s.trim().match(/^(-?\d+|[a-z]+)(?:\s*([+-])\s*(\d+))?$/i);
  if (!m) return 0;
  let v = /^-?\d+$/.test(m[1]) ? +m[1] : (PRIO_NAMES[m[1].toLowerCase()] || 0);
  if (m[2]) v += (m[2] === '+' ? 1 : -1) * (+m[3]);
  return v;
}

const unq = s => (s.length > 1 && s[0] === '"' && s[s.length - 1] === '"') ? s.slice(1, -1) : s;

/* tokeny pravidla: "reťazce v úvodzovkách" a { skupiny } sú jeden token */
function nftTokens(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') { if (s[j] === '\\') j++; j++; }
      out.push(s.slice(i, j + 1)); i = j + 1; continue;
    }
    if (ch === '{') {
      let d = 0, j = i, inq = false;
      for (; j < s.length; j++) {
        const c = s[j];
        if (inq) { if (c === '\\') j++; else if (c === '"') inq = false; continue; }
        if (c === '"') inq = true;
        else if (c === '{') d++;
        else if (c === '}') { d--; if (d === 0) break; }
      }
      out.push(s.slice(i, j + 1)); i = j + 1; continue;
    }
    let j = i;
    while (j < s.length && !/\s/.test(s[j]) && s[j] !== '"' && s[j] !== '{') j++;
    out.push(s.slice(i, j)); i = j;
  }
  return out;
}

const NFT_VERDICT = { accept: 'ACCEPT', drop: 'DROP', reject: 'REJECT', return: 'RETURN', jump: 'JUMP', goto: 'GOTO', continue: 'CONTINUE', queue: 'QUEUE' };

function nftRule(chain, idx, text) {
  let tk = nftTokens(text);
  let counters = null;

  // anonymný counter: "counter packets N bytes M" (alebo holé "counter") sa vyberie z textu
  for (let k = 0; k < tk.length; k++) {
    if (tk[k] !== 'counter') continue;
    if (tk[k + 1] === 'packets' && tk[k + 3] === 'bytes') {
      counters = { pkts: +tk[k + 2] || 0, bytes: +tk[k + 4] || 0 };
      tk.splice(k, 5); k--;
    } else if (tk[k + 1] !== 'name') { tk.splice(k, 1); k--; }
  }

  let cmt = '';
  for (let k = 0; k + 1 < tk.length; k++) {
    if (tk[k] === 'comment' && tk[k + 1][0] === '"') { cmt = tk[k] + ' ' + tk[k + 1]; tk.splice(k, 2); break; }
  }

  const rule = {
    chain, idx, line: tk.join(' '), match: tk.join(' '), target: null, args: '',
    isGoto: false, counters, jumpTos: [], jumpTo: null, jumpNames: null, kind: 'none',
  };
  classifyNft(rule, tk);
  if (cmt) { rule.match = (rule.match + ' ' + cmt).trim(); rule.line = (rule.line + ' ' + cmt).trim(); }
  return rule;
}

function classifyNft(rule, tk) {
  const split = (start, end, tgt, kind, argFrom) => {
    rule.match = tk.slice(0, start).join(' ');
    rule.args = tk.slice(argFrom === undefined ? end : argFrom).join(' ');
    rule.target = tgt; rule.kind = kind;
  };

  // 1) verdict map:  iifname vmap { "eth0" : jump wan_in, ... }
  const vm = tk.indexOf('vmap');
  if (vm >= 0 && tk[vm + 1] && tk[vm + 1][0] === '{') {
    const names = [...tk[vm + 1].matchAll(/(?:jump|goto)\s+("[^"]*"|[\w.\-]+)/g)].map(m => unq(m[1]));
    rule.target = 'vmap';
    if (names.length) { rule.jumpNames = names; rule.kind = undefined; } else rule.kind = 'other';
    return rule;
  }

  // 2) verdict (posledný výskyt)
  let vi = -1;
  for (let k = tk.length - 1; k >= 0; k--) if (NFT_VERDICT[tk[k]] !== undefined) { vi = k; break; }
  if (vi >= 0) {
    const v = tk[vi];
    if (v === 'jump' || v === 'goto') {
      const name = unq(tk[vi + 1] || '');
      rule.jumpNames = [name]; rule.isGoto = v === 'goto'; rule.kind = undefined;
      split(vi, vi + 2, name, undefined);
    } else {
      const t = NFT_VERDICT[v];
      split(vi, vi + 1, t, KIND_OF_TARGET[t] || 'other');
    }
    return rule;
  }

  // 3) NAT
  for (const w of ['snat', 'dnat', 'masquerade', 'redirect', 'tproxy']) {
    const k = tk.indexOf(w);
    if (k >= 0 && tk[k - 1] !== 'status') {
      const t = w.toUpperCase();
      split(k, k + 1, t, KIND_OF_TARGET[t]);
      return rule;
    }
  }
  // 4) log
  let k = tk.indexOf('log');
  if (k < 0) k = tk.indexOf('nflog');
  if (k >= 0) { split(k, k + 1, 'LOG', 'log'); return rule; }
  // 5) "<pole> set <hodnota>"  (meta mark set, ct mark set, ip dscp set, ...)
  k = tk.indexOf('set');
  if (k > 0) {
    const field = tk[k - 1];
    const start = ['meta', 'ct', 'ip', 'ip6', 'ether', 'vlan', 'tcp', 'udp'].includes(tk[k - 2]) ? k - 2 : k - 1;
    const tgt = (field === 'mark' && tk[k - 2] === 'ct') ? 'CONNMARK' : field.toUpperCase();
    split(start, k + 1, tgt, 'mark', k + 1);
    return rule;
  }
  // 6) ostatné akcie
  for (const w of ['notrack', 'flow', 'update', 'add', 'delete', 'synproxy', 'fwd', 'dup']) {
    const j = tk.indexOf(w);
    if (j >= 0) { split(j, j + 1, w.toUpperCase(), 'other'); return rule; }
  }
  return rule;   // len podmienky (alebo len counter) – bez cieľa
}

function parseNft(text) {
  const tables = {};
  let i = 0;
  const n = text.length;

  // načíta jednu "položku" po newline / ';' / '}' (na hĺbke 0); {…} vnútri patrí položke
  function scanItem(allowBlock) {
    let buf = '', depth = 0, inq = false;
    while (i < n) {
      const ch = text[i];
      if (inq) {
        buf += ch; i++;
        if (ch === '\\' && i < n) buf += text[i++];
        else if (ch === '"') inq = false;
        continue;
      }
      if (ch === '"') { inq = true; buf += ch; i++; continue; }
      if (ch === '#') { while (i < n && text[i] !== '\n') i++; continue; }
      if (ch === '{') {
        if (depth === 0 && allowBlock) { i++; return { text: buf.trim(), term: '{' }; }
        depth++; buf += ch; i++; continue;
      }
      if (ch === '}') {
        if (depth === 0) return { text: buf.trim(), term: '}' };
        depth--; buf += ch; i++; continue;
      }
      if ((ch === '\n' || ch === ';') && depth === 0) { i++; return { text: buf.trim(), term: ch }; }
      buf += ch === '\n' ? ' ' : ch; i++;
    }
    return { text: buf.trim(), term: 'EOF' };
  }

  function skipBlock() {
    let d = 1, inq = false;
    while (i < n && d > 0) {
      const ch = text[i++];
      if (inq) { if (ch === '\\') i++; else if (ch === '"') inq = false; continue; }
      if (ch === '"') inq = true;
      else if (ch === '#') { while (i < n && text[i] !== '\n') i++; }
      else if (ch === '{') d++;
      else if (ch === '}') d--;
    }
  }

  function chainItem(c, t) {
    let m;
    if (/^type\s/.test(t)) {
      const type = (t.match(/^type\s+(\S+)/) || [])[1] || '';
      const hook = (t.match(/\bhook\s+(\S+)/) || [])[1] || '';
      const prioTxt = (t.match(/\bpriority\s+(.+)$/) || [])[1] || '0';
      c.builtin = true;
      c.hook = hook.toLowerCase();
      c.prio = parsePrio(prioTxt);
      c.meta = `${type} hook ${hook} priority ${prioTxt}`;
      c.metaShort = `${hook} · ${c.prio}`;
      if (!c.policy) c.policy = 'ACCEPT';
    } else if ((m = t.match(/^policy\s+(\S+)/))) {
      c.policy = m[1].toUpperCase();
    } else if (/^comment\s/.test(t)) {
      /* komentár chainu – ignoruj */
    } else {
      c.rules.push(nftRule(c.name, c.rules.length, t));
    }
  }

  function parseChain(tbl, name) {
    if (!tbl.chains[name]) { tbl.chains[name] = newChain(name); tbl.order.push(name); }
    const c = tbl.chains[name];
    while (i < n) {
      const it = scanItem(false);
      if (it.text) chainItem(c, it.text);
      if (it.term === '}') { i++; return; }
      if (it.term === 'EOF') return;
    }
  }

  function parseTable(family, name) {
    const key = `${family} ${unq(name)}`;
    const tbl = tables[key] || (tables[key] = { name: key, chains: {}, order: [] });
    while (i < n) {
      const it = scanItem(true);
      if (it.term === '}') { i++; return; }
      if (it.term === '{') {
        const m = it.text.match(/^chain\s+("[^"]+"|\S+)$/);
        if (m) parseChain(tbl, unq(m[1])); else skipBlock();   // set / map / counter / flowtable …
        continue;
      }
      if (it.term === 'EOF') return;
    }
  }

  while (i < n) {
    const it = scanItem(true);
    if (it.term === '}') { i++; continue; }
    if (it.term === '{') {
      const m = it.text.match(/^table\s+(\S+)\s+("[^"]+"|\S+)$/);
      if (m) parseTable(m[1], m[2]); else skipBlock();
    }
    if (it.term === 'EOF') break;
  }
  return finalize(tables);
}

/* ------------------------------------------------------------------ spoločné */

function finalize(tables) {
  for (const tbl of Object.values(tables)) {
    const chains = tbl.chains;
    for (const c of Object.values(chains)) {
      if (c.builtin && !c.hook) c.hook = c.name.toLowerCase();   // iptables: INPUT -> input
      for (const r of c.rules) {
        const names = r.jumpNames || (r.target && chains[r.target] ? [r.target] : []);
        const valid = [...new Set(names.filter(nm => chains[nm]))];
        r.jumpTos = valid;
        r.jumpTo = valid[0] || null;
        if (valid.length) {
          r.kind = 'jump';
          valid.forEach(nm => chains[nm].incoming.push({ from: c.name, idx: r.idx, isGoto: r.isGoto }));
        } else if (r.kind === undefined || r.kind === 'jump') {
          r.kind = !r.target ? 'none' : (KIND_OF_TARGET[r.target] || 'other');
        }
      }
    }
    for (const c of Object.values(chains)) c.orphan = !c.builtin && c.incoming.length === 0;

    // hĺbka = stĺpec v diagrame (najdlhšia cesta od koreňov)
    const names = Object.keys(chains);
    for (const nm of names) chains[nm].depth = -1;
    names.filter(nm => chains[nm].incoming.length === 0).forEach(nm => { chains[nm].depth = 0; });
    for (let it = 0; it < names.length; it++) {      // limit iterácií chráni pred cyklom
      let changed = false;
      for (const nm of names) {
        const c = chains[nm];
        if (c.depth < 0) continue;
        for (const r of c.rules) for (const tn of r.jumpTos) {
          if (chains[tn].depth < c.depth + 1) { chains[tn].depth = c.depth + 1; changed = true; }
        }
      }
      if (!changed) break;
    }
    for (const nm of names) if (chains[nm].depth < 0) chains[nm].depth = 0;
  }
  return tables;
}

function detectFormat(text) {
  if (/^\s*\*\w+/m.test(text)) return 'iptables';
  if (/^\s*table\s+\S+\s+\S+\s*\{/m.test(text)) return 'nft';
  return null;
}

function parseRuleset(text) {
  const f = detectFormat(text);
  return f === 'iptables' ? parseIptablesSave(text) : f === 'nft' ? parseNft(text) : {};
}

if (typeof module !== 'undefined') module.exports = { parseRuleset, parseIptablesSave, parseNft, detectFormat };
