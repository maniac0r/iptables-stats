/* Parser výstupu `iptables-save` (aj `iptables-save -c`, aj ip6tables-save).
 * Funguje v prehliadači (globálna funkcia) aj v Node (module.exports). */

const KIND_OF_TARGET = {
  ACCEPT: 'accept',
  DROP: 'drop',
  REJECT: 'reject',
  RETURN: 'return',
  SNAT: 'snat', MASQUERADE: 'snat', NETMAP: 'snat',
  DNAT: 'dnat', REDIRECT: 'dnat', TPROXY: 'dnat',
  MARK: 'mark', CONNMARK: 'mark', SECMARK: 'mark', CONNSECMARK: 'mark',
  CLASSIFY: 'mark', DSCP: 'mark', TOS: 'mark',
  LOG: 'log', NFLOG: 'log', ULOG: 'log',
};

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
    if (!tbl.chains[name]) {
      tbl.chains[name] = {
        name, policy: null, builtin: false, counters: null,
        rules: [], incoming: [], depth: 0, orphan: false,
      };
      tbl.order.push(name);
    }
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
      match, target, args, isGoto, counters, kind: 'none', jumpTo: null,
    });
  }

  // klasifikácia pravidiel + hrany + hĺbka (stĺpec) v diagrame
  for (const tbl of Object.values(tables)) {
    const chains = tbl.chains;
    for (const c of Object.values(chains)) {
      for (const r of c.rules) {
        if (!r.target) { r.kind = 'none'; continue; }
        if (chains[r.target]) {
          r.kind = 'jump';
          r.jumpTo = r.target;
          chains[r.target].incoming.push({ from: c.name, idx: r.idx, isGoto: r.isGoto });
        } else {
          r.kind = KIND_OF_TARGET[r.target] || 'other';
        }
      }
    }
    for (const c of Object.values(chains)) c.orphan = !c.builtin && c.incoming.length === 0;

    const names = Object.keys(chains);
    const roots = names.filter(n => chains[n].incoming.length === 0);
    for (const n of names) chains[n].depth = -1;
    roots.forEach(n => { chains[n].depth = 0; });
    // najdlhšia cesta od koreňov (limit iterácií chráni pred cyklom)
    for (let it = 0; it < names.length + 1; it++) {
      let changed = false;
      for (const n of names) {
        const c = chains[n];
        if (c.depth < 0) continue;
        for (const r of c.rules) {
          if (r.jumpTo && chains[r.jumpTo].depth < c.depth + 1 && it < names.length) {
            chains[r.jumpTo].depth = c.depth + 1; changed = true;
          }
        }
      }
      if (!changed) break;
    }
    for (const n of names) if (chains[n].depth < 0) chains[n].depth = 0;
  }
  return tables;
}

if (typeof module !== 'undefined') module.exports = { parseIptablesSave };
