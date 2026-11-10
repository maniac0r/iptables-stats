'use strict';
const $ = s => document.querySelector(s);
const SVGNS = 'http://www.w3.org/2000/svg';

const W0 = 480, GAPX = 170, GAPY = 22, PADX = 30, PADY = 28, HEAD = 36;
const HOOKS = ['ingress', 'prerouting', 'input', 'forward', 'output', 'postrouting', 'egress'];
const LEGEND = [
  ['accept', 'ACCEPT'], ['drop', 'DROP'], ['reject', 'REJECT'],
  ['snat', 'SNAT / MASQUERADE'], ['dnat', 'DNAT / REDIRECT'], ['mark', 'MARK / CONNMARK'],
  ['return', 'RETURN'], ['log', 'LOG'], ['jump', 'skok do chainu'], ['other', 'iné ciele'],
];

let DATA = null, cur = null, zoom = 1, kindFilter = null;
let boxes = {}, size = { w: 300, h: 100 };
let info = { colOf: {}, colX: [], colW: [], colBoxes: [] };
const STATE = {};   // stav po tabuľkách: collapsed / wrap / wide / rule
const S = () => STATE[cur] || (STATE[cur] = { collapsed: {}, wrap: {}, wide: {}, rule: {} });

const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = n => n >= 1e9 ? (n / 1e9).toFixed(1) + 'G' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n);
const isHidden = el => el.classList.contains('hide');

/* ---------- načítanie ---------- */
let source = null, lastText = '', refreshTimer = null, refreshing = false, cmode = '', FORMAT = 'iptables', focusMode = false;
const darkMq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : { matches: true };
if (darkMq.addEventListener) darkMq.addEventListener('change', () => DATA && drawEdges());

const sigOf = T => JSON.stringify(Object.keys(T).map(t => [t, T[t].order.map(n => {
  const c = T[t].chains[n];
  return [n, c.policy, c.rules.map(r => (r.counters ? 'c|' : 'n|') + r.line)];
})]));

const cntTitle = (c, delta) => `${c.pkts} paketov, ${c.bytes} B` + (delta ? ` (+${delta} od poslednej obnovy)` : '');

function updateSeg() { document.querySelectorAll('#cnt button').forEach(b => b.classList.toggle('on', b.dataset.m === cmode)); }
function updateCountersUi() {
  const has = !!DATA && Object.values(DATA).some(t => Object.values(t.chains).some(c => c.rules.some(r => r.counters)));
  document.querySelectorAll('#cnt button').forEach(b => { if (b.dataset.m) b.disabled = !has; });
  $('#cnt').title = has ? '' : 'Export neobsahuje počítadlá – vytvor ho cez iptables-save -c';
  if (!has) cmode = '';
  updateSeg();
}

function updateRefreshUi() {
  const sel = $('#auto');
  sel.disabled = source !== 'server';
  $('#autoLbl').title = sel.disabled
    ? 'Auto-obnova funguje len pri súbore zo servera (/data/iptables.rules) – použi ⟳'
    : 'Automaticky znova načíta súbor zo servera a aktualizuje počítadlá';
  clearInterval(refreshTimer);
  refreshTimer = null;
  const sec = +sel.value;
  if (source === 'server' && sec > 0) refreshTimer = setInterval(() => { if (!document.hidden) loadFromServer(true); }, sec * 1000);
}

function load(text, label, src = 'local') {
  const parsed = parseRuleset(text);
  const names = Object.keys(parsed);
  if (!names.length) {
    alert('V texte som nenašiel žiadnu tabuľku.\nOčakávam výstup `iptables-save` (riadok *filter …) alebo `nft list ruleset` (table inet filter { …).');
    return;
  }
  DATA = parsed;
  FORMAT = detectFormat(text);
  source = src;
  if (!DATA[cur]) cur = names.find(n => n === 'filter' || n.endsWith(' filter')) || names[0];
  $('#src').textContent = (label || '') + ' · ' + FORMAT;
  $('#empty').style.display = 'none';
  updateRefreshUi();
  updateCountersUi();
  buildTabs();
  render();
}

/* rovnaká štruktúra pravidiel -> aktualizuj len počítadlá (bez prekreslenia a zmeny rozloženia) */
function updateChips(n) {
  const el = boxes[n] && boxes[n].querySelector('.chips');
  if (el) el.innerHTML = chipsHtml(DATA[cur].chains[n]);
}
function refreshActivity(flash) {
  if (!DATA) return;
  for (const n of DATA[cur].order) updateChips(n);
  drawEdges(flash);
}
/* zhodný obsah súboru = od poslednej obnovy nepribudli žiadne pakety */
function resetDeltas() {
  let any = false;
  for (const tb of Object.values(DATA)) for (const c of Object.values(tb.chains)) for (const r of c.rules) if (r.delta) { r.delta = 0; any = true; }
  if (!any) return;
  for (const n in boxes) boxes[n].querySelectorAll('.rule').forEach((row, i) => {
    const r = DATA[cur].chains[n].rules[i], el = row.querySelector('.cnt');
    if (el && r.counters) el.title = cntTitle(r.counters, 0);
  });
  refreshActivity(false);
}

function updateCounters(nd) {
  for (const tn of Object.keys(nd)) {
    for (const n of nd[tn].order) {
      const nc = nd[tn].chains[n], oc = DATA[tn].chains[n];
      oc.counters = nc.counters;
      nc.rules.forEach((nr, i) => {
        const old = oc.rules[i];
        const delta = (nr.counters && old.counters) ? nr.counters.pkts - old.counters.pkts : 0;
        old.delta = delta > 0 ? delta : 0;
        old.counters = nr.counters;
        if (tn !== cur || !nr.counters) return;
        const row = boxes[n] && boxes[n].querySelector(`.rule[data-i="${i}"]`);
        const el = row && row.querySelector('.cnt');
        if (!el) return;
        el.textContent = fmt(nr.counters.pkts);
        el.title = cntTitle(nr.counters, delta > 0 ? delta : 0);
        if (delta > 0) { row.classList.remove('bump'); void row.offsetWidth; row.classList.add('bump'); }
      });
    }
  }
  if (cmode) applyFilters();   // pravidlá mohli prejsť medzi "nulové" a "nenulové"
  refreshActivity(true);       // chipy + zvýraznenie čiar s aktivitou
}

async function loadFromServer(auto = false) {
  if (refreshing) return false;
  refreshing = true;
  try {
    const r = await fetch('api/rules', { cache: 'no-store' });
    if (!r.ok) { if (auto) $('#src').textContent = 'chyba obnovy: HTTP ' + r.status; return false; }
    const text = await r.text();
    const when = r.headers.get('X-Rules-Mtime');
    const label = (r.headers.get('X-Rules-File') || 'server') + (when ? ' · ' + when : '') +
      ' · načítané ' + new Date().toLocaleTimeString('sk-SK');
    if (DATA && source === 'server') {
      if (text === lastText) resetDeltas();
      else {
        lastText = text;
        const nd = parseRuleset(text);
        if (sigOf(nd) === sigOf(DATA)) updateCounters(nd);
        else load(text, label, 'server');     // zmenili sa samotné pravidlá -> prekresli
      }
      $('#src').textContent = label + ' · ' + FORMAT;
      return true;
    }
    lastText = text;
    load(text, label, 'server');
    return true;
  } catch (e) {
    if (auto) $('#src').textContent = 'chyba obnovy: ' + e.message;
    return false;
  } finally { refreshing = false; }
}

/* ---------- záložky / legenda ---------- */
function buildTabs() {
  const tabs = $('#tabs');
  tabs.innerHTML = '';
  const order = ['filter', 'nat', 'mangle', 'raw', 'security'];
  const rank = n => (order.indexOf(n.split(' ').pop()) + 99) % 99;
  for (const n of Object.keys(DATA).sort((a, b) => rank(a) - rank(b))) {
    const rules = Object.values(DATA[n].chains).reduce((s, c) => s + c.rules.length, 0);
    const b = document.createElement('button');
    b.textContent = `${n} (${rules})`;
    b.className = n === cur ? 'on' : '';
    b.onclick = () => { cur = n; buildTabs(); render(); };
    tabs.appendChild(b);
  }
}

function buildLegend() {
  const el = $('#legend');
  for (const [k, label] of LEGEND) {
    const b = document.createElement('button');
    b.className = 'k-' + k;
    b.innerHTML = `<i></i>${label}`;
    b.title = 'Klik: zvýrazniť len tento typ pravidiel';
    b.onclick = () => {
      kindFilter = kindFilter === k ? null : k;
      el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b && !!kindFilter));
      applyFilters();
    };
    el.appendChild(b);
  }
}

/* ---------- vykreslenie ---------- */
function ruleHtml(r) {
  const tag = r.kind === 'jump' ? (r.isGoto ? '⇒ ' : '→ ') + r.target : (r.target || '·');
  let m = esc(r.match).replace(/(?:-m comment --comment|\bcomment) (&quot;.*?&quot;|\S+)/g,
    (_, c) => `<span class="cmt"># ${c.replace(/^&quot;|&quot;$/g, '')}</span>`);
  if (!r.match) m = '<span class="all">(všetky pakety)</span>';
  const args = r.args ? ` <span class="args">⟶ ${esc(r.args)}</span>` : '';
  const cnt = r.counters ? `<span class="cnt" title="${cntTitle(r.counters, 0)}">${fmt(r.counters.pkts)}</span>` : '';
  const open = S().rule[r.chain + '#' + r.idx] ? ' open' : '';
  return `<div class="rule k-${r.kind}${open}" data-i="${r.idx}" title="${esc((FORMAT === 'nft' ? '' : '-A ' + r.chain + ' ') + r.line)}">` +
    `<span class="tag">${esc(tag)}</span><span class="txt">${m}${args}</span>${cnt}</div>`;
}

function chipsHtml(c) {
  const g = {};
  for (const r of c.rules) {
    const e = g[r.kind] || (g[r.kind] = { n: 0, hits: 0, d: 0, has: false });
    e.n++;
    if (r.counters) { e.has = true; e.hits += r.counters.pkts; }
    e.d += r.delta || 0;
  }
  return Object.keys(g).map(k => {
    const e = g[k];
    let txt = String(e.n);
    if (e.has) txt += ` · ${fmt(e.hits)}`;
    if (e.d > 0) txt += ` · <b>+${fmt(e.d)}</b>`;
    const tip = `${e.n}× ${k}` + (e.has ? ` · ${e.hits} paketov celkom` : '') + (e.d > 0 ? ` · +${e.d} od poslednej obnovy` : '');
    return `<span class="chip k-${k}" title="${tip}">${txt}</span>`;
  }).join('');
}

function setModes(name) {
  const st = S(), box = boxes[name];
  box.classList.toggle('wide', !!($('#chkWide').checked || st.wide[name]));
  box.classList.toggle('wrapbox', !!st.wrap[name]);
  box.querySelector('.bw').classList.toggle('on', !!st.wide[name]);
  box.querySelector('.bt').classList.toggle('on', !!st.wrap[name]);
}

function render() {
  const t = DATA[cur], st = S();
  const canvas = $('#canvas');
  canvas.innerHTML = '';
  canvas.classList.toggle('wrap', $('#chkWrap').checked);
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.id = 'edges';
  canvas.appendChild(svg);
  const nm = document.createElement('div');
  nm.id = 'nomatch'; nm.className = 'hide'; nm.textContent = 'Filtru nevyhovuje žiadne pravidlo.';
  canvas.appendChild(nm);
  boxes = {};

  for (const name of t.order) {
    const c = t.chains[name];
    const box = document.createElement('div');
    box.className = 'chain' + (c.builtin ? ' builtin' : '') + (c.orphan ? ' orphan' : '') + (st.collapsed[name] ? ' collapsed' : '');
    box.style.width = W0 + 'px';
    box.dataset.chain = name;
    const pol = c.policy ? `<span class="pol k-${c.policy.toLowerCase()}">policy ${c.policy}</span>` : '';
    box.innerHTML =
      `<div class="chead" tabindex="0" role="button"><span class="chev">▾</span>` +
      `<span class="cname" title="${esc(name)}">${esc(name)}</span>${pol}` +
      (c.meta ? `<span class="meta" title="${esc(c.meta)}">${esc(c.metaShort)}</span>` : '') +
      `<button class="wbtn bw" title="Roztiahnuť box na šírku – celé pravidlá na jeden riadok">⇔</button>` +
      `<button class="wbtn bt" title="Zalomiť dlhé pravidlá v tomto chaine">↵</button>` +
      `<span class="chips">${chipsHtml(c)}</span></div>` +
      `<div class="rules">${c.rules.map(ruleHtml).join('')}</div>`;
    canvas.appendChild(box);
    boxes[name] = box;

    const head = box.querySelector('.chead');
    const toggle = () => {
      if (focusMode) { focusOn(name); return; }
      const collapsing = !st.collapsed[name];
      st.collapsed[name] = collapsing;
      if (collapsing) for (const d of descendants(name)) st.collapsed[d] = true;   // zbalí sa aj podstrom
      applyCollapsed();
      relayout();
    };
    head.onclick = toggle;
    head.onkeydown = e => { if (e.target === head && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggle(); } };
    box.querySelector('.bw').onclick = e => { e.stopPropagation(); st.wide[name] = !st.wide[name]; setModes(name); relayout(); };
    box.querySelector('.bt').onclick = e => { e.stopPropagation(); st.wrap[name] = !st.wrap[name]; setModes(name); relayout(); };

    box.addEventListener('mouseenter', () => hot(e => e.dataset.from === name || e.dataset.to === name));
    box.addEventListener('mouseleave', () => hot(null));
    box.querySelectorAll('.rule').forEach(row => {
      row.addEventListener('click', () => {
        if (String(window.getSelection && window.getSelection()).length) return;  // označovanie textu nerozbaľuje
        const key = name + '#' + row.dataset.i;
        st.rule[key] = !st.rule[key];
        row.classList.toggle('open', !!st.rule[key]);
        relayout();
      });
      row.addEventListener('mouseenter', () => hot(e => e.dataset.from === name && e.dataset.idx === row.dataset.i));
      row.addEventListener('mouseleave', () => hot(e => e.dataset.from === name || e.dataset.to === name));
    });
    setModes(name);
    box.classList.toggle('focus', focusMode && st.focus === name);
  }
  applyFilters();   // volá aj relayout()
}

/* chainy, do ktorých sa dá dostať z `name` (potomkovia) */
function descendants(name) {
  const t = DATA[cur], out = new Set(), todo = [name];
  while (todo.length) {
    const n = todo.pop();
    for (const r of t.chains[n].rules) for (const x of r.jumpTos) if (x !== name && !out.has(x)) { out.add(x); todo.push(x); }
  }
  return out;
}
/* chainy, z ktorých sa dá dostať do `name` (rodičia) */
function ancestors(name) {
  const t = DATA[cur], out = new Set(), todo = [name];
  while (todo.length) {
    const n = todo.pop();
    for (const e of t.chains[n].incoming) if (e.from !== name && !out.has(e.from)) { out.add(e.from); todo.push(e.from); }
  }
  return out;
}
function applyCollapsed() {
  const st = S();
  for (const n in boxes) boxes[n].classList.toggle('collapsed', !!st.collapsed[n]);
}
function focusOn(name) {
  const st = S();
  const keep = new Set([name, ...descendants(name), ...ancestors(name)]);
  st.collapsed = {};
  for (const n of DATA[cur].order) if (!keep.has(n)) st.collapsed[n] = true;
  st.focus = name;
  applyCollapsed();
  for (const n in boxes) boxes[n].classList.toggle('focus', n === name);
  relayout();
  if (boxes[name].scrollIntoView) boxes[name].scrollIntoView({ block: 'nearest', inline: 'nearest' });
}

function hot(pred) {
  const svg = $('#edges');
  let any = false;
  svg.querySelectorAll('.edge').forEach(e => {
    const on = !!pred && pred(e);
    e.classList.toggle('hot', on);
    any = any || on;
  });
  svg.classList.toggle('has-hot', any);
}

/* y stredu pravidla v rámci boxu; null = pravidlo je skryté filtrom */
const hm = box => ((box.firstElementChild && box.firstElementChild.offsetHeight) || HEAD) / 2 + 1;

function rowY(chain, idx) {
  const box = boxes[chain];
  if (!box || isHidden(box)) return null;
  if (box.classList.contains('collapsed')) return hm(box);
  const row = box.querySelector(`.rule[data-i="${idx}"]`);
  if (!row || isHidden(row)) return null;
  return row.offsetTop + row.offsetHeight / 2;
}

/* ---------- rozloženie ---------- */
function relayout() {
  const t = DATA[cur];
  const vis = t.order.filter(n => !isHidden(boxes[n]));
  $('#nomatch').classList.toggle('hide', vis.length > 0);

  // stĺpce = hĺbka chainu; prázdne stĺpce (všetko skryté filtrom) sa zlisujú
  const depths = [...new Set(vis.map(n => t.chains[n].depth))].sort((a, b) => a - b);
  const cmap = new Map(depths.map((d, i) => [d, i]));
  const cols = depths.map(() => []);
  info = { colOf: {}, colX: [], colW: [], colBoxes: depths.map(() => []) };
  vis.forEach(n => { const ci = cmap.get(t.chains[n].depth); cols[ci].push(n); info.colOf[n] = ci; });

  let x = PADX;
  cols.forEach((names, ci) => {
    info.colX[ci] = x;
    info.colW[ci] = Math.max(W0, ...names.map(n => boxes[n].offsetWidth));
    x += info.colW[ci] + GAPX;
  });

  const tieBreak = n => {
    const c = t.chains[n];
    if (!c.builtin) return 1e6 + t.order.indexOf(n);
    const h = HOOKS.indexOf(c.hook);
    return (h < 0 ? 50 : h) * 1e4 + (c.prio || 0);
  };
  const top = {};
  let maxY = 0;
  cols.forEach((names, ci) => {
    const callY = n => {
      let m = Infinity;
      for (const e of t.chains[n].incoming) {
        if (top[e.from] === undefined) continue;
        const ry = rowY(e.from, e.idx);
        if (ry !== null) m = Math.min(m, top[e.from] + ry);
      }
      return m;
    };
    const key = {};
    names.forEach(n => { key[n] = ci === 0 ? Infinity : callY(n); });
    const sorted = names.slice().sort((a, b) => key[a] !== key[b] ? (key[a] < key[b] ? -1 : 1) : tieBreak(a) - tieBreak(b));
    let cursor = PADY;
    for (const n of sorted) {
      const box = boxes[n];
      let y = cursor;
      if (isFinite(key[n])) y = Math.max(cursor, key[n] - hm(box));
      box.style.left = info.colX[ci] + 'px';
      box.style.top = y + 'px';
      top[n] = y;
      info.colBoxes[ci].push({ top: y, bottom: y + box.offsetHeight });
      cursor = y + box.offsetHeight + GAPY;
      maxY = Math.max(maxY, cursor);
    }
  });
  size = { w: Math.max(300, x - GAPX + PADX), h: Math.max(100, maxY + PADY) };
  drawEdges();
  applyZoom();
}

/* ---------- čiary ---------- */
function roundedPath(pts, r) {
  const p = pts.filter((q, i) => i === 0 || q[0] !== pts[i - 1][0] || q[1] !== pts[i - 1][1]);
  let d = `M${p[0][0]},${p[0][1]}`;
  for (let i = 1; i < p.length - 1; i++) {
    const [x0, y0] = p[i - 1], [x1, y1] = p[i], [x2, y2] = p[i + 1];
    const l1 = Math.hypot(x1 - x0, y1 - y0), l2 = Math.hypot(x2 - x1, y2 - y1);
    const rr = Math.min(r, l1 / 2, l2 / 2);
    if (rr < 0.5) { d += ` L${x1},${y1}`; continue; }
    d += ` L${x1 - (x1 - x0) / l1 * rr},${y1 - (y1 - y0) / l1 * rr} Q${x1},${y1} ${x1 + (x2 - x1) / l2 * rr},${y1 + (y2 - y1) / l2 * rr}`;
  }
  const l = p[p.length - 1];
  return d + ` L${l[0]},${l[1]}`;
}

/* vodorovný "pruh" medzi boxami stĺpcov c1..c2, kam sa dá čiaru viesť bez prekrytia boxov */
function freeLane(c1, c2, yd, laneUse) {
  const occ = [];
  for (let c = c1; c <= c2; c++) for (const b of info.colBoxes[c] || []) occ.push([b.top - 4, b.bottom + 4]);
  occ.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const o of occ) {
    if (merged.length && o[0] <= merged[merged.length - 1][1]) merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], o[1]);
    else merged.push(o.slice());
  }
  const free = [];
  let p = 2;
  for (const o of merged) { if (o[0] - p >= 5) free.push([p, o[0]]); p = Math.max(p, o[1]); }
  if (size.h - 3 - p >= 5) free.push([p, size.h - 3]);
  if (!free.length) return Math.max(2, Math.min(size.h - 3, yd));
  let best = null, bestD = Infinity;
  for (const [a, b] of free) {
    const y = Math.max(a + 2, Math.min(b - 2, yd));
    if (Math.abs(y - yd) < bestD) { bestD = Math.abs(y - yd); best = [a, b, y]; }
  }
  const [a, b, y] = best;
  const key = c1 + ':' + c2 + ':' + Math.round(a);
  const n = laneUse[key] = (laneUse[key] || 0) + 1;
  const step = Math.min(4, (b - a - 4) / 6);
  return Math.max(a + 2, Math.min(b - 2, y + ((n % 7) - 3) * step));
}

function drawEdges(flash = false) {
  const t = DATA[cur];
  const svg = $('#edges');
  svg.innerHTML = '';
  svg.setAttribute('width', size.w);
  svg.setAttribute('height', size.h);
  const route = $('#chkRoute').checked;
  const colorOf = {};
  let ci = 0;
  for (const n of t.order) if (t.chains[n].incoming.length) colorOf[n] = `hsl(${(ci++ * 53) % 360} ${darkMq.matches ? '75% 62%' : '70% 38%'})`;
  const gapUse = {}, laneUse = {};
  const gapCenter = g => info.colX[g] + info.colW[g] + GAPX / 2;
  const gapX = g => { const n = gapUse[g] = (gapUse[g] || 0) + 1; return gapCenter(g) + ((n % 11) - 5) * 6; };

  for (const name of t.order) {
    const sb = boxes[name];
    if (isHidden(sb)) continue;
    for (const r of t.chains[name].rules) {
      for (const jt of r.jumpTos) {
      const tb = boxes[jt];
      const ry = rowY(name, r.idx);
      if (isHidden(tb) || ry === null) continue;
      const x1 = sb.offsetLeft + sb.offsetWidth, y1 = sb.offsetTop + ry;
      const x2 = tb.offsetLeft, y2 = tb.offsetTop + hm(tb);
      const s = info.colOf[name], tc = info.colOf[jt];
      let d;
      if (route && tc > s) {
        const cx1 = gapX(s);
        if (tc === s + 1) {
          d = roundedPath([[x1, y1], [cx1, y1], [cx1, y2], [x2, y2]], 7);
        } else {
          const cx2 = gapX(tc - 1);
          const ly = freeLane(s + 1, tc - 1, (y1 + y2) / 2, laneUse);
          d = roundedPath([[x1, y1], [cx1, y1], [cx1, ly], [cx2, ly], [cx2, y2], [x2, y2]], 7);
        }
      } else {
        const dx = Math.max(40, Math.abs(x2 - x1) / 2);
        d = `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
      }
      const col = colorOf[jt];
      const g = document.createElementNS(SVGNS, 'g');
      let cls = 'edge';
      if ((r.delta || 0) > 0) cls += ' act' + (flash ? ' flash' : '');
      if (!sb.classList.contains('collapsed') && S().rule[name + '#' + r.idx]) cls += ' sel';
      g.setAttribute('class', cls);
      g.dataset.from = name; g.dataset.to = jt; g.dataset.idx = r.idx;
      const p = document.createElementNS(SVGNS, 'path');
      p.setAttribute('d', d); p.setAttribute('fill', 'none'); p.setAttribute('stroke', col); p.setAttribute('stroke-width', 1.6);
      if (r.isGoto) p.setAttribute('stroke-dasharray', '6 4');
      const dot = document.createElementNS(SVGNS, 'circle');
      dot.setAttribute('cx', x1); dot.setAttribute('cy', y1); dot.setAttribute('r', 3.5); dot.setAttribute('fill', col);
      const arr = document.createElementNS(SVGNS, 'polygon');
      arr.setAttribute('points', `${x2},${y2} ${x2 - 9},${y2 - 5} ${x2 - 9},${y2 + 5}`); arr.setAttribute('fill', col);
      g.append(p, dot, arr);
      svg.appendChild(g);
      }
    }
  }
}

/* ---------- zoom / filtre ---------- */
function applyZoom() {
  $('#canvas').style.transform = `scale(${zoom})`;
  $('#canvas').style.width = size.w + 'px';
  $('#canvas').style.height = size.h + 'px';
  $('#stage').style.width = size.w * zoom + 'px';
  $('#stage').style.height = size.h * zoom + 'px';
}
function setZoom(z) { zoom = Math.min(2, Math.max(0.2, z)); applyZoom(); }

function applyFilters() {
  if (!DATA) return;
  const q = $('#q').value.trim().toLowerCase();
  const t = DATA[cur];
  const textActive = !!(q || kindFilter);
  const hideText = textActive && $('#chkHide').checked;
  const hideAny = hideText || !!cmode;

  const tok = (c, r) => (!q || (c.name + ' ' + r.line).toLowerCase().includes(q)) && (!kindFilter || r.kind === kindFilter);
  const cok = r => !cmode || (!!r.counters && (cmode === 'nz' ? r.counters.pkts > 0 : r.counters.pkts === 0));
  const pass = (c, r) => cok(r) && (!hideText || tok(c, r));

  // chain "má zhodu", ak ju má on sám alebo chain, do ktorého skáče (aby zostala viditeľná cesta)
  const mkHas = pred => {
    const memo = {};
    const has = n => {
      if (n in memo) return memo[n];
      memo[n] = false;
      const c = t.chains[n];
      return (memo[n] = c.rules.some(r => pred(c, r) || r.jumpTos.some(x => has(x))));
    };
    return has;
  };
  const hasP = mkHas(pass), hasT = mkHas(tok);

  for (const name of t.order) {
    const c = t.chains[name], box = boxes[name];
    box.querySelectorAll('.rule').forEach((row, i) => {
      const r = c.rules[i];
      const ctx = r.jumpTos.some(x => hasP(x));
      row.classList.toggle('faded', textActive && !hideText && !tok(c, r));
      row.classList.toggle('hide', hideAny && !pass(c, r) && !ctx);
    });
    box.classList.toggle('faded', textActive && !hideText && !hasT(name));
    box.classList.toggle('hide', hideAny && !hasP(name));
  }
  relayout();
}

function setAll(v) {
  const st = S();
  st.collapsed = {};
  st.focus = null;
  if (v) for (const n of DATA[cur].order) st.collapsed[n] = true;
  applyCollapsed();
  for (const n in boxes) boxes[n].classList.remove('focus');
  relayout();
}

function refreshModes() { if (!DATA) return; for (const n in boxes) setModes(n); relayout(); }

/* ---------- UI ---------- */
buildLegend();
$('#btnCollapse').onclick = () => DATA && setAll(true);
$('#btnExpand').onclick = () => DATA && setAll(false);
$('#btnFocus').onclick = () => {
  focusMode = !focusMode;
  $('#btnFocus').classList.toggle('on', focusMode);
  $('#btnFocus').setAttribute('aria-pressed', String(focusMode));
  if (!DATA) return;
  const f = focusMode ? S().focus : null;
  for (const n in boxes) boxes[n].classList.toggle('focus', n === f);
};
$('#zIn').onclick = () => setZoom(zoom * 1.2);
$('#zOut').onclick = () => setZoom(zoom / 1.2);
$('#zFit').onclick = () => size.w && setZoom(($('#viewport').clientWidth - 20) / size.w);
$('#chkWrap').onchange = () => { $('#canvas').classList.toggle('wrap', $('#chkWrap').checked); if (DATA) relayout(); };
$('#chkWide').onchange = refreshModes;
$('#chkHide').onchange = applyFilters;
$('#chkRoute').onchange = () => DATA && drawEdges();
let qTimer;
$('#q').oninput = () => { clearTimeout(qTimer); qTimer = setTimeout(applyFilters, 120); };
$('#btnReload').onclick = () => loadFromServer(false);
document.querySelectorAll('#cnt button').forEach(b => b.onclick = () => { cmode = b.dataset.m; updateSeg(); applyFilters(); });
$('#auto').onchange = () => { try { localStorage.setItem('autoSec', $('#auto').value); } catch (e) { /* ignore */ } updateRefreshUi(); };
try { const v = localStorage.getItem('autoSec'); if (v && [...$('#auto').options].some(o => o.value === v)) $('#auto').value = v; } catch (e) { /* ignore */ }
$('#btnOpen').onclick = () => $('#file').click();
$('#file').onchange = e => { const f = e.target.files[0]; if (f) f.text().then(t => load(t, f.name)); e.target.value = ''; };
$('#viewport').addEventListener('wheel', e => { if (e.ctrlKey) { e.preventDefault(); setZoom(zoom * (e.deltaY < 0 ? 1.1 : 1 / 1.1)); } }, { passive: false });

document.addEventListener('dragover', e => { e.preventDefault(); document.body.classList.add('drag'); });
document.addEventListener('dragleave', e => { if (!e.relatedTarget) document.body.classList.remove('drag'); });
document.addEventListener('drop', e => {
  e.preventDefault(); document.body.classList.remove('drag');
  const f = e.dataTransfer.files[0]; if (f) f.text().then(t => load(t, f.name));
});
document.addEventListener('paste', e => {
  if (e.target.tagName === 'INPUT') return;
  const t = e.clipboardData.getData('text');
  if (t && t.includes('*')) load(t, 'vložený text');
});

loadFromServer();
