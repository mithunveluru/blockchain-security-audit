// dom helpers: nothing here ever assigns innerHTML, so server data cannot inject markup
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') cssText(el, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  append(el, kids);
  return el;
}
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}
// the csp forbids style attributes, so declarations go through the cssom
function cssText(el, text) {
  for (const decl of String(text).split(';')) {
    const i = decl.indexOf(':');
    if (i > 0) el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
  }
}
export const put = (el, ...kids) => { append(el, kids); return el; };
export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
export const svg = (tag, attrs, ...kids) => {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  append(el, kids);
  return el;
};

const pad = (n) => String(n).padStart(2, '0');
export function fmtTime(iso, withDate = true) {
  if (!iso) return 'n/a';
  const d = new Date(iso);
  if (isNaN(d)) return 'n/a';
  const t = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  return withDate ? `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${t} UTC` : `${t} UTC`;
}
export function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (isNaN(s)) return '';
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const timeEl = (iso) => h('time', { datetime: iso || '', title: iso || '' }, fmtTime(iso));
export const fmtNum = (n) => (n == null ? 'n/a' : Number(n).toLocaleString('en-US'));
export function fmtBytes(n) {
  if (n == null) return 'n/a';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}
export const sevBadge = (s) => h('span', { class: `badge sev-${s}` }, s);
export const stateBadge = (s, label) => h('span', { class: `badge st-${s}` }, label || s.replace('_', ' '));
export const provBadge = (p) => h('span', { class: `badge prov-${p}`, title: provText[p] || p }, p.replace('_', ' '));
export const provText = {
  live_capture: 'observed on a live capture interface', simulation: 'synthetic traffic from the built-in simulator',
  synthetic_test: 'synthetic test fixture', historical: 'recorded by an earlier version', integrity_monitor: 'raised by the integrity monitor',
  operator: 'operator action',
};
export const shortHash = (x) => (x ? `${x.slice(0, 10)}…${x.slice(-6)}` : 'n/a');

export function skeleton(n = 3) { return h('div', { 'aria-busy': 'true', 'aria-label': 'Loading' }, Array.from({ length: n }, () => h('div', { class: 'skeleton' }))); }
export function empty(title, text, action) {
  return h('div', { class: 'empty' }, h('h3', null, title), text && h('p', null, text), action);
}
export function errorBox(msg, retry) {
  return h('div', { class: 'notice bad', role: 'alert' }, h('strong', null, 'Could not load this. '), msg, ' ',
    retry && h('button', { class: 'btn small', onclick: retry }, 'Retry'));
}
export function card(title, hint, ...body) {
  return h('section', { class: 'card' }, (title || hint) && h('header', null, h('h2', null, title), hint && h('span', { class: 'hint' }, hint)), body);
}
export function kv(rows) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of rows) { if (v == null || v === '') continue; dl.append(h('dt', null, k), h('dd', null, v)); }
  return dl;
}

export function toast(msg, kind = '') {
  const t = h('div', { class: `toast ${kind}` }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), kind === 'bad' ? 8000 : 4500);
}
export function confirmDialog(title, text, okLabel = 'Confirm', danger = false) {
  return new Promise((resolve) => {
    const dlg = document.getElementById('dialog');
    clear(dlg).append(
      h('h2', null, title), h('p', { class: 'muted' }, text),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', onclick: () => dlg.close('no') }, 'Cancel'),
        h('button', { class: `btn ${danger ? 'danger' : 'primary'}`, onclick: () => dlg.close('yes') }, okLabel)));
    dlg.onclose = () => resolve(dlg.returnValue === 'yes');
    dlg.showModal();
  });
}

// charts: plain svg sized to the container, rebuilt on resize
export function chart(container, draw) {
  let last = 0;
  const render = () => {
    const w = Math.floor(container.clientWidth);
    if (w < 40 || w === last) return;
    last = w;
    clear(container).append(draw(w));
  };
  const ro = new ResizeObserver(render);
  ro.observe(container);
  render();
  return () => ro.disconnect();
}
export function barChart(series, { height = 170, colors = ['var(--accent)'], labelEvery = 6 } = {}) {
  // series: [{label, values:[...], title}] stacked
  return (w) => {
    const m = { l: 34, r: 8, t: 8, b: 22 }, ih = height - m.t - m.b, iw = w - m.l - m.r;
    const totals = series.map((s) => s.values.reduce((a, b) => a + b, 0));
    const max = Math.max(1, ...totals);
    const bw = Math.min(28, Math.max(2, iw / Math.max(series.length, 1) - 2));
    const g = svg('svg', { viewBox: `0 0 ${w} ${height}`, width: w, height, role: 'img', 'aria-label': 'bar chart' });
    for (const f of [0, .5, 1]) {
      const y = m.t + ih * (1 - f);
      g.append(svg('line', { x1: m.l, x2: w - m.r, y1: y, y2: y, class: 'grid' }), svg('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end' }, fmtNum(Math.round(max * f))));
    }
    series.forEach((s, i) => {
      const x = m.l + (iw / series.length) * i + 1;
      let y = m.t + ih;
      s.values.forEach((v, k) => {
        const bh = (v / max) * ih;
        if (bh <= 0) return;
        y -= bh;
        const r = svg('rect', { x, y, width: bw, height: bh, fill: colors[k % colors.length], rx: 1.5 });
        r.append(svg('title', null, s.title));
        g.append(r);
      });
      if (i % labelEvery === 0) g.append(svg('text', { x: x + bw / 2, y: height - 6, 'text-anchor': 'middle' }, s.label));
    });
    return g;
  };
}
export function areaChart(points, { height = 170, color = 'var(--accent)', fmt = fmtNum, labelEvery = 8 } = {}) {
  // points: [{label, value, title}]
  return (w) => {
    const m = { l: 40, r: 8, t: 8, b: 22 }, ih = height - m.t - m.b, iw = w - m.l - m.r;
    const max = Math.max(1, ...points.map((p) => p.value));
    const g = svg('svg', { viewBox: `0 0 ${w} ${height}`, width: w, height, role: 'img', 'aria-label': 'line chart' });
    for (const f of [0, .5, 1]) {
      const y = m.t + ih * (1 - f);
      g.append(svg('line', { x1: m.l, x2: w - m.r, y1: y, y2: y, class: 'grid' }), svg('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end' }, fmt(Math.round(max * f))));
    }
    if (points.length) {
      const X = (i) => m.l + (points.length === 1 ? iw / 2 : (iw * i) / (points.length - 1));
      const Y = (v) => m.t + ih * (1 - v / max);
      const line = points.map((p, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(p.value).toFixed(1)}`).join('');
      g.append(svg('path', { d: `${line}L${X(points.length - 1)},${m.t + ih}L${X(0)},${m.t + ih}Z`, fill: color, opacity: .15 }),
        svg('path', { d: line, fill: 'none', stroke: color, 'stroke-width': 1.8, 'stroke-linejoin': 'round' }));
      points.forEach((p, i) => {
        const c = svg('circle', { cx: X(i), cy: Y(p.value), r: 6, fill: 'transparent' });
        c.append(svg('title', null, p.title));
        g.append(c);
        if (i % labelEvery === 0) g.append(svg('text', { x: X(i), y: height - 6, 'text-anchor': 'middle' }, p.label));
      });
    }
    return g;
  };
}
