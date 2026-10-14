import { h, svg, put, clear } from '../core/dom.js';
import { fmtCompact, fmtNum, fmtTime, SEVS } from '../core/format.js';
import { sevGlyph } from './icons.js';
import { reduced } from '../core/motion.js';

export const SEV_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
const MAX_POINTS = 240;

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}
function clockLabel(ms, spanMs) {
  const d = new Date(ms), p = (n) => String(n).padStart(2, '0');
  return spanMs > 36 * 3600e3 ? `${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}` : `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}
function downsample(points, bucketMs) {
  if (points.length <= MAX_POINTS) return { points, bucketMs };
  const k = Math.ceil(points.length / MAX_POINTS), out = [];
  for (let i = 0; i < points.length; i += k) {
    const grp = points.slice(i, i + k), values = {};
    grp.forEach((p) => Object.entries(p.values).forEach(([key, v]) => { values[key] = (values[key] || 0) + v; }));
    out.push({ t: grp[0].t, values });
  }
  return { points: out, bucketMs: bucketMs * k };
}

/** responsive time-series chart with crosshair tooltip, keyboard cursor and legend toggles */
export function timeChart(host, cfg0) {
  let cfg = cfg0, hidden = new Set(), cursor = null, width = 0, first = true;
  const tip = h('div', { class: 'ct-tip', hidden: true, 'aria-hidden': 'true' });
  const plot = h('div', { class: 'ct-plot', tabindex: 0, role: 'group' });
  const legend = h('div', { class: 'ct-legend' });
  const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
  clear(host); put(host, plot, legend, live, tip);
  host.classList.add('ct');

  const ro = new ResizeObserver(() => { const w = Math.floor(plot.clientWidth); if (w > 40 && w !== width) { width = w; draw(); } });
  ro.observe(plot);

  function model() {
    const { points, bucketMs } = downsample(cfg.points, cfg.bucketMs);
    const t0 = cfg.domain ? cfg.domain[0] : (points[0]?.t ?? 0), t1 = cfg.domain ? cfg.domain[1] : ((points.at(-1)?.t ?? 0) + bucketMs);
    return { points, bucketMs, t0, t1: Math.max(t1, t0 + bucketMs) };
  }
  function draw() {
    if (!width) return;
    const m = model(), H = cfg.height || 200, mg = { l: 40, r: 10, t: 10, b: 24 }, iw = width - mg.l - mg.r, ih = H - mg.t - mg.b;
    const active = cfg.series.filter((s) => !hidden.has(s.key));
    const stacked = cfg.kind === 'bars' && cfg.stacked !== false;
    const total = (p) => (stacked ? active.reduce((a, s) => a + (p.values[s.key] || 0), 0) : Math.max(0, ...active.map((s) => p.values[s.key] || 0)));
    const ymax = niceMax(Math.max(0, ...m.points.map(total)));
    const X = (t) => mg.l + ((t - m.t0) / (m.t1 - m.t0)) * iw, Y = (v) => mg.t + ih - (v / ymax) * ih;
    const bw = Math.max(2, Math.min(26, (m.bucketMs / (m.t1 - m.t0)) * iw - 2));
    const g = svg('svg', { viewBox: `0 0 ${width} ${H}`, width, height: H, 'aria-hidden': 'true' });
    for (const f of [0, .5, 1]) {
      const y = Y(ymax * f);
      put(g, svg('line', { x1: mg.l, x2: width - mg.r, y1: y, y2: y, class: 'ct-grid' }), svg('text', { x: mg.l - 8, y: y + 4, 'text-anchor': 'end', class: 'ct-axis' }, (cfg.yFormat || fmtCompact)(ymax * f)));
    }
    const nTicks = Math.max(2, Math.floor(iw / 96));
    for (let i = 0; i <= nTicks; i++) {
      const t = m.t0 + ((m.t1 - m.t0) * i) / nTicks;
      put(g, svg('text', { x: Math.min(width - mg.r - 14, Math.max(mg.l + 14, X(t))), y: H - 6, 'text-anchor': 'middle', class: 'ct-axis' }, clockLabel(t, m.t1 - m.t0)));
    }
    const body = svg('g', { class: first && !reduced() ? 'ct-in' : '' });
    if (cfg.kind === 'bars') {
      m.points.forEach((p) => {
        let base = 0;
        const x = X(p.t) + 1;
        (stacked ? active : active.slice(0, 1)).forEach((s) => {
          const v = p.values[s.key] || 0;
          if (!v) return;
          const y1 = Y(base + v), y0 = Y(base);
          put(body, svg('rect', { x, y: y1, width: bw, height: Math.max(1.5, y0 - y1), rx: 1.5, fill: s.color }));
          if (stacked) base += v;
        });
      });
    } else {
      active.forEach((s, si) => {
        const pts = m.points.map((p) => [X(p.t + m.bucketMs / 2), Y(p.values[s.key] || 0)]);
        if (!pts.length) return;
        const d = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('');
        const id = `cg-${Math.random().toString(36).slice(2, 7)}`;
        put(body, svg('defs', null, svg('linearGradient', { id, x1: 0, x2: 0, y1: 0, y2: 1 }, svg('stop', { offset: '0%', 'stop-color': s.color, 'stop-opacity': 0.28 - si * 0.05 }), svg('stop', { offset: '100%', 'stop-color': s.color, 'stop-opacity': 0 }))),
          svg('path', { d: `${d}L${pts.at(-1)[0].toFixed(1)},${Y(0)}L${pts[0][0].toFixed(1)},${Y(0)}Z`, fill: `url(#${id})` }),
          svg('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 1.6, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
      });
    }
    put(g, body);
    const cur = svg('line', { class: 'ct-cursor', y1: mg.t, y2: mg.t + ih, visibility: 'hidden' });
    const marks = svg('g');
    put(g, cur, marks);
    const overlay = svg('rect', { x: mg.l, y: mg.t, width: iw, height: ih, fill: 'transparent', style: cfg.onSelect ? 'cursor:pointer' : null });
    put(g, overlay);
    clear(plot); put(plot, g);
    plot.setAttribute('aria-label', cfg.label ? `${cfg.label}. Use left and right arrows to inspect values${cfg.onSelect ? ', Enter to open' : ''}.` : 'Chart');

    const at = (i) => {
      cursor = i;
      const p = m.points[i];
      if (!p) { cur.setAttribute('visibility', 'hidden'); tip.hidden = true; return; }
      const x = X(p.t) + 1 + bw / 2;
      cur.setAttribute('x1', x); cur.setAttribute('x2', x); cur.setAttribute('visibility', 'visible');
      clear(marks);
      if (cfg.kind !== 'bars') active.forEach((s) => put(marks, svg('circle', { cx: X(p.t + m.bucketMs / 2), cy: Y(p.values[s.key] || 0), r: 3.5, fill: s.color, stroke: 'var(--panel)', 'stroke-width': 1.5 })));
      clear(tip);
      put(tip, h('div', { class: 'ct-tt' }, fmtTime(new Date(p.t).toISOString())), cfg.series.map((s) => h('div', { class: 'ct-row' }, h('i', { style: `background:${s.color}` }), h('span', null, s.label), h('b', { class: 'num' }, (cfg.tipFormat || fmtNum)(p.values[s.key] || 0)))),
        cfg.onSelect && h('div', { class: 'ct-hint' }, 'Click to open these records'));
      tip.hidden = false;
      const pr = plot.getBoundingClientRect(), hr = host.getBoundingClientRect(), tw = tip.offsetWidth;
      const left = Math.max(0, Math.min(width - tw, x - tw / 2)) + (pr.left - hr.left);
      tip.style.left = `${left}px`;
      tip.style.top = `${Math.max(0, Y(total(p)) - tip.offsetHeight - 10) + (pr.top - hr.top)}px`;
      live.textContent = `${fmtTime(new Date(p.t).toISOString(), false)}: ${active.map((s) => `${s.label} ${p.values[s.key] || 0}`).join(', ')}`;
    };
    const idxFromX = (clientX) => {
      const r = overlay.getBoundingClientRect(), t = m.t0 + ((clientX - r.left) / r.width) * (m.t1 - m.t0);
      let best = -1, d = Infinity;
      m.points.forEach((p, i) => { const dd = Math.abs(p.t + m.bucketMs / 2 - t); if (dd < d) { d = dd; best = i; } });
      return d <= m.bucketMs * 1.2 ? best : -1;
    };
    overlay.addEventListener('pointermove', (e) => at(idxFromX(e.clientX)));
    overlay.addEventListener('pointerleave', () => { if (document.activeElement !== plot) at(-1); });
    overlay.addEventListener('click', (e) => { const i = idxFromX(e.clientX); if (i >= 0 && cfg.onSelect) cfg.onSelect({ t: m.points[i].t, end: m.points[i].t + m.bucketMs, values: m.points[i].values }); });
    plot.onkeydown = (e) => {
      if (!m.points.length) return;
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); at(Math.max(0, Math.min(m.points.length - 1, (cursor ?? (e.key === 'ArrowRight' ? -1 : m.points.length)) + (e.key === 'ArrowRight' ? 1 : -1)))); }
      else if (e.key === 'Enter' && cursor != null && m.points[cursor] && cfg.onSelect) cfg.onSelect({ t: m.points[cursor].t, end: m.points[cursor].t + m.bucketMs, values: m.points[cursor].values });
      else if (e.key === 'Escape') at(-1);
    };
    plot.onblur = () => at(-1);
    if (cursor != null && cursor < m.points.length && document.activeElement === plot) at(cursor);
    first = false;
    drawLegend();
    if (!m.points.length) put(plot, h('div', { class: 'ct-empty' }, cfg.emptyText || 'No data in this range'));
  }
  function drawLegend() {
    clear(legend);
    if (cfg.series.length < 2 && !cfg.legendAlways) return;
    cfg.series.forEach((s) => put(legend, h('button', { type: 'button', class: 'ct-key', 'aria-pressed': String(!hidden.has(s.key)), onclick: () => { hidden.has(s.key) ? hidden.delete(s.key) : hidden.add(s.key); draw(); } }, h('i', { style: `background:${s.color}` }), s.label)));
  }
  return { update(next) { cfg = next; draw(); }, destroy() { ro.disconnect(); } };
}

/** tiny trend line for a stat. only used where a real series exists */
export function sparkline(values, { color = 'var(--accent)', w = 96, h: ht = 26 } = {}) {
  if (!values || values.length < 2) return h('span');
  const max = Math.max(...values, 1), step = w / (values.length - 1);
  const pts = values.map((v, i) => [i * step, ht - 2 - (v / max) * (ht - 4)]);
  const d = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('');
  return svg('svg', { viewBox: `0 0 ${w} ${ht}`, width: w, height: ht, class: 'spark', 'aria-hidden': 'true' },
    svg('path', { d: `${d}L${w},${ht}L0,${ht}Z`, fill: color, opacity: 0.14 }), svg('path', { d, fill: 'none', stroke: color, 'stroke-width': 1.4, 'stroke-linejoin': 'round' }),
    svg('circle', { cx: pts.at(-1)[0], cy: pts.at(-1)[1], r: 2, fill: color }));
}

/** ranked horizontal bars that double as filters */
export function distBars(rows, { onPick, selected, fmt = fmtNum, color = 'var(--accent)', empty = 'Nothing observed in this range.' } = {}) {
  if (!rows.length) return h('p', { class: 'faint small', style: 'padding:6px 0' }, empty);
  const max = Math.max(1, ...rows.map((r) => r.value));
  return h('ul', { class: 'dist' }, rows.map((r) => {
    const on = String(selected) === String(r.key);
    const inner = [h('span', { class: `dist-k${r.mono === false ? '' : ' mono'}`, title: r.title || r.label }, r.label), h('span', { class: 'dist-bar' }, h('span', { style: `width:${Math.max(2, (r.value / max) * 100)}%;background:${r.color || color}` })), h('span', { class: 'dist-v num' }, fmt(r.value))];
    return h('li', null, onPick ? h('button', { type: 'button', class: 'dist-row', 'aria-pressed': String(on), 'data-tip': on ? 'Clear filter' : `Filter by ${r.label}`, onclick: () => onPick(on ? null : r.key) }, inner) : h('div', { class: 'dist-row' }, inner));
  }));
}

/** severity composition as one stacked bar with a shape-coded legend */
export function sevComposition(counts, { onPick } = {}) {
  const total = SEVS.reduce((a, s) => a + (counts[s] || 0), 0);
  const bar = h('div', { class: 'sevbar', role: 'img', 'aria-label': total ? SEVS.filter((s) => counts[s]).map((s) => `${counts[s]} ${s.toLowerCase()}`).join(', ') : 'no alerts' });
  SEVS.forEach((s) => counts[s] && put(bar, h('span', { style: `flex:${counts[s]};background:${SEV_COLOR[s]}`, title: `${s}: ${counts[s]}` })));
  if (!total) put(bar, h('span', { style: 'flex:1;background:var(--line)' }));
  const legend = h('div', { class: 'sevlegend' }, SEVS.map((s) => {
    const el = h(onPick ? 'button' : 'span', { class: `sev sev-${s}${counts[s] ? '' : ' zero'}`, type: onPick ? 'button' : null, onclick: onPick && counts[s] ? () => onPick(s) : null }, sevGlyph(s), s.charAt(0) + s.slice(1).toLowerCase(), h('b', { class: 'num' }, String(counts[s] || 0)));
    return el;
  }));
  return h('div', { class: 'sevcomp' }, bar, legend);
}
