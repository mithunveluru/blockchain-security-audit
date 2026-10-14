import { h, put, clear } from '../core/dom.js';
import { reduced } from '../core/motion.js';
import { fmtBytes, fmtNum } from '../core/format.js';

const INTERNAL = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./, /^169\.254\./];
export const isInternal = (ip) => INTERNAL.some((r) => r.test(ip));
const RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const MAX_NODES = 44;

/** relationship map of who talks to whom, drawn from the live flow table. 2d canvas, settles once, no idle animation */
export function createTopology(host, { onPick, label }) {
  const canvas = h('canvas', { tabindex: 0, role: 'img', 'aria-label': label || 'Network relationship map. Use the flow table for the same data as text.' });
  const tip = h('div', { class: 'tipc', hidden: true });
  const legend = h('div', { class: 'overlay' }, h('span', null, h('i', { style: 'background:var(--accent)' }), 'internal'), h('span', null, h('i', { style: 'background:var(--text-3)' }), 'external'), h('span', null, h('i', { style: 'background:transparent;border:2px solid var(--high)' }), 'has alerts'));
  clear(host); put(host, canvas, legend, tip);
  const ctx2d = canvas.getContext('2d');
  const pos = new Map();          // positions survive refreshes so the map does not jump
  let nodes = [], edges = [], W = 0, H = 0, dpr = 1, hover = null, selected = null, focusIdx = -1, raf = 0, visible = true;
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

  function build(flows, alertsBySrc) {
    const w = new Map(), ed = new Map();
    flows.forEach((f) => {
      [f.initiator, f.initiator === f.src_ip ? f.dst_ip : f.src_ip].forEach((ip) => { const n = w.get(ip) || { ip, bytes: 0, packets: 0, flows: 0 }; n.bytes += f.bytes; n.packets += f.packets; n.flows++; w.set(ip, n); });
      const a = f.initiator, b = f.initiator === f.src_ip ? f.dst_ip : f.src_ip, k = `${a}>${b}`;
      const e = ed.get(k) || { a, b, bytes: 0, flows: 0 }; e.bytes += f.bytes; e.flows++; ed.set(k, e);
    });
    nodes = [...w.values()].sort((x, y) => y.packets - x.packets).slice(0, MAX_NODES);
    const keep = new Set(nodes.map((n) => n.ip));
    nodes.forEach((n) => { n.alert = alertsBySrc.get(n.ip) || null; n.internal = isInternal(n.ip); });
    edges = [...ed.values()].filter((e) => keep.has(e.a) && keep.has(e.b));
    const idx = new Map(nodes.map((n, i) => [n.ip, i]));
    edges.forEach((e) => { e.i = idx.get(e.a); e.j = idx.get(e.b); });
    nodes.forEach((n, i) => {
      if (!pos.has(n.ip)) { let s = 7; for (const c of n.ip) s = (s * 31 + c.charCodeAt(0)) >>> 0; const ang = (s % 628) / 100, r = 0.25 + ((s >> 8) % 60) / 100; pos.set(n.ip, { x: 0.5 + Math.cos(ang) * r * 0.5, y: 0.5 + Math.sin(ang) * r * 0.5, vx: 0, vy: 0 }); }
      n.p = pos.get(n.ip); n.r = 4 + Math.min(9, Math.sqrt(n.packets) / 3);
    });
    [...pos.keys()].forEach((k) => { if (!keep.has(k)) pos.delete(k); });
  }
  function settle(iters) {
    const area = Math.max(1, W * H), k = Math.sqrt(area / Math.max(nodes.length, 1)) * 1.15;
    for (let it = 0; it < iters; it++) {
      const cool = 1 - it / iters;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i].p, b = nodes[j].p;
          let dx = (a.x - b.x) * W, dy = (a.y - b.y) * H, d2 = dx * dx + dy * dy + 0.01;
          const f = (k * k) / d2, d = Math.sqrt(d2);
          dx = (dx / d) * f; dy = (dy / d) * f;
          a.vx += dx; a.vy += dy; b.vx -= dx; b.vy -= dy;
        }
      }
      edges.forEach((e) => {
        const a = nodes[e.i].p, b = nodes[e.j].p;
        const dx = (b.x - a.x) * W, dy = (b.y - a.y) * H, d = Math.sqrt(dx * dx + dy * dy) + 0.01, f = ((d - k) / k) * 0.4;
        a.vx += (dx / d) * f * k * 0.05; a.vy += (dy / d) * f * k * 0.05; b.vx -= (dx / d) * f * k * 0.05; b.vy -= (dy / d) * f * k * 0.05;
      });
      nodes.forEach((n) => {
        n.p.vx += (0.5 - n.p.x) * W * 0.006; n.p.vy += (0.5 - n.p.y) * H * 0.006;
        n.p.x += Math.max(-8, Math.min(8, n.p.vx * 0.05 * cool)) / W; n.p.y += Math.max(-8, Math.min(8, n.p.vy * 0.05 * cool)) / H;
        n.p.vx *= 0.55; n.p.vy *= 0.55;
        n.p.x = Math.max(0.05, Math.min(0.95, n.p.x)); n.p.y = Math.max(0.08, Math.min(0.88, n.p.y));
      });
    }
  }
  const SEVC = { CRITICAL: '--crit', HIGH: '--high', MEDIUM: '--med', LOW: '--low', INFO: '--info' };
  function draw() {
    raf = 0;
    if (!W || !visible) return;
    const c = ctx2d;
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, W, H);
    const accent = css('--accent'), mute = css('--text-3'), line = css('--line-strong'), text = css('--text'), panel = css('--panel');
    const focus = hover ?? selected, nb = new Set();
    if (focus != null) { nb.add(focus); edges.forEach((e) => { if (e.i === focus) nb.add(e.j); if (e.j === focus) nb.add(e.i); }); }
    const maxB = Math.max(1, ...edges.map((e) => e.bytes));
    edges.forEach((e) => {
      const a = nodes[e.i].p, b = nodes[e.j].p, hot = focus != null && (e.i === focus || e.j === focus);
      c.globalAlpha = focus != null ? (hot ? 0.9 : 0.12) : 0.5;
      c.strokeStyle = hot ? accent : line; c.lineWidth = 0.8 + (e.bytes / maxB) * 2.2;
      const x1 = a.x * W, y1 = a.y * H, x2 = b.x * W, y2 = b.y * H, mx = (x1 + x2) / 2 + (y2 - y1) * 0.08, my = (y1 + y2) / 2 - (x2 - x1) * 0.08;
      c.beginPath(); c.moveTo(x1, y1); c.quadraticCurveTo(mx, my, x2, y2); c.stroke();
    });
    nodes.forEach((n, i) => {
      const dim = focus != null && !nb.has(i);
      const x = n.p.x * W, y = n.p.y * H;
      c.globalAlpha = dim ? 0.25 : 1;
      if (n.alert) { c.strokeStyle = css(SEVC[n.alert.sev]); c.lineWidth = 2; c.beginPath(); c.arc(x, y, n.r + 4, 0, 6.2832); c.stroke(); }
      c.fillStyle = n.internal ? accent : mute; c.beginPath(); c.arc(x, y, n.r, 0, 6.2832); c.fill();
      c.strokeStyle = panel; c.lineWidth = 1.5; c.beginPath(); c.arc(x, y, n.r, 0, 6.2832); c.stroke();
      if (i === focus || i === focusIdx || (n.alert && !dim) || n.r > 9) { c.globalAlpha = dim ? 0.3 : 1; c.fillStyle = text; c.font = '500 11px "JetBrains Mono", monospace'; c.textAlign = 'center'; c.fillText(n.ip, x, y - n.r - (n.alert ? 9 : 6)); }
    });
    c.globalAlpha = 1;
    if (focusIdx >= 0 && document.activeElement === canvas) { const n = nodes[focusIdx]; if (n) { c.strokeStyle = accent; c.lineWidth = 2; c.setLineDash([3, 3]); c.beginPath(); c.arc(n.p.x * W, n.p.y * H, n.r + 8, 0, 6.2832); c.stroke(); c.setLineDash([]); } }
  }
  const schedule = () => { if (!raf) raf = requestAnimationFrame(draw); };
  function resize() {
    const r = host.getBoundingClientRect();
    if (r.width < 40) return;
    dpr = Math.min(2, window.devicePixelRatio || 1); W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    settle(reduced() ? 260 : 160); schedule();
  }
  const ro = new ResizeObserver(resize); ro.observe(host);
  const io = new IntersectionObserver((e) => { visible = e[0].isIntersecting; if (visible) schedule(); }); io.observe(host);
  const theme = new MutationObserver(schedule); theme.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  function nodeAt(x, y) { let best = null, d = 1e9; nodes.forEach((n, i) => { const dd = Math.hypot(n.p.x * W - x, n.p.y * H - y); if (dd < n.r + 8 && dd < d) { d = dd; best = i; } }); return best; }
  function showTip(i) {
    if (i == null) { tip.hidden = true; return; }
    const n = nodes[i];
    clear(tip); put(tip, h('div', { class: 'mono', style: 'font-weight:600' }, n.ip), h('div', { class: 'faint' }, `${n.internal ? 'Internal' : 'External'} · ${n.flows} flows`), h('div', null, `${fmtNum(n.packets)} packets · ${fmtBytes(n.bytes)}`), n.alert && h('div', { style: `color:var(${SEVC[n.alert.sev]})` }, `${n.alert.count} alert${n.alert.count > 1 ? 's' : ''}, up to ${n.alert.sev.toLowerCase()}`), h('div', { class: 'faint tiny' }, 'Click to filter flows'));
    tip.hidden = false;
    tip.style.left = `${Math.min(W - 200, Math.max(6, n.p.x * W + 14))}px`; tip.style.top = `${Math.max(6, Math.min(H - 90, n.p.y * H - 20))}px`;
  }
  canvas.addEventListener('pointermove', (e) => { const r = canvas.getBoundingClientRect(), i = nodeAt(e.clientX - r.left, e.clientY - r.top); if (i !== hover) { hover = i; canvas.style.cursor = i == null ? 'default' : 'pointer'; showTip(i); schedule(); } });
  canvas.addEventListener('pointerleave', () => { hover = null; showTip(null); schedule(); });
  canvas.addEventListener('click', (e) => { const r = canvas.getBoundingClientRect(), i = nodeAt(e.clientX - r.left, e.clientY - r.top); if (i != null) onPick(nodes[i].ip === selectedIp() ? null : nodes[i].ip); });
  canvas.addEventListener('keydown', (e) => {
    if (!nodes.length) return;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); focusIdx = (focusIdx + 1) % nodes.length; }
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); focusIdx = (focusIdx - 1 + nodes.length) % nodes.length; }
    else if (e.key === 'Enter' && focusIdx >= 0) { e.preventDefault(); onPick(nodes[focusIdx].ip); return; }
    else if (e.key === 'Escape') { focusIdx = -1; showTip(null); schedule(); return; }
    else return;
    showTip(focusIdx); canvas.setAttribute('aria-label', `${nodes[focusIdx].ip}, ${nodes[focusIdx].flows} flows. Press Enter to filter.`); schedule();
  });
  canvas.addEventListener('blur', () => { focusIdx = -1; showTip(null); schedule(); });
  canvas.addEventListener('focus', schedule);
  const selectedIp = () => (selected != null && nodes[selected] ? nodes[selected].ip : null);
  return {
    update(flows, alerts) {
      const by = new Map();
      alerts.forEach((a) => { if (!a.source) return; const cur = by.get(a.source) || { sev: 'INFO', count: 0 }; cur.count++; if (RANK[a.severity] > RANK[cur.sev]) cur.sev = a.severity; by.set(a.source, cur); });
      build(flows, by);
      if (W) { settle(reduced() ? 200 : 60); schedule(); }
      canvas.setAttribute('aria-label', `Network relationship map with ${nodes.length} addresses and ${edges.length} connections. Use the flow table for the same data as text.`);
      return nodes.length;
    },
    select(ip) { selected = ip ? nodes.findIndex((n) => n.ip === ip) : null; if (selected === -1) selected = null; schedule(); },
    destroy() { ro.disconnect(); io.disconnect(); theme.disconnect(); cancelAnimationFrame(raf); },
  };
}
