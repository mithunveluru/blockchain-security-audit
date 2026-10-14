import { svg } from '../core/dom.js';

// original 24px stroke icons: each entry is a list of [tag, attributes]
const P = (d) => ['path', { d }];
const C = (cx, cy, r) => ['circle', { cx, cy, r }];
const R = (x, y, width, height, rx = 2) => ['rect', { x, y, width, height, rx }];
const ICONS = {
  overview: [R(3.5, 3.5, 7, 8), R(13.5, 3.5, 7, 4.5), R(13.5, 11, 7, 9.5), R(3.5, 14.5, 7, 6)],
  alerts: [P('M12 3.2 19.5 6v5.3c0 4.4-3.1 8.1-7.5 9.5-4.4-1.4-7.5-5.1-7.5-9.5V6z'), P('M12 8.2v4.2'), P('M12 15.6h.01')],
  network: [C(5.5, 6, 2), C(18.5, 6, 2), C(12, 18.5, 2), P('M7.3 7.2 10.8 16.7'), P('M16.7 7.2 13.2 16.7'), P('M7.5 6h9')],
  ledger: [R(3.5, 4, 8, 7, 2), R(12.5, 13, 8, 7, 2), P('M11.5 7.5H14a2 2 0 0 1 2 2v3.5'), P('M7.5 11v2.5a2 2 0 0 0 2 2H12.5')],
  health: [P('M3 12.5h4l2.2-6 4.1 12 2.4-6H21')],
  copilot: [P('M12 3.5l1.9 5.2L19 10.6l-5.1 1.9L12 17.7l-1.9-5.2L5 10.6l5.1-1.9z'), P('M18.5 16.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z')],
  settings: [P('M4 7h9'), P('M17 7h3'), P('M4 17h3'), P('M11 17h9'), C(15, 7, 2), C(9, 17, 2)],
  search: [C(10.5, 10.5, 6), P('m15 15 5 5')],
  command: [P('M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z')],
  sun: [C(12, 12, 4), P('M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4')],
  moon: [P('M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z')],
  right: [P('m9 6 6 6-6 6')], down: [P('m6 9 6 6 6-6')], left: [P('m15 6-6 6 6 6')], up: [P('m6 15 6-6 6 6')],
  x: [P('M6 6l12 12M18 6 6 18')], check: [P('m5 12.5 4.5 4.5L19 7.5')],
  warn: [P('M12 4 21 19.5H3z'), P('M12 10v4.5'), P('M12 17.3h.01')],
  info: [C(12, 12, 9), P('M12 11v5'), P('M12 7.8h.01')],
  download: [P('M12 4v11'), P('m7 10.5 5 5 5-5'), P('M5 20h14')],
  refresh: [P('M20 11a8 8 0 0 0-14-4.5L4 9'), P('M4 4.5V9h4.5'), P('M4 13a8 8 0 0 0 14 4.5L20 15'), P('M20 19.5V15h-4.5')],
  filter: [P('M4 5h16l-6 7.5V19l-4-2v-4.5z')],
  arrow: [P('M5 12h14'), P('m13 6 6 6-6 6')], out: [P('M8 16 17 7'), P('M9 7h8v8')],
  clock: [C(12, 12, 9), P('M12 7v5.2l3.3 2')], cpu: [R(6, 6, 12, 12, 2), P('M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3')],
  lock: [R(5, 10.5, 14, 9.5, 2), P('M8 10.5V8a4 4 0 0 1 8 0v2.5')],
  wifi: [P('M3.5 9.5a12 12 0 0 1 17 0'), P('M6.5 12.8a8 8 0 0 1 11 0'), P('M9.5 16a4 4 0 0 1 5 0'), P('M12 19.3h.01')],
  wifiOff: [P('M3 3l18 18'), P('M9.5 16a4 4 0 0 1 5 0'), P('M12 19.3h.01'), P('M6.5 12.8a8 8 0 0 1 3-1.8'), P('M3.5 9.5A12 12 0 0 1 8 6.8')],
  play: [P('M7 5v14l12-7z')], panel: [R(3.5, 4.5, 17, 15, 2.5), P('M9.5 4.5v15')], more: [C(5, 12, 1), C(12, 12, 1), C(19, 12, 1)],
  copy: [R(8.5, 8.5, 11, 11, 2), P('M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2')],
  shield: [P('M12 3.2 19.5 6v5.3c0 4.4-3.1 8.1-7.5 9.5-4.4-1.4-7.5-5.1-7.5-9.5V6z'), P('m9 12 2.2 2.2L15.5 10')],
  sparkle: [P('M12 4l1.6 4.4L18 10l-4.4 1.6L12 16l-1.6-4.4L6 10l4.4-1.6z')], send: [P('M4 12 20 4l-4 16-4.5-6.5z'), P('M11.5 13.5 20 4')],
  stop: [R(6.5, 6.5, 11, 11, 2)], link: [P('M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1'), P('M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1')],
  list: [P('M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01')], graph: [C(6, 17, 2), C(12, 7, 2), C(18, 15, 2), P('M7.5 15.6 10.6 8.7M13.7 8.4l3.2 5.2')],
};

export function icon(name, cls = 'ico', label) {
  const parts = ICONS[name] || ICONS.info;
  const el = svg('svg', { viewBox: '0 0 24 24', class: cls, 'aria-hidden': label ? null : 'true', role: label ? 'img' : null, 'aria-label': label || null, focusable: 'false' },
    ...parts.map(([tag, a]) => svg(tag, a)));
  return el;
}

// severity glyphs differ by shape so the level is readable without colour
const GLYPH = {
  CRITICAL: ['polygon', { points: '6,0.8 11.2,6 6,11.2 0.8,6' }],
  HIGH: ['polygon', { points: '6,1 11.2,10.6 0.8,10.6' }],
  MEDIUM: ['circle', { cx: 6, cy: 6, r: 4.6 }],
  LOW: ['circle', { cx: 6, cy: 6, r: 3.6, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.7 }],
  INFO: ['rect', { x: 1.5, y: 5, width: 9, height: 2, rx: 1 }],
};
export function sevGlyph(sev) {
  const [tag, a] = GLYPH[sev] || GLYPH.INFO;
  return svg('svg', { viewBox: '0 0 12 12', 'aria-hidden': 'true' }, svg(tag, a));
}
export function logoMark(size = 22) {
  return svg('svg', { viewBox: '0 0 24 24', width: size, height: size, 'aria-hidden': 'true' },
    svg('rect', { x: 2.5, y: 2.5, width: 11, height: 11, rx: 3, fill: 'none', stroke: 'var(--accent)', 'stroke-width': 2 }),
    svg('rect', { x: 10.5, y: 10.5, width: 11, height: 11, rx: 3, fill: 'var(--accent)', opacity: 0.95 }),
    svg('path', { d: 'M13.5 8.5h2a2 2 0 0 1 2 2v0', stroke: 'var(--accent-2)', 'stroke-width': 2, fill: 'none', 'stroke-linecap': 'round' }));
}
