import { h, put, clear, scope } from '../core/dom.js';
import { icon, sevGlyph } from './icons.js';
import { fmtTime, ago, typeName } from '../core/format.js';
import { stagger } from '../core/motion.js';

// ---- indicators --------------------------------------------------------------------------
export const sev = (s) => h('span', { class: `sev sev-${s}` }, sevGlyph(s), s.charAt(0) + s.slice(1).toLowerCase());
export const state = (s, label) => h('span', { class: `state state-${s}` }, h('span', { class: 'dot' }), label || String(s).replace('_', ' '));
export const tag = (text, cls = '', title) => h('span', { class: `tag ${cls}`, title }, text);
export const provTag = (p) => (p === 'live_capture' || p === 'historical' ? (p === 'historical' ? tag('legacy', '', 'recorded by an earlier version') : null)
  : tag(p === 'simulation' ? 'simulated' : p.replace('_', ' '), 'sim', 'not observed network traffic'));
export const time = (iso, { rel = false } = {}) => h('time', { datetime: iso || '', title: fmtTime(iso) }, rel ? ago(iso) : fmtTime(iso));
export const statusLabel = (s) => state(s === 'resolved' ? 'ok' : s === 'investigating' ? 'warn' : s === 'false_positive' ? 'disabled' : 'unknown', s.replace('_', ' '));

// ---- layout primitives -------------------------------------------------------------------
export function panel({ title, hint, actions, flush } = {}, ...body) {
  return h('section', { class: 'panel' },
    (title || actions) && h('div', { class: 'ph' }, h('div', { class: 'row' }, title && h('h2', null, title), hint && h('span', { class: 'hint' }, hint)), actions && h('div', { class: 'row' }, actions)),
    h('div', { class: `pb${flush ? ' flush' : ''}` }, body));
}
export function kv(rows) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of rows) { if (v == null || v === '' || v === false) continue; put(dl, h('dt', null, k), h('dd', null, v)); }
  return dl;
}
export function notice(kind, ...kids) {
  const ic = { warn: 'warn', bad: 'warn', ok: 'check', info: 'info' }[kind] || 'info';
  return h('div', { class: `notice ${kind}`, role: kind === 'bad' ? 'alert' : 'status' }, icon(ic), h('div', null, kids));
}
export function empty(title, text, glyph = 'search', ...actions) {
  return h('div', { class: 'empty' }, h('div', { class: 'glyph' }, icon(glyph)), h('h2', null, title), text && h('p', null, text), actions.length ? h('div', { class: 'row', style: 'margin-top:8px' }, actions) : null);
}
export function skeleton(lines = 4, widths = [92, 78, 86, 64, 80]) {
  return h('div', { 'aria-busy': 'true', 'aria-label': 'Loading', style: 'display:grid;gap:10px;padding:4px 0' }, Array.from({ length: lines }, (_, i) => h('div', { class: 'skeleton', style: `width:${widths[i % widths.length]}%` })));
}
// error boundary: a failing widget shows a retry state without taking the page down
export async function boundary(host, build, { onError } = {}) {
  const run = async () => {
    clear(host).append(skeleton(3));
    try { const out = await build(); clear(host); if (out) put(host, out); }
    catch (e) {
      if (e.name === 'AbortError') return;
      onError && onError(e);
      clear(host); put(host, notice('bad', h('strong', null, 'Could not load this section. '), e.message || 'Unexpected error. ', h('button', { class: 'btn sm', style: 'margin-left:8px', onclick: run }, 'Retry')));
    }
  };
  return run();
}
export function btn(label, opts = {}) {
  const { kind = '', size = '', cls = '', ic, onclick, title, disabled, type = 'button', ...rest } = opts;
  return h('button', { ...rest, class: `btn ${kind} ${size} ${cls}`.replace(/\s+/g, ' ').trim(), type, onclick, title, disabled }, ic && icon(ic), label);
}
export const iconBtn = (name, label, onclick, extra = {}) => h('button', { class: 'icon-btn', type: 'button', 'aria-label': label, 'data-tip': label, onclick, ...extra }, icon(name));
export function seg(options, current, onChange, label) {
  const el = h('div', { class: 'seg', role: 'group', 'aria-label': label });
  const draw = (cur) => { clear(el); options.forEach((o) => put(el, h('button', { type: 'button', 'aria-pressed': String(o.value === cur), onclick: () => { onChange(o.value); draw(o.value); } }, o.label ?? o.value))); };
  draw(current);
  return el;
}
export function tabs(items, current, onChange, label = 'Sections') {
  const el = h('div', { class: 'tabs', role: 'tablist', 'aria-label': label });
  items.forEach((t) => put(el, h('button', { type: 'button', role: 'tab', id: `tab-${t.id}`, 'aria-selected': String(t.id === current), 'aria-controls': `pane-${t.id}`, tabindex: t.id === current ? 0 : -1, onclick: () => onChange(t.id) },
    t.label, t.count != null && h('span', { class: 'count' }, t.count))));
  el.addEventListener('keydown', (e) => {
    const btns = [...el.querySelectorAll('[role="tab"]')], i = btns.indexOf(document.activeElement);
    if (i < 0 || !['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
    e.preventDefault();
    const n = e.key === 'Home' ? 0 : e.key === 'End' ? btns.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length;
    btns[n].focus(); btns[n].click();
  });
  return el;
}
export function pager({ page, pages, total, size, onPage, noun = 'items' }) {
  const from = total ? (page - 1) * size + 1 : 0, to = Math.min(total, page * size);
  return h('div', { class: 'pager' }, h('span', { class: 'num' }, `${from}–${to} of ${total.toLocaleString('en-US')} ${noun}`),
    h('div', { class: 'row' }, btn('Previous', { size: 'sm', ic: 'left', disabled: page <= 1, onclick: () => onPage(page - 1) }), btn('Next', { size: 'sm', disabled: page >= pages, onclick: () => onPage(page + 1) })));
}
export const alertTitle = (a) => typeName(a.type);

// ---- toasts ------------------------------------------------------------------------------
export function toast(msg, kind = 'info', ms) {
  const host = document.getElementById('toasts');
  const t = h('div', { class: `toast ${kind}`, role: kind === 'bad' ? 'alert' : 'status' }, icon(kind === 'bad' ? 'warn' : kind === 'ok' ? 'check' : 'info'), h('div', null, msg));
  put(host, t);
  while (host.children.length > 4) host.firstChild.remove();
  setTimeout(() => { t.classList.add('leaving'); setTimeout(() => t.remove(), 220); }, ms || (kind === 'bad' ? 8000 : 4200));
}

// ---- dialogs -----------------------------------------------------------------------------
export function confirmDialog({ title, text, ok = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { class: 'dlg', 'aria-labelledby': 'dlg-t' },
      h('div', { class: 'db' }, h('h2', { id: 'dlg-t', style: 'font-size:15px' }, title), h('p', { class: 'muted' }, text)),
      h('form', { method: 'dialog', class: 'df' }, h('button', { class: 'btn', value: 'no', autofocus: danger }, 'Cancel'), h('button', { class: `btn ${danger ? 'danger' : 'primary'}`, value: 'yes', autofocus: !danger }, ok)));
    dlg.addEventListener('close', () => { resolve(dlg.returnValue === 'yes'); dlg.remove(); });
    document.body.append(dlg);
    dlg.showModal();
  });
}

// ---- tooltips: hover and keyboard focus, never mouse-only ----------------------------------
let tipEl = null;
export function initTooltips() {
  const show = (el) => {
    const text = el.dataset.tip;
    if (!text) return;
    hide();
    tipEl = h('div', { class: 'tip', role: 'tooltip' }, text);
    document.body.append(tipEl);
    const r = el.getBoundingClientRect(), t = tipEl.getBoundingClientRect();
    const below = r.top < 48 || el.dataset.tipSide === 'bottom';
    tipEl.style.left = `${Math.max(8, Math.min(innerWidth - t.width - 8, r.left + r.width / 2 - t.width / 2))}px`;
    tipEl.style.top = `${below ? r.bottom + 8 : r.top - t.height - 8}px`;
  };
  const hide = () => { tipEl && tipEl.remove(); tipEl = null; };
  document.addEventListener('pointerover', (e) => { const el = e.target.closest?.('[data-tip]'); el ? show(el) : hide(); });
  document.addEventListener('focusin', (e) => { const el = e.target.closest?.('[data-tip]'); el && show(el); });
  document.addEventListener('focusout', hide);
  document.addEventListener('pointerdown', hide);
  document.addEventListener('keydown', (e) => e.key === 'Escape' && hide());
}

// ---- popover menu ------------------------------------------------------------------------
export function openMenu(anchor, items) {
  const prev = document.activeElement;
  const m = h('div', { class: 'menu', role: 'menu' }, items.map((it) => it === '-' ? h('hr') : h('button', { role: 'menuitem', type: 'button', onclick: () => { close(); it.run(); } }, it.icon && icon(it.icon), it.label)));
  const close = () => { m.remove(); off(); prev && prev.focus && prev.focus(); };
  const s = scope();
  document.body.append(m);
  const r = anchor.getBoundingClientRect(), mr = m.getBoundingClientRect();
  m.style.left = `${Math.max(8, Math.min(innerWidth - mr.width - 8, r.right - mr.width))}px`;
  m.style.top = `${r.bottom + 6 > innerHeight - mr.height ? r.top - mr.height - 6 : r.bottom + 6}px`;
  const off = () => s.dispose();
  s.on(document, 'pointerdown', (e) => { if (!m.contains(e.target) && e.target !== anchor) close(); });
  s.on(document, 'keydown', (e) => {
    const b = [...m.querySelectorAll('button')], i = b.indexOf(document.activeElement);
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); b[(i + 1) % b.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); b[(i - 1 + b.length) % b.length].focus(); }
  });
  m.querySelector('button')?.focus();
  return close;
}
export { stagger };
