import { api, qs } from '../core/api.js';
import { h, put, clear, debounce } from '../core/dom.js';
import { icon } from './icons.js';
import { typeName, place } from '../core/format.js';
import { sev } from './components.js';

/** command palette: jump to pages, run actions, find alerts by id, address or text */
export function openPalette({ commands, go, state }) {
  const prev = document.activeElement;
  let items = [], sel = 0, ctl = null;
  const input = h('input', { type: 'text', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'pal-list', 'aria-autocomplete': 'list', placeholder: 'Search pages, alerts, addresses, commands…', autocomplete: 'off', spellcheck: 'false' });
  const list = h('ul', { id: 'pal-list', role: 'listbox', 'aria-label': 'Results' });
  const wrap = h('div', { class: 'palette-wrap', onpointerdown: (e) => { if (e.target === wrap) close(); } },
    h('div', { class: 'palette', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Command palette' }, input, list,
      h('div', { class: 'foot' }, h('span', null, h('span', { class: 'kbd' }, '↑↓'), ' navigate'), h('span', null, h('span', { class: 'kbd' }, '↵'), ' open'), h('span', null, h('span', { class: 'kbd' }, 'esc'), ' close'))));
  const close = () => { ctl && ctl.abort(); wrap.remove(); document.removeEventListener('keydown', onKey, true); prev && prev.focus && prev.focus(); };

  const run = (it) => { close(); it.run(); };
  function render() {
    clear(list);
    let group = '';
    items.forEach((it, i) => {
      if (it.group !== group) { group = it.group; put(list, h('li', { class: 'grp', role: 'presentation' }, group)); }
      put(list, h('li', { role: 'option', id: `pal-${i}`, 'aria-selected': String(i === sel), onclick: () => run(it), onpointermove: () => { if (sel !== i) { sel = i; mark(); } } }, it.icon ? icon(it.icon) : null, h('span', null, it.label), it.sev ? sev(it.sev) : null, it.hint && h('span', { class: 'hint' }, it.hint)));
    });
    if (!items.length) put(list, h('li', { role: 'presentation', style: 'padding:18px;color:var(--text-3)' }, 'No matches'));
    input.setAttribute('aria-activedescendant', items.length ? `pal-${sel}` : '');
  }
  function mark() { list.querySelectorAll('[role="option"]').forEach((el, i) => { el.setAttribute('aria-selected', String(i === sel)); if (i === sel) el.scrollIntoView({ block: 'nearest' }); }); input.setAttribute('aria-activedescendant', `pal-${sel}`); }
  const local = (q) => commands.filter((c) => !q || c.label.toLowerCase().includes(q) || (c.keywords || '').includes(q));
  const search = debounce(async (q) => {
    ctl && ctl.abort();
    if (q.length < 2) return;
    ctl = new AbortController();
    try {
      const r = await api(`/api/alerts${qs({ q, page_size: 6, sort: 'time' })}`, { signal: ctl.signal });
      const found = r.items.map((a) => ({ group: 'Alerts', icon: 'alerts', label: `${typeName(a.type)} · ${place(a)}`, sev: a.severity, hint: a.id.slice(4, 12), run: () => go(`#/alerts/${a.id}`) }));
      items = [...local(q), ...found]; sel = Math.min(sel, Math.max(0, items.length - 1)); render();
    } catch { /* keep local results */ }
  }, 180);
  const refresh = () => {
    const q = input.value.trim().toLowerCase();
    items = local(q);
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(q)) items.unshift({ group: 'Address', icon: 'filter', label: `Alerts from ${q}`, run: () => go(`#/alerts?source=${q}`) });
    sel = 0; render(); search(q);
  };
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sel = (sel + 1) % Math.max(1, items.length); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = (sel - 1 + items.length) % Math.max(1, items.length); mark(); }
    else if (e.key === 'Enter' && items[sel]) { e.preventDefault(); run(items[sel]); }
    else if (e.key === 'Tab') { e.preventDefault(); }
  }
  input.addEventListener('input', refresh);
  document.addEventListener('keydown', onKey, true);
  document.body.append(wrap);
  refresh();
  input.focus();
}
