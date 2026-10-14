import { h } from '../core/dom.js';
import { ago, place, typeName } from '../core/format.js';
import { SEV_COLOR } from './charts.js';
import { provTag, sev, statusLabel } from './components.js';

/** one alert as a scannable row. used by the explorer, the overview feed and search */
export function alertRow(a, { selected = false, onOpen, fresh = false, compact = false } = {}) {
  const open = () => onOpen && onOpen(a);
  return h('li', { class: `arow${fresh ? ' fresh' : ''}`, role: 'option', id: `ar-${a.id}`, tabindex: -1, 'aria-selected': String(selected), 'data-id': a.id, onclick: open,
    onkeydown: (e) => { if (e.key === 'Enter') open(); } },
  h('span', { class: 'bar', style: `background:${SEV_COLOR[a.severity]}`, 'aria-hidden': 'true' }),
  h('div', { style: 'min-width:0' },
    h('div', { class: 'l1' }, sev(a.severity), h('span', { class: 'ttl' }, typeName(a.type)), a.occurrences > 1 && h('span', { class: 'faint small num', title: `${a.occurrences} occurrences merged` }, `×${a.occurrences}`), provTag(a.provenance)),
    h('div', { class: 'l2' }, h('span', { class: 'mono wrap' }, place(a)), !compact && h('span', { class: 'faint small', style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:46ch' }, a.description))),
  h('div', { class: 'when' }, h('time', { datetime: a.timestamp, title: a.timestamp }, ago(a.timestamp)), !compact && a.status !== 'new' && statusLabel(a.status)));
}
