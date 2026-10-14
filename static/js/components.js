import { api } from './api.js';
import { clear, h, sevBadge, stateBadge, provBadge, timeEl, fmtTime, toast, put } from './ui.js';

export const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const sevColor = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };

export function sevBar(counts) {
  const total = SEVS.reduce((a, s) => a + (counts[s] || 0), 0);
  const bar = h('div', { class: 'sevbar', role: 'img', 'aria-label': total ? SEVS.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(', ') : 'no alerts' });
  SEVS.forEach((s) => counts[s] && put(bar, h('span', { style: `width:${(counts[s] / total) * 100}%;background:${sevColor[s]}`, title: `${s}: ${counts[s]}` })));
  const legend = h('div', { class: 'legend' }, SEVS.filter((s) => counts[s]).map((s) => h('span', null, h('i', { style: `background:${sevColor[s]}` }), `${counts[s]} ${s.toLowerCase()}`)));
  return h('div', null, bar, legend);
}

export function rangeSelect(current, ranges, onChange) {
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Time range' });
  ranges.forEach((r) => put(seg, h('button', { type: 'button', 'aria-pressed': String(r === current), onclick: () => onChange(r) }, r)));
  return seg;
}

export const place = (a) => {
  const dst = a.destination ? `${a.destination}${a.dst_port ? ':' + a.dst_port : ''}` : null;
  if (a.source && dst) return `${a.source} → ${dst}`;
  return a.source || dst || 'n/a';
};
const TYPE_NAMES = { DDOS: 'DDoS', DOS_FLOOD: 'DoS flood', PORT_SCAN: 'Port scan', BRUTE_FORCE: 'Brute force', DATA_EXFILTRATION: 'Data exfiltration', ANOMALY: 'Anomaly', INTEGRITY: 'Ledger integrity' };
export const typeName = (t) => TYPE_NAMES[t] || t.replace(/_/g, ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase());

export function alertTable(items, open, { compact = false } = {}) {
  const head = ['Severity', 'Time', 'Detection', 'Source → destination', ...(compact ? [] : ['Score', 'Status', 'Data'])];
  const link = (a) => h('a', { href: `#/alerts/${encodeURIComponent(a.id)}`, onclick: (e) => e.stopPropagation() }, typeName(a.type));
  const rows = items.map((a) => h('tr', { class: 'link', onclick: () => open(a) },
    h('td', null, sevBadge(a.severity)), h('td', { class: 'nowrap' }, timeEl(a.timestamp)),
    h('td', null, link(a), a.occurrences > 1 && h('span', { class: 'muted small' }, ` ×${a.occurrences}`)),
    h('td', { class: 'wrap mono' }, place(a)),
    !compact && h('td', { class: 'num' }, a.score != null ? a.score.toFixed(2) : '–'),
    !compact && h('td', null, stateBadge(a.status)), !compact && h('td', null, provBadge(a.provenance))));
  const table = h('table', null, h('thead', null, h('tr', null, head.map((c) => h('th', { scope: 'col' }, c)))), h('tbody', null, rows));
  const cards = h('div', { class: 'cardlist' }, items.map((a) => h('div', { class: 'card', tabindex: 0, role: 'link', onclick: () => open(a), onkeydown: (e) => e.key === 'Enter' && open(a) },
    h('div', { class: 'row' }, sevBadge(a.severity), h('strong', null, typeName(a.type)), !compact && provBadge(a.provenance)),
    h('div', { class: 'mono small', style: 'margin:6px 0' }, place(a)), h('div', { class: 'muted small' }, fmtTime(a.timestamp)))));
  return h('div', { class: 'table-wrap stack' }, table, cards);
}

export function copilotPanel(ctx, { alertId = null, range = '1h', suggestions }) {
  const log = h('div', { class: 'chat', 'aria-live': 'polite' });
  const input = h('textarea', { id: `cq-${alertId || 'g'}`, rows: 2, maxlength: 800, placeholder: 'Ask about the evidence in this system…', 'aria-label': 'Question for the investigation copilot' });
  let abort = null;
  const status = ctx.state.me.copilot;
  const ask = async (q) => {
    q = (q || input.value).trim();
    if (!q) return;
    input.value = '';
    put(log, h('div', { class: 'msg user' }, q));
    const pending = h('div', { class: 'msg' }, h('span', { class: 'muted' }, 'Reading records…'));
    put(log, pending);
    pending.scrollIntoView({ block: 'nearest' });
    abort && abort.abort();
    abort = new AbortController();
    send.disabled = true;
    try {
      const r = await api('/api/copilot/ask', { method: 'POST', body: { question: q, alert_id: alertId, range }, signal: abort.signal });
      pending.replaceWith(renderAnswer(r));
    } catch (e) {
      if (e.name === 'AbortError') return;
      pending.replaceWith(h('div', { class: 'msg notice bad', role: 'alert' }, e.message));
    } finally { send.disabled = false; }
  };
  const send = h('button', { class: 'btn primary', type: 'button', onclick: () => ask() }, 'Ask');
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) ask(); });
  const el = h('div', null,
    h('p', { class: 'muted small' }, status.model_available
      ? `Answers are written by ${status.provider} from retrieved records and checked against them. Read-only: it cannot change anything.`
      : 'No language model is configured. Answers are assembled directly from retrieved records. Read-only: it cannot change anything.'),
    h('div', { class: 'chips', style: 'margin:8px 0 12px' }, suggestions.map((s) => h('button', { class: 'chip', type: 'button', onclick: () => ask(s) }, s))),
    log, h('div', { class: 'compose', style: 'margin-top:12px' }, h('div', { class: 'field', style: 'flex:1' }, h('label', { for: input.id }, 'Question (Ctrl+Enter to send)'), input), send));
  return { el, dispose: () => abort && abort.abort() };
}

const sectionTitles = [['observed', 'Observed in records'], ['inferred', 'Interpretation'], ['recommendations', 'Suggested next steps (not performed)'], ['missing', 'Missing or unverified']];
function renderAnswer(r) {
  const box = h('div', { class: 'msg' });
  const meta = r.mode === 'llm' ? `Model: ${r.provider.name}` : r.provider.status === 'unavailable' ? `Model unavailable (${r.provider.error}). Showing record-based answer.` : 'Record-based answer';
  put(box, h('div', { class: 'muted small' }, meta));
  for (const [key, title] of sectionTitles) {
    const items = r.sections[key] || [];
    if (!items.length) continue;
    put(box, h('h3', null, title), h('ul', null, items.map((it) => h('li', null, it.text, (it.refs || []).map((id) => refLink(id, r.sources))))));
  }
  if (r.sources.length) put(box, h('h3', null, 'Sources'), h('div', { class: 'row' }, r.sources.map((s) => h('a', { class: 'ref', href: s.url, title: s.label }, s.id))));
  put(box, h('details', { style: 'margin-top:10px' }, h('summary', { class: 'small' }, `Tools run (${r.tools_run.length})`),
    h('ul', { class: 'small muted' }, r.tools_run.map((t) => h('li', null, `${t.tool}: ${t.result}`)))));
  return box;
}
const refLink = (id, sources) => { const s = sources.find((x) => x.id === id); return s ? h('a', { class: 'ref', href: s.url }, id) : h('span', { class: 'ref' }, id); };

export function guarded(fn) { return async (...a) => { try { return await fn(...a); } catch (e) { if (e.name !== 'AbortError') toast(e.message, 'bad'); } }; }
export { clear };
