import { api } from '../core/api.js';
import { h, put, clear, scope } from '../core/dom.js';
import { icon } from './icons.js';
import { richText } from './code.js';
import { btn, tag } from './components.js';

const histories = new Map();      // conversation per context, kept while the tab is open
const MAX_TURNS = 24;

const SECTIONS = [
  ['observed', 'Observed in records', 'check'], ['inferred', 'Interpretation', 'sparkle'],
  ['recommendations', 'Suggested next steps · not performed', 'arrow'], ['missing', 'Missing or unverified', 'warn'],
];
export const ALERT_QUESTIONS = ['Why was this alert triggered?', 'Show the evidence behind this detection', 'What happened before and after this event?', 'Which related records should I inspect?', 'Summarize this incident'];
export const GLOBAL_QUESTIONS = ['Summarize the most important incidents', 'Is the audit ledger intact?', 'Which findings remain unverified?', 'Is every sensor working?', 'What should I investigate next?'];

function answerView(r) {
  const n = r.sources.length;
  const grounded = r.mode === 'llm' ? 'Written by the configured model, then checked against the records' : r.provider.status === 'unavailable' ? `Model unavailable (${r.provider.error}); built from records instead` : 'Built directly from retrieved records';
  const box = h('article', { class: 'co-a' },
    h('div', { class: 'meta' }, h('span', null, grounded), h('span', null, `${n} cited ${n === 1 ? 'record' : 'records'} · ${r.tools_run.length} lookups`),
      (r.sections.missing || []).length ? tag('incomplete evidence', 'sim') : tag('no gaps reported', 'ok')));
  for (const [key, title, ic] of SECTIONS) {
    const items = r.sections[key] || [];
    if (!items.length) continue;
    put(box, h('section', { class: `co-sec ${key}` }, h('h2', { class: 'h3' }, icon(ic), title), h('ul', null, items.map((it) => h('li', null, richText(it.text, r.sources))))));
  }
  if (n) put(box, h('div', { class: 'co-src', 'aria-label': 'Sources' }, r.sources.map((s) => h('a', { href: s.url, onclick: () => document.dispatchEvent(new CustomEvent('copilot:navigate')) }, icon(s.kind === 'alert' ? 'alerts' : s.kind === 'ledger_block' ? 'ledger' : s.kind === 'health' ? 'health' : s.kind === 'context' ? 'clock' : 'shield'), h('span', null, s.label), h('span', { class: 'mono' }, s.id)))));
  put(box, h('details', null, h('summary', { class: 'small faint' }, 'How this was gathered'), h('ul', { class: 'small faint', style: 'margin-top:6px;display:grid;gap:3px' }, r.tools_run.map((t) => h('li', { class: 'mono' }, `${t.tool}(${Object.entries(t.args || {}).map(([k, v]) => `${k}=${v}`).join(', ')}) → ${t.result}`)))));
  return box;
}

export function conversation({ state, alertId = null, range = '1h', suggestions, compact = false }) {
  const key = alertId || 'global';
  const turns = histories.get(key) || [];
  histories.set(key, turns);
  const log = h('div', { class: 'co-log', 'aria-live': 'polite', 'aria-label': 'Conversation' });
  const input = h('textarea', { rows: 1, maxlength: 800, placeholder: alertId ? 'Ask about this alert…' : 'Ask about alerts, addresses, the ledger or health…', 'aria-label': 'Question for the investigation copilot' });
  const send = btn('', { kind: 'primary', ic: 'send', 'aria-label': 'Send question', title: 'Send (Enter)' });
  const status = state.me.copilot;
  let ctl = null;
  const s = scope();

  const draw = () => {
    clear(log);
    if (!turns.length) {
      put(log, h('div', { class: 'stack-s', style: 'padding:6px 0' },
        h('p', { class: 'muted' }, alertId ? 'Ask about this alert. The copilot reads its evidence, related alerts, network context and ledger record.' : 'Ask about alerts, an address, the ledger or system health.'),
        h('div', { class: 'stack-s' }, suggestions.map((q) => h('button', { type: 'button', class: 'chip', style: 'height:auto;padding:6px 10px;text-align:left;justify-self:start', onclick: () => ask(q) }, icon('sparkle'), q)))));
      return;
    }
    turns.forEach((t) => {
      put(log, h('div', { class: 'co-q' }, t.q), t.pending ? h('div', { class: 'co-a' }, h('span', { class: 'thinking', role: 'status', 'aria-label': 'Reading records' }, h('i'), h('i'), h('i'))) : t.error ? h('div', { class: 'notice bad', role: 'alert' }, icon('warn'), h('div', null, t.error)) : answerView(t.r));
    });
    const lastQ = log.querySelectorAll('.co-q'); if (lastQ.length) log.scrollTop = lastQ[lastQ.length - 1].offsetTop - 8;
  };
  async function ask(q) {
    q = (q || input.value).trim();
    if (!q || turns.some((t) => t.pending)) return;
    input.value = '';
    turns.push({ q, pending: true });
    while (turns.length > MAX_TURNS) turns.shift();
    const turn = turns.at(-1);
    draw();
    ctl = new AbortController();
    send.disabled = true;
    try { turn.r = await api('/api/copilot/ask', { method: 'POST', body: { question: q, alert_id: alertId, range }, signal: ctl.signal }); }
    catch (e) { if (e.name === 'AbortError') { turns.pop(); } else turn.error = e.message; }
    turn.pending = false;
    send.disabled = false;
    if (log.isConnected) draw();
  }
  send.addEventListener('click', () => ask());
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); } });
  input.addEventListener('input', () => { input.style.height = 'auto'; input.style.height = `${Math.min(160, input.scrollHeight)}px`; });
  s.on(document, 'copilot:navigate', () => {});
  draw();
  const el = h('div', { class: 'co' }, log,
    h('div', { class: 'co-compose' },
      h('div', { class: 'co-ctx' }, alertId ? tag(`Context: ${alertId}`) : tag('Context: whole system'), tag(status.model_available ? `Model: ${status.provider}` : 'Record-based answers', status.model_available ? '' : ''), tag('Read-only', 'ok')),
      h('div', { class: 'co-box' }, input, send)));
  return { el, focus: () => input.focus(), destroy() { ctl && ctl.abort(); s.dispose(); } };
}
