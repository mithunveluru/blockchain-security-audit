import { card, h, put } from '../ui.js';
import { copilotPanel } from '../components.js';

export default function copilot(ctx) {
  const me = ctx.state.me;
  const panel = copilotPanel(ctx, { suggestions: ['Summarize the most important incidents', 'What should I investigate next?', 'Is the audit ledger intact?', 'Which findings remain unverified?', 'Is every sensor working?'] });
  put(ctx.root, 
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Investigation copilot'), h('p', null, 'Ask about alerts, addresses, the ledger or system health. Every answer is built from records retrieved from this system and cites them; anything it cannot find is listed as missing.'))),
    h('div', { class: 'notice info' }, me.copilot.model_available ? `A language model (${me.copilot.provider}) phrases answers from retrieved records. Its output is checked: unknown record ids and unsupported addresses or hashes are removed.` : 'No language model is configured, so answers are assembled directly from records. Set ANTHROPIC_API_KEY on the server to enable model-written explanations.'),
    card(null, null, panel.el),
    h('p', { class: 'muted small' }, 'Tip: include an address (for example 203.0.113.50) or an alert id such as alr-0123456789ab in your question to focus the search. The copilot is read-only and cannot block addresses or change configuration.'));
  return panel.dispose;
}
