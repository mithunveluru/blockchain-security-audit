import { h, put } from '../core/dom.js';
import { icon } from '../ui/icons.js';
import { notice } from '../ui/components.js';
import { conversation, GLOBAL_QUESTIONS } from '../ui/copilot.js';

export default function copilot(ctx) {
  const me = ctx.state.me;
  ctx.setTitle('Investigation copilot', 'Read-only · grounded in your records');
  ctx.toolbar(null);
  ctx.layout('flush');
  const conv = conversation({ state: ctx.state, suggestions: GLOBAL_QUESTIONS });
  put(ctx.root, h('div', { style: 'display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:0;height:100%' },
    h('div', { style: 'padding:8px 28px 16px;min-height:0;max-width:880px;width:100%;margin:0 auto' }, conv.el),
    h('aside', { 'aria-label': 'About the copilot', class: 'only-desktop', style: 'border-left:1px solid var(--line);padding:24px 20px;overflow:auto;display:grid;gap:22px;align-content:start' },
      h('section', { class: 'stack-s' }, h('h2', { class: 'h3' }, 'What it can read'), h('ul', { class: 'stack-s muted small' }, ['Alerts, evidence and thresholds', 'Retained packet headers around an alert', 'Flow summaries', 'Audit ledger records and verification', 'Component health'].map((t) => h('li', { class: 'row', style: 'flex-wrap:nowrap;align-items:flex-start' }, icon('check'), t)))),
      h('section', { class: 'stack-s' }, h('h2', { class: 'h3' }, 'What it cannot do'), h('p', { class: 'muted small' }, 'It cannot block addresses, change configuration, run commands or edit records. Suggested steps are advice for a human.')),
      me.copilot.model_available ? notice('info', `${me.copilot.provider} phrases answers from the retrieved records. Answers are checked: unknown ids and unsupported addresses or hashes are removed.`)
        : notice('info', 'No language model is configured, so answers are assembled directly from records. Set ANTHROPIC_API_KEY on the server to enable model-written explanations.'),
      h('p', { class: 'faint tiny' }, 'Tip: mention an address or an alert id like alr-0123456789ab to focus the search. Press ', h('span', { class: 'kbd' }, '.'), ' anywhere to open the copilot.'))));
  return { cleanup: () => conv.destroy() };
}
