import { api } from '../api.js';
import { card, clear, confirmDialog, errorBox, h, toast, put } from '../ui.js';

export default async function settings(ctx) {
  const me = ctx.state.me, admin = me.role === 'admin';
  const wlBox = h('div');
  async function loadWl() {
    try {
      const w = await api('/api/whitelist');
      const input = h('input', { id: 'wl', placeholder: '198.51.100.0/24 or 203.0.113.7', maxlength: 64, disabled: !admin, 'aria-describedby': 'wl-help' });
      put(clear(wlBox), 
        h('p', { class: 'muted', id: 'wl-help' }, `Alerts whose source or destination matches an entry are suppressed and counted, not recorded. ${w.suppressed} suppressed this session. Suppression hides real attacks from these addresses, so keep the list short.`),
        h('div', { class: 'row', style: 'margin-bottom:10px' }, h('span', { class: `badge ${w.enabled ? 'st-healthy' : 'st-degraded'}` }, w.enabled ? 'enabled' : 'disabled'),
          admin && h('button', { class: 'btn small', onclick: async () => { if (await confirmDialog(w.enabled ? 'Disable the whitelist?' : 'Enable the whitelist?', w.enabled ? 'Alerts from every address will be recorded again.' : 'Alerts matching the entries will be suppressed.')) { await run(() => api('/api/whitelist/toggle', { method: 'POST' })); } } }, w.enabled ? 'Disable' : 'Enable')),
        w.whitelist.length ? h('ul', null, w.whitelist.map((e) => h('li', null, h('code', null, e), ' ', admin && h('button', { class: 'btn small ghost danger', 'aria-label': `Remove ${e}`, onclick: async () => { if (await confirmDialog('Remove entry?', `${e} will no longer be suppressed.`, 'Remove', true)) await run(() => api('/api/whitelist/remove', { method: 'POST', body: { ip: e } })); } }, 'Remove')))) : h('p', { class: 'muted' }, 'No entries.'),
        admin ? h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', { for: 'wl' }, 'Add address or CIDR'), input), h('button', { class: 'btn', style: 'align-self:flex-end', onclick: async () => { if (await confirmDialog('Suppress alerts?', `Alerts involving ${input.value.trim() || 'this address'} will stop being recorded. This action is written to the audit ledger.`, 'Add to whitelist')) await run(() => api('/api/whitelist/add', { method: 'POST', body: { ip: input.value } })); } }, 'Add')) : h('p', { class: 'muted small' }, 'Only administrators can change the whitelist.'));
    } catch (e) { put(clear(wlBox), errorBox(e.message, loadWl)); }
  }
  async function run(fn) { try { await fn(); toast('Saved and recorded in the audit ledger', 'ok'); } catch (e) { toast(e.message, 'bad'); } await loadWl(); }
  put(ctx.root, 
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Settings'), h('p', null, `Signed in with the ${me.role} role. Configuration is set by environment variables on the server; this page covers what can change at runtime.`))),
    me.warnings.length > 0 && h('div', { class: 'notice warn' }, h('ul', null, me.warnings.map((w) => h('li', null, w)))),
    h('div', { class: 'grid cols-2' },
      card('Alert whitelist', null, wlBox),
      h('div', { class: 'grid', style: 'align-content:start' },
        me.scenarios.length > 0 && card('Simulation scenarios', 'synthetic traffic only', h('p', { class: 'muted' }, 'Inject a known attack pattern into the simulator. Resulting alerts are labelled as simulation data.'),
          h('div', { class: 'row' }, me.scenarios.map((s) => h('button', { class: 'btn', disabled: !admin, onclick: async () => { try { await api(`/api/simulate/${s}`, { method: 'POST' }); toast(`Injected ${s.replace('_', ' ')} scenario`, 'ok'); } catch (e) { toast(e.message, 'bad'); } } }, s.replace('_', ' '))))),
        card('Trust model and limits', null, h('ul', null,
          h('li', null, 'The audit ledger is a local hash chain with a checkpoint file. It reveals edits that leave hashes inconsistent; it does not stop an attacker who can rewrite both files.'),
          h('li', null, 'Anomaly scores are uncalibrated model outputs, never proof of malicious activity.'),
          h('li', null, 'Only packet headers are analysed. Payloads, application-layer content and geography are not collected.'),
          h('li', null, 'Detection thresholds are fixed per deployment; each alert shows the threshold that applied.'))))));
  await loadWl();
}
