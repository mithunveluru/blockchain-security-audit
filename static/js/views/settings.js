import { api } from '../core/api.js';
import { h, put, clear } from '../core/dom.js';
import { reduced, setReduced } from '../core/motion.js';
import { btn, confirmDialog, notice, seg, toast } from '../ui/components.js';

export default async function settings(ctx) {
  const me = ctx.state.me, admin = me.role === 'admin';
  ctx.setTitle('Settings', 'Preferences and controls');
  ctx.toolbar(null);
  const wl = h('div');
  const theme = () => document.documentElement.dataset.theme;
  const setTheme = (t) => { document.documentElement.dataset.theme = t; try { localStorage.setItem('blockaudit.theme', JSON.stringify(t)); } catch { /* ignore */ } };
  const sw = h('button', { class: 'switch', role: 'switch', 'aria-checked': String(reduced()), 'aria-label': 'Reduce motion', onclick: () => { setReduced(!reduced()); sw.setAttribute('aria-checked', String(reduced())); } });
  const row = (title, text, body) => h('div', { class: 'set-row' }, h('div', null, h('h2', null, title), h('p', { class: 'small' }, text)), h('div', null, body));

  async function loadWl() {
    try {
      const w = await api('/api/whitelist');
      const input = h('input', { class: 'input', id: 'wl', placeholder: '198.51.100.0/24 or 203.0.113.7', maxlength: 64, disabled: !admin, 'aria-label': 'Address or CIDR to suppress', style: 'flex:1;min-width:200px' });
      const run = async (fn) => { try { await fn(); toast('Saved and recorded in the audit ledger', 'ok'); } catch (e) { toast(e.message, 'bad'); } loadWl(); };
      clear(wl); put(wl, h('div', { class: 'stack' },
        h('div', { class: 'between' }, h('span', { class: 'small muted' }, `${w.suppressed} alerts suppressed this session`), admin && btn(w.enabled ? 'Disable' : 'Enable', { size: 'sm', onclick: async () => { if (await confirmDialog({ title: w.enabled ? 'Disable the whitelist?' : 'Enable the whitelist?', text: w.enabled ? 'Alerts from every address will be recorded again.' : 'Alerts matching the entries will be suppressed.', ok: w.enabled ? 'Disable' : 'Enable' })) run(() => api('/api/whitelist/toggle', { method: 'POST' })); } })),
        h('div', { class: 'row' }, h('span', { class: 'tag' + (w.enabled ? ' ok' : '') }, w.enabled ? 'enabled' : 'disabled')),
        w.whitelist.length ? h('ul', { class: 'list-plain' }, w.whitelist.map((e) => h('li', null, h('code', null, e), admin && btn('Remove', { size: 'sm', kind: 'ghost danger', 'aria-label': `Remove ${e}`, onclick: async () => { if (await confirmDialog({ title: 'Remove entry?', text: `${e} will no longer be suppressed.`, ok: 'Remove', danger: true })) run(() => api('/api/whitelist/remove', { method: 'POST', body: { ip: e } })); } })))) : h('p', { class: 'faint small' }, 'No entries.'),
        admin ? h('div', { class: 'row' }, input, btn('Add', { onclick: async () => { if (await confirmDialog({ title: 'Suppress alerts?', text: `Alerts involving ${input.value.trim() || 'this address'} will stop being recorded. The change is written to the audit ledger.`, ok: 'Add to whitelist' })) run(() => api('/api/whitelist/add', { method: 'POST', body: { ip: input.value } })); } })) : h('p', { class: 'faint small' }, 'Only administrators can change the whitelist.')));
    } catch (e) { clear(wl); put(wl, notice('bad', e.message, ' ', btn('Retry', { size: 'sm', onclick: loadWl }))); }
  }
  put(ctx.root, h('div', { class: 'stack' },
    me.warnings.length > 0 && notice('warn', h('ul', null, me.warnings.map((w) => h('li', null, w.charAt(0).toUpperCase() + w.slice(1))))),
    h('section', { class: 'panel' },
      row('Appearance', 'Dark is the default. Light is a complete theme, not an inversion.', seg([{ value: 'dark', label: 'Dark' }, { value: 'light', label: 'Light' }], theme(), setTheme, 'Theme')),
      row('Reduce motion', 'Turns off transitions, entrance animations and the settling of the relationship map. Follows your operating system setting until you change it here.', h('div', { class: 'row' }, sw, h('span', { class: 'small muted' }, 'Reduce motion'))),
      row('Access', `Signed in with the ${me.role} role. Tokens are set on the server; this tab keeps yours only until it closes.`, h('div', { class: 'small muted' }, me.role === 'admin' ? 'Admin: can change the whitelist, start and stop monitoring and inject simulation scenarios.' : me.role === 'analyst' ? 'Analyst: can set alert status, add notes and run verification.' : 'Viewer: read-only access, including the copilot.')),
      row('Alert whitelist', 'Alerts matching an entry are suppressed and counted, not recorded. This can hide real attacks from those addresses, so keep it short.', wl),
      me.scenarios.length ? row('Simulation scenarios', 'Inject a known attack pattern into the simulator. Resulting alerts are labelled as simulation data.', h('div', { class: 'row' }, me.scenarios.map((s) => btn(s.replace('_', ' '), { disabled: !admin, onclick: async () => { try { await api(`/api/simulate/${s}`, { method: 'POST' }); toast(`Injected ${s.replace('_', ' ')} scenario`, 'ok'); } catch (e) { toast(e.message, 'bad'); } } })))) : null,
      row('Keyboard', 'Shortcuts work when no text field is focused.', h('ul', { class: 'list-plain' }, [['⌘K or Ctrl K', 'Command palette'], ['/', 'Search alerts'], ['j  k', 'Next and previous alert'], ['g then o, a, n, l, h, c, s', 'Go to a page'], ['.', 'Open the copilot'], ['Esc', 'Close the open panel']].map(([k, v]) => h('li', null, h('span', null, v), h('span', { class: 'kbd' }, k))))),
      row('Trust model and limits', 'What the numbers and the ledger can and cannot tell you.', h('ul', { class: 'stack-s small muted' },
        h('li', null, 'The ledger is a local hash chain with a checkpoint. It reveals edits that leave hashes inconsistent; it does not stop an attacker who can rewrite both files.'),
        h('li', null, 'Anomaly scores are uncalibrated model outputs, never proof of malicious activity.'), h('li', null, 'Only packet headers are analysed. Payloads, application-layer content and geography are not collected.'), h('li', null, 'Detection thresholds are fixed per deployment; each alert shows the threshold that applied.')))
    )));
  await loadWl();
  return {};
}
