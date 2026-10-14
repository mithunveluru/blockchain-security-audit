import { api } from '../core/api.js';
import { h, put, clear } from '../core/dom.js';
import { fmtClock, ago } from '../core/format.js';
import { icon } from '../ui/icons.js';
import { btn, notice, state } from '../ui/components.js';

const META = {
  packet_capture: ['Packet capture', 'cpu', 'Receives packets from the capture interface or the simulator.'], flow_analyzer: ['Flow analyzer', 'network', 'Tracks conversations and flags large outbound transfers.'],
  ml_detector: ['Anomaly model', 'sparkle', 'Learns normal per-source behaviour and scores deviations.'], integrity_monitor: ['Integrity monitor', 'shield', 'Re-verifies the ledger file against memory and the checkpoint.'],
  ledger: ['Ledger persistence', 'ledger', 'Writes each alert to the append-only audit ledger.'], background_workers: ['Background workers', 'refresh', 'Packet worker, ticker and monitor threads.'], websocket: ['Live updates', 'wifi', 'Pushes alerts and snapshots to connected dashboards.'],
};
const MEANING = { healthy: 'Working as expected', degraded: 'Running with a problem', unavailable: 'Needed but not working', disabled: 'Turned off' };

export default async function health(ctx) {
  ctx.setTitle('System health', 'Components and sensors');
  ctx.toolbar(null);
  const host = h('div', { class: 'stack' });
  put(ctx.root, host);
  let busy = false;
  async function load() {
    if (busy) return; busy = true;
    try {
      const d = await api('/api/health');
      const bad = d.components.filter((c) => c.state !== 'healthy' && c.state !== 'disabled');
      clear(host);
      put(host,
        notice(d.status === 'ok' ? 'ok' : d.status === 'degraded' ? 'warn' : 'bad', h('strong', null, { ok: 'Every component is healthy. ', degraded: 'Some components need attention. ', critical: 'A critical component has failed. ' }[d.status]),
          `Data mode: ${d.data_mode.replace('_', ' ')}. Uptime ${d.uptime_seconds < 120 ? `${d.uptime_seconds}s` : d.uptime_seconds < 7200 ? `${Math.floor(d.uptime_seconds / 60)}m` : `${Math.floor(d.uptime_seconds / 3600)}h`}. Updated ${fmtClock(d.time)} UTC.`, bad.length ? ` Needs attention: ${bad.map((c) => (META[c.name] || [c.name])[0]).join(', ')}.` : ''),
        h('section', { class: 'panel' }, d.components.map((c) => {
          const [name, ic, what] = META[c.name] || [c.name, 'info', ''];
          const extra = [c.last_packet_at && `last packet ${ago(new Date(c.last_packet_at * 1000).toISOString())}`, c.dropped && `${c.dropped} packets dropped under load`, c.queue_depth > 0 && `queue depth ${c.queue_depth}`, c.last_check && `last check ${fmtClock(c.last_check)} UTC`, c.ticker_errors && `${c.ticker_errors} worker errors`, c.checkpoint_error && `checkpoint failing: ${c.checkpoint_error}`, c.phase === 'learning' && `learning baseline ${c.samples} samples`].filter(Boolean);
          return h('div', { class: 'health-row' }, h('div', { class: 'n' }, icon(ic), name), h('div', { class: 'stack-s' }, h('div', null, c.detail), h('div', { class: 'faint small' }, what), extra.length ? h('div', { class: 'faint small' }, extra.join(' · ')) : null, c.fix ? h('pre', { class: 'code', tabindex: 0 }, c.fix) : null), h('div', { title: MEANING[c.state] }, state(c.state)));
        })));
    } catch (e) { if (e.name !== 'AbortError') { clear(host); put(host, notice('bad', e.message, ' ', btn('Retry', { size: 'sm', onclick: load }))); } }
    finally { busy = false; }
  }
  await load();
  const poll = setInterval(() => { if (!document.hidden) load(); }, 5000);
  ctx.onLive('integrity', load); ctx.onLive('reconnected', load);
  ctx.scope.add(() => clearInterval(poll));
  return {};
}
