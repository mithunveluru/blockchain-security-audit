import { api } from '../api.js';
import { card, clear, errorBox, fmtTime, h, stateBadge, ago, put } from '../ui.js';

const labels = { packet_capture: 'Packet capture', flow_analyzer: 'Flow analyzer', ml_detector: 'Anomaly model', integrity_monitor: 'Integrity monitor', ledger: 'Ledger persistence', background_workers: 'Background workers', websocket: 'Live updates (WebSocket)' };
const meaning = { healthy: 'Working as expected', degraded: 'Running with a problem', unavailable: 'Needed but not working', disabled: 'Turned off' };

export default async function health(ctx) {
  const box = h('div');
  put(ctx.root, h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'System health'), h('p', null, 'Status of each component. “Unavailable” means a component that should be working is not; the web server being up does not make a sensor healthy.'))), box);
  let busy = false;
  async function load() {
    if (busy) return; busy = true;
    try {
      const d = await api('/api/health');
      put(clear(box), 
        h('div', { class: `notice ${d.status === 'ok' ? 'ok' : d.status === 'degraded' ? 'warn' : 'bad'}` }, h('strong', null, { ok: 'All components healthy. ', degraded: 'Some components need attention. ', critical: 'A critical component has failed. ' }[d.status]),
          `Data mode: ${d.data_mode.replace('_', ' ')}. Uptime ${fmtUp(d.uptime_seconds)}. Updated ${fmtTime(d.time, false)}.`),
        h('div', { class: 'grid cols-2' }, d.components.map((c) => card(labels[c.name] || c.name, meaning[c.state],
          h('div', { class: 'row' }, stateBadge(c.state)), h('p', null, c.detail),
          c.fix && h('pre', { tabindex: 0 }, c.fix),
          extras(c)))));
    } catch (e) { put(clear(box), errorBox(e.message, load)); } finally { busy = false; }
  }
  await load();
  const poll = setInterval(load, 5000);
  ctx.on('integrity', load);
  return () => clearInterval(poll);
}
function extras(c) {
  const bits = [];
  if (c.last_packet_at) bits.push(`last packet ${ago(new Date(c.last_packet_at * 1000).toISOString())}`);
  if (c.dropped) bits.push(`${c.dropped} packets dropped under load`);
  if (c.queue_depth != null && c.queue_depth > 0) bits.push(`queue depth ${c.queue_depth}`);
  if (c.last_check) bits.push(`last check ${fmtTime(c.last_check, false)}`);
  if (c.ticker_errors) bits.push(`${c.ticker_errors} worker errors`);
  if (c.checkpoint_error) bits.push(`checkpoint write failing: ${c.checkpoint_error}`);
  return bits.length ? h('p', { class: 'muted small' }, bits.join(' · ')) : null;
}
const fmtUp = (s) => (s < 120 ? `${s}s` : s < 7200 ? `${Math.floor(s / 60)}m` : s < 172800 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`);
