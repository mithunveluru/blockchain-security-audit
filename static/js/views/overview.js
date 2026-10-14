import { api } from '../api.js';
import { areaChart, barChart, card, chart, clear, empty, fmtBytes, fmtNum, fmtTime, h, put } from '../ui.js';
import { alertTable, rangeSelect, sevBar } from '../components.js';

export default async function overview(ctx) {
  let range = '1h', data = null, disposers = [], busy = false;
  try { range = sessionStorage.getItem('blockaudit.range') || '1h'; } catch { /* ignore */ }
  const shell = h('div');
  put(ctx.root, shell);

  async function load() {
    if (busy) return;
    busy = true;
    try { data = await api(`/api/overview?range=${range}`); draw(); } finally { busy = false; }
  }
  function draw() {
    disposers.forEach((d) => d()); disposers = [];
    clear(shell);
    const d = data, hs = d.health, a = d.alerts, lg = d.ledger;
    const bad = hs.components.filter((c) => c.state !== 'healthy');
    const headline = { ok: 'Monitoring is healthy', degraded: 'Monitoring is degraded', critical: 'Attention required' }[hs.status] || hs.status;
    put(shell, 
      h('div', { class: 'page-head' },
        h('div', null, h('h1', null, 'Security overview'), h('p', null, 'Current posture of this deployment: what was detected, whether the evidence is intact, and whether the sensors are working.')),
        rangeSelect(range, ['5m', '15m', '1h', '6h', '24h', '7d'], (r) => { range = r; try { sessionStorage.setItem('blockaudit.range', r); } catch { /* ignore */ } load(); })),
      d.data_mode !== 'live_capture' && h('div', { class: 'notice warn' }, h('strong', null, d.data_mode === 'simulation' ? 'Simulation mode. ' : 'Test data. '),
        'All traffic and alerts below are synthetic and do not describe a real network.'),
      lg.tampering_detected && h('div', { class: 'notice bad', role: 'alert' }, h('strong', null, 'Ledger integrity failure. '), 'The audit ledger no longer matches its recorded hashes. ', h('a', { href: '#/ledger' }, 'Inspect the failing records')),
      h('div', { class: 'grid cols-4' },
        card(null, null, h('div', { class: 'status-hero' }, h('span', { class: `pip ${hs.status}` }), h('div', null, h('h2', null, headline),
          h('div', { class: 'muted small', style: 'margin-top:4px' }, bad.length ? bad.map((c) => `${c.name.replace(/_/g, ' ')}: ${c.state}`).join(' · ') : 'All components report healthy.'),
          h('a', { href: '#/health', class: 'small' }, 'System health')))),
        kpi(`Alerts · last ${range}`, fmtNum(a.total), sevBar(a.by_severity)),
        kpi(`Packets · last ${range}`, fmtNum(d.traffic.packets), h('span', null, `${fmtBytes(d.traffic.bytes)} · ${d.data_mode === 'live_capture' ? 'observed' : 'synthetic'}`)),
        kpi('Audit ledger', lg.verified === false ? 'Failed' : lg.verified ? 'Verified' : 'Pending',
          h('span', null, `${fmtNum(lg.blocks)} blocks`, lg.verified_at ? ` · checked ${fmtTime(lg.verified_at, false)}` : '', ' ', h('a', { href: '#/ledger' }, 'Details')))),
      h('div', { class: 'grid cols-2', style: 'margin-top:16px' },
        card('Alerts over time', `${range}, all severities`, chartBox('alerts')),
        card('Packet rate', `${range}, per ${d.traffic.bucket_seconds}s bucket`, chartBox('packets'))),
      h('div', { style: 'margin-top:16px' }, card('Recent high-priority alerts', 'HIGH and CRITICAL in range',
        d.recent_high_priority.length ? alertTable(d.recent_high_priority, (x) => ctx.go(`#/alerts/${encodeURIComponent(x.id)}`), { compact: true })
          : empty('No high-priority alerts in this range', d.health.components.find((c) => c.name === 'ml_detector')?.state === 'degraded' ? 'The anomaly model is still learning a baseline; rule-based detections are active.' : 'Detection is running. New alerts appear here as they are raised.'),
        a.total > 0 && h('p', null, h('a', { href: '#/alerts' }, `View all ${fmtNum(a.total)} alerts`)))),
      guide(d, ctx));
    const al = d.alert_timeline.map((t) => ({ label: fmtTime(t.t, false).slice(0, 5), values: [t.total - t.high, t.high], title: `${fmtTime(t.t)}: ${t.total} alerts (${t.high} high or critical)` }));
    const pk = d.traffic.series.map((t) => ({ label: fmtTime(t.t, false).slice(0, 5), value: t.packets / d.traffic.bucket_seconds, title: `${fmtTime(t.t)}: ${(t.packets / d.traffic.bucket_seconds).toFixed(1)} packets/s` }));
    mount('alerts', al.length ? barChart(al, { colors: ['var(--accent)', 'var(--crit)'] }) : null, 'No alerts in this range.');
    mount('packets', pk.length ? areaChart(pk, { fmt: (v) => fmtNum(v) }) : null, 'No packets observed in this range.');
  }
  const boxes = {};
  function chartBox(name) { return (boxes[name] = h('div', { class: 'chart' })); }
  function mount(name, drawFn, emptyText) {
    if (!drawFn) { boxes[name].append(h('p', { class: 'muted' }, emptyText)); return; }
    disposers.push(chart(boxes[name], drawFn));
  }
  await load();
  let t = null;
  const refresh = () => { clearTimeout(t); t = setTimeout(load, 1500); };
  ctx.on('alert', refresh);
  const poll = setInterval(load, 15000);
  return () => { clearInterval(poll); clearTimeout(t); disposers.forEach((d) => d()); };
}

const kpi = (label, value, sub) => card(null, null, h('div', { class: 'kpi' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'sub' }, sub)));

function guide(d, ctx) {
  if (d.alerts.total > 0) return null;
  const admin = ctx.state.me.role === 'admin' && ctx.state.me.scenarios.length;
  return h('div', { style: 'margin-top:16px' }, card('Getting started', 'shown until the first alert',
    h('ol', null,
      h('li', null, d.data_mode === 'simulation' ? 'You are in simulation mode: benign synthetic traffic is flowing and attack scenarios are injected on a timer.' : 'BlockAudit is watching the configured interface. Alerts appear when a detection rule fires.'),
      h('li', null, 'Open an alert to see why it fired, the packets behind it and the ledger record that preserves it.'),
      h('li', null, 'Use the ', h('a', { href: '#/copilot' }, 'investigation copilot'), ' to ask questions grounded in those records.')),
    admin && h('p', null, 'Trigger a synthetic scenario now: ', ctx.state.me.scenarios.map((s) => h('button', { class: 'btn small', style: 'margin-right:6px', onclick: () => api(`/api/simulate/${s}`, { method: 'POST' }).catch(() => {}) }, s.replace('_', ' '))))));
}
