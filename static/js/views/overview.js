import { api } from '../core/api.js';
import { h, put, clear, debounce } from '../core/dom.js';
import { fmtBytes, fmtCompact, fmtNum, fmtClock, typeName, SEVS } from '../core/format.js';
import { RANGES, domainFor, getRange, setRange } from '../core/range.js';
import { stagger, tween } from '../core/motion.js';

import { SEV_COLOR, distBars, sevComposition, sparkline, timeChart } from '../ui/charts.js';
import { boundary, btn, empty, notice, panel, seg, state } from '../ui/components.js';
import { alertRow } from '../ui/alertrow.js';

const COMP = { packet_capture: 'Packet capture', flow_analyzer: 'Flow analyzer', ml_detector: 'Anomaly model', integrity_monitor: 'Integrity monitor', ledger: 'Ledger persistence', background_workers: 'Background workers', websocket: 'Live updates' };

export default async function overview(ctx) {
  let range = getRange(), data = null, chart = null, tab = 'alerts', busy = false;
  const root = h('div', { class: 'stack' });
  put(ctx.root, root);
  ctx.setTitle('Overview', 'Security posture');
  const toolbar = () => seg(RANGES.map((r) => ({ value: r })), range, (r) => { range = r; setRange(r); load(); }, 'Time range');
  ctx.toolbar(toolbar());
  const feedHost = h('ul', { class: 'feed', role: 'list' });
  const freshIds = new Set();

  async function load() {
    if (busy) return;
    busy = true;
    try { data = await api(`/api/overview?range=${range}`); draw(); }
    catch (e) { if (e.name !== 'AbortError') { clear(root); put(root, notice('bad', h('strong', null, 'Overview unavailable. '), e.message, ' ', btn('Retry', { size: 'sm', onclick: load }))); } }
    finally { busy = false; }
  }

  function draw() {
    chart && chart.destroy(); chart = null;
    const d = data, hs = d.health, a = d.alerts, lg = d.ledger;
    const bad = hs.components.filter((c) => c.state !== 'healthy');
    const hot = (a.by_severity.CRITICAL || 0) + (a.by_severity.HIGH || 0);
    const status = hs.status === 'ok' ? '' : hs.status === 'degraded' ? 'warn' : 'bad';
    const headline = lg.tampering_detected ? 'Ledger integrity failure detected'
      : hot ? `${hot} high-priority ${hot === 1 ? 'alert needs' : 'alerts need'} attention` : a.total ? `${a.total} ${a.total === 1 ? 'alert' : 'alerts'}, none high priority` : 'No alerts in this range';
    const sub = [hs.status === 'ok' ? 'All components are healthy.' : `${bad.map((c) => `${COMP[c.name] || c.name} ${c.state}`).join(', ')}.`,
      lg.verified === false ? 'The audit ledger failed verification.' : lg.verified ? `Audit ledger verified at ${fmtClock(lg.verified_at)} UTC.` : 'Audit ledger not yet verified.'].join(' ');
    const total = d.traffic.series.map((p) => p.packets / d.traffic.bucket_seconds);
    const sensors = hs.components.filter((c) => c.state === 'healthy').length;
    const pk = h('span', { 'data-v': '' }), al = h('span'), bl = h('span');
    clear(root);
    put(root,
      d.data_mode !== 'live_capture' && notice('warn', h('strong', null, d.data_mode === 'simulation' ? 'Simulation mode. ' : 'Test data. '), 'Traffic and alerts on this page are synthetic and do not describe a real network.'),
      h('section', { class: 'panel posture' },
        h('div', { class: 'lead' }, h('div', { class: 'state-line' }, h('span', { class: `pulse ${status}` }), hs.status === 'ok' ? 'Monitoring healthy' : hs.status === 'degraded' ? 'Monitoring degraded' : 'Attention required'),
          h('h1', null, headline), h('p', null, sub)),
        h('div', { class: 'stats' },
          h('div', { class: 'stat' }, h('div', { class: 'k' }, `Alerts · ${range}`), h('div', { class: 'v' }, al), h('div', { class: 's' }, hot ? h('span', { class: 'sev sev-HIGH' }, `${hot} high or critical`) : 'none high priority')),
          h('div', { class: 'stat' }, h('div', { class: 'k' }, `Packets · ${range}`), h('div', { class: 'v' }, pk), h('div', { class: 's' }, sparkline(total), h('span', null, fmtBytes(d.traffic.bytes)))),
          h('div', { class: 'stat' }, h('div', { class: 'k' }, 'Ledger'), h('div', { class: 'v' }, bl), h('div', { class: 's' }, state(lg.verified === false ? 'failed' : lg.verified ? 'passed' : 'unknown', lg.verified === false ? 'failed' : lg.verified ? 'verified' : 'pending'))),
          h('div', { class: 'stat' }, h('div', { class: 'k' }, 'Components'), h('div', { class: 'v' }, `${sensors}/${hs.components.length}`), h('div', { class: 's' }, bad.length ? `${bad.length} need attention` : 'all healthy')))),
      h('div', { class: 'ov-grid' },
        h('div', { class: 'stack' }, activity(d), priority(d)),
        h('div', { class: 'stack' }, feedPanel(), detections(d), components(hs), chainPanel(lg))));
    tween(al, a.total); tween(pk, d.traffic.packets, fmtCompact); tween(bl, lg.blocks, fmtNum);
    stagger(root, ':scope > .panel, .ov-grid > .stack > .panel');
  }

  function activity(d) {
    const host = h('div', { style: 'padding:14px 16px 12px' });
    const mount = () => {
      chart && chart.destroy();
      const [t0, t1] = domainFor(range);
      if (tab === 'alerts') {
        const bucket = Math.max(60, Math.round(((t1 - t0) / 1000) / 60)) * 1000;
        chart = timeChart(host, { kind: 'bars', stacked: true, bucketMs: bucket, domain: [t0, t1], height: 190, label: `Alerts over time, last ${range}`,
          series: SEVS.slice(0, 4).map((s) => ({ key: s, label: s[0] + s.slice(1).toLowerCase(), color: SEV_COLOR[s] })),
          points: d.alert_timeline.map((p) => ({ t: Date.parse(p.t), values: p.sev || {} })), emptyText: 'No alerts in this range',
          onSelect: (b) => ctx.go(`#/alerts?since=${new Date(b.t).toISOString()}&until=${new Date(b.end).toISOString()}`) });
      } else {
        const bs = d.traffic.bucket_seconds * 1000;
        chart = timeChart(host, { kind: 'area', bucketMs: bs, domain: [t0, t1], height: 190, label: `Packet rate, last ${range}`, tipFormat: (v) => `${v.toFixed(1)} /s`, yFormat: fmtCompact,
          series: [{ key: 'pps', label: 'Packets per second', color: 'var(--accent)' }], points: d.traffic.series.map((p) => ({ t: Date.parse(p.t), values: { pps: p.packets / d.traffic.bucket_seconds } })),
          emptyText: 'No packets observed in this range' });
      }
    };
    const sw = h('div');
    const drawSeg = () => put(clear(sw), seg([{ value: 'alerts', label: 'Alerts' }, { value: 'traffic', label: 'Traffic' }], tab, (v) => { tab = v; mount(); }, 'Chart'));
    drawSeg(); mount();
    return panel({ title: 'Activity', hint: `last ${range} · UTC`, actions: sw }, h('div', { style: 'margin:-16px' }, host,
      tab === 'alerts' ? h('div', { style: 'padding:0 16px 14px' }, sevComposition(d.alerts.by_severity, { onPick: (s) => ctx.go(`#/alerts?severity=${s}&range=${range}`) })) : null));
  }

  function priority(d) {
    const rows = d.recent_high_priority;
    if (!rows.length) {
      const adminSim = ctx.state.me.role === 'admin' && ctx.state.me.scenarios.length;
      return panel({ title: 'Priority alerts' }, empty(d.alerts.total ? 'No high-priority alerts' : 'Nothing to investigate yet',
        d.alerts.total ? 'Lower-severity alerts exist in this range.' : d.data_mode === 'simulation' ? 'The simulator is running. Alerts appear when a detection rule fires, or you can trigger a labelled scenario now.' : 'Detection is active. When a rule fires the alert appears here with its evidence.', 'shield',
        ...(adminSim ? ctx.state.me.scenarios.map((s) => btn(s.replace('_', ' '), { size: 'sm', onclick: () => api(`/api/simulate/${s}`, { method: 'POST' }).catch(() => {}) })) : []),
        d.alerts.total ? btn('View all alerts', { size: 'sm', onclick: () => ctx.go('#/alerts') }) : null));
    }
    return panel({ title: 'Priority alerts', hint: 'high and critical', actions: btn('All alerts', { size: 'sm', kind: 'ghost', onclick: () => ctx.go('#/alerts') }), flush: true },
      h('ul', { class: 'alist', role: 'listbox', 'aria-label': 'Priority alerts' }, rows.map((a) => alertRow(a, { compact: true, onOpen: (x) => ctx.go(`#/alerts/${x.id}`) }))));
  }

  function feedPanel() {
    return panel({ title: 'Live activity', hint: 'newest first', flush: true }, feedHost);
  }
  async function loadFeed() {
    try {
      const r = await api('/api/alerts?page_size=6&sort=time');
      renderFeed(r.items);
    } catch { /* feed is secondary */ }
  }
  function renderFeed(items) {
    clear(feedHost);
    if (!items.length) { put(feedHost, h('li', { style: 'display:block;cursor:default;color:var(--text-3)' }, 'Waiting for the first alert.')); return; }
    items.forEach((a) => put(feedHost, h('li', { class: freshIds.has(a.id) ? 'fresh' : '', onclick: () => ctx.go(`#/alerts/${a.id}`) },
      h('span', { class: 'bar', style: `background:${SEV_COLOR[a.severity]}` }), h('div', null, h('div', { class: 't' }, h('span', null, typeName(a.type)), h('span', { class: 'faint small' }, fmtClock(a.timestamp))), h('div', { class: 'd mono' }, a.source || a.destination || ''), ))));
  }

  function detections(d) {
    const rows = Object.entries(d.alerts.by_type).sort((x, y) => y[1] - x[1]).map(([k, v]) => ({ key: k, label: typeName(k), value: v, mono: false }));
    return panel({ title: 'Detections', hint: `last ${range}` }, distBars(rows, { onPick: (k) => k && ctx.go(`#/alerts?type=${k}&range=${range}`), empty: 'No detections in this range.' }));
  }
  function components(hs) {
    return panel({ title: 'Components', actions: btn('Details', { size: 'sm', kind: 'ghost', onclick: () => ctx.go('#/health') }), flush: true },
      h('ul', { class: 'comp' }, hs.components.map((c) => h('li', null, h('span', { class: 'n' }, COMP[c.name] || c.name), state(c.state)))));
  }
  function chainPanel(lg) {
    const host = h('div');
    boundary(host, async () => {
      const r = await api('/api/ledger/blocks?page_size=5');
      return h('ol', { class: 'chain', 'aria-label': 'Most recent ledger records' }, r.items.map((b) => h('li', { onclick: () => ctx.go(`#/ledger/${b.index}`), style: 'cursor:pointer' }, h('span', { class: `node ${lg.verified === false ? 'bad' : lg.verified ? 'ok' : ''}` }),
        h('div', null, h('div', { class: 'idx mono' }, `#${b.index}`, h('span', { class: 'meta', style: 'margin-left:8px;font-family:var(--font)' }, b.kind.toLowerCase().replace('_', ' '))), h('div', { class: 'meta mono' }, `${b.hash.slice(0, 14)}… ← ${b.previous_hash.slice(0, 8)}…`)))));
    });
    return panel({ title: 'Audit ledger', hint: `${fmtNum(lg.blocks)} records`, actions: btn('Open', { size: 'sm', kind: 'ghost', onclick: () => ctx.go('#/ledger') }), flush: true }, host);
  }

  put(root, h('div', { class: 'skeleton', style: 'height:150px;border-radius:10px' }));
  await load();
  loadFeed();
  const reload = debounce(() => { load(); loadFeed(); }, 1200);
  ctx.onLive('alerts', (e) => { e.detail.forEach((a) => freshIds.add(a.id)); setTimeout(() => e.detail.forEach((a) => freshIds.delete(a.id)), 2500); reload(); });
  ctx.onLive('integrity', reload);
  ctx.onLive('reconnected', reload);
  const poll = setInterval(() => { if (!document.hidden) load(); }, 20000);
  ctx.scope.add(() => { clearInterval(poll); chart && chart.destroy(); reload.cancel(); });
  return { update() {} };
}
