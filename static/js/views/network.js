import { api, qs } from '../core/api.js';
import { h, put, clear, debounce } from '../core/dom.js';
import { fmtBytes, fmtClock, fmtCompact, fmtNum, SEVS } from '../core/format.js';
import { RANGES, domainFor, getRange, setRange } from '../core/range.js';
import { stagger, tween } from '../core/motion.js';
import { SEV_COLOR, distBars, timeChart } from '../ui/charts.js';
import { boundary, btn, empty, notice, panel, seg } from '../ui/components.js';
import { createTopology } from '../ui/topology.js';

export default async function network(ctx) {
  let range = getRange(), data = null, filt = { proto: null, ip: null, port: null }, busy = false;
  const charts = [];
  let topo = null;
  ctx.setTitle('Network activity', 'Traffic, flows and detections');
  ctx.toolbar(seg(RANGES.map((r) => ({ value: r })), range, (r) => { range = r; setRange(r); load(); }, 'Time range'));
  const root = h('div', { class: 'stack' });
  put(ctx.root, root);
  const flowsHost = h('div'), topoHost = h('div', { class: 'topo' }), filterBar = h('div', { class: 'filterbar' });
  let flows = [], recentAlerts = [];

  async function load() {
    if (busy) return;
    busy = true;
    try {
      const [d, al] = await Promise.all([api(`/api/network?range=${range}`), api(`/api/alerts?page_size=100&range=${range}`)]);
      data = d; recentAlerts = al.items; draw(); loadFlows();
    } catch (e) { if (e.name !== 'AbortError') { clear(root); put(root, notice('bad', h('strong', null, 'Network data unavailable. '), e.message, ' ', btn('Retry', { size: 'sm', onclick: load }))); } }
    finally { busy = false; }
  }
  function draw() {
    charts.splice(0).forEach((c) => c.destroy()); topo && topo.destroy(); topo = null;
    const d = data, [t0, t1] = domainFor(range);
    const trafficHost = h('div', { style: 'padding:14px 16px 8px' }), detHost = h('div', { style: 'padding:6px 16px 12px' });
    const pk = h('span'), by = h('span'), fl = h('span'), dr = h('span');
    clear(root);
    put(root,
      d.data_mode !== 'live_capture' && notice('warn', h('strong', null, 'Synthetic traffic. '), 'These figures describe the simulator, not a real network.'),
      h('section', { class: 'panel' }, h('div', { class: 'stats', style: 'border-left:0;grid-template-columns:repeat(4,minmax(0,1fr))' },
        h('div', { class: 'stat' }, h('div', { class: 'k' }, `Packets · ${range}`), h('div', { class: 'v' }, pk)), h('div', { class: 'stat' }, h('div', { class: 'k' }, 'Volume'), h('div', { class: 'v' }, by)),
        h('div', { class: 'stat' }, h('div', { class: 'k' }, 'Active flows'), h('div', { class: 'v' }, fl), h('div', { class: 's' }, `table capacity ${fmtCompact(d.flows.max_flows)}`)), h('div', { class: 'stat' }, h('div', { class: 'k' }, 'Flows evicted'), h('div', { class: 'v' }, dr), h('div', { class: 's' }, 'oldest dropped when full')))),
      panel({ title: 'Traffic and detections', hint: `last ${range} · click a bar or point to open those alerts` }, h('div', { style: 'margin:-16px -16px -4px' }, trafficHost, h('div', { class: 'hr' }), detHost)),
      h('div', { class: 'net-grid' },
        panel({ title: 'Relationships', hint: 'active flows · who talks to whom', actions: filt.ip ? btn('Clear', { size: 'sm', kind: 'ghost', onclick: () => pick('ip', null) }) : null, flush: true }, topoHost),
        h('div', { class: 'stack' },
          panel({ title: 'Protocols' }, distBars(Object.entries(d.protocols).map(([k, v]) => ({ key: k, label: k, value: v, mono: false })), { selected: filt.proto, onPick: (k) => pick('proto', k) })),
          panel({ title: 'Destination ports', hint: 'by packets' }, distBars(d.top_ports.slice(0, 8).map((p) => ({ key: p.port, label: String(p.port), value: p.packets })), { selected: filt.port, onPick: (k) => pick('port', k) })))),
      h('div', { class: 'net-grid' },
        panel({ title: 'Top sources', hint: 'select to filter flows' }, distBars(d.top_sources.map((s) => ({ key: s.ip, label: s.ip, value: s.packets })), { selected: filt.ip, onPick: (k) => pick('ip', k) })),
        panel({ title: 'Top destinations' }, distBars(d.top_destinations.map((s) => ({ key: s.ip, label: s.ip, value: s.packets })), { selected: filt.ip, onPick: (k) => pick('ip', k) }))),
      panel({ title: 'Active flows', hint: 'most recent first, up to 100', actions: filterBar, flush: true }, flowsHost));
    tween(pk, d.packets, fmtCompact); tween(by, d.bytes, fmtBytes); tween(fl, d.flows.active_flows, fmtNum); tween(dr, d.flows.evicted_flows, fmtNum);
    const bs = d.bucket_seconds * 1000;
    charts.push(timeChart(trafficHost, { kind: 'area', bucketMs: bs, domain: [t0, t1], height: 170, label: `Packet rate, last ${range}`, yFormat: fmtCompact, tipFormat: (v) => `${v.toFixed(1)} /s`,
      series: [{ key: 'pps', label: 'Packets per second', color: 'var(--accent)' }], points: d.series.map((p) => ({ t: Date.parse(p.t), values: { pps: p.packets / d.bucket_seconds } })), emptyText: 'No traffic in this range',
      onSelect: (b) => ctx.go(`#/alerts?since=${new Date(b.t).toISOString()}&until=${new Date(b.end).toISOString()}`) }));
    const dbs = Math.max(60, Math.round((t1 - t0) / 1000 / 60)) * 1000;
    charts.push(timeChart(detHost, { kind: 'bars', stacked: true, bucketMs: dbs, domain: [t0, t1], height: 110, label: `Detections, last ${range}`,
      series: SEVS.slice(0, 4).map((s) => ({ key: s, label: s[0] + s.slice(1).toLowerCase(), color: SEV_COLOR[s] })), points: d.alert_timeline.map((p) => ({ t: Date.parse(p.t), values: p.sev || {} })), emptyText: 'No detections in this range',
      onSelect: (b) => ctx.go(`#/alerts?since=${new Date(b.t).toISOString()}&until=${new Date(b.end).toISOString()}`) }));
    topo = createTopology(topoHost, { onPick: (ip) => pick('ip', ip) });
    stagger(root, ':scope > .panel, :scope > .net-grid > *');
    drawFilter();
  }
  function pick(k, v) { filt[k] = v; draw(); }
  function drawFilter() {
    clear(filterBar);
    [['protocol', filt.proto, 'proto'], ['address', filt.ip, 'ip'], ['port', filt.port, 'port']].filter(([, v]) => v).forEach(([n, v, key]) => put(filterBar, h('button', { class: 'chip removable', onclick: () => pick(key, null) }, `${n} ${v}`)));
    if (filt.ip) put(filterBar, h('a', { class: 'small', href: `#/alerts?source=${filt.ip}` }, 'Alerts from this address'));
  }
  let fctl = null;
  async function loadFlows() {
    fctl && fctl.abort(); fctl = new AbortController();
    await boundary(flowsHost, async () => {
      const all = await api(`/api/network/flows${qs({ limit: 100 })}`, { signal: fctl.signal });
      flows = all.items;
      topo && topo.update(flows, recentAlerts); topo && topo.select(filt.ip);
      if (topoHost.isConnected && !flows.length) put(topoHost, h('div', { style: 'position:absolute;inset:0;display:grid;place-items:center' }, empty('No active flows', 'Flows appear as soon as traffic is observed.', 'network')));
      let rows = flows;
      if (filt.ip) rows = rows.filter((f) => f.src_ip === filt.ip || f.dst_ip === filt.ip);
      if (filt.port) rows = rows.filter((f) => String(f.dst_port) === String(filt.port) || String(f.src_port) === String(filt.port));
      if (filt.proto) rows = rows.filter((f) => f.protocol === filt.proto);
      if (!rows.length) return empty('No flows match', 'Clear a filter or widen the selection.', 'filter');
      return h('div', { class: 'table-wrap', tabindex: 0, role: 'region', 'aria-label': 'Active flows' }, h('table', { class: 't' }, h('thead', null, h('tr', null, ['Initiator', 'Peer', 'Proto', 'Packets', 'Out', 'In', 'Last seen'].map((c, i) => h('th', { class: i > 2 && i < 6 ? 'r' : '' }, c)))),
        h('tbody', null, rows.map((f) => h('tr', null, h('td', { class: 'mono' }, f.initiator), h('td', { class: 'mono' }, f.initiator === f.src_ip ? `${f.dst_ip}:${f.dst_port}` : `${f.src_ip}:${f.src_port}`), h('td', null, f.protocol), h('td', { class: 'r num' }, fmtNum(f.packets)), h('td', { class: 'r num' }, fmtBytes(f.outbound_bytes)), h('td', { class: 'r num' }, fmtBytes(f.inbound_bytes)), h('td', { class: 'nowrap' }, fmtClock(f.last_seen)))))));
    });
  }
  put(root, h('div', { class: 'skeleton', style: 'height:120px;border-radius:10px' }));
  await load();
  const reload = debounce(load, 2000);
  ctx.onLive('alerts', reload); ctx.onLive('reconnected', load);
  const poll = setInterval(() => { if (!document.hidden) load(); }, 20000);
  ctx.scope.add(() => { clearInterval(poll); fctl && fctl.abort(); charts.forEach((c) => c.destroy()); topo && topo.destroy(); reload.cancel(); });
  return {};
}
