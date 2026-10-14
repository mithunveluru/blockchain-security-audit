import { api, qs } from '../api.js';
import { areaChart, card, chart, clear, empty, errorBox, fmtBytes, fmtNum, fmtTime, h, skeleton, put } from '../ui.js';
import { rangeSelect } from '../components.js';

export default async function network(ctx) {
  let range = '1h', data = null, proto = '', ip = '', port = '', disposers = [], busy = false;
  try { range = sessionStorage.getItem('blockaudit.range') || '1h'; } catch { /* ignore */ }
  const root = h('div');
  put(ctx.root, root);
  const flowsBox = h('div');

  async function load() {
    if (busy) return;
    busy = true;
    try { data = await api(`/api/network?range=${range}`); draw(); loadFlows(); } catch (e) { put(clear(root), errorBox(e.message, load)); } finally { busy = false; }
  }
  const bars = (rows, label, key, onPick, selected) => {
    const max = Math.max(1, ...rows.map((r) => r[key]));
    if (!rows.length) return h('p', { class: 'muted' }, 'Nothing observed in this range.');
    return h('div', null, rows.map((r) => {
      const name = String(label(r));
      return h('div', { class: 'bar-row' }, h('button', { type: 'button', 'aria-pressed': String(selected === name), title: `Filter flows by ${name}`, onclick: () => onPick(selected === name ? '' : name) },
        h('span', { class: 'mono', style: selected === name ? 'font-weight:700;color:var(--accent)' : '' }, name), h('span', { class: 'bar' }, h('span', { style: `width:${(r[key] / max) * 100}%` })), h('span', { class: 'num muted' }, fmtNum(r[key]))));
    }));
  };
  function draw() {
    disposers.forEach((d) => d()); disposers = [];
    clear(root);
    const d = data, chartBox = h('div', { class: 'chart' });
    const protoRows = Object.entries(d.protocols).map(([name, packets]) => ({ name, packets }));
    put(root, 
      h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Network activity'), h('p', null, 'Traffic and flows as seen by the sensor. Only packet headers are inspected; payloads are never captured. Select a protocol, address or port to narrow the flow table.')),
        rangeSelect(range, ['5m', '15m', '1h', '6h', '24h'], (r) => { range = r; try { sessionStorage.setItem('blockaudit.range', r); } catch { /* ignore */ } load(); })),
      d.data_mode !== 'live_capture' && h('div', { class: 'notice warn' }, 'Synthetic traffic: these figures describe the simulator, not a real network.'),
      h('div', { class: 'grid cols-4' },
        stat('Packets', fmtNum(d.packets)), stat('Volume', fmtBytes(d.bytes)), stat('Active flows', fmtNum(d.flows.active_flows)),
        stat('Flow table', `${fmtNum(d.flows.evicted_flows)} evicted`, `capacity ${fmtNum(d.flows.max_flows)}`)),
      h('div', { style: 'margin-top:16px' }, card('Traffic and detections', `packets per second · ${range}`, chartBox, h('p', { class: 'muted small' }, `${d.alert_timeline.reduce((a, b) => a + b.total, 0)} alerts in range. `, h('a', { href: `#/alerts?range=${range}` }, 'Open them')))),
      h('div', { class: 'grid cols-2', style: 'margin-top:16px' },
        card('Protocols', 'packets', bars(protoRows, (r) => r.name, 'packets', (v) => { proto = v; loadFlows(); draw2(); }, proto)),
        card('Top ports', 'by destination port', bars(d.top_ports, (r) => r.port, 'packets', (v) => { port = v; loadFlows(); draw2(); }, port))),
      h('div', { class: 'grid cols-2', style: 'margin-top:16px' },
        card('Top sources', 'select to filter flows', bars(d.top_sources, (r) => r.ip, 'packets', (v) => { ip = v; loadFlows(); draw2(); }, ip)),
        card('Top destinations', null, bars(d.top_destinations, (r) => r.ip, 'packets', (v) => { ip = v; loadFlows(); draw2(); }, ip))),
      h('div', { style: 'margin-top:16px' }, card('Active flows', 'most recent first, up to 100', h('div', { class: 'row', style: 'margin-bottom:8px' }, filterChips(), ip && h('a', { href: `#/alerts?source=${encodeURIComponent(ip)}` }, `Alerts from ${ip}`)), flowsBox)));
    const pts = d.series.map((t) => ({ label: fmtTime(t.t, false).slice(0, 5), value: t.packets / d.bucket_seconds, title: `${fmtTime(t.t)}: ${(t.packets / d.bucket_seconds).toFixed(1)} packets/s, ${t.alerts} alerts` }));
    if (pts.length) disposers.push(chart(chartBox, areaChart(pts))); else put(chartBox, h('p', { class: 'muted' }, 'No traffic in this range.'));
  }
  const draw2 = () => draw();
  const filterChips = () => h('div', { class: 'chips' }, [['protocol', proto, () => { proto = ''; }], ['address', ip, () => { ip = ''; }], ['port', port, () => { port = ''; }]].filter(([, v]) => v).map(([n, v, clr]) => h('button', { class: 'chip', 'aria-pressed': 'true', onclick: () => { clr(); loadFlows(); draw(); }, title: 'Clear filter' }, `${n}: ${v} ×`)));

  let fctl = null;
  async function loadFlows() {
    fctl && fctl.abort(); fctl = new AbortController();
    put(clear(flowsBox), skeleton(3));
    try {
      const r = await api(`/api/network/flows${qs({ limit: 100, src: ip, port })}`, { signal: fctl.signal });
      const rows = proto ? r.items.filter((f) => f.protocol === proto) : r.items;
      clear(flowsBox);
      if (!rows.length) { put(flowsBox, empty('No matching flows', 'Flows expire after 5 minutes without traffic.')); return; }
      put(flowsBox, h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['Initiator', 'Peer', 'Proto', 'Packets', 'Out', 'In', 'Last seen'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, rows.map((f) => h('tr', null, h('td', { class: 'mono' }, `${f.initiator}`), h('td', { class: 'mono' }, f.initiator === f.src_ip ? `${f.dst_ip}:${f.dst_port}` : `${f.src_ip}:${f.src_port}`), h('td', null, f.protocol), h('td', { class: 'num' }, fmtNum(f.packets)), h('td', { class: 'num' }, fmtBytes(f.outbound_bytes)), h('td', { class: 'num' }, fmtBytes(f.inbound_bytes)), h('td', { class: 'nowrap' }, fmtTime(f.last_seen, false))))))));
    } catch (e) { if (e.name !== 'AbortError') put(clear(flowsBox), errorBox(e.message, loadFlows)); }
  }
  await load();
  const poll = setInterval(load, 15000);
  return () => { clearInterval(poll); fctl && fctl.abort(); disposers.forEach((d) => d()); };
}
const stat = (label, value, sub) => card(null, null, h('div', { class: 'kpi' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), sub && h('div', { class: 'sub' }, sub)));
