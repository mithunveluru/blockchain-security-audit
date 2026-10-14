import { api, qs, download } from '../api.js';
import { card, clear, empty, errorBox, fmtNum, fmtTime, h, kv, provBadge, sevBadge, skeleton, stateBadge, timeEl, toast, put } from '../ui.js';
import { SEVS, alertTable, copilotPanel, place, typeName } from '../components.js';

const KEY = 'blockaudit.alertfilters';

export default function alerts(ctx) {
  return ctx.params[0] ? detail(ctx, ctx.params[0]) : list(ctx);
}

async function list(ctx) {
  const me = ctx.state.me;
  let f = { q: '', severity: [], type: '', status: '', provenance: '', range: '', source: '', sort: 'time', order: 'desc', page: 1 };
  try { Object.assign(f, JSON.parse(sessionStorage.getItem(KEY) || '{}')); } catch { /* ignore */ }
  for (const [k, v] of ctx.query) if (k in f) f[k] = k === 'severity' ? v.split(',') : k === 'page' ? Number(v) || 1 : v;
  const pageSize = 25;
  let ctl = null, pending = 0;
  const loaded = new Set();
  const body = h('div'), banner = h('div');
  const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(f)); } catch { /* ignore */ } };

  const input = (label, key, attrs = {}) => h('div', { class: 'field' }, h('label', { for: `f-${key}` }, label),
    h('input', { id: `f-${key}`, value: f[key], ...attrs, onchange: (e) => { f[key] = e.target.value.trim(); f.page = 1; run(); } }));
  const select = (label, key, options) => h('div', { class: 'field' }, h('label', { for: `f-${key}` }, label),
    h('select', { id: `f-${key}`, onchange: (e) => { f[key] = e.target.value; f.page = 1; run(); } },
      options.map(([v, t]) => h('option', { value: v, selected: f[key] === v }, t))));
  const sevChips = h('div', { class: 'field' }, h('label', null, 'Severity'), h('div', { class: 'chips', role: 'group', 'aria-label': 'Severity filter' },
    SEVS.map((s) => h('button', { type: 'button', class: 'chip', 'aria-pressed': String(f.severity.includes(s)), onclick: (e) => {
      f.severity = f.severity.includes(s) ? f.severity.filter((x) => x !== s) : [...f.severity, s];
      e.currentTarget.setAttribute('aria-pressed', String(f.severity.includes(s))); f.page = 1; run();
    } }, s))));

  put(ctx.root, 
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Alerts'), h('p', null, 'Every detection with its evidence. Open one to see why it fired and what supports it.'))),
    banner,
    h('form', { class: 'filters', onsubmit: (e) => e.preventDefault(), role: 'search' },
      input('Search', 'q', { type: 'search', placeholder: 'id, address, description', maxlength: 100 }), sevChips,
      select('Detection', 'type', [['', 'All'], ...Object.keys(me.rules).map((t) => [t, typeName(t)])]),
      select('Status', 'status', [['', 'All'], ...me.statuses.map((s) => [s, s.replace('_', ' ')])]),
      select('Data', 'provenance', [['', 'All'], ...me.provenance.map((p) => [p, p.replace('_', ' ')])]),
      select('Time range', 'range', [['', 'All time'], ...me.ranges.map((r) => [r, `Last ${r}`])]),
      input('Source address', 'source', { placeholder: '203.0.113.5', maxlength: 45 }),
      select('Sort', 'sort', [['time', 'Time'], ['severity', 'Severity'], ['score', 'Score']]),
      select('Order', 'order', [['desc', 'Descending'], ['asc', 'Ascending']]),
      h('button', { class: 'btn ghost small', type: 'button', onclick: () => { try { sessionStorage.removeItem(KEY); } catch { /* ignore */ } ctx.go(`#/alerts?reset=${Date.now()}`); } }, 'Reset')),
    body);

  async function run() {
    save();
    ctl && ctl.abort();
    ctl = new AbortController();
    const my = ++pending;
    put(clear(body), skeleton(5));
    try {
      const r = await api(`/api/alerts${qs({ q: f.q, severity: f.severity, type: f.type, status: f.status, provenance: f.provenance, range: f.range, source: f.source, sort: f.sort, order: f.order, page: f.page, page_size: pageSize })}`, { signal: ctl.signal });
      if (my !== pending) return;
      loaded.clear();
      r.items.forEach((x) => { loaded.add(x.id); arrived.delete(x.id); });
      showBanner();
      clear(body);
      if (!r.items.length) {
        put(body, empty(f.q || f.severity.length || f.type || f.status || f.source || f.range ? 'No alerts match these filters' : 'No alerts yet',
          f.q || f.severity.length || f.type || f.status || f.source || f.range ? 'Widen the time range or clear a filter.' : 'Detection is running. Alerts appear here as soon as a rule fires.'));
        return;
      }
      const pages = Math.ceil(r.total / pageSize);
      put(body, alertTable(r.items, (a) => ctx.go(`#/alerts/${encodeURIComponent(a.id)}`)),
        h('div', { class: 'pager' }, h('span', { class: 'muted' }, `${fmtNum(r.total)} alerts · page ${f.page} of ${pages}`),
          h('div', { class: 'row' },
            h('button', { class: 'btn small', disabled: f.page <= 1, onclick: () => { f.page--; run(); } }, 'Previous'),
            h('button', { class: 'btn small', disabled: f.page >= pages, onclick: () => { f.page++; run(); } }, 'Next'))));
    } catch (e) {
      if (e.name === 'AbortError') return;
      put(clear(body), errorBox(e.message, run));
    }
  }
  const arrived = new Set();
  const showBanner = () => {
    clear(banner);
    if (arrived.size) put(banner, h('div', { class: 'notice info', role: 'status' }, `${arrived.size} new alert${arrived.size > 1 ? 's' : ''} arrived. `,
      h('button', { class: 'btn small', onclick: () => { arrived.clear(); run(); } }, 'Refresh list')));
  };
  ctx.on('alert', (e) => { if (!loaded.has(e.detail.id)) { arrived.add(e.detail.id); showBanner(); } });
  await run();
  return () => ctl && ctl.abort();
}

async function detail(ctx, id) {
  const me = ctx.state.me, canWrite = me.role !== 'viewer';
  const d = await api(`/api/alerts/${encodeURIComponent(id)}`);
  const a = d.alert, ev = a.evidence || {}, rule = d.rule || {};
  const notes = h('div');
  const status = h('select', { id: 'st', disabled: !canWrite, onchange: async (e) => {
    try { await api(`/api/alerts/${encodeURIComponent(id)}`, { method: 'PATCH', body: { status: e.target.value } }); toast('Status updated', 'ok'); } catch (err) { toast(err.message, 'bad'); e.target.value = a.status; }
  } }, me.statuses.map((s) => h('option', { value: s, selected: a.status === s }, s.replace('_', ' '))));
  const drawNotes = (list) => {
    put(clear(notes), list.length ? h('ul', null, list.map((n) => h('li', null, h('span', { class: 'muted small' }, `${fmtTime(n.at)} · ${n.by}`), h('div', null, n.text)))) : h('p', { class: 'muted' }, 'No notes yet.'));
  };
  drawNotes(d.investigation.notes);
  const noteIn = h('textarea', { id: 'note', maxlength: 2000, 'aria-label': 'Analyst note' });

  const observed = Object.entries(ev.observed || {}), thresholds = ev.thresholds || {};
  const samples = ev.sample_packets || [];
  const panel = copilotPanel(ctx, { alertId: id, suggestions: ['Why was this alert raised?', 'What evidence supports it?', 'What happened around this time?', 'Which other alerts involve this source?', 'What should I investigate next?'] });

  put(ctx.root, 
    h('p', { class: 'small' }, h('a', { href: '#/alerts' }, '← All alerts')),
    h('div', { class: 'page-head' }, h('div', null,
      h('div', { class: 'row' }, sevBadge(a.severity), provBadge(a.provenance), h('span', { class: 'muted mono small' }, a.id)),
      h('h1', { style: 'margin-top:6px' }, typeName(a.type)), h('p', null, a.description)),
      h('div', { class: 'row' },
        h('div', { class: 'field' }, h('label', { for: 'st' }, 'Investigation status'), status),
        h('button', { class: 'btn', onclick: () => download(`/api/alerts/${encodeURIComponent(id)}/report?format=md`, `${id}.md`).catch((e) => toast(e.message, 'bad')) }, 'Export report'),
        h('button', { class: 'btn', onclick: () => download(`/api/alerts/${encodeURIComponent(id)}/report`, `${id}.json`).catch((e) => toast(e.message, 'bad')) }, 'Export JSON'))),
    a.provenance !== 'live_capture' && a.provenance !== 'historical' && h('div', { class: 'notice warn' }, `This alert comes from ${a.provenance.replace('_', ' ')} data, not observed network traffic.`),
    h('div', { class: 'grid cols-21' },
      h('div', { class: 'grid' },
        card('Why it was flagged', rule.rule || a.rule,
          h('p', null, rule.explains || 'No explanation is recorded for this detection type.'),
          (observed.length || Object.keys(thresholds).length) && h('div', { class: 'table-wrap', style: 'margin:10px 0' }, h('table', null,
            h('thead', null, h('tr', null, h('th', null, 'Measure'), h('th', null, 'Observed'), h('th', null, 'Threshold'))),
            h('tbody', null, observed.filter(([, v]) => typeof v !== 'object' || v === null).map(([k, v]) => h('tr', null, h('td', null, k.replace(/_/g, ' ')), h('td', { class: 'num' }, String(v)), h('td', { class: 'num muted' }, thresholdFor(k, thresholds))))))),
          a.score != null && h('p', null, h('strong', null, `Anomaly score ${a.score.toFixed(2)}`), ' on a 0 to 1 scale. This is an uncalibrated model output, not a probability that the activity is malicious.'),
          ev.observed?.contributors && h('ul', null, ev.observed.contributors.map((c) => h('li', null, `${c.feature.replace(/_/g, ' ')}: ${c.value} against a baseline median of ${c.baseline_median} (robust z ${c.robust_z})`))),
          rule.false_positives && h('p', { class: 'muted small' }, `Common benign causes: ${rule.false_positives}.`)),
        card('Evidence', `${samples.length} packet summaries · payloads are never captured`,
          samples.length ? h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['Time', 'Source', 'Destination', 'Proto', 'Size', 'Flags'].map((c) => h('th', null, c)))),
            h('tbody', null, samples.map((s) => h('tr', null, h('td', { class: 'nowrap' }, fmtTime(s.time, false)), h('td', { class: 'mono' }, `${s.src}:${s.sport}`), h('td', { class: 'mono' }, `${s.dst}:${s.dport}`), h('td', null, s.proto), h('td', { class: 'num' }, s.size), h('td', null, s.flags || '–'))))))
            : h('p', { class: 'muted' }, 'No packet samples are stored for this alert.'),
          d.missing_evidence.length > 0 && h('div', { class: 'notice info', style: 'margin-top:12px' }, h('strong', null, 'Missing or limited evidence'), h('ul', null, d.missing_evidence.map((m) => h('li', null, m))))),
        card('Timeline', 'alerts sharing this source or destination within 15 minutes',
          h('ul', { class: 'timeline' },
            [...d.related.map((r) => ({ ...r, current: false })), { ...a, current: true, relation: 'this alert' }].sort((x, y) => x.timestamp.localeCompare(y.timestamp)).map((r) =>
              h('li', { class: r.current ? 'current' : '' }, h('div', { class: 'row' }, sevBadge(r.severity), r.current ? h('strong', null, typeName(r.type)) : h('a', { href: `#/alerts/${encodeURIComponent(r.id)}` }, typeName(r.type)), h('span', { class: 'muted small' }, r.relation)),
                h('div', { class: 'muted small' }, `${fmtTime(r.timestamp)} · ${place(r)}`)))),
          !d.related.length && h('p', { class: 'muted' }, 'No related alerts in this window.')),
        card('Analyst notes', canWrite ? null : 'read only for your role', notes, canWrite && h('div', { style: 'margin-top:10px' }, h('label', { for: 'note' }, 'Add a note'), noteIn,
          h('button', { class: 'btn', style: 'margin-top:8px', onclick: async () => {
            try { const n = await api(`/api/alerts/${encodeURIComponent(id)}/notes`, { method: 'POST', body: { text: noteIn.value } }); d.investigation.notes.push(n); drawNotes(d.investigation.notes); noteIn.value = ''; toast('Note added', 'ok'); } catch (e) { toast(e.message, 'bad'); }
          } }, 'Add note')))),
      h('div', { class: 'grid', style: 'align-content:start' },
        card('Details', null, kv([['First seen', timeEl(a.timestamp)], ['Last seen', timeEl(a.last_seen)], ['Occurrences', a.occurrences], ['Source', a.source && h('span', { class: 'mono' }, a.source, ' ', h('a', { class: 'small', href: `#/alerts?source=${encodeURIComponent(a.source)}` }, 'all alerts'))],
          ['Destination', a.destination && h('span', { class: 'mono' }, `${a.destination}${a.dst_port ? ':' + a.dst_port : ''}`)], ['Protocol', a.protocol], ['Rule', a.rule], ['Status', stateBadge(a.status)]])),
        card('Audit ledger record', null, a.ledger_index == null ? h('p', { class: 'muted' }, 'This alert is not recorded in the ledger, so its integrity cannot be checked.')
          : kv([['Block', h('a', { href: `#/ledger/${a.ledger_index}` }, `#${a.ledger_index}`)], ['Block hash', h('span', { class: 'hash' }, a.ledger_hash)], ['Previous block hash', d.ledger_block && h('span', { class: 'hash' }, d.ledger_block.previous_hash)]]),
          h('p', { class: 'small' }, h('a', { href: a.ledger_index == null ? '#/ledger' : `#/ledger/${a.ledger_index}` }, 'Inspect and verify this record'))),
        card('Ask the copilot', 'read only', panel.el))));
  return panel.dispose;
}
function thresholdFor(k, t) {
  const map = { distinct_ports: 'distinct_ports', connection_attempts: 'connection_attempts', packets_per_second: 'packets_per_second', outbound_bytes: 'outbound_bytes', unique_sources: 'min_sources_for_ddos' };
  const v = t[map[k]];
  return v == null ? '–' : String(v);
}
