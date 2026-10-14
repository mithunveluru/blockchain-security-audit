import { api, qs, download } from '../core/api.js';
import { h, put, clear, debounce, sess } from '../core/dom.js';
import { fmtNum, fmtTime, place, typeName, SEVS } from '../core/format.js';

import { icon } from '../ui/icons.js';
import { SEV_COLOR } from '../ui/charts.js';
import { boundary, btn, empty, kv, notice, openMenu, pager, provTag, sev, skeleton, state, statusLabel, tabs, tag, time, toast } from '../ui/components.js';
import { alertRow } from '../ui/alertrow.js';
import { jsonView } from '../ui/code.js';
import { conversation, ALERT_QUESTIONS } from '../ui/copilot.js';
import { failureMeaning } from '../ui/ledgerx.js';

const DEFAULT = { q: '', severity: [], type: [], status: '', provenance: '', range: '', since: '', until: '', source: '', destination: '', sort: 'time', order: 'desc', page: 1 };
const PRESET_KEYS = ['q', 'severity', 'type', 'status', 'provenance', 'range', 'since', 'until', 'source', 'destination'];
const PAGE = 30;
const TABS = [['summary', 'Summary'], ['evidence', 'Evidence'], ['timeline', 'Timeline'], ['ledger', 'Ledger'], ['copilot', 'Copilot']];

export default async function alerts(ctx) {
  const me = ctx.state.me, canWrite = me.role !== 'viewer';
  let f = { ...DEFAULT, ...sess.get('alertfilters', {}) };
  const preset = PRESET_KEYS.filter((k) => ctx.query.has(k));
  if (preset.length) {
    f = { ...DEFAULT };
    preset.forEach((k) => { const v = ctx.query.get(k); f[k] = k === 'severity' || k === 'type' ? v.split(',').filter(Boolean) : v; });
    ctx.replaceQuery(Object.fromEntries(PRESET_KEYS.map((k) => [k, null])));
  }
  let more = !!(f.status || f.provenance), selected = ctx.params[0] || null, tab = ctx.query.get('tab') || 'summary', items = [], total = 0, facets = {}, ctl = null, gen = 0, detailGen = 0, panelScope = null;
  const loaded = new Set(), arrived = new Set();
  ctx.layout('flush');
  ctx.setTitle('Alerts', 'Investigate detections');
  ctx.toolbar(null);

  const listBox = h('ul', { class: 'alist', role: 'listbox', 'aria-label': 'Alerts', tabindex: 0 });
  const head = h('div', { class: 'ex-head' });
  const scroller = h('div', { class: 'ex-scroll' }, listBox);
  const pagerHost = h('div');
  const detailHost = h('section', { class: 'ex-detail', 'aria-label': 'Alert investigation', hidden: true });
  const ex = h('div', { class: 'explorer' }, h('div', { class: 'ex-list' }, head, scroller, pagerHost), detailHost);
  put(ctx.root, ex);

  const save = () => sess.set('alertfilters', f);
  const apply = (patch) => { Object.assign(f, patch, { page: patch.page || 1 }); save(); drawHead(); load(); };
  const active = () => f.q || f.severity.length || f.type.length || f.status || f.provenance || f.range || f.since || f.source || f.destination;

  // ---- filter bar ---------------------------------------------------------------------------
  const searchIn = h('input', { class: 'input', id: 'alert-search', type: 'search', placeholder: 'Search id, address, text   /', maxlength: 100, value: f.q, 'aria-label': 'Search alerts' });
  searchIn.addEventListener('input', debounce(() => apply({ q: searchIn.value.trim() }), 220));
  const sel = (label, key, opts) => h('select', { class: 'select', 'aria-label': label, onchange: (e) => apply({ [key]: e.target.value }) }, opts.map(([v, t]) => h('option', { value: v, selected: f[key] === v }, t)));
  function drawHead() {
    clear(head);
    const fc = facets;
    put(head,
      h('div', { class: 'filters' },
        h('div', { class: 'search', style: 'flex:1 1 220px;min-width:180px' }, icon('search'), searchIn),
        sel('Time range', 'range', [['', 'All time'], ...me.ranges.map((r) => [r, `Last ${r}`])]),
        h('select', { class: 'select', 'aria-label': 'Sort', onchange: (e) => { const [sort, order] = e.target.value.split(':'); apply({ sort, order }); } },
          [['time:desc', 'Newest first'], ['time:asc', 'Oldest first'], ['severity:desc', 'Severity'], ['score:desc', 'Anomaly score']].map(([v, t]) => h('option', { value: v, selected: `${f.sort}:${f.order}` === v }, t))),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More filters', 'aria-expanded': String(more), 'aria-pressed': String(more || !!(f.status || f.provenance)), 'data-tip': 'More filters', onclick: () => { more = !more; drawHead(); } }, icon('filter'))),
      more ? h('div', { class: 'filters' }, sel('Status', 'status', [['', 'Any status'], ...me.statuses.map((s) => [s, s.replace('_', ' ')])]), sel('Data source', 'provenance', [['', 'Any data'], ...me.provenance.filter((p) => p !== 'operator').map((p) => [p, p === 'simulation' ? 'Simulated' : p.replace('_', ' ')])])) : null,
      h('div', { class: 'facet-row', role: 'group', 'aria-label': 'Severity' }, SEVS.map((s) => {
        const on = f.severity.includes(s), n = fc.severity?.[s] || 0;
        return h('button', { type: 'button', class: 'chip', 'aria-pressed': String(on), disabled: !n && !on, onclick: () => apply({ severity: on ? f.severity.filter((x) => x !== s) : [...f.severity, s] }) }, h('span', { class: `sev sev-${s}`, style: 'gap:0' }, h('span', { style: `width:7px;height:7px;border-radius:50%;background:${SEV_COLOR[s]};display:inline-block;margin-right:6px` })), s.charAt(0) + s.slice(1).toLowerCase(), h('span', { class: 'n' }, fmtNum(n)));
      })),
      Object.keys(fc.type || {}).length > 0 || f.type.length ? h('div', { class: 'facet-row', role: 'group', 'aria-label': 'Detection type' }, [...new Set([...Object.keys(fc.type || {}), ...f.type])].sort().map((t) => {
        const on = f.type.includes(t);
        return h('button', { type: 'button', class: 'chip', 'aria-pressed': String(on), onclick: () => apply({ type: on ? f.type.filter((x) => x !== t) : [...f.type, t] }) }, typeName(t), h('span', { class: 'n' }, fmtNum(fc.type?.[t] || 0)));
      })) : null,
      active() ? h('div', { class: 'facet-row' }, h('span', { class: 'faint small' }, `${fmtNum(total)} ${total === 1 ? 'match' : 'matches'}`),
        f.since && h('button', { class: 'chip removable', onclick: () => apply({ since: '', until: '' }) }, `${fmtTime(f.since, false)} – ${fmtTime(f.until || new Date().toISOString(), false)}`),
        f.source && h('button', { class: 'chip removable', onclick: () => apply({ source: '' }) }, `source ${f.source}`), f.destination && h('button', { class: 'chip removable', onclick: () => apply({ destination: '' }) }, `destination ${f.destination}`),
        btn('Clear all', { size: 'sm', kind: 'ghost', onclick: () => { f = { ...DEFAULT }; searchIn.value = ''; save(); drawHead(); load(); } })) : null);
  }

  // ---- list ---------------------------------------------------------------------------------
  async function load(keepScroll = false) {
    ctl && ctl.abort(); ctl = new AbortController();
    const my = ++gen, top = scroller.scrollTop;
    if (!items.length) { clear(listBox); put(listBox, h('li', { role: 'presentation', style: 'padding:14px 20px' }, skeleton(5))); }
    try {
      const since = f.since || (f.range ? '' : '');
      const r = await api(`/api/alerts${qs({ q: f.q, severity: f.severity, type: f.type, status: f.status, provenance: f.provenance, range: f.range, since, until: f.until, source: f.source, destination: f.destination, sort: f.sort, order: f.order, page: f.page, page_size: PAGE })}`, { signal: ctl.signal });
      if (my !== gen) return;
      items = r.items; total = r.total; facets = r.facets;
      loaded.clear(); items.forEach((a) => { loaded.add(a.id); arrived.delete(a.id); });
      drawHead(); drawList(); if (keepScroll) scroller.scrollTop = top;
    } catch (e) {
      if (e.name === 'AbortError') return;
      clear(listBox); put(listBox, h('li', { role: 'presentation', style: 'padding:16px 20px' }, notice('bad', e.message, ' ', btn('Retry', { size: 'sm', onclick: () => load() }))));
    }
  }
  function drawList(fresh = new Set()) {
    clear(listBox);
    if (!items.length) {
      put(listBox, h('li', { role: 'presentation' }, active() ? empty('No alerts match these filters', 'Widen the time range or clear a filter.', 'filter', btn('Clear filters', { size: 'sm', onclick: () => { f = { ...DEFAULT }; searchIn.value = ''; save(); drawHead(); load(); } }))
        : empty('No alerts yet', me.simulation ? 'Simulation mode is running. The first scenario fires within about 20 seconds.' : 'Detection is running. Alerts appear here as soon as a rule fires.', 'shield')));
      clear(pagerHost); return;
    }
    if (arrived.size) put(listBox, h('li', { role: 'presentation', style: 'padding:8px 14px;background:var(--accent-soft);border-bottom:1px solid var(--line)' }, h('div', { class: 'between' }, h('span', { class: 'small' }, `${arrived.size} new ${arrived.size === 1 ? 'alert' : 'alerts'} since you loaded this list`), btn('Show', { size: 'sm', onclick: () => { const ids = new Set(arrived); arrived.clear(); f.page = 1; load().then(() => ids.forEach((id) => listBox.querySelector(`[data-id="${id}"]`)?.classList.add('fresh'))); } }))));
    items.forEach((a) => put(listBox, alertRow(a, { selected: a.id === selected, fresh: fresh.has(a.id), onOpen: (x) => ctx.go(`#/alerts/${x.id}${tab !== 'summary' ? `?tab=${tab}` : ''}`) })));
    clear(pagerHost); put(pagerHost, pager({ page: f.page, pages: Math.ceil(total / PAGE), total, size: PAGE, noun: 'alerts', onPage: (p) => { f.page = p; save(); load(); scroller.scrollTop = 0; } }));
    if (selected) listBox.setAttribute('aria-activedescendant', `ar-${selected}`);
  }
  listBox.addEventListener('keydown', (e) => {
    const i = items.findIndex((a) => a.id === selected);
    if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); const n = items[Math.min(items.length - 1, i + 1)]; n && ctx.go(`#/alerts/${n.id}${tab !== 'summary' ? `?tab=${tab}` : ''}`); }
    else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); const n = items[Math.max(0, i - 1)]; n && ctx.go(`#/alerts/${n.id}${tab !== 'summary' ? `?tab=${tab}` : ''}`); }
  });
  const onKey = (e) => {
    if (e.key === '/' && !e.target.matches('input, textarea, select')) { e.preventDefault(); searchIn.focus(); }
    else if (e.key === 'Escape' && selected && !e.target.matches('input, textarea, select') && !document.querySelector('dialog[open], .palette-wrap, .drawer')) ctx.go('#/alerts');
  };
  document.addEventListener('keydown', onKey);
  ctx.scope.add(() => document.removeEventListener('keydown', onKey));

  // ---- detail -------------------------------------------------------------------------------
  function markSelected() {
    listBox.querySelectorAll('.arow').forEach((el) => el.setAttribute('aria-selected', String(el.dataset.id === selected)));
    const el = selected && listBox.querySelector(`[data-id="${CSS.escape(selected)}"]`);
    el && el.scrollIntoView({ block: 'nearest' });
  }
  function closeDetail() { panelScope && panelScope.dispose(); panelScope = null; detailHost.hidden = true; clear(detailHost); ex.classList.remove('has-detail'); ctx.setTitle('Alerts', 'Investigate detections'); }
  async function openDetail() {
    const my = ++detailGen;
    ex.classList.add('has-detail'); detailHost.hidden = false;
    panelScope && panelScope.dispose();
    const s = (await import('../core/dom.js')).scope(); panelScope = s;
    clear(detailHost); put(detailHost, h('div', { class: 'db' }, skeleton(6)));
    try {
      const d = await api(`/api/alerts/${encodeURIComponent(selected)}`);
      if (my !== detailGen) return;
      drawDetail(d, s);
    } catch (e) {
      if (my !== detailGen) return;
      clear(detailHost); put(detailHost, h('div', { class: 'db' }, h('div', null, btn('Back to alerts', { size: 'sm', ic: 'left', onclick: () => ctx.go('#/alerts') })), notice('bad', e.status === 404 ? 'This alert is not in the retained history. It may be older than the retention window or from another deployment.' : e.message)));
    }
  }
  function drawDetail(d, s) {
    const a = d.alert, rule = d.rule || {}, ev = a.evidence || {};
    ctx.setTitle('Alerts', `${typeName(a.type)} · ${a.id}`);
    const body = h('div', { class: 'db', role: 'tabpanel', id: `pane-${tab}`, 'aria-labelledby': `tab-${tab}`, tabindex: 0 });
    const draw = () => {
      clear(body); body.id = `pane-${tab}`; body.setAttribute('aria-labelledby', `tab-${tab}`);
      ({ summary, evidence, timeline, ledgerTab, copilotTab }[{ summary: 'summary', evidence: 'evidence', timeline: 'timeline', ledger: 'ledgerTab', copilot: 'copilotTab' }[tab] || 'summary'])();
    };
    const setTab = (t) => { tab = t; ctx.replaceQuery({ tab: t === 'summary' ? null : t }); drawTabs(); draw(); };
    const tabHost = h('div');
    const drawTabs = () => { clear(tabHost); put(tabHost, tabs(TABS.map(([id, label]) => ({ id, label, count: id === 'evidence' ? (ev.sample_packets || []).length || null : id === 'timeline' ? d.related.length || null : null })), tab, setTab, 'Investigation sections')); };
    drawTabs();
    const exportMenu = (e) => openMenu(e.currentTarget, [{ label: 'Incident report (Markdown)', icon: 'download', run: () => download(`/api/alerts/${encodeURIComponent(a.id)}/report?format=md`, `${a.id}.md`).catch((x) => toast(x.message, 'bad')) }, { label: 'Incident report (JSON)', icon: 'download', run: () => download(`/api/alerts/${encodeURIComponent(a.id)}/report`, `${a.id}.json`).catch((x) => toast(x.message, 'bad')) }]);
    put(clear(detailHost),
      h('div', { class: 'dh' },
        h('div', { class: 'between' }, h('div', { class: 'row' }, btn('Alerts', { size: 'sm', kind: 'ghost', ic: 'left', cls: 'back', onclick: () => ctx.go('#/alerts') }), sev(a.severity), provTag(a.provenance), tag(a.rule || 'rule n/a'), h('span', { class: 'mono faint tiny' }, a.id)),
          h('div', { class: 'row' }, btn('Export', { size: 'sm', ic: 'download', onclick: exportMenu, 'aria-haspopup': 'menu' }), h('button', { class: 'icon-btn only-desktop', 'aria-label': 'Close investigation', 'data-tip': 'Close (Esc)', onclick: () => ctx.go('#/alerts') }, icon('x')))),
        h('div', { class: 'finding' }, h('h1', null, typeName(a.type)), h('p', { class: 'why' }, a.description), h('div', { class: 'row small faint' }, time(a.timestamp), a.occurrences > 1 && h('span', null, `· seen ${a.occurrences}×, last ${fmtTime(a.last_seen, false)}`), h('span', null, '·'), statusLabel(a.status))),
        tabHost), body);
    draw();

    function summary() {
      const th = ev.thresholds || {}, obs = Object.entries(ev.observed || {}).filter(([, v]) => typeof v === 'number');
      const map = { distinct_ports: 'distinct_ports', connection_attempts: 'connection_attempts', packets_per_second: 'packets_per_second', outbound_bytes: 'outbound_bytes', unique_sources: 'min_sources_for_ddos' };
      put(body,
        h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Why it was flagged'), rule.rule && h('span', { class: 'mono faint tiny' }, rule.rule)),
          h('p', null, rule.explains || 'No explanation is recorded for this detection.'),
          obs.length ? h('div', { class: 'measure', style: 'margin-top:12px' }, h('span', { class: 'faint tiny' }, 'MEASURE'), h('span', { class: 'faint tiny', style: 'text-align:right' }, 'OBSERVED'), h('span', { class: 'faint tiny', style: 'text-align:right' }, 'THRESHOLD'),
            obs.flatMap(([k, v]) => { const t = th[map[k]]; return [h('span', { class: 'k' }, k.replace(/_/g, ' ')), h('span', { class: 'v' }, fmtNum(v)), h('span', { class: 'th' }, t != null ? `≥ ${fmtNum(t)}` : '–'), t ? h('div', { class: 'meter' }, h('span', { style: `width:${Math.min(100, (v / t) * 100)}%;background:${v >= t ? 'var(--high)' : 'var(--accent)'}` })) : null]; })) : null,
          a.score != null && h('p', { style: 'margin-top:12px' }, h('strong', null, `Anomaly score ${a.score.toFixed(2)}`), h('span', { class: 'muted' }, ' on a 0 to 1 scale. Uncalibrated model output, not a probability that the activity is malicious.')),
          ev.observed?.contributors && h('ul', { class: 'stack-s', style: 'margin-top:8px' }, ev.observed.contributors.map((c) => h('li', { class: 'small muted' }, h('strong', { style: 'color:var(--text)' }, c.feature.replace(/_/g, ' ')), `: ${c.value} against a baseline median of ${c.baseline_median} (robust z ${c.robust_z})`))),
          rule.false_positives && h('p', { class: 'small faint', style: 'margin-top:10px' }, `Common benign causes: ${rule.false_positives}.`)),
        h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Participants')), kv([['Source', a.source && h('span', { class: 'row' }, h('span', { class: 'mono tk-ip' }, a.source), h('a', { class: 'small', href: `#/alerts?source=${a.source}` }, 'all alerts'))],
          ['Destination', a.destination && h('span', { class: 'mono tk-ip' }, `${a.destination}${a.dst_port ? `:${a.dst_port}` : ''}`)], ['Protocol', a.protocol]])),
        rule.next_steps?.length ? h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Suggested investigation steps'), h('span', { class: 'faint tiny' }, 'guidance only, nothing is executed')), h('ol', { class: 'steps' }, rule.next_steps.map((t) => h('li', null, t)))) : null,
        investigation(), d.missing_evidence.length ? notice('info', h('strong', null, 'Missing or limited evidence'), h('ul', { class: 'stack-s', style: 'margin-top:6px' }, d.missing_evidence.map((m) => h('li', null, m)))) : null);
    }
    function investigation() {
      const notes = h('div'), drawNotes = () => { clear(notes); const list = d.investigation.notes; put(notes, list.length ? list.map((n) => h('div', { class: 'note' }, h('div', { class: 'by' }, `${fmtTime(n.at)} · ${n.by}`), h('div', null, n.text))) : h('p', { class: 'faint small' }, 'No notes yet.')); };
      drawNotes();
      const input = h('textarea', { maxlength: 2000, placeholder: 'Add a finding, decision or hand-off note…', 'aria-label': 'Analyst note' });
      const st = h('select', { class: 'select', 'aria-label': 'Investigation status', disabled: !canWrite, onchange: async (e) => { try { await api(`/api/alerts/${encodeURIComponent(a.id)}`, { method: 'PATCH', body: { status: e.target.value } }); a.status = e.target.value; const row = items.find((x) => x.id === a.id); row && (row.status = a.status); drawList(); toast('Status updated', 'ok'); } catch (x) { toast(x.message, 'bad'); e.target.value = a.status; } } }, me.statuses.map((x) => h('option', { value: x, selected: a.status === x }, x.replace('_', ' '))));
      return h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Investigation'), h('div', { class: 'row' }, h('label', { class: 'small faint', for: 'x' }, 'Status'), st)), notes,
        canWrite ? h('div', { class: 'stack-s', style: 'margin-top:10px' }, input, h('div', null, btn('Add note', { size: 'sm', onclick: async () => { try { const n = await api(`/api/alerts/${encodeURIComponent(a.id)}/notes`, { method: 'POST', body: { text: input.value } }); d.investigation.notes.push(n); drawNotes(); input.value = ''; toast('Note added', 'ok'); } catch (x) { toast(x.message, 'bad'); } } }))) : h('p', { class: 'faint small' }, 'Your role can read notes but not add them.'));
    }
    function evidence() {
      const samples = ev.sample_packets || [];
      put(body,
        h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Packet headers'), h('span', { class: 'faint tiny' }, 'payloads are never captured')),
          samples.length ? h('div', { class: 'panel' }, h('div', { class: 'table-wrap', tabindex: 0, role: 'region', 'aria-label': 'Packet headers' }, h('table', { class: 't' }, h('thead', null, h('tr', null, ['Time', 'Source', 'Destination', 'Proto', 'Size', 'Flags'].map((c, i) => h('th', { class: i > 3 ? 'r' : '' }, c)))),
            h('tbody', null, samples.map((p) => h('tr', null, h('td', { class: 'nowrap mono' }, fmtTime(p.time, false).replace(' UTC', '')), h('td', { class: 'mono tk-ip' }, `${p.src}:${p.sport}`), h('td', { class: 'mono tk-ip' }, `${p.dst}:${p.dport}`), h('td', null, p.proto), h('td', { class: 'r num' }, p.size), h('td', { class: 'r mono' }, p.flags || '–'))))))) : notice('info', 'No packet samples are stored for this alert.')),
        h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Recorded evidence')), jsonView({ observed: ev.observed ?? null, thresholds: ev.thresholds ?? null, window_seconds: ev.window_seconds ?? null })));
    }
    async function timeline() {
      const host = h('div'); put(body, host);
      await boundary(host, async () => {
        const c = await api(`/api/alerts/${encodeURIComponent(a.id)}/context`);
        const rel = d.related.map((r) => ({ kind: 'alert', t: Date.parse(r.timestamp), r })), before = c.before.map((p) => ({ kind: 'pkt', t: Date.parse(p.time), p })), after = c.after.map((p) => ({ kind: 'pkt', t: Date.parse(p.time), p }));
        const seq = [...before, ...rel, { kind: 'now', t: Date.parse(a.timestamp) }, ...after].sort((x, y) => x.t - y.t);
        const items_ = seq.map((x) => x.kind === 'now' ? h('li', { class: 'now' }, h('div', { class: 't1' }, h('strong', null, typeName(a.type)), h('span', { class: 'faint small' }, 'this alert'), sev(a.severity)), h('div', { class: 't2' }, fmtTime(a.timestamp)))
          : x.kind === 'alert' ? h('li', null, h('div', { class: 't1' }, h('a', { href: `#/alerts/${x.r.id}?tab=timeline` }, typeName(x.r.type)), sev(x.r.severity), h('span', { class: 'faint small' }, x.r.relation)), h('div', { class: 't2' }, `${fmtTime(x.r.timestamp)} · ${place(x.r)}`))
            : h('li', { class: 'pkt' }, h('div', { class: 't1 mono small' }, `${x.p.src}:${x.p.sport} → ${x.p.dst}:${x.p.dport}`, h('span', { class: 'faint' }, `${x.p.proto} ${x.p.flags || ''} ${x.p.size}B`)), h('div', { class: 't2' }, fmtTime(x.p.time, false))));
        return h('div', { class: 'stack' },
          h('div', { class: 'between' }, h('p', { class: 'muted small' }, `Retained packet headers and alerts within ±${c.window_seconds}s that involve ${[a.source, a.destination].filter(Boolean).join(' or ')}.`), h('span', { class: 'faint small num' }, `${c.before_count} before · ${c.after_count} after`)),
          c.note && notice(c.complete ? 'info' : 'warn', c.note), c.data_mode !== 'live_capture' && notice('warn', 'These packets are synthetic.'),
          h('ul', { class: 'timeline' }, items_.length > 1 ? items_ : [...items_, h('li', null, h('div', { class: 't2' }, 'No other retained records in this window.'))]),
          c.flows.length ? h('section', null, h('div', { class: 'section-t' }, h('h2', { class: 'h3' }, 'Active flows from this source')), h('div', { class: 'panel' }, h('div', { class: 'table-wrap', tabindex: 0, role: 'region', 'aria-label': 'Active flows from this source' }, h('table', { class: 't' }, h('thead', null, h('tr', null, ['Peer', 'Proto', 'Packets', 'Out', 'In'].map((x, i) => h('th', { class: i > 1 ? 'r' : '' }, x)))), h('tbody', null, c.flows.map((fl) => h('tr', null, h('td', { class: 'mono' }, `${fl.dst_ip}:${fl.dst_port}`), h('td', null, fl.protocol), h('td', { class: 'r num' }, fmtNum(fl.packets)), h('td', { class: 'r num' }, fmtNum(fl.outbound_bytes)), h('td', { class: 'r num' }, fmtNum(fl.inbound_bytes))))))))) : null);
      });
    }
    async function ledgerTab() {
      const host = h('div'); put(body, host);
      if (a.ledger_index == null) { put(host, notice('warn', 'This alert is not recorded in the audit ledger, so its integrity cannot be checked.')); return; }
      await boundary(host, async () => {
        const [b, status] = await Promise.all([api(`/api/ledger/blocks/${a.ledger_index}`), api('/api/ledger/status')]);
        const lv = status.last_verification, mine = lv ? lv.failures.filter((x) => x.index === a.ledger_index) : [];
        const ok = b.checks.hash_matches_contents && b.checks.links_to_previous && !mine.length;
        const out = h('div', { class: 'stack' });
        put(out, ok ? notice('ok', h('strong', null, 'This record checks out. '), `Its contents produce the stored hash and it links to record #${a.ledger_index - 1}.${lv ? ` The chain was last verified at ${fmtTime(lv.checked_at, false)}${lv.valid ? ' with no failures' : ', and other records failed'}.` : ''}`) : notice('bad', h('strong', null, 'Verification failed for this record. '), mine.length ? mine.map((m) => failureMeaning(m.check)).join(' ') : 'See the checks below.'),
          h('div', { class: 'panel' }, h('div', { class: 'pb' }, kv([['Record', h('a', { href: `#/ledger/${a.ledger_index}` }, `#${a.ledger_index}`)], ['Recorded', time(b.block.timestamp)], ['Hash', h('span', { class: 'hash' }, b.block.hash)], ['Previous hash', h('span', { class: 'hash' }, b.block.previous_hash)],
            ['Contents match hash', state(b.checks.hash_matches_contents ? 'passed' : 'failed', b.checks.hash_matches_contents ? 'yes' : 'no')], ['Links to previous', state(b.checks.links_to_previous ? 'passed' : 'failed', b.checks.links_to_previous ? 'yes' : 'no')],
            ['Merkle proof', b.merkle && state(b.merkle.valid ? 'passed' : 'failed', b.merkle.valid ? `valid · ${b.merkle.path.length} steps` : 'invalid')]]))),
          h('div', { class: 'row' }, btn('Open in ledger', { ic: 'ledger', onclick: () => ctx.go(`#/ledger/${a.ledger_index}`) }), canWrite && btn('Verify whole chain', { ic: 'shield', onclick: async (e) => { e.currentTarget.disabled = true; try { const r = await api('/api/ledger/verify', { method: 'POST' }); toast(r.valid ? 'Ledger verified' : r.message, r.valid ? 'ok' : 'bad'); draw(); } catch (x) { toast(x.message, 'bad'); } } })),
          h('p', { class: 'faint small' }, 'A passing check shows the record was not edited since it was written. It does not prove the original detection was correct.'));
        return out;
      });
    }
    function copilotTab() {
      const c = conversation({ state: ctx.state, alertId: a.id, suggestions: ALERT_QUESTIONS });
      s.add(() => c.destroy());
      body.style.padding = '0 24px 8px'; body.style.height = '100%'; put(body, h('div', { style: 'height:calc(100vh - 330px);min-height:360px' }, c.el));
    }
  }

  // ---- go -----------------------------------------------------------------------------------
  drawHead();
  await load();
  if (selected) openDetail();
  ctx.onLive('alerts', (e) => { const n = e.detail.filter((a) => !loaded.has(a.id)); if (!n.length) return; n.forEach((a) => arrived.add(a.id)); drawList(); });
  ctx.onLive('reconnected', () => load(true));
  const poll = setInterval(() => { if (!document.hidden && !document.activeElement?.matches('textarea')) load(true); }, 30000);
  ctx.scope.add(() => { clearInterval(poll); ctl && ctl.abort(); panelScope && panelScope.dispose(); });
  return {
    async update(c2) {
      const id = c2.params[0] || null, t = c2.query.get('tab') || 'summary';
      const anyPreset = PRESET_KEYS.some((k) => c2.query.has(k));
      if (anyPreset) return false;
      if (id === selected && t === tab) return;
      const changed = id !== selected;
      selected = id; tab = t;
      markSelected();
      if (!id) { closeDetail(); return; }
      if (changed) openDetail(); else openDetail();
    },
  };
}
