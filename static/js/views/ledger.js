import { api, download, qs } from '../core/api.js';
import { h, put, clear, debounce } from '../core/dom.js';
import { fmtNum, fmtTime, shortHash, typeName } from '../core/format.js';
import { stagger } from '../core/motion.js';
import { icon } from '../ui/icons.js';
import { boundary, btn, empty, kv, notice, pager, panel, sev, skeleton, state, tabs, time, toast } from '../ui/components.js';
import { jsonView } from '../ui/code.js';
import { LIMITS, failureMeaning, failureTitle } from '../ui/ledgerx.js';

const KINDS = [['', 'All records'], ['ALERT', 'Alerts'], ['OPERATOR_ACTION', 'Operator actions'], ['SECURITY_THREAT', 'Legacy threats'], ['LEDGER_RESTART', 'Restarts'], ['GENESIS', 'Genesis']];
const PAGE = 20;
const LABELS = { hash_mismatch: ['recomputed from contents', 'stored'], diverged_from_memory: ['service holds', 'file has'], link_broken: ['previous record is', 'this record points to'], history_rewritten: ['checkpoint says', 'file has'] };
const SUMMARY = /^(CRITICAL|HIGH|MEDIUM|LOW|INFO) (\S+)\s*(.*)$/;
function summary(b) {
  const m = b.kind === 'ALERT' && SUMMARY.exec(b.summary);
  return m ? h('span', { class: 'sevline' }, sev(m[1]), h('strong', null, typeName(m[2])), h('span', { class: 'mono faint small' }, m[3])) : b.summary;
}

export default async function ledger(ctx) {
  const canVerify = ctx.state.me.role !== 'viewer';
  let selected = ctx.params[0] != null ? Number(ctx.params[0]) : null, status = null, f = { q: '', kind: '', page: 1 }, items = [], total = 0, ctl = null, tab = 'record';
  ctx.setTitle('Audit ledger', 'Hash-linked evidence');
  ctx.toolbar(null);
  const root = h('div', { class: 'stack' }), banner = h('div', { class: 'stack' }), listHost = h('div'), detail = h('div', { style: 'position:sticky;top:0' });
  put(ctx.root, root);
  const failedIdx = () => new Set((status?.last_verification?.failures || []).map((x) => x.index).filter((i) => i != null));
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Search hash, alert id, text', maxlength: 100, 'aria-label': 'Search ledger records', style: 'flex:1;min-width:160px' });
  search.addEventListener('input', debounce(() => { f.q = search.value.trim(); f.page = 1; loadList(); }, 220));
  const kind = h('select', { class: 'select', 'aria-label': 'Record type', onchange: (e) => { f.kind = e.target.value; f.page = 1; loadList(); } }, KINDS.map(([v, t]) => h('option', { value: v }, t)));
  put(root, banner, h('div', { class: 'ledger-grid' },
    panel({ title: 'Records', hint: 'newest first', actions: null, flush: true }, h('div', { class: 'filters', style: 'padding:10px 14px;border-bottom:1px solid var(--line)' }, search, kind), listHost),
    detail));

  async function loadStatus() {
    try { status = await api('/api/ledger/status'); drawBanner(); markList(); }
    catch (e) { clear(banner); put(banner, notice('bad', e.message, ' ', btn('Retry', { size: 'sm', onclick: loadStatus }))); }
  }
  function drawBanner() {
    const s = status, lv = s.last_verification, im = s.integrity, bad = im.tampering_detected || (lv && !lv.valid);
    clear(banner);
    const has = (...c) => lv.failures.some((x) => c.includes(x.check)) || (lv.failure_count > lv.failures.length);
    const cks = lv ? [['Every hash recomputed', !has('hash_mismatch', 'malformed', 'unparseable')], ['Links and numbering', !has('link_broken', 'index', 'genesis', 'duplicate', 'empty')], ['Saved checkpoint', lv.checks.checkpoint === 'matched'], ['Running service copy', lv.checks.memory_copy === 'matched']] : [];
    put(banner,
      s.recovery && notice('warn', h('strong', null, 'Recovered at startup. '), ({ migrated_legacy_json: `The earlier JSON-array ledger was converted (${s.recovery.blocks} records) and a backup named ${s.recovery.backup} was kept.`, truncated_partial_tail: `An incomplete last record from an interrupted write was moved to ${s.recovery.quarantined_to}.`, quarantined_corrupt_ledger: `An unreadable record at line ${s.recovery.line} was found. The old file is kept as ${s.recovery.quarantined_to} and a new chain references it.` })[s.recovery.kind] || s.recovery.kind),
      s.last_write_error && notice('bad', `The last ledger write failed (${s.last_write_error.error}). New records may be missing.`),
      h('section', { class: `panel integrity ${bad ? 'bad' : lv ? 'ok' : ''}` },
        h('div', { class: 'seal' }, icon(bad ? 'warn' : 'shield')),
        h('div', null, h('h2', null, bad ? `Integrity failure: ${lv ? lv.failure_count : ''} check${lv && lv.failure_count === 1 ? '' : 's'} failed` : lv ? `Verified · ${fmtNum(lv.checked_blocks)} records` : 'Not verified yet'),
          h('p', { class: 'muted small', style: 'margin-top:2px' }, lv ? `${lv.message}. Last checked ${fmtTime(lv.checked_at)} (${lv.source === 'disk' ? 'file on disk against the running service' : 'in memory'}). ${im.checks} background checks, every ${im.check_interval_seconds}s.` : 'The first background check runs shortly after start.'),
          cks.length ? h('div', { class: 'checks' }, cks.map(([t, ok]) => h('span', null, state(ok ? 'passed' : 'failed', t)))) : null),
        h('div', { class: 'row' }, canVerify && btn('Verify now', { kind: 'primary', ic: 'shield', onclick: verify }), btn('Export checkpoint', { ic: 'download', onclick: exportCp }))),
      bad && lv ? panel({ title: 'What failed', hint: 'in plain language' }, lv.failures.slice(0, 8).map((x) => h('div', { class: 'failure' }, h('div', { class: 'row' }, h('strong', null, failureTitle(x.check)), x.index != null ? h('a', { href: `#/ledger/${x.index}` }, `record #${x.index}`) : h('span', { class: 'faint' }, 'whole ledger')), h('p', { class: 'why' }, failureMeaning(x.check)), x.expected && h('div', { class: 'hash' }, `${LABELS[x.check]?.[0] || 'expected'} ${shortHash(String(x.expected), 12, 8)}`, ' · ', `${LABELS[x.check]?.[1] || 'found'} ${shortHash(String(x.actual ?? ''), 12, 8)}`)))) : null,
      h('details', null, h('summary', { class: 'small faint' }, 'What this does and does not prove'), h('p', { class: 'small muted', style: 'margin-top:8px;max-width:80ch' }, LIMITS), h('p', { class: 'small faint', style: 'margin-top:6px' }, `Durability: ${s.durability}. Checkpoint writes ${s.checkpoint_error ? `failing (${s.checkpoint_error})` : 'ok'}. Merkle root of all records: ${shortHash(s.merkle_root, 14, 8)}`)));
  }
  async function verify(e) {
    const b = e.currentTarget; b.disabled = true;
    try { const r = await api('/api/ledger/verify', { method: 'POST' }); toast(r.valid ? 'Ledger verified' : r.message, r.valid ? 'ok' : 'bad'); await loadStatus(); if (selected != null) drawDetail(); } catch (x) { toast(x.message, 'bad'); }
    b.disabled = false;
  }
  async function exportCp() { try { await download('/api/ledger/checkpoint', 'blockaudit-checkpoint.json'); toast('Checkpoint downloaded. Store it away from this host.', 'ok'); } catch (e) { toast(e.message, 'bad'); } }

  async function loadList() {
    ctl && ctl.abort(); ctl = new AbortController();
    if (!items.length) { clear(listHost); put(listHost, h('div', { style: 'padding:14px' }, skeleton(5))); }
    try {
      const r = await api(`/api/ledger/blocks${qs({ q: f.q, kind: f.kind, page: f.page, page_size: PAGE })}`, { signal: ctl.signal });
      items = r.items; total = r.total; drawList();
    } catch (e) { if (e.name !== 'AbortError') { clear(listHost); put(listHost, notice('bad', e.message, ' ', btn('Retry', { size: 'sm', onclick: loadList }))); } }
  }
  function drawList() {
    clear(listHost);
    if (!items.length) { put(listHost, empty('No matching records', 'Try a different search or record type.', 'ledger')); return; }
    const bad = failedIdx();
    put(listHost, h('ol', { class: 'blocks', role: 'listbox', 'aria-label': 'Ledger records' }, items.map((b) => h('li', { role: 'option', tabindex: 0, 'aria-selected': String(b.index === selected), class: bad.has(b.index) ? 'bad' : '', 'data-i': b.index, onclick: () => ctx.go(`#/ledger/${b.index}`), onkeydown: (e) => { if (e.key === 'Enter') ctx.go(`#/ledger/${b.index}`); } },
      h('span', { class: 'rail' }, h('span', { class: 'node' })), h('div', { style: 'min-width:0' }, h('div', { class: 'h' }, h('span', { class: 'idx' }, `#${b.index}`), h('span', { class: 'tag' }, b.kind.toLowerCase().replace('_', ' ')), bad.has(b.index) && state('failed', 'failed verification')), h('div', { class: 'sum wrap' }, summary(b)), h('div', { class: 'hs' }, `${shortHash(b.hash, 12, 6)} ← ${shortHash(b.previous_hash, 8, 4)}`)),
      h('time', { class: 'faint tiny nowrap', datetime: b.timestamp, title: b.timestamp }, fmtTime(b.timestamp, false).replace(' UTC', ''))))),
    pager({ page: f.page, pages: Math.ceil(total / PAGE), total, size: PAGE, noun: 'records', onPage: (p) => { f.page = p; loadList(); } }));
  }
  function markList() { const bad = failedIdx(); listHost.querySelectorAll('li[data-i]').forEach((li) => { const i = Number(li.dataset.i); li.setAttribute('aria-selected', String(i === selected)); li.classList.toggle('bad', bad.has(i)); }); }

  async function drawDetail() {
    clear(detail);
    if (selected == null || !Number.isInteger(selected)) {
      put(detail, panel({ title: 'Record details' }, empty('Select a record', 'Choose a record to see its hashes, how it links to its neighbours, and whether it verifies.', 'ledger')));
      return;
    }
    const host = h('div'); put(detail, host);
    await boundary(host, async () => {
      const d = await api(`/api/ledger/blocks/${selected}`);
      const b = d.block, fails = (status?.last_verification?.failures || []).filter((x) => x.index === selected);
      const ok = d.checks.hash_matches_contents && d.checks.links_to_previous && !fails.length;
      const body = h('div', { class: 'pb stack' });
      const draw = () => {
        clear(body);
        if (tab === 'record') put(body,
          !ok && notice('bad', h('strong', null, 'This record fails verification. '), fails.length ? fails.map((x) => `${failureTitle(x.check)}. ${failureMeaning(x.check)}`).join(' ') : 'Its contents or its link to the previous record do not check out.'),
          kv([['Recorded', time(b.timestamp)], ['Type', d.summary.kind.toLowerCase().replace('_', ' ')], ['Hash', h('span', { class: 'hash' }, b.hash)],
            ['Previous hash', h('span', { class: 'row' }, h('span', { class: 'hash' }, b.previous_hash), selected > 0 && h('a', { class: 'small', href: `#/ledger/${selected - 1}` }, `open #${selected - 1}`))],
            ['Next record', d.next_hash ? h('span', { class: 'row' }, h('span', { class: 'hash' }, `links back with ${shortHash(b.hash, 10, 6)}`), h('a', { class: 'small', href: `#/ledger/${selected + 1}` }, `open #${selected + 1}`)) : 'None yet. This is the newest record.'],
            ['Linked alerts', d.summary.alert_ids.length ? h('span', { class: 'row' }, d.summary.alert_ids.map((id) => h('a', { class: 'ref', href: `#/alerts/${encodeURIComponent(id)}` }, id))) : null]]),
          h('div', { class: 'stack-s' }, h('h2', { class: 'h3' }, 'Checks on this record'), h('div', { class: 'row', style: 'gap:18px' }, state(d.checks.hash_matches_contents ? 'passed' : 'failed', d.checks.hash_matches_contents ? 'contents match hash' : 'contents do not match hash'), state(d.checks.links_to_previous ? 'passed' : 'failed', d.checks.links_to_previous ? 'links to previous' : 'link broken'))));
        else if (tab === 'proof') put(body, d.merkle ? h('div', { class: 'stack' },
          kv([['Root', h('span', { class: 'hash' }, d.merkle.root)], ['Leaf', h('span', { class: 'hash' }, d.merkle.leaf)], ['Result', state(d.merkle.valid ? 'passed' : 'failed', d.merkle.valid ? 'proof verifies' : 'proof does not verify')]]),
          h('ol', { class: 'proof' }, d.merkle.path.map((s, i) => h('li', null, h('span', { class: 'faint small' }, `step ${i + 1} · ${s.leaf_is_left ? 'right' : 'left'}`), h('span', { class: 'hash' }, s.sibling)))),
          h('p', { class: 'faint small' }, 'The root changes with every appended record, so a proof is only meaningful against a root you saved earlier.')) : notice('info', 'No proof is available for this record.'));
        else put(body, jsonView(d.event ?? b.data));
      };
      const el = h('section', { class: 'panel' }, h('div', { class: 'ph' }, h('div', { class: 'row' }, h('h2', null, `Record #${selected}`), state(ok ? 'passed' : 'failed', ok ? 'verified' : 'failed')), h('div', { class: 'row' }, btn('', { size: 'sm', kind: 'ghost', ic: 'left', 'aria-label': 'Previous record', disabled: selected <= 0, onclick: () => ctx.go(`#/ledger/${selected - 1}`) }), btn('', { size: 'sm', kind: 'ghost', ic: 'right', 'aria-label': 'Next record', disabled: !d.next_hash, onclick: () => ctx.go(`#/ledger/${selected + 1}`) }))),
        h('div', { style: 'padding:0 8px' }, tabs([{ id: 'record', label: 'Record' }, { id: 'proof', label: 'Merkle proof' }, { id: 'event', label: 'Stored event' }], tab, (t) => { tab = t; draw(); })), body);
      draw();
      return el;
    });
  }

  await Promise.all([loadStatus(), loadList()]);
  drawDetail();
  stagger(root, ':scope > .panel');
  ctx.onLive('integrity', loadStatus); ctx.onLive('reconnected', () => { loadStatus(); loadList(); });
  ctx.onLive('alerts', debounce(() => { loadStatus(); if (f.page === 1) loadList(); }, 1500));
  const poll = setInterval(() => { if (!document.hidden) loadStatus(); }, 15000);
  ctx.scope.add(() => { clearInterval(poll); ctl && ctl.abort(); });
  return { update(c2) { const n = c2.params[0] != null ? Number(c2.params[0]) : null; if (n === selected) return; selected = n; markList(); drawDetail(); } };
}
