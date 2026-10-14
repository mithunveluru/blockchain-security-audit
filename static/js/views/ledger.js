import { api, download, qs } from '../api.js';
import { card, clear, empty, errorBox, fmtNum, fmtTime, h, kv, shortHash, skeleton, stateBadge, toast, timeEl, put } from '../ui.js';

export default function ledger(ctx) {
  return ctx.params[0] != null ? block(ctx, Number(ctx.params[0])) : overview(ctx);
}

const LIMITS = 'A hash chain shows that blocks were not edited, removed or reordered without detection, as long as the hashes and the independently kept checkpoint are trusted. It is a local file, not a distributed or consensus-backed blockchain. Someone who can rewrite both the ledger and its checkpoint can recompute every hash, so keep exported checkpoints on a separate system.';

async function overview(ctx) {
  const canVerify = ctx.state.me.role !== 'viewer';
  let f = { q: '', kind: '', page: 1 };
  const statusBox = h('div'), listBox = h('div');
  put(ctx.root, h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Audit ledger'), h('p', null, 'Every alert and operator action is appended as a hash-linked record. Verification recomputes every hash and compares the file with the running service and the saved checkpoint.'))), statusBox,
    h('div', { style: 'margin-top:16px' }, card('Records', null,
      h('form', { class: 'filters', onsubmit: (e) => { e.preventDefault(); f.q = e.target.q.value.trim(); f.kind = e.target.kind.value; f.page = 1; loadList(); } },
        h('div', { class: 'field' }, h('label', { for: 'lq' }, 'Search'), h('input', { id: 'lq', name: 'q', type: 'search', placeholder: 'hash, alert id, text', maxlength: 100 })),
        h('div', { class: 'field' }, h('label', { for: 'lk' }, 'Record type'), h('select', { id: 'lk', name: 'kind' }, ['', 'ALERT', 'OPERATOR_ACTION', 'SECURITY_THREAT', 'LEDGER_RESTART', 'GENESIS'].map((k) => h('option', { value: k }, k ? k.replace('_', ' ').toLowerCase() : 'All')))),
        h('button', { class: 'btn', type: 'submit' }, 'Apply')), listBox)));

  async function loadStatus() {
    try {
      const s = await api('/api/ledger/status');
      const lv = s.last_verification, im = s.integrity;
      clear(statusBox);
      put(statusBox, 
        im.tampering_detected && h('div', { class: 'notice bad', role: 'alert' }, h('strong', null, 'Integrity failure. '), lv ? lv.message : 'The monitor detected tampering.'),
        s.recovery && h('div', { class: 'notice warn' }, h('strong', null, 'Recovered at startup: '), recoveryText(s.recovery)),
        s.last_write_error && h('div', { class: 'notice bad' }, `The last ledger write failed (${s.last_write_error.error}). New records may be missing.`),
        h('div', { class: 'grid cols-2' },
          card('Integrity', null, lv ? kv([['Result', stateBadge(lv.valid ? 'passed' : 'failed', lv.valid ? 'verified' : 'failed')], ['Checked', timeEl(lv.checked_at)], ['Source', lv.source === 'disk' ? 'file on disk compared with running service' : 'in-memory chain'], ['Blocks checked', `${fmtNum(lv.checked_blocks)}${s.block_count > lv.block_count ? ` (${s.block_count - lv.block_count} appended since this check)` : ''}`],
            ['Checkpoint', lv.checks.checkpoint], ['Memory copy', lv.checks.memory_copy], ['Background checks', `${im.checks} (every ${im.check_interval_seconds}s)`]]) : h('p', { class: 'muted' }, 'Not verified yet this session.'),
            lv && !lv.valid && failures(lv),
            h('div', { class: 'row', style: 'margin-top:12px' }, canVerify && h('button', { class: 'btn primary', id: 'vbtn', onclick: verify }, 'Verify now'),
              h('button', { class: 'btn', onclick: exportCp }, 'Export checkpoint'))),
          card('Chain', null, kv([['Blocks', fmtNum(s.block_count)], ['Tip hash', h('span', { class: 'hash' }, s.tip_hash)], ['Merkle root', h('span', { class: 'hash' }, s.merkle_root)], ['Durability', s.durability], ['Checkpoint write', s.checkpoint_error ? `failing: ${s.checkpoint_error}` : 'ok']]),
            h('details', { style: 'margin-top:10px' }, h('summary', null, 'What this does and does not prove'), h('p', { class: 'small muted' }, LIMITS)))),
        s.history.length > 0 && h('div', { style: 'margin-top:16px' }, card('Verification history', 'most recent last', h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['Checked', 'Source', 'Blocks', 'Result'].map((c) => h('th', null, c)))),
          h('tbody', null, s.history.slice().reverse().map((x) => h('tr', null, h('td', { class: 'nowrap' }, fmtTime(x.checked_at)), h('td', null, x.source), h('td', { class: 'num' }, x.block_count), h('td', null, stateBadge(x.valid ? 'passed' : 'failed', x.valid ? 'verified' : x.message))))))))));
    } catch (e) { put(clear(statusBox), errorBox(e.message, loadStatus)); }
  }
  const failures = (lv) => h('div', { style: 'margin-top:10px' }, h('h3', null, `${lv.failure_count} failure${lv.failure_count > 1 ? 's' : ''}`), h('ul', null, lv.failures.slice(0, 8).map((x) => h('li', null,
    x.index != null ? h('a', { href: `#/ledger/${x.index}` }, `Block ${x.index}`) : 'Ledger', `: ${x.check.replace(/_/g, ' ')}. ${x.detail}`))));
  async function verify(e) {
    e.target.disabled = true;
    try { const r = await api('/api/ledger/verify', { method: 'POST' }); toast(r.valid ? 'Ledger verified' : r.message, r.valid ? 'ok' : 'bad'); await loadStatus(); } catch (err) { toast(err.message, 'bad'); e.target.disabled = false; }
  }
  async function exportCp() { try { await download('/api/ledger/checkpoint', 'blockaudit-checkpoint.json'); toast('Checkpoint downloaded. Store it away from this host.', 'ok'); } catch (e) { toast(e.message, 'bad'); } }

  async function loadList() {
    put(clear(listBox), skeleton(4));
    try {
      const r = await api(`/api/ledger/blocks${qs({ q: f.q, kind: f.kind, page: f.page, page_size: 25 })}`);
      clear(listBox);
      if (!r.items.length) { put(listBox, empty('No matching records')); return; }
      const pages = Math.ceil(r.total / 25);
      put(listBox, h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['#', 'Time', 'Type', 'Summary', 'Hash', 'Previous'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, r.items.map((b) => h('tr', { class: 'link', onclick: () => ctx.go(`#/ledger/${b.index}`) }, h('td', { class: 'num' }, h('a', { href: `#/ledger/${b.index}` }, b.index)), h('td', { class: 'nowrap' }, fmtTime(b.timestamp)), h('td', null, b.kind.toLowerCase().replace('_', ' ')), h('td', { class: 'wrap' }, b.summary), h('td', { class: 'hash' }, shortHash(b.hash)), h('td', { class: 'hash' }, shortHash(b.previous_hash))))))),
        h('div', { class: 'pager' }, h('span', { class: 'muted' }, `${fmtNum(r.total)} records · page ${f.page} of ${pages}`), h('div', { class: 'row' },
          h('button', { class: 'btn small', disabled: f.page <= 1, onclick: () => { f.page--; loadList(); } }, 'Newer'), h('button', { class: 'btn small', disabled: f.page >= pages, onclick: () => { f.page++; loadList(); } }, 'Older'))));
    } catch (e) { put(clear(listBox), errorBox(e.message, loadList)); }
  }
  await Promise.all([loadStatus(), loadList()]);
  ctx.on('integrity', loadStatus);
}
const recoveryText = (r) => ({
  migrated_legacy_json: `the original json-array ledger was converted to the append-only format (${r.blocks} blocks). A backup named ${r.backup} was kept.`,
  truncated_partial_tail: `an incomplete last record from an interrupted write was moved to ${r.quarantined_to} and the chain continued from the last complete block.`,
  quarantined_corrupt_ledger: `an unreadable record was found at line ${r.line}. The old file was kept as ${r.quarantined_to} and a new chain started that references it.`,
}[r.kind] || r.kind);

async function block(ctx, index) {
  if (!Number.isInteger(index) || index < 0) throw new Error('Invalid block number');
  const d = await api(`/api/ledger/blocks/${index}`);
  const b = d.block, ok = d.checks.hash_matches_contents && d.checks.links_to_previous;
  put(ctx.root, h('p', { class: 'small' }, h('a', { href: '#/ledger' }, '← Audit ledger')),
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, `Block ${index}`), h('p', null, d.summary.summary)), stateBadge(ok ? 'passed' : 'failed', ok ? 'record checks pass' : 'record checks fail')),
    !ok && h('div', { class: 'notice bad', role: 'alert' }, 'This record does not satisfy its own checks. It was modified or its neighbour was.'),
    h('div', { class: 'grid cols-2' },
      card('Record', null, kv([['Time', timeEl(b.timestamp)], ['Type', d.summary.kind.toLowerCase().replace('_', ' ')], ['Hash', h('span', { class: 'hash' }, b.hash)],
        ['Previous hash', h('span', { class: 'hash' }, b.previous_hash)], ['Next block links to', d.next_hash ? h('span', { class: 'hash' }, d.next_hash) : 'none yet (this is the tip)'],
        ['Linked alerts', d.summary.alert_ids.length ? h('span', null, d.summary.alert_ids.map((x) => h('a', { href: `#/alerts/${encodeURIComponent(x)}`, style: 'margin-right:8px' }, x))) : null]]),
        h('div', { style: 'margin-top:12px' }, h('div', null, stateBadge(d.checks.hash_matches_contents ? 'passed' : 'failed', d.checks.hash_matches_contents ? 'hash matches contents' : 'hash does not match contents')),
          h('div', { style: 'margin-top:6px' }, stateBadge(d.checks.links_to_previous ? 'passed' : 'failed', d.checks.links_to_previous ? 'links to the previous block' : 'link to previous block is broken')))),
      card('Merkle proof', 'inclusion in the current root', d.merkle ? h('div', null, kv([['Root', h('span', { class: 'hash' }, d.merkle.root)], ['Proof steps', d.merkle.path.length], ['Proof verifies', stateBadge(d.merkle.valid ? 'passed' : 'failed', d.merkle.valid ? 'yes' : 'no')]]),
        h('p', { class: 'small muted' }, 'The root changes whenever a block is appended, so a proof is only meaningful against the root exported at the time you need to prove.')) : h('p', { class: 'muted' }, 'Unavailable'))),
    h('div', { style: 'margin-top:16px' }, card('Stored event', 'as recorded', h('pre', null, JSON.stringify(d.event ?? b.data, null, 2)))));
}
