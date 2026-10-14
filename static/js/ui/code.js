import { h, put } from '../core/dom.js';

const IP = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HEX = /^[0-9a-f]{64}$/;

/** syntax-highlighted JSON built from text nodes, never markup */
export function jsonView(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const pre = h('pre', { class: 'code', tabindex: 0, 'aria-label': 'Evidence data' });
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) put(pre, text.slice(last, m.index));
    if (m[1] !== undefined) {
      const raw = m[1].slice(1, -1);
      const cls = m[2] ? 'tk-key' : IP.test(raw) ? 'tk-ip' : HEX.test(raw) ? 'tk-hash' : 'tk-str';
      put(pre, h('span', { class: cls }, m[1]), m[2] || '');
    } else if (m[3]) put(pre, h('span', { class: 'tk-num' }, m[3]));
    else put(pre, h('span', { class: 'tk-num' }, m[4]));
    last = re.lastIndex;
  }
  if (last < text.length) put(pre, text.slice(last));
  return pre;
}

/** turns ids, addresses and hashes inside prose into typed spans and links */
export function richText(text, sources = []) {
  const known = new Map(sources.map((s) => [s.id, s]));
  const out = [];
  const re = /(alr-[A-Za-z0-9-]{4,24}|blk-\d+|ctx-alr-[A-Za-z0-9-]+|ledger-verification|system-health|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b[0-9a-f]{64}\b)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[1];
    if (known.has(tok)) out.push(h('a', { class: 'ref', href: known.get(tok).url, 'data-tip': known.get(tok).label }, tok));
    else if (HEX.test(tok)) out.push(h('span', { class: 'mono tk-hash', title: tok }, `${tok.slice(0, 10)}…${tok.slice(-6)}`));
    else if (/^(alr|blk|ctx|ledger|system)/.test(tok)) out.push(h('span', { class: 'ref' }, tok));
    else out.push(h('span', { class: 'mono tk-ip' }, tok));
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
