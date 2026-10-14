/** plain-language explanations of ledger verification failures */
export const FAILURES = {
  hash_mismatch: ['Contents no longer match the stored hash', 'The record was edited after it was written: hashing its contents now gives a different value than the hash saved with it.'],
  link_broken: ['Link to the previous record is broken', 'This record points to a previous hash that does not match the record before it, so a record was altered, removed or reordered.'],
  index: ['Position does not match its number', 'Records are numbered in sequence. A record is out of place, which usually means one was removed or reordered.'],
  genesis: ['First record is invalid', 'The first record of the chain must point to "0". It was changed.'],
  duplicate: ['Repeated record', 'Two records carry the same hash, which a legitimate chain never produces.'],
  malformed: ['Record is incomplete', 'The record is missing fields or has the wrong types, so it cannot be verified.'],
  truncated: ['The ledger is shorter than the checkpoint', 'The checkpoint saved at the last write says more records existed. Records at the end were removed.'],
  history_rewritten: ['History differs from the checkpoint', 'The record at this position no longer matches the hash saved in the independent checkpoint. The chain was rewritten, even if its own hashes look consistent.'],
  diverged_from_memory: ['File differs from what the service wrote', 'The record on disk is not the one this running service holds in memory. The file was changed outside BlockAudit.'],
  missing_vs_memory: ['A record the service wrote is missing on disk', 'The running service holds a record that is no longer in the ledger file.'],
  unparseable: ['The file contains unreadable data', 'A line of the ledger file is not valid JSON, so the records after it cannot be trusted.'],
  unreadable: ['The ledger file cannot be read', 'The file is missing or has no read permission.'],
  empty: ['The ledger is empty', 'A ledger always has at least its first record.'],
};
export const failureTitle = (c) => (FAILURES[c] || [c.replace(/_/g, ' ')])[0];
export const failureMeaning = (c) => (FAILURES[c] || ['', 'The check failed.'])[1];

export const LIMITS = 'A hash chain reveals edits, removals and reordering as long as the hashes and the saved checkpoint can be trusted. This ledger is a local file, not a decentralized or consensus-backed blockchain: someone who can rewrite both the ledger and its checkpoint can recompute every hash. Export checkpoints to a separate system to detect that.';
