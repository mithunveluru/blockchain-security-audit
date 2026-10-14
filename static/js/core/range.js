import { sess } from './dom.js';
import { RANGE_SECONDS } from './format.js';

export const RANGES = ['15m', '1h', '6h', '24h', '7d'];
export const getRange = () => { const r = sess.get('range', '1h'); return RANGE_SECONDS[r] ? r : '1h'; };
export const setRange = (r) => sess.set('range', r);
export const domainFor = (range) => { const now = Date.now(); return [now - RANGE_SECONDS[range] * 1000, now]; };
