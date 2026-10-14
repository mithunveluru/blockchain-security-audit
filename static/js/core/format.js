const pad = (n) => String(n).padStart(2, '0');
export function fmtTime(iso, withDate = true) {
  if (!iso) return 'n/a';
  const d = new Date(iso);
  if (isNaN(d)) return 'n/a';
  const t = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  return withDate ? `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${t} UTC` : `${t} UTC`;
}
export const fmtClock = (iso) => (fmtTime(iso, false) || '').replace(' UTC', '');
export function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (isNaN(s)) return '';
  if (s < 5) return 'just now';
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const fmtNum = (n) => (n == null ? 'n/a' : Number(n).toLocaleString('en-US'));
export function fmtCompact(n) {
  if (n == null) return 'n/a';
  const a = Math.abs(n);
  if (a >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (a >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (a >= 1e4) return `${(n / 1e3).toFixed(0)}k`;
  if (a >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n * 10) / 10);
}
export function fmtBytes(n) {
  if (n == null) return 'n/a';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}
export const shortHash = (x, a = 8, b = 6) => (x ? `${x.slice(0, a)}…${x.slice(-b)}` : 'n/a');
export const TYPE_NAMES = { DDOS: 'DDoS', DOS_FLOOD: 'DoS flood', PORT_SCAN: 'Port scan', BRUTE_FORCE: 'Brute force', DATA_EXFILTRATION: 'Data exfiltration', ANOMALY: 'Anomaly', INTEGRITY: 'Ledger integrity' };
export const typeName = (t) => TYPE_NAMES[t] || String(t).replace(/_/g, ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase());
export const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const place = (a) => {
  const dst = a.destination ? `${a.destination}${a.dst_port ? ':' + a.dst_port : ''}` : null;
  if (a.source && dst) return `${a.source} → ${dst}`;
  return a.source || dst || 'n/a';
};
export const RANGE_SECONDS = { '5m': 300, '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800 };
