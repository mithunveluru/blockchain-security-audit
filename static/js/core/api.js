const KEY = 'blockaudit.token';
export const session = {
  get token() { try { return sessionStorage.getItem(KEY) || ''; } catch { return ''; } },
  set token(v) { try { v ? sessionStorage.setItem(KEY, v) : sessionStorage.removeItem(KEY); } catch { /* storage unavailable */ } },
};
export class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}
export const bus = new EventTarget();

export async function api(path, { method = 'GET', body, signal, raw } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method, signal,
      headers: { Authorization: `Bearer ${session.token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    bus.dispatchEvent(new CustomEvent('offline'));
    throw new ApiError(0, 'The server is unreachable.');
  }
  if (res.status === 401) { bus.dispatchEvent(new Event('unauthorized')); throw new ApiError(401, 'Your session is not valid. Sign in again.'); }
  if (raw && res.ok) return res;
  let data = null;
  try { data = await res.json(); } catch { /* non-json */ }
  if (!res.ok) {
    const msg = res.status === 429 ? `Rate limit reached. Try again in ${data?.retry_after_seconds ?? 'a few'}s.` : (data?.error || `Request failed (${res.status})`);
    throw new ApiError(res.status, msg, data);
  }
  return data;
}
export const qs = (obj) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v != null && v !== '' && !(Array.isArray(v) && !v.length)) p.set(k, Array.isArray(v) ? v.join(',') : v);
  const s = p.toString();
  return s ? `?${s}` : '';
};
export async function download(path, filename) {
  const res = await api(path, { raw: true });
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
