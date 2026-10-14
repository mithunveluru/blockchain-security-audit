import { api, events, session } from './api.js';
import { clear, toast, errorBox, skeleton, ago } from './ui.js';

export const state = { me: null, snapshot: null, connected: false, lastUpdate: null };
export const live = new EventTarget();

const routes = {
  overview: () => import('./views/overview.js'), alerts: () => import('./views/alerts.js'),
  network: () => import('./views/network.js'), ledger: () => import('./views/ledger.js'),
  health: () => import('./views/health.js'), copilot: () => import('./views/copilot.js'),
  settings: () => import('./views/settings.js'),
};
const $ = (id) => document.getElementById(id);
let cleanup = null, socket = null, gen = 0, staleTimer = null;

function theme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('blockaudit.theme', t); } catch { /* ignore */ }
}
function initTheme() {
  let t = null;
  try { t = localStorage.getItem('blockaudit.theme'); } catch { /* ignore */ }
  theme(t || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  $('theme').onclick = () => theme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = raw.split('?');
  const [route = 'overview', ...rest] = path.split('/').filter(Boolean);
  return { route: routes[route] ? route : 'overview', params: rest.map(decodeURIComponent), query: new URLSearchParams(query) };
}

async function render() {
  const my = ++gen;
  if (cleanup) { try { cleanup(); } catch { /* view teardown must not block navigation */ } cleanup = null; }
  const { route, params, query } = parseHash();
  document.querySelectorAll('.nav a').forEach((a) => (a.dataset.route === route ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  closeNav();
  const root = clear($('view'));
  root.append(skeleton(4));
  document.title = `${route[0].toUpperCase()}${route.slice(1)} · BlockAudit`;
  const subs = [];
  const ctx = {
    root, params, query, state,
    on(type, fn) { live.addEventListener(type, fn); subs.push([type, fn]); },
    go(hash) { location.hash = hash; },
  };
  try {
    const mod = await routes[route]();
    if (my !== gen) return;
    clear(root);
    const c = await mod.default(ctx);
    if (my !== gen) { c && c(); return; }
    cleanup = () => { subs.forEach(([t, f]) => live.removeEventListener(t, f)); c && c(); };
    root.focus({ preventScroll: true });
  } catch (e) {
    if (my !== gen || e.name === 'AbortError') return;
    clear(root).append(errorBox(e.message || 'Unexpected error', render));
  }
}

function setConn(kind, text) {
  $('conn').className = `conn ${kind}`;
  $('conn-text').textContent = text;
}
function updateConn() {
  if (!socket) return;
  if (!state.connected) return;
  const stale = state.lastUpdate && Date.now() - state.lastUpdate > 6000;
  setConn(stale ? 'wait' : 'on', stale ? `Stale · last update ${ago(new Date(state.lastUpdate).toISOString())}` : 'Live');
}

function connect() {
  if (socket) socket.disconnect();
  socket = io({ auth: { token: session.token }, reconnectionDelayMax: 8000 });
  socket.on('connect', () => { state.connected = true; setConn('on', 'Live'); });
  socket.on('disconnect', () => { state.connected = false; setConn('off', 'Disconnected · retrying'); });
  socket.on('connect_error', () => { state.connected = false; setConn('off', 'Cannot connect · retrying'); });
  socket.io.on('reconnect_attempt', () => setConn('wait', 'Reconnecting'));
  socket.on('snapshot', (s) => { state.snapshot = s; state.lastUpdate = Date.now(); updateConn(); live.dispatchEvent(new CustomEvent('snapshot', { detail: s })); });
  socket.on('alert', (a) => {
    live.dispatchEvent(new CustomEvent('alert', { detail: a }));
    if (a.severity === 'CRITICAL' || a.severity === 'HIGH') toast(`${a.severity} ${a.type.replace('_', ' ').toLowerCase()}${a.source ? ` from ${a.source}` : ''}`, 'bad');
  });
  socket.on('integrity_alert', (a) => live.dispatchEvent(new CustomEvent('integrity', { detail: a })));
  clearInterval(staleTimer);
  staleTimer = setInterval(updateConn, 2000);
}

function closeNav() { $('nav').classList.remove('open'); $('scrim').hidden = true; $('menu').setAttribute('aria-expanded', 'false'); }

async function boot() {
  initTheme();
  $('menu').onclick = () => { const o = $('nav').classList.toggle('open'); $('scrim').hidden = !o; $('menu').setAttribute('aria-expanded', String(o)); };
  $('scrim').onclick = closeNav;
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeNav(); });
  $('signout').onclick = () => { session.token = ''; location.hash = ''; location.reload(); };
  events.addEventListener('unauthorized', () => { session.token = ''; showLogin('Your session ended. Sign in again.'); });
  $('login-form').onsubmit = async (e) => {
    e.preventDefault();
    session.token = $('token').value.trim();
    $('token').value = '';
    try { await start(); } catch (err) { session.token = ''; showLogin(err.status === 401 ? 'That token was not accepted.' : err.message); }
  };
  if (session.token) { try { await start(); return; } catch { session.token = ''; } }
  showLogin();
}
function showLogin(msg) {
  if (socket) socket.disconnect();
  $('app').hidden = true; $('login').hidden = false;
  const err = $('login-error'); err.hidden = !msg; err.textContent = msg || '';
  $('token').focus();
}
async function start() {
  state.me = await api('/api/me');
  $('login').hidden = true; $('app').hidden = false;
  $('role').textContent = state.me.role;
  const mode = $('mode');
  mode.hidden = state.me.data_mode === 'live_capture';
  mode.textContent = state.me.data_mode === 'simulation' ? 'SIMULATION · synthetic data' : 'TEST DATA';
  $('nav-foot').textContent = state.me.auth_enabled ? '' : 'Authentication is disabled';
  connect();
  window.removeEventListener('hashchange', render);
  window.addEventListener('hashchange', render);
  render();
}
boot();
