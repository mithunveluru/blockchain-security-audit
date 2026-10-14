import { api, bus, session } from './core/api.js';
import { $, clear, h, put, scope, pref } from './core/dom.js';
import { reduced, setReduced, transition } from './core/motion.js';
import { ago } from './core/format.js';
import { icon, logoMark } from './ui/icons.js';
import { btn, initTooltips, openMenu, toast } from './ui/components.js';
import { openPalette } from './ui/palette.js';
import { conversation, ALERT_QUESTIONS, GLOBAL_QUESTIONS } from './ui/copilot.js';

export const app = { me: null, snapshot: null, connected: false, lastUpdate: null };
export const live = new EventTarget();

const NAV = [
  ['Monitor', [['overview', 'Overview', 'overview'], ['alerts', 'Alerts', 'alerts'], ['network', 'Network activity', 'network']]],
  ['Evidence', [['ledger', 'Audit ledger', 'ledger'], ['copilot', 'Investigation copilot', 'copilot']]],
  ['System', [['health', 'System health', 'health'], ['settings', 'Settings', 'settings']]],
];
const VIEWS = {
  overview: () => import('./views/overview.js'), alerts: () => import('./views/alerts.js'), network: () => import('./views/network.js'),
  ledger: () => import('./views/ledger.js'), health: () => import('./views/health.js'), copilot: () => import('./views/copilot.js'), settings: () => import('./views/settings.js'),
};
const TITLES = { overview: 'Overview', alerts: 'Alerts', network: 'Network activity', ledger: 'Audit ledger', health: 'System health', copilot: 'Investigation copilot', settings: 'Settings' };

let firstRender = true, shell = null, current = null, socket = null, gen = 0, staleTimer = null, drawer = null;

// ---- theme ----------------------------------------------------------------------------------
function setTheme(t) { document.documentElement.dataset.theme = t; pref.set('theme', t); }
function initTheme() { setTheme(pref.get('theme', matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')); }
const toggleTheme = () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');

// ---- routing --------------------------------------------------------------------------------
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = raw.split('?');
  const [route = 'overview', ...rest] = path.split('/').filter(Boolean);
  return { route: VIEWS[route] ? route : 'overview', params: rest.map(decodeURIComponent), query: new URLSearchParams(query) };
}
export const go = (hash) => { if (location.hash === hash) window.dispatchEvent(new HashChangeEvent('hashchange')); else location.hash = hash; };

const narrow = matchMedia('(max-width: 860px)');
// on small screens the contextual toolbar moves below the top bar instead of disappearing
function placeToolbar() {
  if (!shell) return;
  const has = shell.toolbar.childNodes.length > 0;
  if (narrow.matches) { shell.subbar.hidden = !has; if (shell.toolbar.parentNode !== shell.subbar) put(shell.subbar, shell.toolbar); }
  else { shell.subbar.hidden = true; if (shell.toolbar.parentNode !== shell.topbarEl) shell.topbarEl.insertBefore(shell.toolbar, shell.topbarEl.querySelector('.spacer')); }
}
narrow.addEventListener('change', placeToolbar);

function makeCtx(route, params, query, s) {
  return {
    route, params, query, state: app, live, scope: s, go,
    root: shell.view,
    setTitle(title, sub) { shell.title.textContent = title; shell.sub.textContent = sub || ''; document.title = `${title} · BlockAudit`; },
    toolbar(el) { clear(shell.toolbar); el && put(shell.toolbar, el); placeToolbar(); },
    layout(kind) { shell.view.className = kind === 'flush' ? 'page flush' : 'page'; },
    replaceQuery(obj) {
      const q = new URLSearchParams(location.hash.split('?')[1] || '');
      Object.entries(obj).forEach(([k, v]) => (v == null || v === '' ? q.delete(k) : q.set(k, v)));
      const base = location.hash.split('?')[0] || '#/overview';
      history.replaceState(null, '', `${base}${q.toString() ? `?${q}` : ''}`);
    },
    onLive(type, fn) { live.addEventListener(type, fn); s.add(() => live.removeEventListener(type, fn)); },
  };
}

async function render() {
  const my = ++gen;
  const { route, params, query } = parseHash();
  shell.nav.querySelectorAll('a').forEach((a) => (a.dataset.route === route ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  shell.tabbar.querySelectorAll('a').forEach((a) => (a.dataset.route === route ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  // same view, new parameters: let the view update in place so lists keep their scroll and selection
  if (current && current.route === route && current.api?.update) {
    const ctx = makeCtx(route, params, query, current.scope);
    try { if ((await current.api.update(ctx)) !== false) return; } catch (e) { if (e.name !== 'AbortError') console.error(e); }
  }
  if (current) { try { current.api?.cleanup?.(); current.scope.dispose(); } catch { /* teardown must not block navigation */ } current = null; }
  await transition(async () => {
    const s = scope();
    const ctx = makeCtx(route, params, query, s);
    ctx.layout('page'); ctx.toolbar(null); ctx.setTitle(TITLES[route], '');
    clear(shell.view);
    shell.content.scrollTop = 0;
    try {
      const mod = await VIEWS[route]();
      if (my !== gen) { s.dispose(); return; }
      const api_ = (await mod.default(ctx)) || {};
      if (my !== gen) { api_.cleanup?.(); s.dispose(); return; }
      current = { route, api: api_, scope: s };
    } catch (e) {
      s.dispose();
      if (my !== gen || e.name === 'AbortError') return;
      ctx.layout('page'); clear(shell.view);
      put(shell.view, h('div', { class: 'notice bad', role: 'alert' }, icon('warn'), h('div', null, h('strong', null, 'This page could not be loaded. '), e.message || 'Unexpected error. ', btn('Retry', { size: 'sm', onclick: render }))));
    }
  });
  if (my === gen && !firstRender) shell.view.focus({ preventScroll: true });
  firstRender = false;
}

// ---- live connection ------------------------------------------------------------------------
function setConn(kind, text) { shell.live.className = `live ${kind}`; shell.liveText.textContent = text; shell.live.setAttribute('aria-label', `Live updates: ${text}`); }
function connStatus() {
  if (!socket || !app.connected) return;
  const stale = app.lastUpdate && Date.now() - app.lastUpdate > 6000;
  setConn(stale ? 'wait' : 'on', stale ? `Stale · ${ago(new Date(app.lastUpdate).toISOString())}` : 'Live');
}
let pendingAlerts = [], flushTimer = null;
function flushAlerts() {
  flushTimer = null;
  const batch = pendingAlerts; pendingAlerts = [];
  if (!batch.length) return;
  live.dispatchEvent(new CustomEvent('alerts', { detail: batch }));
  const hot = batch.filter((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH');
  hot.slice(0, 2).forEach((a) => toast(h('span', null, h('strong', null, `${a.severity[0]}${a.severity.slice(1).toLowerCase()} · `), a.type.replace(/_/g, ' ').toLowerCase(), a.source ? ` from ${a.source}` : ''), 'bad'));
  if (hot.length > 2) toast(`${hot.length - 2} more high-priority alerts`, 'bad');
}
function connect() {
  if (socket) socket.disconnect();
  socket = io({ auth: { token: session.token }, reconnectionDelayMax: 8000 });
  socket.on('connect', () => { app.connected = true; setConn('on', 'Live'); live.dispatchEvent(new CustomEvent('connection', { detail: true })); });
  socket.on('disconnect', () => { app.connected = false; setConn('off', 'Disconnected'); live.dispatchEvent(new CustomEvent('connection', { detail: false })); });
  socket.on('connect_error', () => { app.connected = false; setConn('off', 'Reconnecting'); });
  socket.io.on('reconnect_attempt', () => setConn('wait', 'Reconnecting'));
  socket.io.on('reconnect', () => live.dispatchEvent(new CustomEvent('reconnected')));
  socket.on('snapshot', (snap) => { app.snapshot = snap; app.lastUpdate = Date.now(); connStatus(); paintSide(); live.dispatchEvent(new CustomEvent('snapshot', { detail: snap })); });
  socket.on('alert', (a) => { pendingAlerts.push(a); if (pendingAlerts.length > 200) pendingAlerts.shift(); flushTimer ||= setTimeout(flushAlerts, 400); });
  socket.on('integrity_alert', (a) => live.dispatchEvent(new CustomEvent('integrity', { detail: a })));
  clearInterval(staleTimer);
  staleTimer = setInterval(connStatus, 2000);
}
function paintSide() {
  const s = app.snapshot;
  if (!s || !shell) return;
  const hot = (s.by_severity?.CRITICAL || 0) + (s.by_severity?.HIGH || 0);
  const b = shell.alertBadge;
  b.textContent = hot > 99 ? '99+' : String(hot); b.hidden = !hot; b.className = `badge-count${s.by_severity?.CRITICAL ? ' hot' : ''}`;
  b.setAttribute('aria-label', `${hot} high-priority alerts in the last hour`);
  const bad = s.tampering_detected || s.ledger_valid === false;
  shell.sideStatus.className = `side-status`;
  clear(shell.sideStatus);
  put(shell.sideStatus, h('span', { class: `pulse${bad ? ' bad' : s.running ? '' : ' warn'}`, style: 'width:8px;height:8px;box-shadow:none' }), h('span', { class: 'lbl' }, bad ? 'Ledger integrity failure' : s.running ? 'Monitoring active' : 'Monitoring stopped'));
}

// ---- copilot drawer -------------------------------------------------------------------------
function toggleDrawer(force) {
  if (drawer) { drawer.close(); return; }
  if (force === false) return;
  const alertId = parseHash().route === 'alerts' ? parseHash().params[0] || null : null;
  const prev = document.activeElement;
  const conv = conversation({ state: app, alertId, suggestions: alertId ? ALERT_QUESTIONS : GLOBAL_QUESTIONS });
  const scrim = h('div', { class: 'scrim', onclick: () => drawer.close() });
  const el = h('aside', { class: 'drawer', role: 'dialog', 'aria-label': 'Investigation copilot' },
    h('div', { class: 'dh2' }, h('div', { class: 'row' }, icon('copilot'), h('h2', null, 'Investigation copilot')), h('div', { class: 'row' }, btn('Full page', { size: 'sm', kind: 'ghost', onclick: () => { drawer.close(); go('#/copilot'); } }), h('button', { class: 'icon-btn', 'aria-label': 'Close copilot', onclick: () => drawer.close() }, icon('x')))),
    h('div', { class: 'dbody' }, conv.el));
  const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); drawer.close(); } };
  document.addEventListener('keydown', onKey, true);
  document.addEventListener('copilot:navigate', () => drawer?.close(), { once: true });
  put(document.body, scrim, el);
  conv.focus();
  drawer = { close() { document.removeEventListener('keydown', onKey, true); conv.destroy(); scrim.remove(); el.remove(); drawer = null; prev && prev.focus && prev.focus(); } };
}

// ---- shell ----------------------------------------------------------------------------------
function palette() {
  const me = app.me;
  const nav = NAV.flatMap(([, items]) => items).map(([id, label, ic]) => ({ group: 'Go to', icon: ic, label, hint: `g ${id[0]}`, keywords: id, run: () => go(`#/${id}`) }));
  const actions = [
    { group: 'Actions', icon: 'copilot', label: 'Ask the investigation copilot', keywords: 'ask ai chat', run: () => toggleDrawer() },
    { group: 'Actions', icon: document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon', label: 'Toggle light and dark theme', keywords: 'theme appearance', run: toggleTheme },
    { group: 'Actions', icon: 'play', label: reduced() ? 'Allow motion' : 'Reduce motion', keywords: 'animation accessibility', run: () => setReduced(!reduced()) },
    ...(me.role !== 'viewer' ? [{ group: 'Actions', icon: 'shield', label: 'Verify the audit ledger now', keywords: 'integrity check', run: async () => { try { const r = await api('/api/ledger/verify', { method: 'POST' }); toast(r.valid ? 'Ledger verified' : r.message, r.valid ? 'ok' : 'bad'); } catch (e) { toast(e.message, 'bad'); } } }] : []),
    { group: 'Actions', icon: 'lock', label: 'Sign out', keywords: 'logout', run: signOut },
  ];
  openPalette({ commands: [...nav, ...actions], go, state: app });
}
function signOut() { session.token = ''; location.hash = ''; location.reload(); }

function buildShell() {
  const root = $('#root');
  clear(root);
  const collapsed = pref.get('sidebar-collapsed', false);
  const navEl = h('nav', { class: 'nav', 'aria-label': 'Primary' });
  let alertBadge = null;
  NAV.forEach(([group, items]) => {
    put(navEl, h('div', { class: 'nav-label' }, group));
    items.forEach(([id, label, ic]) => {
      const a = h('a', { href: `#/${id}`, 'data-route': id, 'data-tip': collapsed ? label : null, 'data-tip-side': 'right' }, icon(ic), h('span', { class: 'lbl' }, label));
      if (id === 'alerts') { alertBadge = h('span', { class: 'badge-count', hidden: true }); put(a, alertBadge); }
      put(navEl, a);
    });
  });
  const sideStatus = h('div', { class: 'side-status' });
  const toggle = h('button', { class: 'icon-btn', 'aria-label': 'Collapse sidebar', 'aria-pressed': String(collapsed), onclick: () => { const c = shellEl.dataset.collapsed !== 'true'; shellEl.dataset.collapsed = String(c); pref.set('sidebar-collapsed', c); toggle.setAttribute('aria-pressed', String(c)); navEl.querySelectorAll('a').forEach((a) => { if (c) a.dataset.tip = a.textContent; else delete a.dataset.tip; }); } }, icon('panel'));
  const sidebar = h('aside', { class: 'sidebar', 'aria-label': 'Sidebar' }, h('div', { class: 'brand' }, logoMark(), h('span', { class: 'word' }, 'Block', h('b', null, 'Audit'))), navEl,
    h('div', { class: 'side-foot' }, sideStatus, h('div', { class: 'row', style: 'justify-content:flex-start' }, toggle)));
  const title = h('h1', null, ''), sub = h('span', { class: 'sub' }), toolbar = h('div', { class: 'toolbar' });
  const liveText = h('span', { class: 'lbl' }, 'Connecting'), liveEl = h('div', { class: 'live', role: 'status' }, h('span', { class: 'dot' }), liveText);
  const mode = app.me.data_mode;
  const user = h('button', { class: 'icon-btn', 'aria-label': 'Account and preferences', 'aria-haspopup': 'menu', onclick: () => openMenu(user, [
    { label: `Signed in as ${app.me.role}`, run() {} }, '-',
    { label: `Theme: ${document.documentElement.dataset.theme === 'dark' ? 'switch to light' : 'switch to dark'}`, icon: 'sun', run: toggleTheme },
    { label: reduced() ? 'Allow motion' : 'Reduce motion', icon: 'play', run: () => setReduced(!reduced()) },
    { label: 'Settings', icon: 'settings', run: () => go('#/settings') }, '-', { label: 'Sign out', icon: 'lock', run: signOut }]) }, icon('lock'));
  const topbar = h('header', { class: 'topbar' }, h('div', { class: 'brand only-mobile', style: 'padding:0;height:auto' }, logoMark(20)), h('div', { class: 'crumbs' }, title, sub), toolbar, h('div', { class: 'spacer' }),
    mode !== 'live_capture' && h('span', { class: 'mode-tag', title: mode === 'simulation' ? 'All traffic and alerts are synthetic' : 'Test data' }, mode === 'simulation' ? 'Simulation' : 'Test data'),
    h('button', { class: 'cmdk', type: 'button', 'aria-keyshortcuts': 'Control+K Meta+K', onclick: palette }, icon('search'), h('span', { class: 'lbl' }, 'Search or jump to…'), h('span', { class: 'kbd' }, '⌘K')),
    h('button', { class: 'icon-btn', 'aria-label': 'Ask the copilot', 'data-tip': 'Ask the copilot', 'data-tip-side': 'bottom', onclick: () => toggleDrawer() }, icon('copilot')),
    h('button', { class: 'icon-btn only-desktop', 'aria-label': 'Switch theme', 'data-tip': 'Switch theme', 'data-tip-side': 'bottom', onclick: toggleTheme }, icon(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon')),
    liveEl, user);
  const subbar = h('div', { class: 'subbar', role: 'region', 'aria-label': 'Page controls', hidden: true });
  const view = h('main', { id: 'view', class: 'page', tabindex: -1 });
  const content = h('div', { class: 'content' }, view);
  const tabbar = h('nav', { class: 'tabbar', 'aria-label': 'Primary mobile' },
    ...[['overview', 'Overview', 'overview'], ['alerts', 'Alerts', 'alerts'], ['network', 'Network', 'network'], ['ledger', 'Ledger', 'ledger']].map(([id, label, ic]) => h('a', { href: `#/${id}`, 'data-route': id }, icon(ic), h('span', null, label))),
    h('button', { type: 'button', 'aria-haspopup': 'menu', onclick: (e) => openMenu(e.currentTarget, [{ label: 'System health', icon: 'health', run: () => go('#/health') }, { label: 'Investigation copilot', icon: 'copilot', run: () => go('#/copilot') }, { label: 'Settings', icon: 'settings', run: () => go('#/settings') }, '-', { label: 'Switch theme', icon: 'sun', run: toggleTheme }, { label: 'Sign out', icon: 'lock', run: signOut }]) }, icon('more'), h('span', null, 'More')));
  const shellEl = h('div', { class: 'shell', 'data-collapsed': String(collapsed) }, sidebar, h('div', { class: 'main' }, topbar, subbar, content), tabbar);
  put(root, shellEl);
  shell = { subbar, topbarEl: topbar, el: shellEl, nav: navEl, tabbar, title, sub, toolbar, view, content, live: liveEl, liveText, alertBadge, sideStatus };
  if (collapsed) navEl.querySelectorAll('a').forEach((a) => { a.dataset.tip = a.textContent; });
}

// ---- boot -----------------------------------------------------------------------------------
function showLogin(msg) {
  if (socket) { socket.disconnect(); socket = null; }
  const root = $('#root');
  clear(root);
  const err = h('p', { class: 'small', style: 'color:var(--crit)', role: 'alert', hidden: !msg }, msg || '');
  const input = h('input', { class: 'input', id: 'token', type: 'password', required: true, minlength: 16, autocomplete: 'off', spellcheck: 'false', style: 'height:36px' });
  const form = h('form', { onsubmit: async (e) => {
    e.preventDefault();
    session.token = input.value.trim(); input.value = '';
    try { await start(); } catch (x) { session.token = ''; showLogin(x.status === 401 ? 'That token was not accepted.' : x.message); }
  } }, h('div', { class: 'brand' }, logoMark(26), h('span', { class: 'word' }, 'Block', h('b', null, 'Audit'))),
  h('div', { class: 'panel box' }, h('div', null, h('h1', null, 'Sign in'), h('p', { class: 'muted small', style: 'margin-top:4px' }, 'Enter an access token from your administrator. For a local development run, the token is printed once in the terminal that started BlockAudit.')),
    h('div', { class: 'field' }, h('label', { for: 'token' }, 'Access token'), input), err, btn('Continue', { kind: 'primary lg', type: 'submit' })),
  h('p', { class: 'faint tiny', style: 'text-align:center' }, 'The token stays in this tab and is cleared when you close it.'));
  put(root, h('div', { class: 'login' }, form));
  input.focus();
}
async function start() {
  app.me = await api('/api/me');
  buildShell();
  connect();
  window.removeEventListener('hashchange', render);
  window.addEventListener('hashchange', render);
  await render();
}
function keys() {
  let gPending = false, gTimer = null;
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (app.me) palette(); return; }
    if (!app.me || e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target, typing = t.matches?.('input, textarea, select, [contenteditable]');
    if (typing) return;
    if (e.key === 'g') { gPending = true; clearTimeout(gTimer); gTimer = setTimeout(() => { gPending = false; }, 900); return; }
    if (gPending) {
      gPending = false;
      const hit = NAV.flatMap(([, i]) => i).find(([id]) => id[0] === e.key);
      if (hit) { e.preventDefault(); go(`#/${hit[0]}`); }
      return;
    }
    if (e.key === '.' ) { e.preventDefault(); toggleDrawer(); }
  });
}
bus.addEventListener('unauthorized', () => { session.token = ''; showLogin('Your session ended. Sign in again.'); });
initTheme();
initTooltips();
keys();
(async function boot() {
  if (session.token) { try { await start(); return; } catch { session.token = ''; } }
  showLogin();
})();
