// ── State ─────────────────────────────────────────────────────────────────
const state = {
  threats:    [],
  events:     [],
  stats:      {},
  latestData: null,
  intChecks:  0,
  intBroken:  false,
  sevFilter:  'all',
  toastTimer: null,
};

// ── Helpers ───────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function el(id)      { return document.getElementById(id); }
function setText(id, v) { const e = el(id); if (e) e.textContent = v; }
function setHtml(id, v) { const e = el(id); if (e) e.innerHTML = v; }

// ── Clock ─────────────────────────────────────────────────────────────────
setInterval(() => {
  const e = el('clock');
  if (e) e.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
}, 1000);

// ── Navigation ────────────────────────────────────────────────────────────
function switchView(view, btn) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.tnav').forEach(n => n.classList.remove('active'));
  const v = el('view-' + view);
  if (v) v.classList.add('active');
  if (btn) btn.classList.add('active');

  if (view === 'threats')    { if (!socCharts.timeline) initTimelineChart(); renderThreatsTable(); }
  if (view === 'network')    { if (!socCharts.protocol) initNetworkCharts(); if (state.latestData) updateNetworkCharts(state.latestData); }
  if (view === 'blockchain') renderBlockchainTable();
  if (view === 'whitelist')  fetchWhitelist();
  if (view === 'system')     fetchHealth();
}

function setRange(r, btn) {
  document.querySelectorAll('[onclick*="setRange"]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

// ── Socket.IO ─────────────────────────────────────────────────────────────
const socket = io();

socket.on('connect', ()    => updateStatusPill('ok', 'Connected'));
socket.on('disconnect', () => updateStatusPill('err', 'Disconnected'));

socket.on('dashboard_update', (data) => {
  state.latestData = data;
  if (data.stats)          updateKPIs(data.stats);
  if (data.recent_events)  { state.events = data.recent_events; renderEventsTable(); }
  if (data.recent_threats) { state.threats = data.recent_threats; renderActiveThreatsList(); }
  if (data.capture_status) updateCaptureBanner(data.capture_status);

  state.intChecks++;
  setText('intChecks', state.intChecks);
  setText('bcChecks',  state.intChecks);

  if (socCharts.timeline) updateTimelineChart(data);

  if (el('view-network').classList.contains('active') && socCharts.protocol) updateNetworkCharts(data);
  if (el('view-threats').classList.contains('active'))  renderThreatsTable();
  if (el('view-blockchain').classList.contains('active')) renderBlockchainTable();
});

socket.on('integrity_alert', (alert) => {
  state.intBroken = alert.severity === 'CRITICAL';
  updateIntegrityPanels(alert);
  showIntegrityToast(alert);
  if (alert.severity === 'CRITICAL') playTone();
});

// ── Status pill ───────────────────────────────────────────────────────────
function updateStatusPill(type, label) {
  const pill = el('statusPill');
  const text = el('statusText');
  if (pill) pill.className = `status-pill ${type}`;
  if (text) text.textContent = label;
}

// ── KPIs ──────────────────────────────────────────────────────────────────
function updateKPIs(stats) {
  const t = stats.threats_detected || 0;
  setText('kpi-threats', t.toLocaleString());
  setText('kpi-packets', (stats.packets_analyzed || 0).toLocaleString());
  setText('kpi-flows',   (stats.flows_tracked || 0).toLocaleString());
  setText('kpi-blocks',  (stats.blockchain_blocks || 1).toLocaleString());
  setText('kpi-uptime',  ((stats.uptime_hours || 0).toFixed(2)) + 'h');

  const sub = el('kpi-threats-sub');
  if (sub) sub.textContent = t === 0 ? 'No active threats' : `${t} threat${t !== 1 ? 's' : ''} active`;

  const badge = el('threatBadge');
  if (badge) { badge.textContent = t; badge.style.display = t > 0 ? '' : 'none'; }

  setText('intBlocks', stats.blockchain_blocks || 1);
  setText('bcBlocks',  stats.blockchain_blocks || 1);
}

// ── Events table ──────────────────────────────────────────────────────────
function renderEventsTable() {
  const tbody = el('eventsBody');
  if (!tbody) return;
  if (!state.events.length) {
    tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state"><div class="empty-title">No events yet</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = state.events.map(e => {
    const sev = (e.threat_level || 'normal').toLowerCase();
    const cls = e.block_index === 'INTEGRITY' ? 'badge-integrity' : `badge-${sev}`;
    return `<tr>
      <td style="font-variant-numeric:tabular-nums;color:var(--text-3);font-size:12px;font-weight:600">${esc(String(e.block_index))}</td>
      <td style="white-space:nowrap;font-size:12px;color:var(--text-3)">${new Date(e.timestamp).toLocaleString()}</td>
      <td><span class="badge ${cls}">${esc(e.threat_level || 'normal')}</span></td>
      <td style="max-width:320px;font-size:13px">${esc(e.summary || '')}</td>
    </tr>`;
  }).join('');
}

// ── Active threats (overview) ─────────────────────────────────────────────
function renderActiveThreatsList() {
  const el_ = el('activeThreatsList');
  if (!el_) return;
  if (!state.threats.length) {
    el_.innerHTML = '<div class="empty-state"><div class="empty-title">No active threats</div><div class="empty-desc">System is operating normally</div></div>';
    return;
  }
  el_.innerHTML = '<div class="threat-list">' +
    [...state.threats].reverse().slice(0, 5).map(t => {
      const types = (t.threats || []).map(x => esc(x.type || '')).join(', ');
      const desc  = ((t.threats || [])[0] || {}).description || '';
      const sev   = (t.threat_level || 'low').toLowerCase();
      return `<div class="threat-item">
        <div class="threat-sev"><span class="badge badge-${sev}">${esc(t.threat_level || 'low')}</span></div>
        <div class="threat-body">
          <div class="threat-name">${types || 'Unknown'}</div>
          <div class="threat-detail">${esc(desc.substring(0,80))}${desc.length > 80 ? '...' : ''}</div>
          <div class="threat-ts">${new Date(t.timestamp).toLocaleString()}</div>
        </div>
      </div>`;
    }).join('') + '</div>';
}

// ── Threats table ─────────────────────────────────────────────────────────
function renderThreatsTable() {
  const tbody = el('threatsBody');
  if (!tbody) return;
  const f = state.sevFilter;
  const list = f === 'all'
    ? state.threats
    : state.threats.filter(t => (t.threat_level || '').toLowerCase() === f);

  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-title">${f === 'all' ? 'No incidents' : 'No ' + f + ' threats'}</div></div></td></tr>`;
    return;
  }
  tbody.innerHTML = [...list].reverse().slice(0, 25).map(t => {
    const types = (t.threats || []).map(x => esc(x.type || '')).join(', ');
    const desc  = ((t.threats || [])[0] || {}).description || '';
    const src   = ((t.threats || [])[0] || {}).source || '-';
    const sev   = (t.threat_level || 'low').toLowerCase();
    return `<tr>
      <td style="white-space:nowrap;font-size:12px;color:var(--text-3)">${new Date(t.timestamp).toLocaleTimeString()}</td>
      <td style="font-weight:500">${types || '-'}</td>
      <td><span class="badge badge-${sev}">${esc(t.threat_level || 'low')}</span></td>
      <td style="font-family:var(--ff-mono);font-size:11px;color:var(--text-3)">${esc(src)}</td>
      <td style="max-width:240px;font-size:12px;color:var(--text-2)">${esc(desc.substring(0,70))}${desc.length > 70 ? '...' : ''}</td>
    </tr>`;
  }).join('');
}

function filterSev(sev, btn) {
  state.sevFilter = sev;
  document.querySelectorAll('#sevFilter .filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderThreatsTable();
}

// ── Blockchain table ──────────────────────────────────────────────────────
function renderBlockchainTable() {
  const tbody = el('blockchainBody');
  if (!tbody) return;
  if (!state.events.length) {
    tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state"><div class="empty-title">No blocks yet</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = state.events.map(e => {
    const sev = (e.threat_level || 'normal').toLowerCase();
    const cls = e.block_index === 'INTEGRITY' ? 'badge-integrity' : `badge-${sev}`;
    return `<tr>
      <td style="font-variant-numeric:tabular-nums;font-weight:600;font-size:12px;color:var(--text-3)">${esc(String(e.block_index))}</td>
      <td style="white-space:nowrap;font-size:12px;color:var(--text-3)">${new Date(e.timestamp).toLocaleString()}</td>
      <td><span class="badge ${cls}">${esc(e.threat_level || 'normal')}</span></td>
      <td style="font-size:13px">${esc(e.summary || '')}</td>
    </tr>`;
  }).join('');
}

// ── Integrity panels ──────────────────────────────────────────────────────
function updateIntegrityPanels(alert) {
  const broken  = alert.severity === 'CRITICAL';
  const status  = broken ? 'err' : 'ok';
  const title   = broken ? 'Tampering Detected' : 'Chain Valid';
  const desc    = broken
    ? (alert.message || 'Chain integrity compromised').substring(0, 80)
    : 'All blocks verified and immutable';

  const iconSvg = broken
    ? `<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="currentColor" stroke-width="2.5"/>
       <line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
       <line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`
    : `<path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>`;

  for (const [panel, icon, t, d] of [
    ['intPanel', 'intIcon', 'intTitle', 'intDesc'],
    ['bcPanel',  'bcIcon',  'bcTitle',  'bcDesc'],
  ]) {
    const p = el(panel), ic = el(icon), te = el(t), de = el(d);
    if (p)  p.className  = `int-panel ${status}`;
    if (ic) { ic.className = `int-icon ${status}`; ic.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none">${iconSvg}</svg>`; }
    if (te) te.textContent = title;
    if (de) de.textContent = desc;
  }
  setText('bcStatus', broken ? 'TAMPERED' : 'Valid');
}

// ── Capture banner ────────────────────────────────────────────────────────
function updateCaptureBanner(cs) {
  const banner = el('captureBanner');
  if (!banner || !cs) return;
  if (cs.status === 'capture_running') { banner.className = 'capture-banner'; return; }

  const cfgs = {
    simulation:        { cls: 'sim',  t: 'Simulation mode',             d: 'ENABLE_SIMULATION_MODE active. Data is synthetic.',      f: null },
    permission_denied: { cls: 'warn', t: 'Insufficient permissions',    d: 'CAP_NET_RAW not granted. Live capture disabled.',         f: cs.fix },
    interface_missing: { cls: 'err',  t: 'Interface not found',         d: cs.error || `Interface '${cs.interface}' not found.`,      f: 'Set NETWORK_INTERFACE env var and restart.' },
    scapy_missing:     { cls: 'err',  t: 'Scapy not installed',         d: 'Install Scapy for live capture.',                        f: cs.fix || 'pip install scapy' },
    capture_failed:    { cls: 'err',  t: 'Capture failed',              d: cs.error || 'Capture thread encountered a fatal error.',  f: cs.fix },
  };

  const cfg = cfgs[cs.status];
  if (!cfg) { banner.className = 'capture-banner'; return; }

  banner.className = `capture-banner ${cfg.cls} visible`;
  setText('captureBannerTitle', cfg.t);
  setText('captureBannerDesc',  cfg.d);
  const fix = el('captureBannerFix');
  if (fix) { fix.textContent = cfg.f || ''; fix.style.display = cfg.f ? '' : 'none'; }
}

// ── Integrity toast ───────────────────────────────────────────────────────
function showIntegrityToast(alert) {
  const toast = el('integrityToast');
  if (!toast) return;
  const critical = alert.severity === 'CRITICAL';
  toast.className = `toast ${critical ? 'critical' : ''} show`;
  const icon = el('toastIcon');
  if (icon) icon.className = `toast-icon ${critical ? 'err' : 'info'}`;
  setText('toastTitle', critical ? 'Blockchain Tampering Detected' : 'Integrity Update');
  setText('toastBody',  alert.message || '');
  setText('toastTime',  new Date(alert.timestamp).toLocaleString());
  toast.style.display = 'block';
  if (state.toastTimer) clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(dismissToast, 30000);
}

function dismissToast() {
  const toast = el('integrityToast');
  if (toast) toast.style.display = 'none';
  if (state.toastTimer) clearTimeout(state.toastTimer);
}

// ── Whitelist ─────────────────────────────────────────────────────────────
function fetchWhitelist() {
  fetch('/api/whitelist').then(r => r.json()).then(renderWhitelist).catch(() => {});
}

function renderWhitelist(data) {
  setText('wlEnabled', data.enabled ? 'Enabled' : 'Disabled');
  setText('wlCount',   data.count   || 0);
  const list = el('wlList');
  if (!list) return;
  const entries = data.whitelist || [];
  if (!entries.length) {
    list.innerHTML = '<div class="empty-state"><div class="empty-title">No entries</div><div class="empty-desc">All traffic is subject to threat detection</div></div>';
    return;
  }
  list.innerHTML = entries.map(ip => `
    <div class="wl-entry">
      <span class="wl-ip">${esc(ip)}</span>
      <button class="wl-remove" onclick="removeFromWhitelist('${esc(ip)}')" aria-label="Remove ${esc(ip)}">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
          <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </button>
    </div>`).join('');
}

function addToWhitelist() {
  const input = el('wlInput');
  const errEl = el('wlError');
  const okEl  = el('wlSuccess');
  const val   = (input?.value || '').trim();
  if (!val) { showMsg(errEl, 'Enter an IP address or CIDR range.'); return; }

  fetch('/api/whitelist/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: val }),
  })
  .then(r => r.json())
  .then(d => {
    if (d.error) { showMsg(errEl, d.error); }
    else { if (input) input.value = ''; showMsg(okEl, `Added ${val}`); fetchWhitelist(); }
  })
  .catch(() => showMsg(errEl, 'Request failed.'));
}

function removeFromWhitelist(ip) {
  fetch('/api/whitelist/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  }).then(() => fetchWhitelist()).catch(() => {});
}

function showMsg(el_, msg) {
  if (!el_) return;
  el_.textContent = msg; el_.style.display = 'block';
  setTimeout(() => { el_.style.display = 'none'; }, 4000);
}

// ── Health ────────────────────────────────────────────────────────────────
function fetchHealth() {
  fetch('/api/health').then(r => r.json()).then(renderHealth).catch(() => {});
}

function renderHealth(h) {
  const deps = h.dependencies || {};
  const env  = h.environment  || {};
  const cap  = h.capture      || {};
  const perm = h.permissions  || {};
  const bc   = h.blockchain   || {};

  setHtml('depGrid', [
    { l:'Flask',    v: deps.flask    ? 'installed':'missing', s: deps.flask    ?'ok':'err' },
    { l:'Scapy',    v: deps.scapy    ? (deps.scapy_version||'installed'):'missing', s: deps.scapy ?'ok':'err' },
    { l:'Numpy',    v: deps.numpy    ? 'installed':'missing', s: deps.numpy    ?'ok':'err' },
    { l:'Watchdog', v: deps.watchdog ? 'installed':'missing', s: deps.watchdog ?'ok':'err' },
  ].map(d => `<div class="health-item"><div class="h-dot ${d.s}"></div><div class="h-body"><div class="h-label">${d.l}</div><div class="h-val">${d.v}</div></div></div>`).join(''));

  setHtml('envGrid', [
    ['Python',    env.python_version || '-'],
    ['Runtime',   `${env.env_type||'-'} / ${env.env_name||'-'}`],
    ['Path',      env.python_real || env.python || '-'],
    ['User',      `${env.user||'-'} (uid=${env.uid||'-'})`],
    ['Interface', env.interface || '-'],
    ['Uptime',    `${(h.system?.uptime_hours||0).toFixed(2)}h`],
  ].map(([l,v]) => `<div class="status-row"><span class="status-label">${esc(l)}</span><span class="status-value" style="font-family:var(--ff-mono);font-size:11px">${esc(v)}</span></div>`).join(''));

  const capOk  = cap.status === 'capture_running';
  const capSim = cap.status === 'simulation';
  const capSt  = capOk ? 'ok' : capSim ? 'warn' : 'err';
  const capLbl = capOk ? 'Live capture' : capSim ? 'Simulation' : (cap.status||'unknown').replace(/_/g,' ');
  const permOk = perm.can_capture;

  let html = `
    <div class="status-row">
      <span class="status-label">Capture mode</span>
      <span class="status-value"><span class="h-dot ${capSt}" style="display:inline-block;margin-right:6px;vertical-align:middle"></span>${esc(capLbl)}</span>
    </div>
    <div class="status-row">
      <span class="status-label">CAP_NET_RAW</span>
      <span class="status-value">${perm.cap_net_raw ? 'Granted' : 'Not set'}</span>
    </div>
    <div class="status-row">
      <span class="status-label">Raw socket</span>
      <span class="status-value">${perm.can_raw_socket ? 'Allowed' : 'Denied'}</span>
    </div>
    <div class="status-row">
      <span class="status-label">Blockchain</span>
      <span class="status-value">${bc.valid ? `Valid (${bc.blocks} blocks)` : 'Tampered'}</span>
    </div>`;

  if (!permOk && !capSim) {
    const py = esc(env.python_real || env.python || '');
    html += `<div style="margin-top:12px;padding:10px 12px;background:var(--amber-bg);border:1px solid var(--amber);border-radius:var(--radius);font-size:12px;color:var(--amber-t)">
      <strong>Fix packet capture:</strong><br>
      <code style="font-size:11px;font-family:var(--ff-mono);word-break:break-all;display:block;margin-top:3px">sudo /usr/sbin/setcap cap_net_raw,cap_net_admin=eip ${py}</code>
    </div>`;
    const badge = el('systemBadge');
    if (badge) badge.style.display = '';
  } else {
    const badge = el('systemBadge');
    if (badge) badge.style.display = 'none';
  }

  setHtml('captureHealthBody', html);
}

setInterval(fetchHealth, 30000);

// ── Audio alert ───────────────────────────────────────────────────────────
function playTone() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator(), gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.frequency.value = 440; osc.type = 'sine';
    gain.gain.setValueAtTime(0.12, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.5);
    osc.start(); osc.stop(ctx.currentTime + 0.5);
  } catch(e) {}
}

// ── Init ──────────────────────────────────────────────────────────────────
fetchHealth();
fetchWhitelist();
