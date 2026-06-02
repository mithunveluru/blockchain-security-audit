// ── SOC chart instances ───────────────────────────────────────────────────
const socCharts = { timeline: null, protocol: null, dist: null, health: null };

function chartPalette() {
  return {
    text:   '#768390',
    grid:   'rgba(48,54,61,.5)',
    blue:   '#388bfd',
    red:    '#f85149',
    green:  '#3fb950',
    amber:  '#d29922',
    orange: '#f78166',
    cyan:   '#39c5cf',
    gray:   '#30363d',
  };
}

// ── Timeline ──────────────────────────────────────────────────────────────
function initTimelineChart() {
  const canvas = document.getElementById('timelineCanvas');
  if (!canvas || socCharts.timeline) return;
  const c = chartPalette();
  socCharts.timeline = new Chart(canvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Threats',
        data: [],
        borderColor: c.red,
        backgroundColor: 'rgba(248,81,73,.07)',
        borderWidth: 1.5,
        fill: true,
        tension: 0.35,
        pointRadius: 2.5,
        pointBackgroundColor: c.red,
        pointHoverRadius: 5,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { color: c.text, font: { size: 11 } }, grid: { color: c.grid } },
        x: { ticks: { color: c.text, font: { size: 11 }, maxTicksLimit: 12 }, grid: { display: false } },
      },
    },
  });
}

function updateTimelineChart(data) {
  if (!socCharts.timeline || !data.stats) return;
  const now = new Date().toLocaleTimeString('en-US', { hour12: false });
  socCharts.timeline.data.labels.push(now);
  socCharts.timeline.data.datasets[0].data.push(data.stats.threats_detected || 0);
  if (socCharts.timeline.data.labels.length > 30) {
    socCharts.timeline.data.labels.shift();
    socCharts.timeline.data.datasets[0].data.shift();
  }
  socCharts.timeline.update('none');
}

// ── Network charts ────────────────────────────────────────────────────────
function initNetworkCharts() {
  const c = chartPalette();

  const ctxP = document.getElementById('protocolCanvas')?.getContext('2d');
  if (ctxP && !socCharts.protocol) {
    socCharts.protocol = new Chart(ctxP, {
      type: 'bar',
      data: {
        labels: ['TCP','UDP','ICMP','HTTP','HTTPS'],
        datasets: [{ label: 'Packets', data: [0,0,0,0,0], backgroundColor: [c.blue, c.cyan, c.amber, c.orange, c.green], borderRadius: 3 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { color: c.text, font: { size: 11 } }, grid: { color: c.grid } },
          x: { ticks: { color: c.text, font: { size: 11 } }, grid: { display: false } },
        },
      },
    });
  }

  const ctxD = document.getElementById('distCanvas')?.getContext('2d');
  if (ctxD && !socCharts.dist) {
    socCharts.dist = new Chart(ctxD, {
      type: 'doughnut',
      data: {
        labels: ['Port Scan','DDoS','Brute Force','Anomaly','Clean'],
        datasets: [{ data: [0,0,0,0,100], backgroundColor: [c.red, c.orange, c.amber, c.blue, c.gray], borderWidth: 0, hoverOffset: 4 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: c.text, font: { size: 11 }, padding: 12, boxWidth: 10 } } },
      },
    });
  }

  const ctxH = document.getElementById('healthCanvas')?.getContext('2d');
  if (ctxH && !socCharts.health) {
    socCharts.health = new Chart(ctxH, {
      type: 'radar',
      data: {
        labels: ['Availability','Security','Performance','Integrity','Response'],
        datasets: [{
          label: 'Health',
          data: [95,88,92,100,90],
          borderColor: c.green,
          backgroundColor: 'rgba(63,185,80,.1)',
          pointBackgroundColor: c.green,
          borderWidth: 1.5,
          pointRadius: 3,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { r: {
          ticks: { display: false },
          grid: { color: c.grid },
          angleLines: { color: c.grid },
          pointLabels: { color: c.text, font: { size: 10 } },
          suggestedMin: 0, suggestedMax: 100,
        }},
      },
    });
  }
}

// ── Network chart updates ─────────────────────────────────────────────────
function updateNetworkCharts(data) {
  const intBroken = typeof state !== 'undefined' ? state.intBroken : false;

  if (socCharts.protocol && data.network_stats?.protocol_distribution) {
    const dist = data.network_stats.protocol_distribution;
    socCharts.protocol.data.labels = Object.keys(dist);
    socCharts.protocol.data.datasets[0].data = Object.values(dist);
    socCharts.protocol.update('none');
  }

  if (socCharts.dist && data.recent_threats) {
    const counts = { PORT_SCAN: 0, DDOS_ATTACK: 0, BRUTE_FORCE: 0, ANOMALY: 0, CLEAN: 0 };
    data.recent_threats.forEach(t => {
      (t.threats || []).forEach(th => {
        const k = Object.prototype.hasOwnProperty.call(counts, th.type) ? th.type : 'ANOMALY';
        counts[k]++;
      });
    });
    const det = Object.values(counts).reduce((a,b) => a+b, 0);
    counts.CLEAN = det > 0 ? 0 : 100;
    const total = Object.values(counts).reduce((a,b) => a+b, 0) || 1;
    socCharts.dist.data.datasets[0].data = [
      (counts.PORT_SCAN   / total) * 100,
      (counts.DDOS_ATTACK / total) * 100,
      (counts.BRUTE_FORCE / total) * 100,
      (counts.ANOMALY     / total) * 100,
      (counts.CLEAN       / total) * 100,
    ];
    socCharts.dist.update('none');
  }

  if (socCharts.health && data.stats) {
    const t   = data.stats.threats_detected || 0;
    const p   = data.stats.packets_analyzed || 0;
    const sec = p > 0 ? Math.max(0, 100 - (t / p) * 1000) : 100;
    socCharts.health.data.datasets[0].data = [
      Math.min(100, 90 + Math.random() * 10),
      Math.min(100, sec),
      Math.min(100, 85 + Math.random() * 15),
      intBroken ? 10 : 100,
      Math.min(100, 88 + Math.random() * 12),
    ];
    socCharts.health.update('none');
  }

  updatePortBars(data.network_stats?.top_ports);
}

// ── Port bars ─────────────────────────────────────────────────────────────
function updatePortBars(topPorts) {
  const container = document.getElementById('portBars');
  if (!container) return;
  let ports;
  if (topPorts && topPorts.length > 0) {
    const maxC = topPorts[0][1] || 1;
    ports = topPorts.slice(0, 10).map(([p, c]) => ({ port: p, pct: (c / maxC) * 100 }));
  } else {
    ports = [80,443,22,3389,53,3306,5432,8080,8443,21].map(p => ({ port: p, pct: 0 }));
  }
  container.innerHTML = ports.map(({ port, pct }) => {
    const h  = Math.max(8, (pct / 100) * 90);
    const op = 0.35 + (pct / 200);
    return `<div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex:1;min-width:0">
      <div style="font-size:9px;color:var(--text-3);font-weight:500">${pct > 0 ? Math.round(pct) + '%' : ''}</div>
      <div style="width:100%;height:${h}px;background:var(--blue);border-radius:3px 3px 0 0;opacity:${op}"></div>
      <div style="font-size:9px;color:var(--text-3);font-variant-numeric:tabular-nums;white-space:nowrap">${port}</div>
    </div>`;
  }).join('');
}

// ── Expose for switchView ─────────────────────────────────────────────────
window.initTimelineChart   = initTimelineChart;
window.initNetworkCharts   = initNetworkCharts;
window.updateNetworkCharts = updateNetworkCharts;
window.updateTimelineChart = updateTimelineChart;
