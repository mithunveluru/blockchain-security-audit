let threatTimelineChart, threatDistChart, healthChart, protocolChart;
const chartColors = {
    accent: '#0ea5e9',
    accent2: '#06b6d4',
    danger: '#ef4444',
    warning: '#f59e0b',
    success: '#10b981',
    border: '#334155'
};

function initCharts() {
    const ctxTimeline = document.getElementById('threatTimeline')?.getContext('2d');
    if (ctxTimeline) {
        threatTimelineChart = new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threats Detected',
                    data: [],
                    borderColor: chartColors.danger,
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 6,
                    pointBackgroundColor: chartColors.danger,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        ticks: { color: chartColors.border },
                        grid: { color: 'rgba(51, 65, 85, 0.2)' },
                        beginAtZero: true
                    },
                    x: {
                        ticks: { color: chartColors.border },
                        grid: { color: 'rgba(51, 65, 85, 0.1)' }
                    }
                }
            }
        });
    }

    const ctxDist = document.getElementById('threatDistribution')?.getContext('2d');
    if (ctxDist) {
        threatDistChart = new Chart(ctxDist, {
            type: 'doughnut',
            data: {
                labels: ['Port Scan', 'DDoS', 'Brute Force', 'Anomaly', 'Clean'],
                datasets: [{
                    data: [0, 0, 0, 0, 100],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.8)',
                        'rgba(245, 158, 11, 0.8)',
                        'rgba(251, 191, 36, 0.8)',
                        'rgba(59, 130, 246, 0.8)',
                        'rgba(51, 65, 85, 0.5)'
                    ],
                    borderColor: '#1e293b',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: chartColors.border, font: { size: 12 } }
                    }
                }
            }
        });
    }

    const ctxHealth = document.getElementById('networkHealth')?.getContext('2d');
    if (ctxHealth) {
        healthChart = new Chart(ctxHealth, {
            type: 'radar',
            data: {
                labels: ['Availability', 'Security', 'Performance', 'Integrity', 'Response Time'],
                datasets: [{
                    label: 'Health Score',
                    data: [95, 88, 92, 100, 90],
                    borderColor: chartColors.success,
                    backgroundColor: 'rgba(16, 185, 129, 0.2)',
                    pointBackgroundColor: chartColors.success,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { labels: { color: chartColors.border } }
                },
                scales: {
                    r: {
                        grid: { color: 'rgba(51, 65, 85, 0.3)' },
                        ticks: { color: chartColors.border }
                    }
                }
            }
        });
    }

    const ctxProtocol = document.getElementById('protocolDist')?.getContext('2d');
    if (ctxProtocol) {
        protocolChart = new Chart(ctxProtocol, {
            type: 'bar',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'],
                datasets: [{
                    label: 'Packets',
                    data: [1200, 900, 300, 1500, 2100],
                    backgroundColor: [
                        chartColors.accent,
                        chartColors.accent2,
                        chartColors.danger,
                        chartColors.warning,
                        chartColors.success
                    ],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        ticks: { color: chartColors.border },
                        grid: { color: 'rgba(51, 65, 85, 0.2)' }
                    },
                    x: {
                        ticks: { color: chartColors.border },
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

function updateAllCharts(data) {
    if (!data.stats) return;

    if (threatTimelineChart) {
        const now = new Date().toLocaleTimeString();
        threatTimelineChart.data.labels.push(now);
        threatTimelineChart.data.datasets[0].data.push(data.stats.threats_detected || 0);
        
        if (threatTimelineChart.data.labels.length > 24) {
            threatTimelineChart.data.labels.shift();
            threatTimelineChart.data.datasets[0].data.shift();
        }
        threatTimelineChart.update('none');
    }

    if (threatDistChart && data.recent_threats) {
        const counts = { PORT_SCAN: 0, DDOS_ATTACK: 0, BRUTE_FORCE: 0, ANOMALY: 0, CLEAN: 100 };
        data.recent_threats.forEach(t => {
            t.threats?.forEach(threat => {
                counts[threat.type] = (counts[threat.type] || 0) + 1;
            });
        });
        
        const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
        threatDistChart.data.datasets[0].data = [
            (counts.PORT_SCAN / total) * 100,
            (counts.DDOS_ATTACK / total) * 100,
            (counts.BRUTE_FORCE / total) * 100,
            (counts.ANOMALY / total) * 100,
            (counts.CLEAN / total) * 100
        ];
        threatDistChart.update('none');
    }

    updatePortHeatmap();
}

function updatePortHeatmap() {
    const heatmap = document.getElementById('portHeatmap');
    if (!heatmap) return;

    const ports = [80, 443, 22, 3389, 53, 3306, 5432, 8080];
    heatmap.innerHTML = ports.map((port, i) => {
        const value = Math.random() * 100;
        return `<div class="port-bar" style="height: ${30 + (value / 100) * 70}px; opacity: ${0.5 + (value / 200)}">
            <div style="font-size: 8px; margin-top: 4px;">${port}</div>
        </div>`;
    }).join('');
}

document.addEventListener('DOMContentLoaded', initCharts);
window.updateAllCharts = updateAllCharts;

