const socket = io();

window.dashboardData = {
    stats: {},
    threats: [],
    history: {
        packets: [],
        threats: [],
        times: []
    }
};

socket.on('connect', () => {
    console.log('✓ Connected to Security Operations Center');
});

socket.on('dashboard_update', (data) => {
    window.dashboardData.stats = data.stats;
    window.dashboardData.threats = data.recent_threats || [];
    
    updateKPIs(data.stats);
    updateThreatIndicator(data.stats);
    updateIncidentsTable(data.recent_threats);
    updateCharts(data);
    updateIntegrityStatus();
    
    document.getElementById('loadingScreen').classList.add('hidden');
});

socket.on('integrity_alert', (alert) => {
    console.log('🚨 INTEGRITY ALERT:', alert);
    updateIntegrityStatus(alert);
    showAlertNotification(alert);
});

function updateKPIs(stats) {
    const kpiValues = {
        'threats': stats.threats_detected || 0,
        'packets': (stats.packets_analyzed || 0).toLocaleString(),
        'flows': stats.flows_tracked || 0,
        'blocks': stats.blockchain_blocks || 1
    };

    for (let [key, value] of Object.entries(kpiValues)) {
        const element = document.getElementById(`kpi-${key}`);
        if (element && element.textContent !== value.toString()) {
            animateValue(element, value);
        }
    }
}

function updateThreatIndicator(stats) {
    const threatLevel = stats.threats_detected || 0;
    let status = 'System Secure';
    let description = 'No active threats';
    let color = 'green';

    if (threatLevel > 0 && threatLevel < 3) {
        status = 'Low Activity';
        description = `${threatLevel} threat(s) detected`;
        color = 'blue';
    } else if (threatLevel >= 3 && threatLevel < 10) {
        status = 'Medium Activity';
        description = `${threatLevel} threat(s) detected`;
        color = 'orange';
    } else if (threatLevel >= 10) {
        status = 'High Threat Level';
        description = `${threatLevel} active threats!`;
        color = 'red';
    }

    document.getElementById('threatStatus').textContent = status;
    document.getElementById('threatDescription').textContent = description;
    
    const percentage = Math.min((threatLevel / 20) * 100, 100);
    const circumference = 2 * Math.PI * 40;
    const strokeDash = circumference - (percentage / 100) * circumference;
    
    const gaugeFill = document.getElementById('gaugeFill');
    if (gaugeFill) {
        gaugeFill.style.strokeDasharray = `${circumference - strokeDash}, ${circumference}`;
        gaugeFill.style.stroke = color === 'red' ? '#ef4444' : color === 'orange' ? '#f59e0b' : '#0ea5e9';
    }

    const threatLevel_ = document.querySelector('.gauge-text');
    if (threatLevel_) threatLevel_.textContent = Math.min(threatLevel, 99);
}

function updateIncidentsTable(threats) {
    const tbody = document.getElementById('incidentsBody');
    if (!tbody) return;

    if (!threats || threats.length === 0) {
        tbody.innerHTML = '<tr class="no-data"><td colspan="6">No active incidents...</td></tr>';
        return;
    }

    tbody.innerHTML = threats.reverse().slice(0, 10).map(threat => {
        const threatTypes = (threat.threats || []).map(t => `<strong>${t.type}</strong>`).join(', ');
        const time = new Date(threat.timestamp).toLocaleTimeString();
        
        return `
            <tr>
                <td>${time}</td>
                <td>${threatTypes}</td>
                <td><span class="threat-badge ${threat.threat_level}">${threat.threat_level}</span></td>
                <td>${(threat.threats && threat.threats[0]) ? (threat.threats[0].source || threat.threats[0].target || '-') : '-'}</td>
                <td>${(threat.threats && threat.threats[0]) ? threat.threats[0].description.substring(0, 40) + '...' : ''}</td>
                <td><span class="status-indicator active"></span>Active</td>
            </tr>
        `;
    }).join('');
}

function animateValue(element, newValue) {
    const currentText = element.textContent;
    const currentValue = parseInt(currentText.replace(/,/g, '')) || 0;
    
    if (currentValue === newValue) return;
    
    gsap.to({ value: currentValue }, {
        value: newValue,
        duration: 0.6,
        ease: 'power2.out',
        onUpdate: function() {
            element.textContent = Math.round(this.targets()[0].value).toLocaleString();
        }
    });
}

function updateIntegrityStatus(alert = null) {
    const statusCircle = document.getElementById('integrityStatus');
    const title = document.getElementById('integrityTitle');
    const desc = document.getElementById('integrityDesc');

    if (alert && alert.severity === 'CRITICAL') {
        statusCircle.textContent = '⚠️';
        statusCircle.style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
        title.textContent = 'Tampering Detected!';
        desc.textContent = alert.message.substring(0, 50) + '...';
    } else {
        statusCircle.textContent = '✓';
        statusCircle.style.background = 'linear-gradient(135deg, #10b981, #059669)';
        title.textContent = 'Blockchain Valid';
        desc.textContent = 'All blocks verified and immutable';
    }
}

function updateCharts(data) {
    if (window.updateAllCharts) {
        window.updateAllCharts(data);
    }
}

function showAlertNotification(alert) {
    gsap.timeline()
        .from(document.body, { duration: 0.3, background: 'rgba(239, 68, 68, 0.1)' })
        .to(document.body, { duration: 0.3, background: 'linear-gradient(135deg, #0f172a 0%, #1a1f3a 100%)' });
}

setInterval(() => {
    const now = new Date();
    document.getElementById('currentTime').textContent = 
        now.toLocaleTimeString('en-US', { hour12: false });
}, 1000);

