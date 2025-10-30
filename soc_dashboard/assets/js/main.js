// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeAnimations();
    initializeEventListeners();
    console.log('✓ SOC Dashboard initialized');
});

function initializeAnimations() {
    // Stagger KPI cards
    gsap.from('.kpi-card', {
        duration: 0.6,
        y: 30,
        opacity: 0,
        stagger: 0.1,
        ease: 'back.out'
    });

    // Threat indicator float animation
    gsap.to('.threat-gauge', {
        duration: 3,
        y: -10,
        repeat: -1,
        yoyo: true,
        ease: 'sine.inOut'
    });

    // Header glow
    gsap.to('.header', {
        duration: 2,
        boxShadow: '0 0 20px rgba(14, 165, 233, 0.5)',
        repeat: -1,
        yoyo: true
    });
}

function initializeEventListeners() {
    // Chart range controls
    document.querySelectorAll('.chart-control-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.chart-control-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
        });
    });

    // Make charts responsive
    window.addEventListener('resize', () => {
        if (window.threatTimelineChart) window.threatTimelineChart.resize();
        if (window.threatDistChart) window.threatDistChart.resize();
        if (window.healthChart) window.healthChart.resize();
        if (window.protocolChart) window.protocolChart.resize();
    });
}

// Spark charts for KPI cards
function initSparkCharts() {
    const sparkConfigs = {
        'spark-threats': { color: '#ef4444', data: [1, 2, 3, 2, 1] },
        'spark-packets': { color: '#0ea5e9', data: [5, 10, 8, 12, 15] },
        'spark-flows': { color: '#06b6d4', data: [3, 5, 4, 6, 5] },
        'spark-blocks': { color: '#10b981', data: [1, 1, 1, 2, 2] }
    };

    for (let [id, config] of Object.entries(sparkConfigs)) {
        const canvas = document.getElementById(id);
        if (!canvas) continue;

        const ctx = canvas.getContext('2d');
        new Chart(canvas, {
            type: 'line',
            data: {
                labels: Array(config.data.length).fill(''),
                datasets: [{
                    data: config.data,
                    borderColor: config.color,
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { display: false }
                }
            }
        });
    }
}

// Initialize spark charts after a delay
setTimeout(initSparkCharts, 1000);

