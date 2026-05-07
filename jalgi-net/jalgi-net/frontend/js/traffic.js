/**
 * JalgiNet – Traffic Analysis Tab (traffic.js)
 * RPS line chart, protocol donut, top-IPs bar chart.
 */

let trafficRpsChart  = null;
let protocolChart    = null;
let topIpsBarChart   = null;
const rpsLabels = [], rpsData = [];

function initTrafficRpsChart() {
  const ctx = document.getElementById('trafficRpsChart');
  if (!ctx) return;
  trafficRpsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: rpsLabels,
      datasets: [{
        label: 'RPS',
        data: rpsData,
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.07)',
        borderWidth: 2,
        pointRadius: 2,
        tension: 0.4,
        fill: true,
      }, {
        label: 'Spike Threshold',
        data: rpsData.map(() => 50),
        borderColor: 'rgba(255,51,102,0.5)',
        borderWidth: 1,
        borderDash: [6, 4],
        pointRadius: 0,
        fill: false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      animation: { duration: 300 },
      scales: {
        x: { ticks: { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { beginAtZero: true, ticks: { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
      },
      plugins: {
        legend: { labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } } },
        tooltip: { backgroundColor: '#0e1524', borderColor: '#00d4ff', borderWidth: 1, titleColor: '#00d4ff', bodyColor: '#94a3b8' }
      }
    }
  });
}

function initProtocolChart() {
  const ctx = document.getElementById('protocolChart');
  if (!ctx) return;
  protocolChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{ data: [], backgroundColor: ['#00d4ff','#a855f7','#ffc107','#ff3366','#00ff88','#ff6b35'], borderColor: '#121929', borderWidth: 3 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '65%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 }, padding: 10 } },
        tooltip: { backgroundColor: '#0e1524', borderColor: 'rgba(0,212,255,0.3)', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' }
      }
    }
  });
}

function initTopIpsBarChart() {
  const ctx = document.getElementById('topIpsChart');
  if (!ctx) return;
  topIpsBarChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{ label: 'Packets', data: [], backgroundColor: 'rgba(0,212,255,0.25)', borderColor: '#00d4ff', borderWidth: 1, borderRadius: 4 }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        x: { ticks: { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
      },
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: '#0e1524', borderColor: '#00d4ff', borderWidth: 1, titleColor: '#00d4ff', bodyColor: '#94a3b8' }
      }
    }
  });
}

async function refreshTraffic() {
  const [statsData, protoData, topIpsData] = await Promise.all([
    apiFetch('/api/traffic/stats?limit=50'),
    apiFetch('/api/traffic/protocols'),
    apiFetch('/api/traffic/top-ips?limit=10'),
  ]);

  // RPS chart
  if (statsData && statsData.stats && trafficRpsChart) {
    const stats = statsData.stats;
    stats.slice(-5).forEach(s => {
      const label = new Date(s.timestamp).toLocaleTimeString('en-US', { hour12: false });
      if (rpsLabels.includes(label)) return;
      rpsLabels.push(label);
      rpsData.push(parseFloat(s.rps).toFixed(2));
      if (rpsLabels.length > 50) { rpsLabels.shift(); rpsData.shift(); }
    });
    // Update spike threshold line
    trafficRpsChart.data.datasets[1].data = rpsLabels.map(() => 50);
    trafficRpsChart.update('none');
  }

  // Protocol donut
  if (protoData && protoData.protocols && protocolChart) {
    protocolChart.data.labels = protoData.protocols.map(p => p.protocol);
    protocolChart.data.datasets[0].data = protoData.protocols.map(p => p.count);
    protocolChart.update();
  }

  // Top IPs bar
  if (topIpsData && topIpsData.top_ips && topIpsBarChart) {
    topIpsBarChart.data.labels = topIpsData.top_ips.map(i => i.source_ip);
    topIpsBarChart.data.datasets[0].data = topIpsData.top_ips.map(i => i.packet_count);
    topIpsBarChart.update();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initTrafficRpsChart();
  initProtocolChart();
  initTopIpsBarChart();
  refreshTraffic();
  setInterval(refreshTraffic, window.REFRESH_INTERVAL);
});
