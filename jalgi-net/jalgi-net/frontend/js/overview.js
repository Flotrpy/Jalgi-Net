/**
 * JalgiNet - Overview Tab (overview.js)
 * KPI counters, live traffic area chart, top-IPs list,
 * severity donut chart, and recent critical alerts list.
 */

let overviewTrafficChart = null;
let severityDonutChart   = null;
const MAX_TRAFFIC_POINTS = 40;
const trafficLabels      = [];
const trafficData        = [];

//  Animated counter helper
function animateNum(elId, target) {
  const el = document.getElementById(elId);
  if (!el) return;
  const start   = parseInt(el.textContent) || 0;
  const delta   = target - start;
  const steps   = 20;
  const stepVal = delta / steps;
  let current   = start;
  let step      = 0;
  const id = setInterval(() => {
    step++;
    current += stepVal;
    el.textContent = Math.round(step < steps ? current : target);
    if (step >= steps) clearInterval(id);
  }, 30);
}

//  Build / update traffic chart
function initTrafficChart() {
  const ctx = document.getElementById('overviewTrafficChart');
  if (!ctx) return;
  overviewTrafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels:   trafficLabels,
      datasets: [{
        label:           'Packets / sec',
        data:            trafficData,
        borderColor:     '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.06)',
        borderWidth:     2,
        pointRadius:     2,
        pointHoverRadius: 5,
        pointBackgroundColor: '#00d4ff',
        tension:         0.4,
        fill:            true,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      animation: { duration: 400 },
      scales: {
        x: {
          ticks:  { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 } },
          grid:   { color: 'rgba(255,255,255,0.04)' },
        },
        y: {
          beginAtZero: true,
          ticks:  { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 } },
          grid:   { color: 'rgba(255,255,255,0.04)' },
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0e1524',
          borderColor: '#00d4ff',
          borderWidth: 1,
          titleColor: '#00d4ff',
          bodyColor:  '#94a3b8',
        }
      }
    }
  });
}

function updateTrafficChart(stats) {
  if (!overviewTrafficChart || !stats.length) return;
  // Append new points
  stats.slice(-5).forEach(s => {
    const ts = new Date(s.timestamp);
    const label = ts.toLocaleTimeString('en-US', { hour12: false });
    if (trafficLabels.includes(label)) return;
    trafficLabels.push(label);
    trafficData.push(parseFloat(s.rps).toFixed(2));
    if (trafficLabels.length > MAX_TRAFFIC_POINTS) {
      trafficLabels.shift();
      trafficData.shift();
    }
  });
  overviewTrafficChart.update('none');
}

//  Severity donut chart
function initSeverityDonut() {
  const ctx = document.getElementById('severityDonutChart');
  if (!ctx) return;
  severityDonutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data:            [0, 0, 0, 0],
        backgroundColor: ['#ff3366', '#ff6b35', '#ffc107', '#00ff88'],
        borderColor:     '#121929',
        borderWidth:     3,
        hoverOffset:     6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 }, padding: 12 }
        },
        tooltip: {
          backgroundColor: '#0e1524',
          borderColor: 'rgba(0,212,255,0.3)',
          borderWidth: 1,
          titleColor:  '#e2e8f0',
          bodyColor:   '#94a3b8',
        }
      }
    }
  });
}

function updateSeverityDonut(counts) {
  if (!severityDonutChart) return;
  severityDonutChart.data.datasets[0].data = [
    counts.Critical || 0,
    counts.High     || 0,
    counts.Medium   || 0,
    counts.Low      || 0,
  ];
  severityDonutChart.update();
}


//  Recent critical alerts
function renderRecentCritical(alerts) {
  const ul = document.getElementById('recentCriticalList');
  if (!ul) return;
  const critical = alerts.filter(a => a.severity === 'Critical').slice(0, 5);
  if (!critical.length) {
    ul.innerHTML = '<li class="mini-alert-item" style="border-left-color:#00ff88;background:rgba(0,255,136,0.06)"><div class="mini-alert-desc" style="color:#00ff88">No critical alerts</div></li>';
    return;
  }
  ul.innerHTML = critical.map(a => `
    <li class="mini-alert-item">
      <div class="mini-alert-ip">${a.source_ip}</div>
      <div class="mini-alert-desc">${a.description.substring(0, 72)}...</div>
      <div class="mini-alert-time">${formatTimestamp(a.timestamp)}</div>
    </li>`).join('');
}

//  Main refresh
async function refreshOverview() {
  const [summary, trafficStats, alerts] = await Promise.all([
    apiFetch('/api/alerts/summary'),
    apiFetch('/api/traffic/stats?limit=40'),
    apiFetch('/api/alerts?limit=20'),
  ]);

  if (summary && summary.data) {
    const s = summary.data;
    animateNum('totalAlertsNum',   s.total_alerts    || 0);
    animateNum('activeThreatsNum', s.active_threats  || 0);
    animateNum('criticalAlertsNum',s.critical_alerts || 0);
    animateNum('blockedIpsNum',    s.blocked_ips     || 0);
    animateNum('idsEventsNum',     s.ids_events      || 0);
    document.getElementById('currentRpsNum').textContent =
      (s.current_rps || 0).toFixed(1);
    updateSeverityDonut(s.severity_counts || {});

    // Notify on new Critical
    if (s.critical_alerts > 0 && !window.JalgiNet.notifiedIds.has('crit_overview')) {
      window.JalgiNet.notifiedIds.add('crit_overview');
      showToast('Critical Alert', `${s.critical_alerts} critical threat(s) detected!`, 'Critical');
      setTimeout(() => window.JalgiNet.notifiedIds.delete('crit_overview'), 30000);
    }
  }

  if (trafficStats && trafficStats.stats) {
    updateTrafficChart(trafficStats.stats);
  }


  if (alerts && alerts.alerts) {
    renderRecentCritical(alerts.alerts);
  }
}

//  Init
document.addEventListener('DOMContentLoaded', () => {
  initTrafficChart();
  initSeverityDonut();
  refreshOverview();
  setInterval(refreshOverview, window.REFRESH_INTERVAL);
});
