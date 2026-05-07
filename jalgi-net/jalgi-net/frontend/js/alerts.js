/**
 * JalgiNet – Alerts Feed Tab (alerts.js)
 * Real-time alert stream with severity/type filters and search.
 */

let alertSeverityFilter = '';
let alertTypeFilter     = '';
let alertSearchQuery    = '';
let lastAlertId         = 0;

function buildAlertHTML(a) {
  return `
    <div class="alert-item ${a.severity}" id="alert-${a.id}">
      <div class="alert-body">
        <div class="alert-badges">
          <span class="severity-badge ${a.severity}">${a.severity}</span>
          <span class="type-badge ${a.type}">${a.type}</span>
        </div>
        <div class="alert-desc">${a.description}</div>
        <div class="alert-meta">
          <span class="alert-ip">⬡ ${a.source_ip}</span>
          <span>${formatTimestamp(a.timestamp)}</span>
        </div>
      </div>
      <button class="alert-action-btn" onclick="blockAlertIp('${a.source_ip}')">⛔ Block</button>
    </div>`;
}

async function blockAlertIp(ip) {
  const res = await apiFetch('/api/threats/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason: 'Blocked from Alerts Feed' }),
  });
  if (res && res.status === 'ok') {
    showToast('IP Blocked', `${ip} has been added to the block list.`, 'High');
  }
}
window.blockAlertIp = blockAlertIp;

async function refreshAlerts() {
  const params = new URLSearchParams({ limit: 80 });
  if (alertSeverityFilter) params.set('severity', alertSeverityFilter);
  if (alertTypeFilter)     params.set('type',     alertTypeFilter);

  const data = await apiFetch(`/api/alerts?${params}`);
  if (!data || !data.alerts) return;

  let alerts = data.alerts;

  // Client-side search filter
  if (alertSearchQuery) {
    const q = alertSearchQuery.toLowerCase();
    alerts = alerts.filter(a =>
      a.source_ip.includes(q) ||
      a.description.toLowerCase().includes(q) ||
      a.severity.toLowerCase().includes(q) ||
      a.type.toLowerCase().includes(q)
    );
  }

  const stream = document.getElementById('alertStream');
  if (!stream) return;

  // Check for new alerts to toast
  if (alerts.length && alerts[0].id > lastAlertId) {
    const newest = alerts[0];
    if (lastAlertId > 0 && (newest.severity === 'Critical' || newest.severity === 'High')) {
      showToast(
        `${newest.severity} Alert`,
        `${newest.type}: ${newest.description.substring(0, 80)}`,
        newest.severity
      );
    }
    lastAlertId = alerts[0].id;
  }

  stream.innerHTML = alerts.length
    ? alerts.map(buildAlertHTML).join('')
    : '<p style="color:var(--text-muted);padding:20px;text-align:center;">No alerts match the current filter.</p>';
}

// ── Filter bindings ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Severity filter
  document.querySelectorAll('.filter-btn:not(.type-btn)').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn:not(.type-btn)').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      alertSeverityFilter = btn.dataset.filter;
      refreshAlerts();
    });
  });

  // Type filter
  document.querySelectorAll('.type-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      alertTypeFilter = btn.dataset.type;
      refreshAlerts();
    });
  });

  // Search
  const searchEl = document.getElementById('alertSearch');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      alertSearchQuery = searchEl.value.trim();
      refreshAlerts();
    });
  }

  refreshAlerts();
  setInterval(refreshAlerts, window.REFRESH_INTERVAL);
});
