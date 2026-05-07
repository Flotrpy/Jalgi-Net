/**
 * JalgiNet – Core App Controller (app.js)
 * Tab routing, global state, API helpers, clock, and toasts.
 */

const API_BASE = 'http://localhost:5000';
const REFRESH_INTERVAL = 3000; // ms

// ── Global state ─────────────────────────────────────────────────────────────
window.JalgiNet = {
  currentTab: 'overview',
  stats: {},
  refreshTimers: [],
  notifiedIds: new Set(),
  socket: null,
};

// ── API helper ────────────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  try {
    const res = await fetch(API_BASE + path, options);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    console.warn(`[API] ${path} failed:`, e.message);
    return null;
  }
}
window.apiFetch = apiFetch;

// ── Tab routing ───────────────────────────────────────────────────────────────
const TAB_TITLES = {
  overview: ['Overview',            'Real-time network threat monitoring'],
  alerts:   ['Alerts Feed',         'Live stream of detected security events'],
  traffic:  ['Traffic Analysis',    'Packet flow analysis and rate monitoring'],
  ids:      ['IDS Events',          'Parsed Snort / Suricata intrusion alerts'],
  threats:  ['Correlated Threats',  'Multi-stage attack correlation & risk scoring'],
  devices:  ['Devices',             'Security profiles for active network assets'],
  settings: ['Settings',            'Configure thresholds, modules & data management'],
};

function switchTab(tabName) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));

  const navEl   = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
  const panelEl = document.getElementById(`panel-${tabName}`);
  if (navEl)   navEl.classList.add('active');
  if (panelEl) panelEl.classList.add('active');

  const [title, subtitle] = TAB_TITLES[tabName] || [tabName, ''];
  document.getElementById('pageTitle').textContent    = title;
  document.getElementById('pageSubtitle').textContent = subtitle;
  window.JalgiNet.currentTab = tabName;
}

document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => switchTab(el.dataset.tab));
});

// ── Live clock ────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clockDisplay').textContent =
    now.toUTCString().replace('GMT', 'UTC');
}
setInterval(updateClock, 1000);
updateClock();

// ── System health check ───────────────────────────────────────────────────────
async function checkHealth() {
  const data = await apiFetch('/api/health');
  const dot   = document.getElementById('systemStatusDot');
  const label = document.getElementById('systemStatusLabel');
  if (data && data.status === 'ok') {
    dot.className   = 'status-dot online';
    label.textContent = 'All Systems Online';
    // Update health badges from modules
    const m = data.modules || {};
    setHealthBadge('hDos',   m.dos_detection);
    setHealthBadge('hIds',   m.ids_integration);
    setHealthBadge('hCorr',  m.correlation);
    setHealthBadge('hGeo',   m.geo_ip);
    document.getElementById('hCapture').textContent = data.capture_status || 'OFFLINE';
    document.getElementById('sidebarCaptureInfo').textContent = (data.capture_status || 'OFFLINE').toUpperCase();

    // Check for failure to toast
    if (data.capture_status && data.capture_status.startsWith('Failed')) {
      if (!window.JalgiNet.notifiedIds.has('cap_fail')) {
        showToast('Capture Error', data.capture_status, 'Critical');
        window.JalgiNet.notifiedIds.add('cap_fail');
      }
    } else {
      window.JalgiNet.notifiedIds.delete('cap_fail');
    }
  } else {
    dot.className   = 'status-dot offline';
    label.textContent = 'API Offline';
  }
}

function setHealthBadge(elId, active) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (active) {
    el.textContent = 'ACTIVE';
    el.className   = 'health-badge green';
  } else {
    el.textContent = 'DISABLED';
    el.className   = 'health-badge red';
  }
}

// ── Global KPI bar (topbar) ───────────────────────────────────────────────────
function updateUIFromStats(s) {
  if (!s) return;
  document.getElementById('topbarRPS').textContent =
    s.current_rps != null ? s.current_rps.toFixed(1) : '—';
  document.getElementById('topbarCritical').textContent =
    s.critical_alerts ?? 0;

  // Update nav badges
  document.getElementById('alertsBadge').textContent  = s.total_alerts  ?? 0;
  document.getElementById('idsBadge').textContent     = s.ids_events    ?? 0;
  document.getElementById('threatsBadge').textContent = s.active_threats ?? 0;

  window.JalgiNet.stats = s;

  // Also update overview KPIs if on that tab
  if (window.JalgiNet.currentTab === 'overview') {
    if (typeof refreshOverviewKPIs === 'function') {
      refreshOverviewKPIs(s);
    }
  }
}

async function refreshTopbar() {
  const data = await apiFetch('/api/alerts/summary');
  if (data && data.status === 'ok') {
    updateUIFromStats(data.data);
  }
}

// ── Toast notifications ───────────────────────────────────────────────────────
function showToast(title, message, severity = 'info', duration = 5000) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${severity}`;
  toast.innerHTML = `
    <div style="flex:1">
      <div class="toast-title">${title}</div>
      <div class="toast-msg">${message}</div>
    </div>
    <button class="toast-close" onclick="this.closest('.toast').remove()">✕</button>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);

  // Browser notification for Critical
  if (severity === 'Critical' && Notification.permission === 'granted') {
    new Notification(`JalgiNet – ${title}`, { body: message, icon: '/favicon.ico' });
  }
}
window.showToast = showToast;

// Request notification permission on load
if ('Notification' in window && Notification.permission === 'default') {
  Notification.requestPermission();
}

// ── Severity color helpers ────────────────────────────────────────────────────
const SEVERITY_COLOR = {
  Critical: '#ff3366',
  High:     '#ff6b35',
  Medium:   '#ffc107',
  Low:      '#00ff88',
};
window.SEVERITY_COLOR = SEVERITY_COLOR;

function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false }) + ' ' +
         d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' });
}
window.formatTimestamp = formatTimestamp;

function attackPillClass(type) {
  const map = {
    'Port Scan':             'port-scan',
    'SQL Injection':         'sql',
    'Brute Force':           'brute',
    'XSS':                   'xss',
    'Remote Code Execution': 'rce',
    'Malware C2':            'malware',
    'DNS Exfiltration':      'dns',
  };
  return map[type] || 'default';
}
window.attackPillClass = attackPillClass;

// ── WebSocket setup ──────────────────────────────────────────────────────────
function initWebSockets() {
  const socket = io(API_BASE);
  window.JalgiNet.socket = socket;

  socket.on('connect', () => {
    console.log('[WS] Connected to server');
  });

  socket.on('update_stats', (stats) => {
    updateUIFromStats(stats);
  });

  socket.on('new_alert', (alert) => {
    if (alert.severity === 'Critical') {
      showToast('Critical Alert', alert.description, 'Critical');
    }
    // Refresh alerts if on tab
    if (window.JalgiNet.currentTab === 'alerts' && typeof refreshAlerts === 'function') {
      refreshAlerts();
    }
  });

  socket.on('disconnect', () => {
    console.warn('[WS] Disconnected');
  });
}

// ── Boot sequence ─────────────────────────────────────────────────────────────
async function boot() {
  await checkHealth();
  await refreshTopbar();

  initWebSockets();

  setInterval(checkHealth, 15000);

  // Notify each tab's init function if defined
  switchTab('overview');
}

document.addEventListener('DOMContentLoaded', boot);
window.REFRESH_INTERVAL = REFRESH_INTERVAL;
