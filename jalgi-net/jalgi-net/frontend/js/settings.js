/**
 * JalgiNet – Settings Tab (settings.js)
 * Threshold sliders, module toggles, blocked IPs, log management, export.
 */

// ── Load current settings from API ───────────────────────────────────────────
async function loadSettings() {
  const data = await apiFetch('/api/settings');
  if (!data || !data.settings) return;
  const s = data.settings;

  // DoS thresholds
  if (s.dos_thresholds) {
    setVal('s-window', s.dos_thresholds.window_seconds);
    setVal('s-low',    s.dos_thresholds.Low);
    setVal('s-medium', s.dos_thresholds.Medium);
    setVal('s-high',   s.dos_thresholds.High);
    setVal('s-critical',s.dos_thresholds.Critical);
    setVal('s-syn',    s.dos_thresholds.syn_flood_ratio);
  }

  // Module toggles
  if (s.modules) {
    setCheck('m-dos',   s.modules.dos_detection);
    setCheck('m-ids',   s.modules.ids_integration);
    setCheck('m-corr',  s.modules.correlation);
    setCheck('m-geo',   s.modules.geo_ip);
    setCheck('m-block', s.auto_block && s.auto_block.enabled);
  }

  // Correlation window
  if (s.correlation_window) setVal('s-corrWindow', s.correlation_window);

  // Simulation mode
  if (s.simulation_mode !== undefined) setCheck('s-simMode', s.simulation_mode);

  // Capture status badge
  const badge = document.getElementById('captureStatusBadge');
  if (badge && s.capture_status) {
    badge.textContent = s.capture_status.toUpperCase();
    if (s.capture_status.startsWith('Live')) {
      badge.className = 'health-badge green';
    } else if (s.capture_status.startsWith('Failed')) {
      badge.className = 'health-badge red';
    } else {
      badge.className = 'health-badge blue';
    }
  }
}

function setVal(id, v) { const el = document.getElementById(id); if (el) el.value = v; }
function setCheck(id, v) { const el = document.getElementById(id); if (el) el.checked = !!v; }
function getVal(id) { const el = document.getElementById(id); return el ? parseFloat(el.value) : null; }
function getCheck(id) { const el = document.getElementById(id); return el ? el.checked : false; }

// ── Save settings ─────────────────────────────────────────────────────────────
async function saveSettings() {
  const payload = {
    dos_thresholds: {
      window_seconds:  getVal('s-window'),
      Low:             getVal('s-low'),
      Medium:          getVal('s-medium'),
      High:            getVal('s-high'),
      Critical:        getVal('s-critical'),
      syn_flood_ratio: getVal('s-syn'),
    },
    modules: {
      dos_detection:   getCheck('m-dos'),
      ids_integration: getCheck('m-ids'),
      correlation:     getCheck('m-corr'),
      geo_ip:          getCheck('m-geo'),
    },
    auto_block: { enabled: getCheck('m-block') },
    correlation_window: getVal('s-corrWindow'),
    simulation_mode:    getCheck('s-simMode'),
  };

  const res = await apiFetch('/api/settings', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  });

  const msgEl = document.getElementById('settingsSaveMsg');
  if (res && res.status === 'ok') {
    showToast('Settings Saved', 'All thresholds and module toggles updated.', 'success');
    if (msgEl) { msgEl.textContent = '✓ Saved successfully'; msgEl.style.color = 'var(--green)'; }
  } else {
    if (msgEl) { msgEl.textContent = '✗ Save failed – check API'; msgEl.style.color = 'var(--red)'; }
  }
  setTimeout(() => { if (msgEl) msgEl.textContent = ''; }, 4000);
}

// ── Block / Unblock IPs ───────────────────────────────────────────────────────
async function loadBlockedIps() {
  const data = await apiFetch('/api/threats/blocked-ips');
  const container = document.getElementById('blockedIpsList');
  if (!container) return;
  const ips = data && data.blocked_ips ? data.blocked_ips : [];
  if (!ips.length) {
    container.innerHTML = '<p class="muted">No IPs currently blocked.</p>';
    return;
  }
  container.innerHTML = ips.map(entry => `
    <div class="blocked-ip-row">
      <span class="blocked-ip-addr">⛔ ${entry.ip}</span>
      <span style="color:var(--text-muted);font-size:0.7rem">${entry.reason || ''}</span>
      <button class="unblock-btn" onclick="unblockIp('${entry.ip}')">Unblock</button>
    </div>`).join('');
}

async function unblockIp(ip) {
  await apiFetch('/api/threats/unblock', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ ip }),
  });
  showToast('IP Unblocked', `${ip} removed from block list.`, 'success');
  loadBlockedIps();
}
window.unblockIp = unblockIp;

// ── Clear logs ────────────────────────────────────────────────────────────────
async function clearLogs() {
  if (!confirm('⚠️ This will permanently delete ALL alerts, traffic logs, IDS events and correlated threats. Continue?')) return;
  const res = await apiFetch('/api/logs/clear', { method: 'DELETE' });
  if (res && res.status === 'ok') {
    showToast('Logs Cleared', 'All data has been wiped from the database.', 'High');
  }
}

// ── Export JSON ───────────────────────────────────────────────────────────────
async function exportJson() {
  const data = await apiFetch('/api/export/json');
  if (!data) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `jalgi-net-export-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Export Ready', 'JSON report downloaded successfully.', 'success');
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadBlockedIps();
  setInterval(loadBlockedIps, 10000);

  document.getElementById('saveSettingsBtn')?.addEventListener('click', saveSettings);
  document.getElementById('clearLogsBtn')?.addEventListener('click',  clearLogs);
  document.getElementById('exportJsonBtn')?.addEventListener('click',  exportJson);

  document.getElementById('blockIpBtn')?.addEventListener('click', async () => {
    const ip = document.getElementById('blockIpInput')?.value?.trim();
    if (!ip) return;
    await apiFetch('/api/threats/block', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ip, reason: 'Manual block via Settings' }),
    });
    document.getElementById('blockIpInput').value = '';
    showToast('IP Blocked', `${ip} added to block list.`, 'High');
    loadBlockedIps();
  });
});
