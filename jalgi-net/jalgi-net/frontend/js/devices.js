/**
 * JalgiNet - Devices Tab (devices.js)
 * Provides a detailed security profile for each unique IP address.
 */

async function refreshDevices() {
  console.log('[Devices] Refreshing...');
  try {
    const [topIpsData, threatsData] = await Promise.all([
      apiFetch('/api/traffic/top-ips'),
      apiFetch('/api/threats/correlated?limit=100'),
    ]);

    const devicesListEl = document.getElementById('devicesList');
    if (!devicesListEl) return;

    const topIps = Array.isArray(topIpsData) ? topIpsData : [];
    const threats = (threatsData && Array.isArray(threatsData.threats)) ? threatsData.threats : [];

    // Create a map of IP -> Device Data
    const deviceMap = new Map();

    // Initialize with traffic data
    topIps.forEach(item => {
      deviceMap.set(item.source_ip, {
        ip: item.source_ip,
        packetCount: item.packet_count,
        threat: null
      });
    });

    // Merge with threat data
    threats.forEach(t => {
      if (deviceMap.has(t.source_ip)) {
        deviceMap.get(t.source_ip).threat = t;
      } else {
        deviceMap.set(t.source_ip, {
          ip: t.source_ip,
          packetCount: 0,
          threat: t
        });
      }
    });

    const devices = Array.from(deviceMap.values()).sort((a, b) => {
      const scoreA = a.threat ? a.threat.risk_score : 0;
      const scoreB = b.threat ? b.threat.risk_score : 0;
      return scoreB - scoreA;
    });

    if (devices.length === 0) {
      devicesListEl.innerHTML = '<div class="card" style="padding:20px; text-align:center; color:var(--text-muted);">No devices detected yet.</div>';
      return;
    }

    devicesListEl.innerHTML = devices.map(d => buildDeviceCard(d)).join('');
    if (window.lucide) lucide.createIcons();
  } catch (e) {
    console.error('[Devices] Error refreshing:', e);
  }
}

function getSeverityColor(sev) {
  const colors = {
    'Critical': 'var(--red)',
    'High': 'var(--orange)',
    'Medium': 'var(--yellow)',
    'Low': 'var(--green)'
  };
  return colors[sev] || 'var(--cyan)';
}

function buildDeviceCard(d) {
  const t = d.threat;
  const severity = t ? t.severity : 'Low';
  const riskScore = t ? t.risk_score.toFixed(1) : '0.0';
  const borderColor = getSeverityColor(severity);

  const aiSummary = (t && t.ai_summary) ? `
    <div style="margin-top:10px; font-size:0.75rem; color:var(--text-secondary); background:rgba(0,212,255,0.05); padding:8px; border-radius:4px; border: 1px solid rgba(0,212,255,0.1);">
      <b style="color:var(--cyan)">AI Profile:</b> ${t.ai_summary}
    </div>
  ` : '';

  return `
    <div class="card" style="margin-bottom:12px; padding:15px; border-left: 4px solid ${borderColor}; background:var(--bg-card-alt);">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:12px;">
          <div style="width:40px; height:40px; background:var(--bg-base); border-radius:8px; display:flex; align-items:center; justify-content:center; color:var(--cyan); border: 1px solid var(--border);">
            <i data-lucide="server" style="width:20px; height:20px;"></i>
          </div>
          <div>
            <div style="font-family:var(--font-mono); font-weight:700; color:var(--text-primary); font-size:1rem;">${d.ip}</div>
            <div style="font-size:0.75rem; color:var(--text-muted);">${d.packetCount} packets detected</div>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:0.6rem; color:var(--text-muted); font-weight:600; margin-bottom:4px; letter-spacing:0.05em;">SECURITY STATUS</div>
          <span class="severity-badge ${severity}">${severity}</span>
          <div style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-muted); margin-top:4px;">Risk: ${riskScore}/10</div>
        </div>
      </div>
      ${aiSummary}
    </div>
  `;
}

document.addEventListener('DOMContentLoaded', () => {
  refreshDevices();
  // Listen for tab switches to refresh devices
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      if (item.dataset.tab === 'devices') {
        refreshDevices();
      }
    });
  });

  setInterval(() => {
    if (window.JalgiNet.currentTab === 'devices') {
      refreshDevices();
    }
  }, window.REFRESH_INTERVAL * 2);
});
