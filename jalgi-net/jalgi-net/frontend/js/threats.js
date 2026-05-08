/**
 * JalgiNet - Correlated Threats Tab (threats.js)
 * Risk-scored multi-stage attack cards with block action.
 */

function buildChainHTML(chain) {
  if (!chain || !chain.length) return '<span style="color:var(--text-muted)">-</span>';
  return chain.map((item, i) =>
    `<span class="chain-item">${item.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>` +
    (i < chain.length - 1 ? '<span class="chain-arrow">></span>' : '')
  ).join('');
}

function buildThreatCard(t) {
  const scoreFixed = parseFloat(t.risk_score).toFixed(1);

  const aiSection = t.ai_summary ? `
    <div class="ai-analysis-box" style="margin-top:15px; padding:12px; background:rgba(0,212,255,0.05); border-radius:8px; border:1px solid rgba(0,212,255,0.2);">
      <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px; color:var(--cyan); font-weight:600; font-size:0.8rem;">
        <i data-lucide="sparkles" style="width:14px; height:14px;"></i> AI SECURITY SUMMARY
      </div>
      <p style="font-size:0.8rem; color:var(--text-primary); margin-bottom:8px;">${t.ai_summary}</p>
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; font-size:0.75rem;">
        <div>
          <div style="color:var(--red); font-weight:600; margin-bottom:2px;">SECURITY IMPACT</div>
          <div style="color:var(--text-secondary)">${t.security_impact || 'N/A'}</div>
        </div>
        <div>
          <div style="color:var(--green); font-weight:600; margin-bottom:2px;">RECOMMENDED ACTIONS</div>
          <div style="color:var(--text-secondary)">${t.recommended_actions || 'N/A'}</div>
        </div>
      </div>
    </div>
  ` : '';

  return `
    <div class="threat-card ${t.severity}">
      <div class="threat-card-header">
        <div>
          <div class="threat-ip">${t.source_ip}</div>
          <span class="severity-badge ${t.severity}" style="margin-top:6px;display:inline-block">${t.severity}</span>
        </div>
        <div class="risk-score-badge ${t.severity}">
          <span class="risk-score-num">${scoreFixed}</span>
          <span class="risk-score-label">RISK / 10</span>
        </div>
      </div>
      <div class="threat-card-body">
        <p class="threat-desc">${t.description}</p>
        <div class="attack-chain">${buildChainHTML(t.attack_chain)}</div>
        <div class="threat-timeline">
          <span><b>First Seen</b>${formatTimestamp(t.first_seen)}</span>
          <span><b>Last Seen</b>${formatTimestamp(t.last_seen)}</span>
          <span><b>Events</b>${(t.event_ids || []).length} linked</span>
        </div>
        ${aiSection}
        <button class="threat-block-btn" onclick="blockThreatIp('${t.source_ip}')">Block ${t.source_ip}</button>
      </div>
    </div>`;
}

async function blockThreatIp(ip) {
  const res = await apiFetch('/api/threats/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason: 'Blocked from Correlated Threats panel' }),
  });
  if (res && res.status === 'ok') {
    showToast('IP Blocked', `${ip} added to block list.`, 'High');
  }
}
window.blockThreatIp = blockThreatIp;

async function refreshThreats() {
  const [threatsData, summaryData] = await Promise.all([
    apiFetch('/api/threats/correlated?limit=50'),
    apiFetch('/api/threats/summary'),
  ]);

  // KPI row
  if (summaryData) {
    const kpiEl = document.getElementById('threatKpis');
    if (kpiEl) {
      kpiEl.innerHTML = `
        <div class="threat-kpi-item">
          <span class="threat-kpi-num" style="color:var(--cyan)">${summaryData.total_threats ?? 0}</span>
          <span class="threat-kpi-label">Total Threats</span>
        </div>
        <div class="threat-kpi-item">
          <span class="threat-kpi-num" style="color:var(--red)">${summaryData.critical_threats ?? 0}</span>
          <span class="threat-kpi-label">Critical</span>
        </div>
        <div class="threat-kpi-item">
          <span class="threat-kpi-num" style="color:var(--yellow)">${(summaryData.avg_risk_score ?? 0).toFixed(1)}</span>
          <span class="threat-kpi-label">Avg Risk Score</span>
        </div>`;
    }
  }

  // Threat cards
  const listEl = document.getElementById('threatList');
  if (!listEl || !threatsData) return;
  const threats = threatsData.threats || [];
  if (!threats.length) {
    listEl.innerHTML = `
      <div class="card" style="padding:30px;text-align:center;color:var(--text-muted)">
        <div style="font-size:2rem;margin-bottom:8px"><i data-lucide="check-circle"></i></div>
        <div>No correlated threats detected yet. Monitoring in progress...</div>
      </div>`;
    return;
  }
  listEl.innerHTML = threats.map(buildThreatCard).join('');
  if (window.lucide) lucide.createIcons();
}

document.addEventListener('DOMContentLoaded', () => {
  refreshThreats();
  setInterval(refreshThreats, window.REFRESH_INTERVAL * 2);
});
