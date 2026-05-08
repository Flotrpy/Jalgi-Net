/**
 * JalgiNet - IDS Events Tab (ids.js)
 * Filterable table of parsed Snort/Suricata events.
 */

let idsAttackFilter = '';
let idsSearchQuery  = '';

function getAttackPillClass(type) {
  const map = {
    'Port Scan': 'port-scan', 'SQL Injection': 'sql',
    'Brute Force': 'brute', 'XSS': 'xss',
    'Remote Code Execution': 'rce', 'Malware C2': 'malware',
    'DNS Exfiltration': 'dns',
  };
  return map[type] || 'default';
}

function buildIdsRow(e, i) {
  const pillClass = getAttackPillClass(e.attack_type);
  return `<tr>
    <td>${e.id}</td>
    <td>${formatTimestamp(e.timestamp)}</td>
    <td><span class="attack-pill ${pillClass}">${e.attack_type}</span></td>
    <td class="ip-cell">${e.source_ip}</td>
    <td class="ip-cell">${e.dest_ip || '-'}:${e.dest_port || '-'}</td>
    <td class="rule-cell">${e.rule_id || '-'}</td>
    <td class="msg-cell" title="${e.rule_msg}">${e.rule_msg || '-'}</td>
    <td><span class="severity-badge ${e.severity}">${e.severity}</span></td>
  </tr>`;
}

async function loadAttackTypeFilters() {
  const data = await apiFetch('/api/ids/attack-types');
  if (!data || !data.attack_types) return;
  const container = document.getElementById('attackTypeFilters');
  if (!container) return;
  const extra = data.attack_types.map(t =>
    `<button class="filter-btn" data-attack="${t.attack_type}">${t.attack_type} <span style="opacity:.6">(${t.count})</span></button>`
  ).join('');
  container.innerHTML = `<button class="filter-btn active" data-attack="">All Types</button>${extra}`;
  container.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      idsAttackFilter = btn.dataset.attack;
      refreshIds();
    });
  });
}

async function refreshIds() {
  const params = new URLSearchParams({ limit: 100 });
  if (idsAttackFilter) params.set('attack_type', idsAttackFilter);
  const data = await apiFetch(`/api/ids/events?${params}`);
  if (!data || !data.events) return;

  let events = data.events;
  if (idsSearchQuery) {
    const q = idsSearchQuery.toLowerCase();
    events = events.filter(e =>
      e.source_ip.includes(q) ||
      e.attack_type.toLowerCase().includes(q) ||
      (e.rule_msg || '').toLowerCase().includes(q)
    );
  }

  const tbody = document.getElementById('idsTableBody');
  const count = document.getElementById('idsEventCount');
  if (tbody) tbody.innerHTML = events.length
    ? events.map(buildIdsRow).join('')
    : '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:20px;">No IDS events found.</td></tr>';
  if (count) count.textContent = `${events.length} events`;
}

document.addEventListener('DOMContentLoaded', () => {
  loadAttackTypeFilters();
  refreshIds();
  setInterval(refreshIds, window.REFRESH_INTERVAL);
  setInterval(loadAttackTypeFilters, 15000);

  const searchEl = document.getElementById('idsSearch');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      idsSearchQuery = searchEl.value.trim();
      refreshIds();
    });
  }
});
