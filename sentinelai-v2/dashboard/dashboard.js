/**
 * SentinelAI v2.0 — Dashboard Logic
 * Reads scan history from backend, renders stats, activity feed, agent info.
 */

document.addEventListener('DOMContentLoaded', () => {
  const BACKEND_URL = 'http://127.0.0.1:8000';

  // ── Tab Navigation ──
  const navItems = document.querySelectorAll('.nav-item');
  const tabContents = document.querySelectorAll('.tab-content');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tab = item.dataset.tab;
      navItems.forEach(n => n.classList.remove('active'));
      tabContents.forEach(t => t.classList.remove('active'));
      item.classList.add('active');
      document.getElementById(`tab-${tab}`).classList.add('active');

      if (tab === 'history') loadHistory();
      if (tab === 'settings') loadSettings();
    });
  });

  // ── Load Overview Stats ──
  async function loadOverview() {
    try {
      const resp = await fetch(`${BACKEND_URL}/history?limit=100`);
      const data = await resp.json();
      const history = data.history || [];

      const safe = history.filter(h => h.level === 'safe' || h.level === 'low').length;
      const threats = history.reduce((sum, h) => sum + (h.threat_count || 0), 0);
      const blocked = history.filter(h => h.level === 'critical' || h.level === 'high').length;

      document.getElementById('stat-safe').textContent = safe;
      document.getElementById('stat-threats').textContent = threats;
      document.getElementById('stat-scans').textContent = history.length;
      document.getElementById('stat-blocked').textContent = blocked;

      // ── Recent scans ──
      const recentList = document.getElementById('recent-scans');
      if (history.length === 0) {
        recentList.innerHTML = '<div class="empty-state-lg">No scans recorded yet. Browse websites with SentinelAI active.</div>';
        return;
      }

      // ── Location Context Integration ──
      const latestScan = history[0];
      const locContainer = document.getElementById('current-location-context');
      if (latestScan && latestScan.location_info && locContainer) {
        const loc = latestScan.location_info;
        const ratingClass = (loc.law_rating || 'unknown').toLowerCase();
        locContainer.innerHTML = `
          <div class="badge-loc">
            <span>📍 Server: ${loc.city || 'Unknown'}, ${loc.country || 'Unknown'} ${loc.flag || '🌐'}</span>
          </div>
          <div class="badge-loc ${ratingClass}">
            <span>⚖️ Jurisdiction: ${loc.law || 'Unknown Privacy Law'} (${loc.law_rating || 'Unknown'})</span>
          </div>
          <div class="badge-loc info">
            <span>🏢 Org: ${loc.org || 'Unknown Provider'}</span>
          </div>
        `;
      } else if (locContainer) {
        locContainer.innerHTML = '';
      }

      recentList.innerHTML = history.slice(0, 20).map(scan => `
        <div class="activity-item">
          <div class="activity-level ${scan.level}"></div>
          <div class="activity-info">
            <div class="activity-url">${escapeHtml(scan.hostname || scan.url)}</div>
            <div class="activity-meta">${formatTime(scan.timestamp)} · ${scan.threat_count || 0} threats</div>
          </div>
          <div class="activity-score" style="color: ${getLevelColor(scan.level)}">${Math.round(scan.score)}</div>
        </div>
      `).join('');
    } catch(err) {
      document.getElementById('recent-scans').innerHTML = 
        '<div class="empty-state-lg">⚠️ Backend not available. Start the API with: uvicorn backend.main:app</div>';
    }
  }

  // ── Load History Table ──
  async function loadHistory() {
    try {
      const resp = await fetch(`${BACKEND_URL}/history?limit=100`);
      const data = await resp.json();
      const history = data.history || [];

      const tbody = document.getElementById('history-tbody');
      if (history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state-lg">No scan history</td></tr>';
        return;
      }

      tbody.innerHTML = history.map(scan => `
        <tr>
          <td>${formatTime(scan.timestamp)}</td>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(scan.url)}</td>
          <td style="color:${getLevelColor(scan.level)};font-weight:600">${Math.round(scan.score)}</td>
          <td><span class="level-badge ${scan.level}">${scan.level}</span></td>
          <td>${scan.threat_count || 0}</td>
        </tr>
      `).join('');
    } catch(err) {
      document.getElementById('history-tbody').innerHTML = 
        '<tr><td colspan="5" class="empty-state-lg">Backend not available</td></tr>';
    }
  }

  // ── Load Settings ──
  async function loadSettings() {
    try {
      const resp = await fetch(`${BACKEND_URL}/whitelist`);
      const data = await resp.json();
      const whitelist = data.whitelist || [];

      const display = document.getElementById('whitelist-display');
      if (whitelist.length === 0) {
        display.innerHTML = '<div class="empty-state-lg">No whitelisted sites</div>';
      } else {
        display.innerHTML = whitelist.map(h => `
          <div class="activity-item">
            <div class="activity-level safe"></div>
            <div class="activity-info">
              <div class="activity-url">${escapeHtml(h)}</div>
            </div>
          </div>
        `).join('');
      }
    } catch(err) {
      // silently fail
    }
  }

  // ── Buttons ──
  document.getElementById('btn-clear-history')?.addEventListener('click', async () => {
    try {
      await fetch(`${BACKEND_URL}/history`, { method: 'DELETE' });
      loadOverview();
    } catch(e) { /* ignore */ }
  });

  document.getElementById('btn-clear-whitelist')?.addEventListener('click', async () => {
    // Would need individual delete calls, simplified here
    loadSettings();
  });

  // ── Helpers ──
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  function formatTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return d.toLocaleString('en-US', { 
      month: 'short', day: 'numeric', 
      hour: '2-digit', minute: '2-digit' 
    });
  }

  function getLevelColor(level) {
    const colors = {
      safe: '#00e676', low: '#69f0ae', medium: '#ffd740',
      high: '#ff6e40', critical: '#ff1744'
    };
    return colors[level] || '#999';
  }

  // ── Init ──
  loadOverview();
  setInterval(loadOverview, 10000); // Refresh every 10s
});
