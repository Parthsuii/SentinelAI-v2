/**
 * SentinelAI v3.0 — Popup Logic
 * Fetches scan state from background, renders threat cards,
 * handles user actions (whitelist, re-scan, open dashboard).
 */

document.addEventListener('DOMContentLoaded', async () => {
  const gaugeScore = document.getElementById('gauge-score');
  const gaugeLabel = document.getElementById('gauge-label');
  const gaugeFill = document.getElementById('gauge-fill');
  const recommendation = document.getElementById('risk-recommendation');
  const urlDisplay = document.getElementById('url-display');
  const urlLock = document.getElementById('url-lock');
  const threatsList = document.getElementById('threats-list');
  const threatCount = document.getElementById('threat-count');
  const dataSharingList = document.getElementById('data-sharing-list');
  const dataSharingCount = document.getElementById('data-sharing-count');
  const privacyMonitorList = document.getElementById('privacy-monitor-list');
  const privacyMonitorCount = document.getElementById('privacy-monitor-count');
  const privacyMonitorSummary = document.getElementById('privacy-monitor-summary');
  const agentBars = document.getElementById('agent-bars');
  const hookEventCount = document.getElementById('hook-event-count');
  const btnRescan = document.getElementById('btn-rescan');
  const btnWhitelist = document.getElementById('btn-whitelist');
  const btnDashboard = document.getElementById('btn-dashboard');
  const btnSimulator = document.getElementById('btn-simulator');

  // ── Get current tab ──
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // Show URL
  try {
    const url = new URL(tab.url);
    urlDisplay.textContent = url.hostname + url.pathname;
    urlLock.textContent = url.protocol === 'https:' ? '🔒' : '🔓';
  } catch {
    urlDisplay.textContent = tab.url || 'Unknown';
  }

  // ── Fetch status from background ──
  loadStatus();

  async function loadStatus() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'SENTINEL_GET_STATUS',
        tabId: tab.id
      });

      if (response && response.verdict) {
        renderVerdict(response.verdict, response.privacyMonitor, response.backendAvailable);
        hookEventCount.textContent = `${response.hookEventCount} events`;
      } else {
        gaugeScore.textContent = '--';
        gaugeLabel.textContent = 'SCANNING...';
        gaugeLabel.classList.add('scanning-anim');
        recommendation.textContent = 'Waiting for page analysis...';
        hookEventCount.textContent = `${response?.hookEventCount || 0} events`;
      }
    } catch (err) {
      gaugeScore.textContent = '?';
      gaugeLabel.textContent = 'ERROR';
      recommendation.textContent = 'Could not connect to service worker.';
    }
  }

  function renderVerdict(verdict, privacyMonitor, backendAvailable) {
    const score = Math.round(verdict.compositeScore);
    const level = verdict.level;

    // Update gauge
    gaugeScore.textContent = score;
    const confStr = verdict.confidenceInterval ? ` &plusmn;${verdict.confidenceInterval}` : '';
    gaugeLabel.innerHTML = `${level.toUpperCase()}${confStr}`;
    gaugeLabel.classList.remove('scanning-anim');

    // Animate gauge arc (251.2 is the full arc length)
    const offset = 251.2 - (251.2 * (score / 100));
    gaugeFill.style.strokeDashoffset = offset;

    // Theme
    document.body.className = `level-${level}`;

    // Colors
    const levelColors = {
      safe: '#00e676', low: '#69f0ae', medium: '#ffd740',
      high: '#ff6e40', critical: '#ff1744'
    };
    gaugeScore.setAttribute('fill', levelColors[level] || '#fff');

    // Recommendation
    const sourceLabel = verdict.analysisSource === 'local'
      ? 'Local fallback'
      : verdict.scanMode === 'tier1'
        ? 'Tier 1'
        : verdict.scanMode === 'tier2'
          ? 'Tier 2'
          : 'Backend';
    recommendation.textContent = `${verdict.recommendation || ''}${backendAvailable === false ? ' [backend unavailable]' : ''} [${sourceLabel}]`;

    // Threats
    const threats = verdict.allThreats || [];
    threatCount.textContent = threats.length;
    threatCount.className = 'threat-count' + (threats.length === 0 ? ' safe' : '');

    if (threats.length === 0) {
      threatsList.innerHTML = '<div class="empty-state">✅ No threats detected</div>';
    } else {
      threatsList.innerHTML = threats.slice(0, 8).map(threat => {
        const severity = getSeverity(threat);
        return `
          <div class="threat-card">
            <div class="threat-dot ${severity}"></div>
            <div class="threat-info">
              <div class="threat-type">${escapeHtml(threat.type)}</div>
              <div class="threat-detail">${escapeHtml(threat.detail)}</div>
              <div class="threat-source">via ${escapeHtml(threat.source || 'analysis')}</div>
            </div>
          </div>
        `;
      }).join('');
    }

    // Data sharing destinations
    const dataSharing = verdict.dataSharing || [];
    dataSharingCount.textContent = dataSharing.length;
    dataSharingCount.className = 'threat-count' + (dataSharing.length === 0 ? ' safe' : '');

    if (dataSharing.length === 0) {
      dataSharingList.innerHTML = '<div class="empty-state">No outbound data sharing detected</div>';
    } else {
      dataSharingList.innerHTML = dataSharing.slice(0, 6).map(entry => {
        const dataTypes = (entry.data_types || []).length ? (entry.data_types || []).join(', ') : 'payload observed';
        const shareClass = entry.cross_origin ? 'critical' : entry.first_party_infra ? 'low' : 'medium';
        const directionLabel = entry.cross_origin
          ? 'third-party destination'
          : entry.first_party_infra
            ? 'first-party infrastructure'
            : 'same-site destination';
        const monitorLocations = privacyMonitor?.domain_locations || {};
        const entryLocation = entry.location && typeof entry.location === 'object'
          ? entry.location
          : monitorLocations[entry.destination] || {};
        const location = entryLocation || {};
        const locationLabel = location.country
          ? `${location.city ? `${location.city}, ` : ''}${location.country}`
          : 'Location unknown';
        return `
          <div class="threat-card">
            <div class="threat-dot ${shareClass}"></div>
            <div class="threat-info">
              <div class="threat-type">${escapeHtml(entry.destination || 'Unknown destination')}</div>
              <div class="threat-detail">${escapeHtml(dataTypes)} via ${escapeHtml(entry.via || 'network')}</div>
              <div class="threat-source">${escapeHtml(directionLabel)} · ${escapeHtml(locationLabel)}</div>
            </div>
          </div>
        `;
      }).join('');
    }

    renderPrivacyMonitor(privacyMonitor);

    // Agent breakdown
    if (verdict.agentBreakdown) {
      for (const [agentName, data] of Object.entries(verdict.agentBreakdown)) {
        const bar = agentBars.querySelector(`[data-agent="${agentName}"]`);
        if (bar) {
          const fill = bar.querySelector('.agent-fill');
          const scoreEl = bar.querySelector('.agent-score');
          const rawScore = Number(data.rawScore ?? data.raw_score ?? 0);
          fill.style.width = `${rawScore}%`;
          scoreEl.textContent = rawScore;
          fill.classList.remove('high', 'medium');

          if (rawScore > 60) fill.classList.add('high');
          else if (rawScore > 30) fill.classList.add('medium');
        }
      }
    }
  }

  function renderPrivacyMonitor(privacyMonitor) {
    const destinations = privacyMonitor?.destinations || [];
    const summary = privacyMonitor?.summary || {};
    privacyMonitorCount.textContent = destinations.length;
    privacyMonitorCount.className = 'threat-count' + (destinations.length === 0 ? ' safe' : '');

    if (destinations.length === 0) {
      privacyMonitorSummary.textContent = 'No separate privacy-monitor findings for this page.';
      privacyMonitorList.innerHTML = '<div class="empty-state">No monitor findings yet</div>';
      return;
    }

    privacyMonitorSummary.textContent =
      `Tracing ${destinations.length} route(s). Primary location: ${summary.primary_location || 'Unknown'}. This section is separate from the 7-layer risk score.`;

    privacyMonitorList.innerHTML = destinations.slice(0, 8).map(entry => {
      const destination = entry.destination || 'Unknown destination';
      const tracker = entry.tracker_name || 'Unknown tracker';
      const dataCollected = entry.data_collected || 'unknown data';
      const monitorLocation = (privacyMonitor?.domain_locations || {})[destination] || {};
      const locationParts = [
        monitorLocation.city,
        monitorLocation.country,
        entry.law || monitorLocation.law,
      ].filter(Boolean);
      const location = locationParts.join(' · ') || entry.location || 'Location unknown';
      const blockTip = entry.first_party_infra
        ? 'This appears to be site-owned cloud infrastructure, so it is shown for transparency but not scored as risky by itself.'
        : entry.how_to_block || 'Block via browser privacy settings.';
      return `
        <div class="threat-card">
          <div class="threat-dot medium"></div>
          <div class="threat-info">
            <div class="threat-type">${escapeHtml(destination)}</div>
            <div class="threat-detail">${escapeHtml(tracker)} collects ${escapeHtml(dataCollected)}</div>
            <div class="threat-source">${escapeHtml(location)}</div>
            <div class="threat-detail">${escapeHtml(blockTip)}</div>
          </div>
        </div>
      `;
    }).join('');
  }

  function getSeverity(threat) {
    const high = ['credential-exfil', 'eval-base64', 'overlay-injection', 'brand-impersonation', 'homoglyph'];
    const critical = ['sensitive-data-exfil', 'credential-exfil'];
    const medium = ['phishing-text', 'cross-origin-form', 'eval-usage', 'iframe-injection'];

    if (critical.some(c => threat.type?.includes(c))) return 'critical';
    if (high.some(h => threat.type?.includes(h))) return 'high';
    if (medium.some(m => threat.type?.includes(m))) return 'medium';
    return 'low';
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  // ── Actions ──
  btnRescan.addEventListener('click', async () => {
    btnRescan.disabled = true;
    btnRescan.textContent = 'Scanning...';

    try {
      const signals = await chrome.tabs.sendMessage(tab.id, { type: 'SENTINEL_GET_PAGE_SIGNALS' });
      if (signals) {
        await chrome.runtime.sendMessage({
          type: 'SENTINEL_SCAN_REQUEST',
          payload: signals
        });
      }
    } catch (e) { /* ignore */ }

    setTimeout(() => {
      loadStatus();
      btnRescan.disabled = false;
      btnRescan.innerHTML = `
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="23 4 23 10 17 10"/>
          <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
        </svg>
        Re-Scan
      `;
    }, 1500);
  });

  btnWhitelist.addEventListener('click', async () => {
    try {
      const hostname = new URL(tab.url).hostname;
      await chrome.runtime.sendMessage({
        type: 'SENTINEL_WHITELIST_SITE',
        hostname
      });
      btnWhitelist.textContent = '✓ Whitelisted';
      btnWhitelist.disabled = true;
      setTimeout(loadStatus, 500);
    } catch (e) { /* ignore */ }
  });

  btnDashboard.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
  });

  btnSimulator.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://127.0.0.1:5000' });
  });

  // Auto-refresh every 3s
  setInterval(loadStatus, 3000);
});
