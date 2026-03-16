/**
 * SentinelAI v2.0 — Master Content Script
 * Injected at document_start. Collects events from all 12 hooks,
 * batches them, and relays to the background service worker.
 */
(function() {
  'use strict';
  if (window.__sentinel_content_ready) return;
  window.__sentinel_content_ready = true;

  const MODULE = 'ContentScript';
  const eventBuffer = [];
  let flushTimer = null;
  const FLUSH_INTERVAL = 300; // 300ms privacy window

  // ── Listen for hook events ──
  window.addEventListener('__sentinel_hook', function(e) {
    const event = e.detail;
    if (!event || !event.hook) return;

    event.url = window.location.href;
    event.origin = window.location.origin;
    event.hostname = window.location.hostname;

    eventBuffer.push(event);

    // Debounced flush
    if (!flushTimer) {
      flushTimer = setTimeout(flushEvents, FLUSH_INTERVAL);
    }
  });

  function flushEvents() {
    flushTimer = null;
    if (eventBuffer.length === 0) return;

    const batch = eventBuffer.splice(0, eventBuffer.length);

    // Send to background service worker
    try {
      chrome.runtime.sendMessage({
        type: 'SENTINEL_HOOK_EVENT',
        payload: {
          url: window.location.href,
          origin: window.location.origin,
          hostname: window.location.hostname,
          title: document.title,
          events: batch,
          timestamp: Date.now()
        }
      }).catch(() => {
        // Extension context may be invalidated
      });
    } catch(e) {
      // Silently fail if extension context is invalid
    }
  }

  // ── Page Content Analysis (for Content Agent) ──
  function extractPageSignals() {
    const signals = {
      title: document.title,
      url: window.location.href,
      hostname: window.location.hostname,
      protocol: window.location.protocol,
      forms: [],
      links: [],
      scripts: [],
      meta: {}
    };

    // Extract forms
    document.querySelectorAll('form').forEach(form => {
      const inputs = form.querySelectorAll('input');
      const types = Array.from(inputs).map(i => i.type || 'text');
      signals.forms.push({
        action: form.action,
        method: form.method,
        hasPassword: types.includes('password'),
        hasEmail: types.includes('email'),
        fieldCount: inputs.length
      });
    });

    // Count external links
    const extLinks = Array.from(document.querySelectorAll('a[href]'))
      .filter(a => {
        try { return new URL(a.href).origin !== window.location.origin; }
        catch { return false; }
      });
    signals.externalLinkCount = extLinks.length;

    // Count scripts
    signals.scriptCount = document.querySelectorAll('script').length;
    signals.inlineScriptCount = document.querySelectorAll('script:not([src])').length;

    // Extract meta tags
    document.querySelectorAll('meta').forEach(meta => {
      const name = meta.getAttribute('name') || meta.getAttribute('property');
      if (name) signals.meta[name] = meta.content;
    });

    // Check for suspicious text patterns
    const bodyText = (document.body?.innerText || '').substring(0, 5000);
    signals.bodyTextPreview = bodyText.substring(0, 1000);

    return signals;
  }

  // ── Handle requests from popup/background ──
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'SENTINEL_GET_PAGE_SIGNALS') {
      sendResponse(extractPageSignals());
      return true;
    }
    if (msg.type === 'SENTINEL_SANDBOX_EXEC') {
      if (window.__sentinel_sandboxExec) {
        window.__sentinel_sandboxExec(msg.code).then(results => {
          sendResponse({ results });
        });
        return true; // async
      }
    }
    if (msg.type === 'SENTINEL_SHOW_OVERLAY') {
      showSentinelOverlay(msg.verdict);
      sendResponse({ ok: true });
    }
  });

  // ── Shadow DOM Overlay UI (Layer 01 Architecture) ──
  function showSentinelOverlay(verdict) {
    if (document.getElementById('sentinel-overlay-container')) return;
    
    const container = document.createElement('div');
    container.id = 'sentinel-overlay-container';
    
    // Position at root to avoid z-index stacking context issues
    Object.assign(container.style, {
      position: 'fixed', top: '0', left: '0', width: '100%', height: '100%',
      zIndex: '2147483647', pointerEvents: 'none'
    });
    
    const shadow = container.attachShadow({ mode: 'closed' });
    
    const isBlock = verdict.level === 'critical' || verdict.level === 'high';
    const bgColor = isBlock ? 'rgba(20, 0, 0, 0.95)' : 'rgba(255, 170, 0, 0.9)';
    const textColor = isBlock ? '#ff5252' : '#ffffff';
    const dataSharing = verdict.dataSharing || verdict.data_sharing || [];
    const destinations = dataSharing
      .filter(entry => entry.destination)
      .map(entry => entry.destination)
      .slice(0, 3)
      .join(', ');
    
    shadow.innerHTML = `
      <style>
        .sentinel-overlay {
          position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
          background: ${bgColor}; color: #fff; font-family: system-ui, -apple-system, sans-serif;
          display: flex; flex-direction: column; align-items: center; justify-content: center;
          z-index: 2147483647; pointer-events: auto; backdrop-filter: blur(8px);
        }
        .sentinel-card {
          background: #1e1e1e; padding: 40px; border-radius: 12px;
          border: 2px solid ${textColor}; max-width: 500px; text-align: center;
          box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        h1 { margin: 0 0 16px 0; font-size: 28px; color: ${textColor}; }
        p { margin: 0 0 24px 0; line-height: 1.5; color: #ccc; font-size: 16px; }
        .details { background: #000; padding: 16px; border-radius: 6px; text-align: left; font-size: 14px; margin-bottom: 24px; color: #aaa; border-left: 4px solid ${textColor}; }
        button {
          background: ${textColor}; color: #000; border: none; padding: 12px 24px;
          border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 16px;
        }
        button.secondary { background: transparent; color: #aaa; border: 1px solid #555; margin-left: 12px; }
      </style>
      <div class="sentinel-overlay">
        <div class="sentinel-card">
          <h1>🛡️ ${isBlock ? 'Access Blocked' : 'Security Warning'}</h1>
          <p>${verdict.recommendation || 'SentinelAI has detected significant risk factors on this page.'}</p>
          <div class="details">
            <strong>Risk Score:</strong> ${verdict.compositeScore || verdict.composite_score}${verdict.confidenceInterval ? ` &plusmn; ${verdict.confidenceInterval}` : ''}/100<br>
            <strong>Top Threat:</strong> ${verdict.allThreats?.[0]?.detail || verdict.all_threats?.[0]?.detail || 'Unknown'}<br>
            <strong>Data Sharing:</strong> ${destinations || 'No outbound destination captured'}
          </div>
          <button id="btn-goback">Go Back to Safety</button>
          ${isBlock ? '' : '<button id="btn-proceed" class="secondary">Proceed Anyway</button>'}
        </div>
      </div>
    `;
    
    shadow.getElementById('btn-goback').addEventListener('click', () => history.back() || window.close());
    const proceedBtn = shadow.getElementById('btn-proceed');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => container.remove());
    }
    
    document.documentElement.appendChild(container);
    if (isBlock) {
      // Prevent scrolling
      document.body.style.overflow = 'hidden';
    }
  }

  // ── Inline Risk Badges (v3 Feature) ──
  let hoveredLink = null;
  let riskBadge = null;

  document.addEventListener('mouseover', (e) => {
    const link = e.target.closest('a');
    if (link && link.href && link !== hoveredLink) {
      hoveredLink = link;
      let urlObj;
      try { urlObj = new URL(link.href); } catch(err) { return; }
      if (urlObj.origin === window.location.origin || (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:')) return;
      
      showInlineBadge(e.clientX, e.clientY, link.href);
    } else if (!link && riskBadge && e.target !== riskBadge && !riskBadge.contains(e.target)) {
      riskBadge.style.opacity = '0';
      setTimeout(() => { if (riskBadge && riskBadge.parentNode) riskBadge.remove(); riskBadge = null; }, 200);
      hoveredLink = null;
    }
  });

  function showInlineBadge(x, y, url) {
    if (riskBadge) riskBadge.remove();
    riskBadge = document.createElement('div');
    Object.assign(riskBadge.style, {
      position: 'fixed', left: `${x + 15}px`, top: `${y + 15}px`, zIndex: '2147483647',
      background: '#222', color: '#fff', padding: '6px 10px', borderRadius: '6px',
      fontSize: '12px', fontFamily: 'system-ui, sans-serif', opacity: '0', transition: 'opacity 0.2s',
      pointerEvents: 'none', border: '1px solid #444', boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
      display: 'flex', alignItems: 'center', gap: '6px', fontWeight: '500'
    });
    riskBadge.innerHTML = '<span class="spin">⏳</span> Scanning...';
    document.documentElement.appendChild(riskBadge);
    
    requestAnimationFrame(() => riskBadge.style.opacity = '1');

    try {
      chrome.runtime.sendMessage({
        type: 'SENTINEL_SCAN_URL_LIGHT',
        payload: { url }
      }, (response) => {
        if (!riskBadge || !document.contains(riskBadge)) return;
        if (response && response.verdict) {
          const v = response.verdict;
          const confStr = v.confidenceInterval ? ` &plusmn; ${v.confidenceInterval}` : '';
          const icon = v.level === 'critical' || v.level === 'high' ? '🚨' : v.level === 'medium' ? '⚠️' : '✅';
          const color = v.level === 'critical' ? '#ff1744' : v.level === 'high' ? '#ff6e40' : v.level === 'medium' ? '#ffd740' : '#00e676';
          
          riskBadge.innerHTML = `<span>${icon}</span> <span>Risk: ${Math.round(v.compositeScore)}${confStr}</span>`;
          riskBadge.style.borderLeft = `3px solid ${color}`;
        } else {
          riskBadge.innerHTML = '<span>❓</span> Unknown';
        }
      });
    } catch(e) {}
  }

  // ── Initial page scan ──
  function onPageReady() {
    // Flush any pending hook events
    flushEvents();

    // Send page signals for initial analysis
    const signals = extractPageSignals();
    try {
      chrome.runtime.sendMessage({
        type: 'SENTINEL_SCAN_REQUEST',
        payload: signals
      }).catch(() => {});
    } catch(e) { /* ignore */ }
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(onPageReady, 100);
  } else {
    document.addEventListener('DOMContentLoaded', () => setTimeout(onPageReady, 100), { once: true });
  }

  // Console announcement
  console.info(
    '%c🛡️ SentinelAI v2.0 Active Runtime Intelligence — 12 hooks loaded',
    'color:#00e5ff;font-weight:bold;font-size:13px'
  );
})();
