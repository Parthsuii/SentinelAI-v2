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
  const PAGE_HOOK_FILES = [
    'content/hooks/fetch-hook.js',
    'content/hooks/xhr-hook.js',
    'content/hooks/eval-hook.js',
    'content/hooks/dom-write-hook.js',
    'content/hooks/mutation-hook.js',
    'content/hooks/beacon-hook.js',
    'content/hooks/websocket-hook.js',
    'content/hooks/postmessage-hook.js',
    'content/hooks/form-hook.js',
    'content/hooks/clipboard-hook.js',
    'content/hooks/canvas-hook.js',
    'content/hooks/timer-hook.js',
    'content/hooks/cookie-hook.js',
    'content/hooks/storage-hook.js',
    'content/hooks/permission-hook.js',
    'content/hooks/css-clickjack-hook.js',
    'content/hooks/serviceworker-hook.js',
    'content/hooks/credentials-hook.js'
  ];
  const eventBuffer = [];
  let flushTimer = null;
  const FLUSH_INTERVAL = 300; // 300ms privacy window

  if (shouldInjectIntoPage()) {
    injectPageHooks();
  }

  function shouldInjectIntoPage() {
    const protocol = window.location.protocol || '';
    return protocol === 'http:' || protocol === 'https:';
  }

  function injectPageHooks() {
    const parent = document.documentElement || document.head || document.body;
    if (!parent) return;

    for (const file of PAGE_HOOK_FILES) {
      const marker = `data-sentinel-injected-${file.replace(/[^a-z0-9]/gi, '-')}`;
      if (document.documentElement?.hasAttribute(marker)) continue;

      const script = document.createElement('script');
      script.src = chrome.runtime.getURL(file);
      script.async = false;
      script.dataset.sentinelInjected = file;
      script.onload = () => script.remove();
      script.onerror = () => {
        console.warn(`[SentinelAI] Failed to inject ${file}`);
        script.remove();
      };
      parent.prepend(script);

      document.documentElement?.setAttribute(marker, '1');
    }
  }

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
      let actionOrigin = '';
      try {
        actionOrigin = form.action ? new URL(form.action, window.location.href).origin : window.location.origin;
      } catch {
        actionOrigin = '';
      }
      signals.forms.push({
        action: form.action,
        actionOrigin,
        method: form.method,
        hasPassword: types.includes('password'),
        hasEmail: types.includes('email'),
        fieldCount: inputs.length
      });
    });

    // External links + link destinations
    const extLinks = Array.from(document.querySelectorAll('a[href]'))
      .filter(a => {
        try { return new URL(a.href).origin !== window.location.origin; }
        catch { return false; }
      });
    signals.links = extLinks.slice(0, 50).map((a) => {
      try {
        const url = new URL(a.href);
        return { href: url.href, origin: url.origin, hostname: url.hostname };
      } catch {
        return null;
      }
    }).filter(Boolean);
    signals.externalLinkCount = extLinks.length;

    // Scripts
    const scriptEls = Array.from(document.querySelectorAll('script'));
    signals.scriptCount = scriptEls.length;
    signals.inlineScriptCount = document.querySelectorAll('script:not([src])').length;
    signals.scripts = scriptEls.slice(0, 50).map((script) => {
      if (!script.src) {
        return { inline: true };
      }
      try {
        const url = new URL(script.src, window.location.href);
        return { src: url.href, origin: url.origin, hostname: url.hostname, inline: false };
      } catch {
        return { src: script.src, inline: false };
      }
    });

    // Iframes
    signals.iframes = Array.from(document.querySelectorAll('iframe[src]')).slice(0, 20).map((frame) => {
      try {
        const url = new URL(frame.src, window.location.href);
        return { src: url.href, origin: url.origin, hostname: url.hostname };
      } catch {
        return { src: frame.src };
      }
    });

    // Extract meta tags
    document.querySelectorAll('meta').forEach(meta => {
      const name = meta.getAttribute('name') || meta.getAttribute('property');
      if (name) signals.meta[name] = meta.content;
    });

    // Check for suspicious text patterns
    const bodyText = (document.body?.innerText || '').substring(0, 5000);
    signals.bodyTextPreview = bodyText.substring(0, 1000);

    // Aggregate outbound domains for monitor/campaign analysis
    const outboundDomains = new Set();
    for (const item of signals.links) {
      if (item.origin && item.origin !== window.location.origin) outboundDomains.add(item.hostname);
    }
    for (const item of signals.scripts) {
      if (item.origin && item.origin !== window.location.origin) outboundDomains.add(item.hostname);
    }
    for (const item of signals.iframes) {
      if (item.origin && item.origin !== window.location.origin) outboundDomains.add(item.hostname);
    }
    for (const form of signals.forms) {
      if (form.actionOrigin && form.actionOrigin !== window.location.origin) {
        try {
          outboundDomains.add(new URL(form.action, window.location.href).hostname);
        } catch {}
      }
    }
    signals.outboundDomains = Array.from(outboundDomains).slice(0, 50);

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
    
    const isBlock = verdict.action === 'block' || verdict.level === 'critical' || verdict.level === 'high';
    const textColor = isBlock ? '#ff3333' : '#ffb74d';
    const dataSharing = verdict.data_sharing || verdict.dataSharing || [];
    const destinations = [...new Set(dataSharing
      .filter(entry => entry.destination)
      .map(entry => entry.destination))]
      .slice(0, 3)
      .join(', ');
    
    // Format top threats
    const threatsList = verdict.all_threats || verdict.allThreats || [];
    const topThreat = threatsList[0]?.detail || threatsList[0]?.type || 'Heuristic Anomaly';
    
    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
        }
        .sentinel-overlay {
          position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
          background: rgba(8, 8, 12, 0.4); 
          display: flex; align-items: center; justify-content: center;
          z-index: 2147483647; pointer-events: auto; 
          backdrop-filter: blur(12px) saturate(180%);
          -webkit-backdrop-filter: blur(12px) saturate(180%);
          font-family: 'Outfit', system-ui, -apple-system, sans-serif;
          animation: fadeIn 0.4s ease-out;
        }
        .sentinel-card {
          background: rgba(30, 30, 35, 0.7);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          padding: 45px; border-radius: 24px;
          border: 1px solid rgba(255, 255, 255, 0.1); 
          max-width: 520px; width: 90%; text-align: center;
          box-shadow: 0 40px 100px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05);
          position: relative;
        }
        .sentinel-card::before {
          content: ''; position: absolute; top: 0; left: 0; right: 0; height: 6px;
          background: ${textColor}; border-radius: 24px 24px 0 0;
        }
        h1 { margin: 0 0 12px 0; font-size: 32px; color: ${textColor}; font-weight: 700; letter-spacing: -0.5px; }
        p { margin: 0 0 28px 0; line-height: 1.6; color: #ccd0d5; font-size: 17px; font-weight: 300; }
        .details-grid {
          background: rgba(0, 0, 0, 0.3);
          padding: 20px; border-radius: 16px;
          text-align: left; font-size: 14px; margin-bottom: 32px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          display: flex; flex-direction: column; gap: 12px;
        }
        .detail-row { display: flex; justify-content: space-between; align-items: baseline; }
        .detail-label { color: #8a8d91; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        .detail-value { color: #fff; font-weight: 500; text-align: right; word-break: break-all; max-width: 60%; }
        
        .actions { display: flex; gap: 12px; justify-content: center; }
        button {
          padding: 14px 28px; border-radius: 12px; font-weight: 600;
          cursor: pointer; font-size: 16px; transition: all 0.2s; border: none;
        }
        #btn-goback {
          background: #fff; color: #000;
        }
        #btn-goback:hover { transform: translateY(-2px); background: #eee; }
        #btn-proceed {
          background: transparent; color: #aaa; border: 1px solid rgba(255,255,255,0.1);
        }
        #btn-proceed:hover { color: #fff; border-color: #fff; background: rgba(255,255,255,0.05); }

        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
      </style>
      <div class="sentinel-overlay">
        <div class="sentinel-card">
          <h1>🛡️ ${isBlock ? 'Access Blocked' : 'Security Warning'}</h1>
          <p>${verdict.recommendation || 'SentinelAI has detected significant risk factors on this page.'}</p>
          <div class="details-grid">
            <div class="detail-row">
              <span class="detail-label">Risk Score</span>
              <span class="detail-value" style="color: ${textColor}; font-weight: 700;">${verdict.compositeScore || verdict.composite_score}${verdict.confidenceInterval ? ` &plusmn; ${verdict.confidenceInterval}` : ''}/100</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Top Threat</span>
              <span class="detail-value">${topThreat}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Data Traffic</span>
              <span class="detail-value">${destinations || 'No unauthorized exfiltration detected'}</span>
            </div>
          </div>
          <div class="actions">
            <button id="btn-goback">Return to Safety</button>
            ${isBlock ? '' : '<button id="btn-proceed">Dismiss Warning</button>'}
          </div>
        </div>
      </div>
    `;
    
    shadow.getElementById('btn-goback').addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.replace('about:blank');
      }
    });
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
    if (!shouldInjectIntoPage()) {
      return;
    }

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
    '%c🛡️ SentinelAI v3.0 Active Runtime Intelligence — 18 hooks loaded',
    'color:#00e5ff;font-weight:bold;font-size:13px'
  );
})();
