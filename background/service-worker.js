/**
 * SentinelAI v2.0 — Background Service Worker (Updated)
 * Forwards hook events + page signals to FastAPI backend (http://localhost:8000).
 * Falls back to local JS analysis if backend is unavailable.
 */

// Load RiskEngine for synchronous background checks
importScripts('./risk-engine.js');
const riskEngine = new SentinelRiskEngine();

const BACKEND_URL = 'http://localhost:8000';
const MODULE = 'ServiceWorker';
const BACKEND_TIMEOUTS = {
  scan: 2500,
  whitelist: 800,
  default: 1500
};
const WHITELIST_CACHE_TTL_MS = 30000;

// ── State Management ──
const tabStates = new Map();
let whitelistCache = {
  hosts: [],
  expiresAt: 0
};

function getTabState(tabId) {
  if (!tabStates.has(tabId)) {
    tabStates.set(tabId, {
      url: '',
      hookEvents: [],
      pageSignals: null,
      verdict: null,
      scanCount: 0,
      lastScan: 0,
      backendAvailable: true
    });
  }
  return tabStates.get(tabId);
}

// ── Badge ──
const BADGE_COLORS = {
  safe: '#00e676', low: '#69f0ae', medium: '#ffd740',
  high: '#ff6e40', critical: '#ff1744'
};
const BADGE_TEXT = {
  safe: '✓', low: 'L', medium: 'M', high: 'H', critical: '!'
};

function updateBadge(tabId, level) {
  try {
    chrome.action.setBadgeText({ text: BADGE_TEXT[level] || '?', tabId });
    chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS[level] || '#666', tabId });
  } catch(e) { /* tab may be closed */ }
}

// ── Backend Communication ──
async function callBackend(endpoint, data, timeoutMs = BACKEND_TIMEOUTS.default) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const resp = await fetch(`${BACKEND_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
      signal: controller.signal
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch(err) {
    console.warn(`[SentinelAI] Backend ${endpoint} failed:`, err.message);
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function callBackendGet(endpoint, timeoutMs = BACKEND_TIMEOUTS.default) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const resp = await fetch(`${BACKEND_URL}${endpoint}`, {
      signal: controller.signal
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch(err) {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function getWhitelistHosts() {
  const now = Date.now();
  if (whitelistCache.expiresAt > now) {
    return whitelistCache.hosts;
  }

  const result = await callBackendGet('/whitelist', BACKEND_TIMEOUTS.whitelist);
  whitelistCache = {
    hosts: result?.whitelist || [],
    expiresAt: now + WHITELIST_CACHE_TTL_MS
  };
  return whitelistCache.hosts;
}

// ── Pre-Warming ──
chrome.runtime.onStartup.addListener(() => {
  console.info('[SentinelAI] Browser started — Pre-warming Tier 1 models');
  callBackendGet('/prewarm').then(res => {
    if (res && res.status === 'ready') console.info('[SentinelAI] Tier 1 models pre-warmed.');
  }).catch(e => console.warn('[SentinelAI] Pre-warm failed:', e));
});
chrome.runtime.onInstalled.addListener(() => {
  callBackendGet('/prewarm').catch(() => {});
});

// ── Message Handler ──
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  switch (msg.type) {
    case 'SENTINEL_HOOK_EVENT':
      handleHookEvents(tabId, msg.payload);
      sendResponse({ ok: true });
      break;

    case 'SENTINEL_SCAN_REQUEST':
      handleScanRequest(tabId, msg.payload).then(() => sendResponse({ ok: true }));
      return true;

    case 'SENTINEL_GET_STATUS':
      handleGetStatus(msg.tabId || tabId, sendResponse);
      return true;

    case 'SENTINEL_GET_HISTORY':
      handleGetHistory(sendResponse);
      return true;

    case 'SENTINEL_CLEAR_HISTORY':
      handleClearHistory(sendResponse);
      return true;

    case 'SENTINEL_WHITELIST_SITE':
      handleWhitelist(msg.hostname, sendResponse);
      return true;

    case 'SENTINEL_SCAN_URL_LIGHT':
      handleLightScan(msg.payload.url, sendResponse);
      return true;

    default:
      sendResponse({ error: 'Unknown message type' });
  }
});

function handleLightScan(url, sendResponse) {
  try {
    const scanResult = riskEngine.quickScan(url);
    sendResponse({
      verdict: {
        compositeScore: scanResult.compositeScore,
        level: scanResult.level,
        confidenceInterval: 10,
        allThreats: scanResult.urlResult.threats || []
      }
    });
  } catch(e) {
    sendResponse({ error: 'Scan failed' });
  }
}

// ── Hook Event Handler ──
function handleHookEvents(tabId, payload) {
  if (!tabId) return;
  const state = getTabState(tabId);
  state.url = payload.url;

  const now = Date.now();
  state.hookEvents = state.hookEvents
    .filter(e => (now - e.timestamp) < 30000)
    .concat(payload.events);

  if (state.hookEvents.length > 200) {
    state.hookEvents = state.hookEvents.slice(-200);
  }

  // Re-scan on significant events
  const significantHooks = ['eval', 'mutation', 'form', 'beacon', 'cookie', 'permission'];
  const hasSignificant = payload.events.some(e => significantHooks.includes(e.hook));
  if (hasSignificant && (now - state.lastScan) > 2000) {
    runScan(tabId);
  }
}

// ── Scan Request ──
async function handleScanRequest(tabId, pageSignals) {
  if (!tabId) return;
  const state = getTabState(tabId);
  state.pageSignals = pageSignals;
  state.url = pageSignals.url;
  await runScan(tabId);
}

// ── Run Full Scan via Backend ──
async function runScan(tabId) {
  const state = getTabState(tabId);
  state.lastScan = Date.now();
  state.scanCount++;

  // Check whitelist
  const hostname = state.pageSignals?.hostname || '';
  const whitelistHosts = hostname ? await getWhitelistHosts() : [];
  if (hostname && whitelistHosts.includes(hostname)) {
    state.verdict = {
      compositeScore: 0, level: 'safe', allThreats: [],
      recommendation: 'This site is whitelisted.',
      agentBreakdown: {}, action: 'allow'
    };
    updateBadge(tabId, 'safe');
    return;
  }

  // Send to backend for full analysis
  const result = await callBackend('/scan', {
    url: state.url,
    hostname: hostname,
    page_signals: state.pageSignals,
    hook_events: state.hookEvents
  }, BACKEND_TIMEOUTS.scan);

  if (result && result.verdict) {
    state.verdict = {
      compositeScore: result.verdict.composite_score,
      level: result.verdict.level,
      allThreats: result.verdict.all_threats || [],
      recommendation: result.verdict.recommendation,
      agentBreakdown: result.verdict.agent_breakdown || {},
      action: result.verdict.action,
      llmExplanation: result.verdict.llm_explanation
    };
    state.backendAvailable = true;
    updateBadge(tabId, result.verdict.level);

    // Log high/critical threats and trigger Shadow DOM overlay
    if (result.verdict.level === 'high' || result.verdict.level === 'critical') {
      console.warn(`[SentinelAI] ⚠️ ${result.verdict.level.toUpperCase()} THREAT on ${state.url}`);
      chrome.tabs.sendMessage(tabId, { type: 'SENTINEL_SHOW_OVERLAY', verdict: result.verdict }).catch(() => {});
    } else if (result.verdict.level === 'medium') {
      chrome.tabs.sendMessage(tabId, { type: 'SENTINEL_SHOW_OVERLAY', verdict: result.verdict }).catch(() => {});
    }
  } else {
    // Backend unavailable — run local heuristic fallback
    state.backendAvailable = false;
    await runLocalFallback(tabId);
  }
}

// ── Local Fallback (when backend is down) ──
async function runLocalFallback(tabId) {
  const state = getTabState(tabId);
  // Simple heuristic scoring
  let score = 0;
  const threats = [];
  const agentBreakdown = {
    'url-agent': { rawScore: 0, weight: 0.25, weightedScore: 0, threatCount: 0 },
    'content-agent': { rawScore: 0, weight: 0.20, weightedScore: 0, threatCount: 0 },
    'runtime-agent': { rawScore: 0, weight: 0.35, weightedScore: 0, threatCount: 0 },
    'visual-agent': { rawScore: 0, weight: 0.05, weightedScore: 0, threatCount: 0 },
    'exfil-agent': { rawScore: 0, weight: 0.15, weightedScore: 0, threatCount: 0 }
  };

  // URL checks
  const url = state.url || '';
  if (url.startsWith('http:')) {
    score += 10;
    agentBreakdown['url-agent'].rawScore += 10;
    agentBreakdown['url-agent'].threatCount += 1;
    threats.push({ type: 'no-https', detail: 'No encryption', source: 'local' });
  }
  if (url.length > 200) {
    score += 5;
    agentBreakdown['url-agent'].rawScore += 5;
    agentBreakdown['url-agent'].threatCount += 1;
    threats.push({ type: 'long-url', detail: 'Unusually long URL', source: 'local' });
  }

  // Hook event checks
  const evalEvents = state.hookEvents.filter(e => e.hook === 'eval').length;
  if (evalEvents > 0) {
    score += 20;
    agentBreakdown['runtime-agent'].rawScore += 20;
    agentBreakdown['runtime-agent'].threatCount += 1;
    threats.push({ type: 'eval-usage', detail: `${evalEvents} eval calls`, source: 'local' });
  }

  const mutationEvents = state.hookEvents.filter(e => e.hook === 'mutation');
  if (mutationEvents.length > 0) {
    score += 15;
    agentBreakdown['runtime-agent'].rawScore += 15;
    agentBreakdown['runtime-agent'].threatCount += 1;
    threats.push({ type: 'dom-injection', detail: 'Dynamic DOM injection', source: 'local' });
  }

  for (const agent of Object.values(agentBreakdown)) {
    agent.rawScore = Math.min(agent.rawScore, 100);
    agent.weightedScore = Math.round(agent.rawScore * agent.weight * 10) / 10;
  }

  const level = score < 15 ? 'safe' : score < 30 ? 'low' : score < 55 ? 'medium' : score < 80 ? 'high' : 'critical';

  state.verdict = {
    compositeScore: Math.min(score, 100),
    level,
    allThreats: threats,
    recommendation: 'Local analysis (backend unavailable).',
    agentBreakdown,
    action: level === 'critical' || level === 'high' ? 'block' : 'allow'
  };
  updateBadge(tabId, level);
}

// ── Status Handler ──
async function handleGetStatus(tabId, sendResponse) {
  const state = tabStates.get(tabId);
  sendResponse({
    url: state?.url || '',
    verdict: state?.verdict || null,
    hookEventCount: state?.hookEvents?.length || 0,
    scanCount: state?.scanCount || 0,
    backendAvailable: state?.backendAvailable ?? true
  });
}

// ── History (via backend) ──
async function handleGetHistory(sendResponse) {
  const result = await callBackendGet('/history?limit=100', BACKEND_TIMEOUTS.default);
  sendResponse({ history: result?.history || [] });
}

async function handleClearHistory(sendResponse) {
  await fetch(`${BACKEND_URL}/history`, { method: 'DELETE' });
  sendResponse({ ok: true });
}

async function handleWhitelist(hostname, sendResponse) {
  await callBackend('/whitelist', { hostname }, BACKEND_TIMEOUTS.default);
  if (hostname && !whitelistCache.hosts.includes(hostname)) {
    whitelistCache = {
      hosts: whitelistCache.hosts.concat(hostname),
      expiresAt: Date.now() + WHITELIST_CACHE_TTL_MS
    };
  }
  sendResponse({ ok: true });
}

// ── Redirect Chain Tracker (Hook 14) ──
const redirectChains = new Map();

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  
  if (!redirectChains.has(tabId)) {
    redirectChains.set(tabId, []);
  }
  
  const chain = redirectChains.get(tabId);
  const isRedirect = details.transitionQualifiers && (details.transitionQualifiers.includes('server_redirect') || details.transitionQualifiers.includes('client_redirect'));
  
  if (isRedirect) {
    chain.push(details.url);
    if (chain.length > 3) {
      console.warn(`[SentinelAI] ⚠️ Suspicious redirect chain detected (${chain.length} hops):`, chain);
      const state = getTabState(tabId);
      state.hookEvents.push({ hook: 'redirect-chain', timestamp: Date.now(), details: { hops: chain.length, chain } });
      runScan(tabId);
    }
  } else {
    redirectChains.set(tabId, [details.url]);
  }
});

// ── Tab Lifecycle & Ultra-Low Latency Pre-Scan ──

chrome.tabs.onRemoved.addListener((tabId) => tabStates.delete(tabId));

// Phase 7 Architecture: Ultra-Low Latency (<30ms) Pre-Scan Blocking
// Intercepts navigation before the browser even requests the first byte
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only intercept main frame navigations (not iframes or subresources)
    if (details.frameId !== 0) return;
    
    // Ignore internal extension pages
    if (details.url.startsWith('chrome-extension://') || details.url.startsWith('chrome://')) return;

    try {
      const startTime = performance.now();
      
      // 1. Synchronous ultra-low latency heuristic check (< 5ms)
      const scanResult = riskEngine.quickScan(details.url);
      
      // 2. High/Critical Risk -> Instant Block before network connection
      if (scanResult.level === 'critical' || scanResult.level === 'high') {
        const threatMsg = scanResult.urlResult.threats[0]?.detail || 'Malicious URL pattern';
        const blockUrl = chrome.runtime.getURL(
          `dashboard/blocked.html?url=${encodeURIComponent(details.url)}&score=${scanResult.compositeScore}&threat=${encodeURIComponent(threatMsg)}`
        );
        
        // Instantly redirect the tab
        chrome.tabs.update(details.tabId, { url: blockUrl });
        
        console.warn(`[SentinelAI] 🛑 PRE-SCAN BLOCKED (${Math.round(performance.now() - startTime)}ms): ${details.url}`);
        updateBadge(details.tabId, scanResult.level);
        
        // Initialize state as blocked
        const state = getTabState(details.tabId);
        state.verdict = {
          compositeScore: scanResult.compositeScore,
          level: scanResult.level,
          recommendation: 'Blocked instantaneously before load.',
          allThreats: scanResult.urlResult.threats
        };
      } else {
        console.info(`[SentinelAI] ✓ PRE-SCAN PASSED (${Math.round(performance.now() - startTime)}ms): ${details.url}`);
      }
    } catch(e) {
      console.warn('[SentinelAI] Pre-scan error:', e);
    }
  });
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    const state = getTabState(tabId);
    state.hookEvents = [];
    state.pageSignals = null;
    state.verdict = null;
    state.url = changeInfo.url || state.url;

      // Sub-30ms quick scan already handled by webNavigation.
      // We keep this lightweight check just for badge initialization if webNavigation didn't fire.
      if (!changeInfo.url) {
        const localScan = riskEngine.quickScan(state.url);
        updateBadge(tabId, localScan.level);
      }
  }
});

console.info('🛡️ SentinelAI v2.0 Service Worker started — Backend:', BACKEND_URL);
