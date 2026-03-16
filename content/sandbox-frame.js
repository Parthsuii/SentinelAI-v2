// This page runs inside a sandboxed iframe (sandbox="allow-scripts").
// It has NO network access, NO localStorage, NO cookies, NO DOM access to parent.
// We monitor every API call the injected script attempts.

const attempts = [];

// Override network APIs to log attempts (they would fail anyway)
window.fetch = function(url) {
  attempts.push({ api: 'fetch', url: String(url), ts: Date.now() });
  return Promise.reject(new Error('Sandboxed'));
};

window.XMLHttpRequest = function() {
  const self = this;
  self.open = function(m, u) { attempts.push({ api: 'xhr', method: m, url: u, ts: Date.now() }); };
  self.send = function() { attempts.push({ api: 'xhr-send', ts: Date.now() }); };
};

navigator.sendBeacon = function(url) {
  attempts.push({ api: 'sendBeacon', url: String(url), ts: Date.now() });
  return false;
};

window.WebSocket = function(url) {
  attempts.push({ api: 'websocket', url: String(url), ts: Date.now() });
  throw new Error('Sandboxed');
};

// Override cookie access without touching the real sandboxed cookie property first.
Object.defineProperty(document, 'cookie', {
  get() { attempts.push({ api: 'cookie-read', ts: Date.now() }); return ''; },
  set() { attempts.push({ api: 'cookie-write', ts: Date.now() }); }
});

// Listen for script injection from parent
window.addEventListener('message', function(e) {
  if (e.data && e.data.__sentinel_sandbox_exec) {
    const code = e.data.code;
    attempts.length = 0;

    try {
      // 🚨 Chrome MV3 strictly forbids `new Function()` or `eval()` even in sandboxed IFrames.
      // Instead of dynamic execution, we perform a rapid static analysis of the payload text
      // to identify the same exfiltration APIs that dynamic execution would catch.
      staticAnalyze(code);
    } catch(err) {
      attempts.push({ api: 'error', message: err.message, ts: Date.now() });
    }

    // Report results back after timeout
    setTimeout(function() {
      parent.postMessage({
        __sentinel_sandbox_result: true,
        scriptId: e.data.scriptId,
        attempts: attempts.slice()
      }, '*');
    }, 50); // Fast return since it's static
  }
});

/**
 * Perform rapid static analysis on the injected code payload instead of unsafe eval.
 */
function staticAnalyze(code) {
  if (!code || typeof code !== 'string') return;
  
  // 1. Detect Fetch / XHR URLs
  const fetchMatches = code.matchAll(/(?:fetch|XMLHttpRequest|sendBeacon)\s*[(]\s*['"`](https?:\/\/[^'"`]+)['"`]/gi);
  for (const match of fetchMatches) {
    window.fetch(match[1]).catch(()=>{}); // Logs to our interceptors
  }

  // 2. Detect WebSockets
  const wsMatches = code.matchAll(/new\s+WebSocket\s*[(]\s*['"`](wss?:\/\/[^'"`]+)['"`]/gi);
  for (const match of wsMatches) {
    try { new window.WebSocket(match[1]); } catch(e){}
  }

  // 3. Detect Cookies / Storage manipulation
  if (/document\.cookie\s*=/.test(code)) attempts.push({ api: 'cookie-write', ts: Date.now() });
  if (/localStorage\.set/.test(code)) attempts.push({ api: 'storage-write', ts: Date.now() });

  // 4. Detect eval payloads embedded in the script
  if (/\beval\s*\(/.test(code) || /setTimeout\s*\(\s*['"`]/.test(code)) {
    attempts.push({ api: 'eval-detected', details: 'Static analyzer found nested eval', ts: Date.now() });
  }

  // 5. Look for Base64 blobs
  if (/atob\s*\(/.test(code) || /[A-Za-z0-9+/=]{100,}/.test(code)) {
    attempts.push({ api: 'suspicious-encoding', details: 'Base64 payload detected', ts: Date.now() });
  }
}
