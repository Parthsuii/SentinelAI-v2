/**
 * SentinelAI v2.0 — Sandbox Execution Engine
 * Clones suspicious scripts into a sandboxed iframe for safe observation.
 * sandbox="allow-scripts" — scripts execute but NO network, storage, cookies, or real DOM.
 */
(function() {
  'use strict';
  if (window.__sentinel_sandbox_ready) return;
  window.__sentinel_sandbox_ready = true;

  let sandboxFrame = null;
  let pendingCallbacks = {};
  let scriptCounter = 0;

  /**
   * Initialize the sandbox iframe
   */
  function initSandbox() {
    if (sandboxFrame) return;

    sandboxFrame = document.createElement('iframe');
    sandboxFrame.sandbox = 'allow-scripts'; // Scripts only — no network, no storage, no cookies
    sandboxFrame.style.cssText = 'display:none!important;width:0;height:0;border:none;position:absolute;left:-9999px';
    sandboxFrame.src = chrome.runtime.getURL('content/sandbox-frame.html');

    // Listen for sandbox results
    window.addEventListener('message', function(e) {
      if (e.data && e.data.__sentinel_sandbox_result) {
        const { scriptId, attempts } = e.data;
        if (pendingCallbacks[scriptId]) {
          pendingCallbacks[scriptId](attempts);
          delete pendingCallbacks[scriptId];
        }
      }
    });

    (document.documentElement || document.body || document.head).appendChild(sandboxFrame);
  }

  /**
   * Execute code in sandbox and get API call attempts
   * @param {string} code - The suspicious code to analyze
   * @returns {Promise<Array>} - List of API calls the script attempted
   */
  window.__sentinel_sandboxExec = function(code) {
    return new Promise((resolve) => {
      if (!sandboxFrame || !sandboxFrame.contentWindow) {
        initSandbox();
        // Wait for iframe to load
        sandboxFrame.addEventListener('load', () => {
          execInSandbox(code, resolve);
        }, { once: true });
      } else {
        execInSandbox(code, resolve);
      }
    });
  };

  function execInSandbox(code, resolve) {
    const scriptId = `sandbox_${++scriptCounter}_${Date.now()}`;
    pendingCallbacks[scriptId] = resolve;

    // Timeout: force resolve after 500ms
    setTimeout(() => {
      if (pendingCallbacks[scriptId]) {
        pendingCallbacks[scriptId]([{ api: 'timeout', ts: Date.now() }]);
        delete pendingCallbacks[scriptId];
      }
    }, 500);

    sandboxFrame.contentWindow.postMessage({
      __sentinel_sandbox_exec: true,
      scriptId,
      code
    }, '*');
  }

  // Lazy-init when first needed
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSandbox, { once: true });
  } else {
    initSandbox();
  }
})();
