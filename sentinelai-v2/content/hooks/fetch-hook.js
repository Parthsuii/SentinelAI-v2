/**
 * SentinelAI v2.0 — Hook 1: fetch() Interception
 * Wraps window.fetch to intercept all outbound fetch requests.
 * Logs URL, method, headers, and body for threat analysis.
 */
(function() {
  'use strict';
  if (window.__sentinel_fetch_hooked) return;
  window.__sentinel_fetch_hooked = true;

  const originalFetch = window.fetch.bind(window);

  window.fetch = function(input, init) {
    const url = (typeof input === 'string') ? input : (input instanceof Request ? input.url : String(input));
    const method = init?.method || (input instanceof Request ? input.method : 'GET');
    let bodyPreview = null;

    try {
      if (init?.body) {
        bodyPreview = typeof init.body === 'string'
          ? init.body.substring(0, 500)
          : '[non-string body]';
      }
    } catch(e) { /* ignore */ }

    const event = {
      hook: 'fetch',
      timestamp: Date.now(),
      data: {
        url,
        method: method.toUpperCase(),
        bodyPreview,
        hasCredentials: init?.credentials === 'include',
        destination: url
      }
    };

    // Send to content.js event bus
    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    return originalFetch(input, init);
  };
})();
