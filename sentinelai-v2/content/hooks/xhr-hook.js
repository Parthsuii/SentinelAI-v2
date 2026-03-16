/**
 * SentinelAI v2.0 — Hook 2: XMLHttpRequest Interception
 * Wraps XHR open/send to catch legacy AJAX exfiltration.
 */
(function() {
  'use strict';
  if (window.__sentinel_xhr_hooked) return;
  window.__sentinel_xhr_hooked = true;

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.__sentinel_method = method;
    this.__sentinel_url = url;
    return originalOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function(body) {
    let bodyPreview = null;
    try {
      if (body) {
        bodyPreview = typeof body === 'string'
          ? body.substring(0, 500)
          : '[non-string body]';
      }
    } catch(e) { /* ignore */ }

    const event = {
      hook: 'xhr',
      timestamp: Date.now(),
      data: {
        url: this.__sentinel_url,
        method: (this.__sentinel_method || 'GET').toUpperCase(),
        bodyPreview,
        destination: this.__sentinel_url
      }
    };

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    return originalSend.call(this, body);
  };
})();
