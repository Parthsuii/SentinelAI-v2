/**
 * SentinelAI v2.0 — Hook 6: navigator.sendBeacon() Interception
 * Catches stealthy data exfiltration via sendBeacon.
 */
(function() {
  'use strict';
  if (window.__sentinel_beacon_hooked) return;
  window.__sentinel_beacon_hooked = true;

  const originalBeacon = navigator.sendBeacon.bind(navigator);

  navigator.sendBeacon = function(url, data) {
    let dataPreview = null;
    try {
      if (data) {
        dataPreview = typeof data === 'string'
          ? data.substring(0, 500)
          : data instanceof Blob
            ? `[Blob: ${data.size} bytes, type: ${data.type}]`
            : data instanceof FormData
              ? '[FormData]'
              : '[unknown data type]';
      }
    } catch(e) { /* ignore */ }

    const event = {
      hook: 'beacon',
      timestamp: Date.now(),
      data: {
        url: String(url),
        dataPreview,
        dataSize: data?.size || (typeof data === 'string' ? data.length : 0)
      }
    };

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    return originalBeacon(url, data);
  };
})();
