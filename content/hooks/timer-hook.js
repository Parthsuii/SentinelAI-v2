/**
 * SentinelAI v2.0 — Hook 12: setTimeout / setInterval Monitoring
 * Detects deferred malware execution via timers.
 */
(function() {
  'use strict';
  if (window.__sentinel_timer_hooked) return;
  window.__sentinel_timer_hooked = true;

  const originalSetTimeout = window.setTimeout;
  const originalSetInterval = window.setInterval;

  window.setTimeout = function(callback, delay, ...args) {
    if (typeof callback === 'string') {
      // String callbacks to setTimeout are essentially eval
      const event = {
        hook: 'timer',
        timestamp: Date.now(),
        data: {
          type: 'setTimeout',
          callbackType: 'string',
          codePreview: callback.substring(0, 300),
          delay: delay || 0,
          isDeferred: (delay || 0) > 2000
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    } else if (typeof callback === 'function') {
      const funcStr = callback.toString();
      // Only log suspicious patterns
      if (/eval|atob|fetch|XMLHttpRequest|sendBeacon|innerHTML|document\.write/i.test(funcStr)) {
        const event = {
          hook: 'timer',
          timestamp: Date.now(),
          data: {
            type: 'setTimeout',
            callbackType: 'function',
            codePreview: funcStr.substring(0, 300),
            delay: delay || 0,
            isDeferred: (delay || 0) > 2000,
            hasSuspiciousPatterns: true
          }
        };
        window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      }
    }

    return originalSetTimeout.call(window, callback, delay, ...args);
  };

  window.setInterval = function(callback, interval, ...args) {
    if (typeof callback === 'string') {
      const event = {
        hook: 'timer',
        timestamp: Date.now(),
        data: {
          type: 'setInterval',
          callbackType: 'string',
          codePreview: callback.substring(0, 300),
          interval: interval || 0
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    }

    return originalSetInterval.call(window, callback, interval, ...args);
  };
})();
