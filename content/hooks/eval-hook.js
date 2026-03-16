/**
 * SentinelAI v2.0 — Hook 3: eval() / Function() Interception
 * Catches runtime code execution — a key vector for decoded malware.
 */
(function() {
  'use strict';
  if (window.__sentinel_eval_hooked) return;
  window.__sentinel_eval_hooked = true;

  const originalEval = window.eval;
  const OriginalFunction = window.Function;

  window.eval = function(code) {
    const codeStr = String(code);
    const event = {
      hook: 'eval',
      timestamp: Date.now(),
      data: {
        codePreview: codeStr.substring(0, 500),
        codeLength: codeStr.length,
        hasBase64: /atob\s*\(|btoa\s*\(/i.test(codeStr),
        hasNetworkCall: /fetch\s*\(|XMLHttpRequest|sendBeacon/i.test(codeStr),
        hasDOMManip: /innerHTML|document\.write|createElement/i.test(codeStr)
      }
    };

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    return originalEval.call(window, code);
  };

  window.Function = function(...args) {
    const bodyStr = args.length > 0 ? String(args[args.length - 1]) : '';
    const event = {
      hook: 'eval',
      timestamp: Date.now(),
      data: {
        type: 'Function-constructor',
        codePreview: bodyStr.substring(0, 500),
        codeLength: bodyStr.length,
        hasBase64: /atob\s*\(|btoa\s*\(/i.test(bodyStr),
        hasNetworkCall: /fetch\s*\(|XMLHttpRequest|sendBeacon/i.test(bodyStr)
      }
    };

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    return new OriginalFunction(...args);
  };
  window.Function.prototype = OriginalFunction.prototype;
})();
