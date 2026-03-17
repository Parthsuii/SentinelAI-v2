/**
 * SentinelAI v2.0 — Hook: document.cookie Interception
 * Detects session token theft via cookie access.
 */
(function() {
  'use strict';
  if (window.__sentinel_cookie_hooked) return;
  window.__sentinel_cookie_hooked = true;

  const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                     Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');

  if (cookieDesc) {
    Object.defineProperty(document, 'cookie', {
      get() {
        const val = cookieDesc.get.call(this);
        // Only log reads that return non-empty values (avoid noise)
        if (val && val.length > 0) {
          const cookiePairs = val.split(';').map(part => part.trim()).filter(Boolean);
          const cookieNames = cookiePairs
            .map(part => part.split('=')[0]?.trim().toLowerCase())
            .filter(Boolean);
          const sensitiveCookieReads = cookieNames.filter(name => /^(?:__secure-|__host-)?(?:session|sess|sid|auth|token|jwt|csrf)/i.test(name));
          const event = {
            hook: 'cookie',
            timestamp: Date.now(),
            data: {
              action: 'read',
              cookieCount: cookiePairs.length,
              hasSessionId: sensitiveCookieReads.length > 0,
              sensitiveCookieCount: sensitiveCookieReads.length,
              sampleCookieNames: cookieNames.slice(0, 5),
              totalLength: val.length
            }
          };
          window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
        }
        return val;
      },
      set(value) {
        const valStr = String(value);
        const event = {
          hook: 'cookie',
          timestamp: Date.now(),
          data: {
            action: 'write',
            cookiePreview: valStr.substring(0, 200),
            isHttpOnly: /httponly/i.test(valStr),
            isSecure: /secure/i.test(valStr),
            hasExpiry: /expires|max-age/i.test(valStr),
            domain: (valStr.match(/domain=([^;]+)/i) || [])[1] || null
          }
        };
        window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
        return cookieDesc.set.call(this, value);
      },
      configurable: true
    });
  }
})();
