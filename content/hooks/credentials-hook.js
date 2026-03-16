/**
 * SentinelAI v3.0 — Credentials API Hook (Hook 18)
 * Intercepts Credential Management API abuse (silent autofill theft).
 */
(function() {
  if (navigator.credentials) {
    const originalGet = navigator.credentials.get;
    const originalStore = navigator.credentials.store;

    navigator.credentials.get = async function(options) {
      const event = {
        hook: 'credentials',
        timestamp: Date.now(),
        details: { action: 'get', options: options }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalGet.apply(this, arguments);
    };

    navigator.credentials.store = async function(credential) {
      const event = {
        hook: 'credentials',
        timestamp: Date.now(),
        details: { action: 'store', id: credential.id }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalStore.apply(this, arguments);
    };
  }
})();
