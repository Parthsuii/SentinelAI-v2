/**
 * SentinelAI v3.0 — Service Worker Hook (Hook 15)
 * Intercepts malicious service worker registrations.
 */
(function() {
  const originalRegister = navigator.serviceWorker ? navigator.serviceWorker.register : null;

  if (originalRegister) {
    navigator.serviceWorker.register = async function(scriptURL, options) {
      const urlStr = scriptURL.toString();
      
      // Log the registration attempt
      try {
        const event = {
          hook: 'service-worker',
          timestamp: Date.now(),
          details: { scriptURL: urlStr, scope: options ? options.scope : undefined }
        };
        window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      } catch (e) {
        // Ignore cross-origin postMessage errors if any
      }

      // We still let it register, but the backend will analyze the URL
      return originalRegister.apply(this, arguments);
    };
  }
})();
