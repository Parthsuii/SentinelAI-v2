/**
 * SentinelAI v3.0 — Service Worker Hook (Hook 15)
 * Intercepts malicious service worker registrations.
 */
(function() {
  let serviceWorkerContainer = null;

  try {
    serviceWorkerContainer = navigator.serviceWorker;
  } catch (e) {
    // Sandboxed iframes can throw a SecurityError when this getter is accessed.
    return;
  }

  if (!serviceWorkerContainer || typeof serviceWorkerContainer.register !== 'function') {
    return;
  }

  const originalRegister = serviceWorkerContainer.register;

  if (originalRegister) {
    serviceWorkerContainer.register = async function(scriptURL, options) {
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
