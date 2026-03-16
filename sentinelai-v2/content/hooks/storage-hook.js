/**
 * SentinelAI v2.0 — Hook: localStorage / sessionStorage Monitoring
 * Detects persistent tracking via Web Storage API access.
 */
(function() {
  'use strict';
  if (window.__sentinel_storage_hooked) return;
  window.__sentinel_storage_hooked = true;

  function hookStorage(storageObj, storageName) {
    const originalSetItem = storageObj.setItem.bind(storageObj);
    const originalGetItem = storageObj.getItem.bind(storageObj);
    const originalRemoveItem = storageObj.removeItem.bind(storageObj);

    storageObj.setItem = function(key, value) {
      const valStr = String(value);
      const event = {
        hook: 'storage',
        timestamp: Date.now(),
        data: {
          storage: storageName,
          action: 'set',
          key: String(key),
          valuePreview: valStr.substring(0, 200),
          valueLength: valStr.length,
          isTrackingId: /track|uid|uuid|fprint|fingerprint|visitor|_ga|_gid|fbp|cid/i.test(key),
          isBase64: /^[A-Za-z0-9+/=]{20,}$/.test(valStr.trim())
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalSetItem(key, value);
    };

    storageObj.getItem = function(key) {
      const keyStr = String(key);
      // Only log reads of potentially sensitive keys
      if (/track|uid|uuid|token|auth|sess|fprint|fingerprint|visitor|_ga|cid/i.test(keyStr)) {
        const event = {
          hook: 'storage',
          timestamp: Date.now(),
          data: {
            storage: storageName,
            action: 'get',
            key: keyStr,
            isTrackingId: true
          }
        };
        window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      }
      return originalGetItem(key);
    };

    storageObj.removeItem = function(key) {
      const event = {
        hook: 'storage',
        timestamp: Date.now(),
        data: {
          storage: storageName,
          action: 'remove',
          key: String(key)
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalRemoveItem(key);
    };
  }

  try { hookStorage(localStorage, 'localStorage'); } catch(e) { /* sandboxed */ }
  try { hookStorage(sessionStorage, 'sessionStorage'); } catch(e) { /* sandboxed */ }
})();
