/**
 * SentinelAI v2.0 — Hook 8: postMessage Interception
 * Monitors cross-origin messaging via window.postMessage.
 */
(function() {
  'use strict';
  if (window.__sentinel_postmsg_hooked) return;
  window.__sentinel_postmsg_hooked = true;

  const originalPostMessage = window.postMessage.bind(window);

  window.postMessage = function(message, targetOrigin, transfer) {
    let msgPreview = '';
    try {
      msgPreview = typeof message === 'string'
        ? message.substring(0, 300)
        : JSON.stringify(message).substring(0, 300);
    } catch(e) {
      msgPreview = '[non-serializable]';
    }

    const event = {
      hook: 'postmessage',
      timestamp: Date.now(),
      data: {
        action: 'send',
        messagePreview: msgPreview,
        targetOrigin: targetOrigin || '*',
        hasTransfer: !!(transfer && transfer.length)
      }
    };

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    return originalPostMessage(message, targetOrigin, transfer);
  };

  // Also listen for incoming messages
  window.addEventListener('message', function(e) {
    // Ignore our own sentinel events
    if (e.data && e.data.__sentinel) return;

    let msgPreview = '';
    try {
      msgPreview = typeof e.data === 'string'
        ? e.data.substring(0, 300)
        : JSON.stringify(e.data).substring(0, 300);
    } catch(err) {
      msgPreview = '[non-serializable]';
    }

    const event = {
      hook: 'postmessage',
      timestamp: Date.now(),
      data: {
        action: 'receive',
        messagePreview: msgPreview,
        origin: e.origin,
        sourceIsNull: e.source === null,
        isTrusted: e.isTrusted
      }
    };

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
  }, true);
})();
