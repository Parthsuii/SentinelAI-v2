/**
 * SentinelAI v2.0 — Hook 7: WebSocket Connection Monitoring
 * Monitors persistent WebSocket connections for data exfiltration.
 */
(function() {
  'use strict';
  if (window.__sentinel_ws_hooked) return;
  window.__sentinel_ws_hooked = true;

  const OriginalWebSocket = window.WebSocket;

  window.WebSocket = function(url, protocols) {
    const event = {
      hook: 'websocket',
      timestamp: Date.now(),
      data: {
        url: String(url),
        protocols: protocols ? (Array.isArray(protocols) ? protocols : [protocols]) : [],
        action: 'connect'
      }
    };
    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));

    const ws = protocols
      ? new OriginalWebSocket(url, protocols)
      : new OriginalWebSocket(url);

    // Monitor send calls
    const originalSend = ws.send.bind(ws);
    ws.send = function(data) {
      let dataPreview = null;
      try {
        dataPreview = typeof data === 'string'
          ? data.substring(0, 300)
          : `[${data.constructor.name}: ${data.byteLength || data.size || '?'} bytes]`;
      } catch(e) { /* ignore */ }

      const sendEvent = {
        hook: 'websocket',
        timestamp: Date.now(),
        data: {
          url: String(url),
          action: 'send',
          dataPreview
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: sendEvent }));

      return originalSend(data);
    };

    return ws;
  };

  // Preserve prototype chain
  window.WebSocket.prototype = OriginalWebSocket.prototype;
  window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  window.WebSocket.OPEN = OriginalWebSocket.OPEN;
  window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
  window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
})();
