/**
 * SentinelAI v2.0 — Hook 10: Clipboard Access Monitoring
 * Detects clipboard hijacking and unauthorized clipboard reads.
 */
(function() {
  'use strict';
  if (window.__sentinel_clipboard_hooked) return;
  window.__sentinel_clipboard_hooked = true;

  // Monitor clipboard API reads
  if (navigator.clipboard && navigator.clipboard.readText) {
    const originalReadText = navigator.clipboard.readText.bind(navigator.clipboard);
    navigator.clipboard.readText = function() {
      const event = {
        hook: 'clipboard',
        timestamp: Date.now(),
        data: { action: 'read' }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalReadText();
    };
  }

  // Monitor clipboard API writes
  if (navigator.clipboard && navigator.clipboard.writeText) {
    const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = function(text) {
      const event = {
        hook: 'clipboard',
        timestamp: Date.now(),
        data: {
          action: 'write',
          contentPreview: String(text).substring(0, 200),
          contentLength: String(text).length
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalWriteText(text);
    };
  }

  // Monitor copy/paste/cut events
  ['copy', 'paste', 'cut'].forEach(eventType => {
    document.addEventListener(eventType, function(e) {
      const event = {
        hook: 'clipboard',
        timestamp: Date.now(),
        data: {
          action: eventType,
          target: e.target?.tagName || 'unknown'
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    }, true);
  });
})();
