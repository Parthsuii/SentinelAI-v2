/**
 * SentinelAI v3.0 — Hook 4: document.write() / innerHTML Monitoring
 * Catches DOM injection attacks via document.write and innerHTML.
 */
(function() {
  'use strict';
  if (window.__sentinel_domwrite_hooked) return;
  window.__sentinel_domwrite_hooked = true;

  // Wrap document.write
  const originalWrite = document.write.bind(document);
  document.write = function(markup) {
    const event = {
      hook: 'dom-write',
      timestamp: Date.now(),
      data: {
        type: 'document.write',
        contentPreview: String(markup).substring(0, 500),
        contentLength: String(markup).length,
        hasScript: /<script/i.test(markup),
        hasIframe: /<iframe/i.test(markup),
        hasForm: /<form/i.test(markup)
      }
    };
    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    return originalWrite(markup);
  };

  // Wrap innerHTML setter on Element prototype
  const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set(value) {
        const valStr = String(value);
        // Only fire event for potentially dangerous content
        if (/<script|<iframe|<form|<object|<embed|onclick|onerror|onload/i.test(valStr)) {
          const event = {
            hook: 'dom-write',
            timestamp: Date.now(),
            data: {
              type: 'innerHTML',
              targetTag: this.tagName,
              contentPreview: valStr.substring(0, 500),
              contentLength: valStr.length,
              hasScript: /<script/i.test(valStr),
              hasIframe: /<iframe/i.test(valStr),
              hasEventHandler: /on\w+\s*=/i.test(valStr)
            }
          };
          window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
        }
        return originalInnerHTMLDescriptor.set.call(this, value);
      },
      get() {
        return originalInnerHTMLDescriptor.get.call(this);
      },
      configurable: true
    });
  }
})();
