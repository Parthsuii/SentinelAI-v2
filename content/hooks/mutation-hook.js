/**
 * SentinelAI v2.0 — Hook 5: MutationObserver for DOM Injection Detection
 * Detects dynamic DOM injection: clickjacking iframes, fake overlays, form injection.
 */
(function() {
  'use strict';
  if (window.__sentinel_mutation_hooked) return;
  window.__sentinel_mutation_hooked = true;

  // We wait until body exists to observe
  const startObserving = () => {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;

          const tag = node.tagName?.toUpperCase();
          let suspicious = false;
          let reason = '';

          // Detect injected iframes (clickjacking)
          if (tag === 'IFRAME') {
            suspicious = true;
            reason = 'iframe-injection';
          }
          // Detect injected scripts
          else if (tag === 'SCRIPT') {
            suspicious = true;
            reason = 'script-injection';
          }
          // Detect injected forms (credential phishing)
          else if (tag === 'FORM') {
            suspicious = true;
            reason = 'form-injection';
          }
          // Detect overlay divs (fake login screens)
          else if (tag === 'DIV') {
            const style = node.style;
            if (style && (
              (style.position === 'fixed' || style.position === 'absolute') &&
              (parseInt(style.zIndex) > 9000 || style.zIndex === 'auto')
            )) {
              suspicious = true;
              reason = 'overlay-injection';
            }
          }
          // Detect object/embed (plugin-based attacks)
          else if (tag === 'OBJECT' || tag === 'EMBED') {
            suspicious = true;
            reason = 'plugin-injection';
          }

          if (suspicious) {
            const event = {
              hook: 'mutation',
              timestamp: Date.now(),
              data: {
                reason,
                tag,
                id: node.id || null,
                classes: node.className || null,
                src: node.src || node.action || null,
                outerHTMLPreview: (node.outerHTML || '').substring(0, 300)
              }
            };
            window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
          }
        }
      }
    });

    const targetNode = document.documentElement || document.body;
    if (targetNode) {
      observer.observe(targetNode, {
        childList: true,
        subtree: true
      });
    }
  };

  // Start observing as soon as documentElement is available
  if (document.documentElement) {
    startObserving();
  } else {
    document.addEventListener('DOMContentLoaded', startObserving, { once: true });
  }
})();
