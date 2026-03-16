/**
 * SentinelAI v3.0 — CSS Clickjacking Hook (Hook 13)
 * Detects pointer-events:none overlays and z-index stacking attacks.
 */
(function() {
  function checkClickjacking() {
    const suspiciousElements = [];
    const elements = document.querySelectorAll('*');
    
    // Use a lighter heuristic to avoid freezing the page
    for (let i = 0; i < elements.length; i++) {
        const el = elements[i];
        // Only check elements that are positioned over the page
        const style = window.getComputedStyle(el);
        if (style.position === 'absolute' || style.position === 'fixed') {
            if (style.opacity === '0' || style.pointerEvents === 'none') {
                const rect = el.getBoundingClientRect();
                // Check if it covers a significant portion of the screen
                if (rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8) {
                    suspiciousElements.push({
                        tag: el.tagName,
                        id: el.id,
                        className: el.className,
                        zIndex: style.zIndex,
                        opacity: style.opacity,
                        pointerEvents: style.pointerEvents
                    });
                }
            } else if (parseInt(style.zIndex, 10) > 9999) {
                // Suspiciously high z-index over the whole page
                const rect = el.getBoundingClientRect();
                if (rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8) {
                    suspiciousElements.push({
                        tag: el.tagName,
                        id: el.id,
                        className: el.className,
                        zIndex: style.zIndex
                    });
                }
            }
        }
    }

    if (suspiciousElements.length > 0) {
      const event = {
        hook: 'css-clickjack',
        timestamp: Date.now(),
        details: { elements: suspiciousElements.slice(0, 3) }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    }
  }

  // Run shortly after load and on window resize
  if (document.readyState === 'complete') {
    setTimeout(checkClickjacking, 1000);
  } else {
    window.addEventListener('load', () => setTimeout(checkClickjacking, 1000));
  }
})();
