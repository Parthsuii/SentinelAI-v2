/**
 * SentinelAI v2.0 — Hook 11: Canvas / WebGL Fingerprinting Detection
 * Detects browser fingerprinting via canvas and WebGL data extraction.
 */
(function() {
  'use strict';
  if (window.__sentinel_canvas_hooked) return;
  window.__sentinel_canvas_hooked = true;

  // Track canvas fingerprinting calls
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
    const event = {
      hook: 'canvas',
      timestamp: Date.now(),
      data: {
        action: 'toDataURL',
        canvasWidth: this.width,
        canvasHeight: this.height,
        mimeType: type || 'image/png'
      }
    };
    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    return originalToDataURL.call(this, type, quality);
  };

  const originalToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
    const event = {
      hook: 'canvas',
      timestamp: Date.now(),
      data: {
        action: 'toBlob',
        canvasWidth: this.width,
        canvasHeight: this.height,
        mimeType: type || 'image/png'
      }
    };
    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    return originalToBlob.call(this, callback, type, quality);
  };

  // Monitor WebGL renderer/vendor queries (fingerprinting)
  const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(param) {
    // RENDERER = 0x1F01, VENDOR = 0x1F00
    if (param === 0x1F01 || param === 0x1F00) {
      const event = {
        hook: 'canvas',
        timestamp: Date.now(),
        data: {
          action: 'webgl-getParameter',
          param: param === 0x1F01 ? 'RENDERER' : 'VENDOR'
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    }
    return originalGetParameter.call(this, param);
  };
})();
