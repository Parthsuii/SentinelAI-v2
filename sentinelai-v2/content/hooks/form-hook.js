/**
 * SentinelAI v2.0 — Hook 9: Form Submission Monitoring
 * Detects credential phishing via form submissions.
 */
(function() {
  'use strict';
  if (window.__sentinel_form_hooked) return;
  window.__sentinel_form_hooked = true;

  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;

    const inputs = form.querySelectorAll('input');
    const fieldTypes = [];
    let hasPasswordField = false;
    let hasEmailField = false;
    let hasCreditCardField = false;

    inputs.forEach(input => {
      const type = (input.type || 'text').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();

      fieldTypes.push(type);

      if (type === 'password') hasPasswordField = true;
      if (type === 'email' || /email|e-mail/i.test(name + placeholder)) hasEmailField = true;
      if (/card|credit|cc|cvv|cvc|expir/i.test(name + placeholder)) hasCreditCardField = true;
    });

    const event = {
      hook: 'form',
      timestamp: Date.now(),
      data: {
        action: form.action || window.location.href,
        method: (form.method || 'GET').toUpperCase(),
        fieldCount: inputs.length,
        fieldTypes,
        hasPasswordField,
        hasEmailField,
        hasCreditCardField,
        actionIsCrossOrigin: false
      }
    };

    // Check if form submits to a different origin
    try {
      const formOrigin = new URL(event.data.action, window.location.href).origin;
      event.data.actionIsCrossOrigin = formOrigin !== window.location.origin;
    } catch(e) { /* ignore */ }

    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
  }, true);

  // Also detect dynamically created forms being submitted via JS
  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    const event = {
      hook: 'form',
      timestamp: Date.now(),
      data: {
        action: this.action || window.location.href,
        method: (this.method || 'GET').toUpperCase(),
        type: 'programmatic-submit'
      }
    };
    window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
    return originalSubmit.call(this);
  };
})();
