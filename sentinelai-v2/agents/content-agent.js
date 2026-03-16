/**
 * SentinelAI v2.0 — Content Agent
 * Page content analysis — detects phishing text patterns, fake login forms.
 * Stub Phi-4-mini LLM call for advanced analysis.
 */

const PHISHING_TEXT_PATTERNS = [
  { pattern: /your account (?:has been|was) (?:suspended|locked|compromised)/i, severity: 30, label: 'Account suspension scare' },
  { pattern: /verify your (?:identity|account|email)/i, severity: 20, label: 'Identity verification prompt' },
  { pattern: /unusual (?:activity|sign.?in|login)/i, severity: 25, label: 'Unusual activity warning' },
  { pattern: /update your (?:payment|billing|credit card)/i, severity: 30, label: 'Payment update request' },
  { pattern: /confirm your (?:password|credentials)/i, severity: 35, label: 'Credential confirmation request' },
  { pattern: /click (?:here|below) (?:to|within) (?:\d+\s*hours?)/i, severity: 25, label: 'Urgency pressure tactic' },
  { pattern: /your (?:package|shipment|order) (?:could not|cannot) be delivered/i, severity: 20, label: 'Delivery scam' },
  { pattern: /you have won/i, severity: 15, label: 'Prize scam' },
  { pattern: /congratulations.*prize/i, severity: 15, label: 'Prize scam' },
  { pattern: /limited time.*act now/i, severity: 15, label: 'Urgency pressure' },
  { pattern: /enter your (?:ssn|social security|tax id)/i, severity: 40, label: 'SSN phishing' },
  { pattern: /we detected (?:a |an )?(?:unauthorized|suspicious)/i, severity: 25, label: 'Fake security alert' }
];

class ContentAgent {
  constructor() {
    this.name = 'content-agent';
  }

  /**
   * Analyze page signals for phishing indicators
   * @param {Object} signals - Page signals from content script
   * @returns {Object} - { score: 0-100, threats: [] }
   */
  analyze(signals) {
    const threats = [];
    let score = 0;

    // 1. Check body text for phishing patterns
    const text = signals.bodyTextPreview || '';
    for (const { pattern, severity, label } of PHISHING_TEXT_PATTERNS) {
      if (pattern.test(text)) {
        score += severity;
        threats.push({ type: 'phishing-text', detail: label });
      }
    }

    // 2. Check forms for credential phishing
    if (signals.forms) {
      for (const form of signals.forms) {
        if (form.hasPassword) {
          // Password form on suspicious page
          if (signals.protocol === 'http:') {
            score += 30;
            threats.push({ type: 'insecure-login', detail: 'Password form on HTTP page' });
          }
          // Cross-origin form submission
          if (form.action) {
            try {
              const formOrigin = new URL(form.action).origin;
              if (formOrigin !== signals.url && formOrigin !== new URL(signals.url).origin) {
                score += 25;
                threats.push({ type: 'cross-origin-form', detail: 'Login form submits to different origin' });
              }
            } catch(e) { /* ignore */ }
          }
        }
        if (form.hasPassword && form.hasEmail) {
          score += 10;
          threats.push({ type: 'credential-form', detail: 'Page contains email + password form' });
        }
      }
    }

    // 3. Check for excessive inline scripts
    if (signals.inlineScriptCount > 10) {
      score += 10;
      threats.push({ type: 'excessive-scripts', detail: `${signals.inlineScriptCount} inline scripts detected` });
    }

    // 4. Check for no/fake title
    if (!signals.title || signals.title.length < 3) {
      score += 5;
      threats.push({ type: 'missing-title', detail: 'Page has no or very short title' });
    }

    // 5. Check for favicon mismatch (brand impersonation)
    const title = (signals.title || '').toLowerCase();
    const hostname = (signals.hostname || '').toLowerCase();
    const brandNames = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix'];
    for (const brand of brandNames) {
      if (title.includes(brand) && !hostname.includes(brand)) {
        score += 20;
        threats.push({ type: 'brand-title-mismatch', detail: `Title mentions "${brand}" but domain doesn't match` });
        break;
      }
    }

    return {
      agent: this.name,
      score: Math.min(score, 100),
      threats,
      timestamp: Date.now()
    };
  }

  /**
   * Stub LLM call — would call Phi-4-mini for deep content analysis
   */
  async analyzeLLM(signals) {
    return this.analyze(signals);
  }
}

if (typeof globalThis !== 'undefined') {
  globalThis.SentinelContentAgent = ContentAgent;
}
