/**
 * SentinelAI v2.0 — Visual Agent
 * Screenshot-based phishing detection.
 * Stub analysis — real implementation would use a vision model.
 */

class VisualAgent {
  constructor() {
    this.name = 'visual-agent';
  }

  /**
   * Analyze page visual characteristics for phishing indicators
   * Uses heuristic checks on page signals (stub for visual model)
   * @param {Object} signals - Page signals
   * @returns {Object} - { score: 0-100, threats: [] }
   */
  analyze(signals) {
    const threats = [];
    let score = 0;

    // 1. Check for login form on non-brand domains
    const hostname = (signals.hostname || '').toLowerCase();
    const hasCreds = signals.forms?.some(f => f.hasPassword);
    const knownBrands = [
      'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
      'amazon.com', 'github.com', 'twitter.com', 'linkedin.com',
      'paypal.com', 'netflix.com', 'instagram.com', 'outlook.com',
      'yahoo.com', 'live.com', 'office.com'
    ];

    if (hasCreds && !knownBrands.some(b => hostname.endsWith(b))) {
      // Login form on unknown domain
      if (signals.externalLinkCount === 0) {
        score += 15;
        threats.push({ type: 'isolated-login', detail: 'Login page with no external navigation (typical of phishing)' });
      }
    }

    // 2. Check for hidden iframes
    const title = (signals.title || '').toLowerCase();
    if (title.includes('redirect') || title.includes('loading')) {
      score += 10;
      threats.push({ type: 'redirect-page', detail: 'Page title suggests redirect (possible phishing redirect)' });
    }

    // 3. Check meta tags for suspicious open graph
    if (signals.meta) {
      const ogTitle = (signals.meta['og:title'] || '').toLowerCase();
      const ogSite = (signals.meta['og:site_name'] || '').toLowerCase();
      for (const brand of ['paypal', 'google', 'microsoft', 'apple', 'amazon']) {
        if ((ogTitle.includes(brand) || ogSite.includes(brand)) && !hostname.includes(brand)) {
          score += 20;
          threats.push({ type: 'og-brand-spoof', detail: `OpenGraph claims to be ${brand} but domain doesn't match` });
          break;
        }
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
   * Capture tab screenshot for visual analysis (stub)
   */
  async captureAndAnalyze(tabId) {
    // In real implementation, would use chrome.tabs.captureVisibleTab
    // then send to a vision model for brand logo detection
    return { agent: this.name, score: 0, threats: [], timestamp: Date.now() };
  }
}

if (typeof globalThis !== 'undefined') {
  globalThis.SentinelVisualAgent = VisualAgent;
}
