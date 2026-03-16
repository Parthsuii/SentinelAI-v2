/**
 * SentinelAI v2.0 — URL Agent
 * URL & Intel analysis — pattern matching, homoglyph detection, TLD reputation.
 * Stub LLM call for advanced analysis (points to Ollama).
 */

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
  '.work', '.date', '.racing', '.win', '.bid', '.stream', '.click',
  '.link', '.loan', '.trade', '.cricket', '.science', '.party'
];

const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
  'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'ɡ': 'g', 'ɩ': 'l'
};

const BRAND_DOMAINS = [
  'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
  'amazon.com', 'paypal.com', 'netflix.com', 'instagram.com',
  'twitter.com', 'linkedin.com', 'chase.com', 'bankofamerica.com',
  'wellsfargo.com', 'dropbox.com', 'outlook.com', 'icloud.com'
];

class URLAgent {
  constructor() {
    this.name = 'url-agent';
  }

  /**
   * Analyze a URL for threat signals
   * @param {string} url - The URL to analyze
   * @returns {Object} - { score: 0-100, threats: [], details: {} }
   */
  analyze(url) {
    const threats = [];
    let score = 0;

    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const fullUrl = parsed.href.toLowerCase();

      // 1. Check suspicious TLD
      const tld = '.' + hostname.split('.').pop();
      if (SUSPICIOUS_TLDS.includes(tld)) {
        score += 20;
        threats.push({ type: 'suspicious-tld', detail: `TLD ${tld} is commonly used in phishing` });
      }

      // 2. Check for homoglyphs in hostname
      const homoglyphCount = this._countHomoglyphs(hostname);
      if (homoglyphCount > 0) {
        score += 30;
        threats.push({ type: 'homoglyph', detail: `${homoglyphCount} homoglyph character(s) detected in hostname` });
      }

      // 3. Check for brand impersonation
      const brandMatch = this._checkBrandImpersonation(hostname);
      if (brandMatch) {
        score += 35;
        threats.push({ type: 'brand-impersonation', detail: `Possible impersonation of ${brandMatch}` });
      }

      // 4. Check for IP address hostname
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        score += 15;
        threats.push({ type: 'ip-hostname', detail: 'URL uses IP address instead of domain name' });
      }

      // 5. Check for excessive subdomains
      const subdomainCount = hostname.split('.').length - 2;
      if (subdomainCount > 3) {
        score += 10;
        threats.push({ type: 'excessive-subdomains', detail: `${subdomainCount} subdomains detected` });
      }

      // 6. Check for suspicious URL patterns
      if (/login|signin|verify|secure|account|update|confirm/i.test(fullUrl) && SUSPICIOUS_TLDS.includes(tld)) {
        score += 15;
        threats.push({ type: 'phishing-pattern', detail: 'Login/verify keywords with suspicious TLD' });
      }

      // 7. Check for data URI
      if (parsed.protocol === 'data:') {
        score += 25;
        threats.push({ type: 'data-uri', detail: 'Data URI can hide malicious content' });
      }

      // 8. Check for non-standard port
      if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
        score += 5;
        threats.push({ type: 'non-standard-port', detail: `Non-standard port: ${parsed.port}` });
      }

      // 9. Check URL length
      if (fullUrl.length > 200) {
        score += 5;
        threats.push({ type: 'long-url', detail: `Unusually long URL (${fullUrl.length} chars)` });
      }

      // 10. HTTP instead of HTTPS
      if (parsed.protocol === 'http:') {
        score += 10;
        threats.push({ type: 'no-https', detail: 'Connection is not encrypted (HTTP)' });
      }

    } catch(e) {
      score += 10;
      threats.push({ type: 'invalid-url', detail: 'URL could not be parsed' });
    }

    return {
      agent: this.name,
      score: Math.min(score, 100),
      threats,
      timestamp: Date.now()
    };
  }

  _countHomoglyphs(hostname) {
    let count = 0;
    for (const char of hostname) {
      if (HOMOGLYPHS[char]) count++;
    }
    return count;
  }

  _checkBrandImpersonation(hostname) {
    for (const brand of BRAND_DOMAINS) {
      const brandName = brand.split('.')[0];
      // Check if hostname contains brand name but isn't the actual domain
      if (hostname.includes(brandName) && !hostname.endsWith(brand)) {
        return brand;
      }
    }
    return null;
  }

  /**
   * Stub LLM call — would call Ollama phi4-mini for advanced URL analysis
   */
  async analyzeLLM(url) {
    // Stub: return heuristic result
    return this.analyze(url);
  }
}

// Export
if (typeof globalThis !== 'undefined') {
  globalThis.SentinelURLAgent = URLAgent;
}
