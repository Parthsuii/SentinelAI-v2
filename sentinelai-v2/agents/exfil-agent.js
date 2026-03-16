/**
 * SentinelAI v2.0 — Exfil Agent
 * Obfuscated outbound payload decoder & analyzer.
 * Detects base64, hex, and encoded exfiltration payloads.
 * Stub Qwen2.5-1.5B LLM call for deep payload analysis.
 */

class ExfilAgent {
  constructor() {
    this.name = 'exfil-agent';
  }

  /**
   * Analyze outbound events for data exfiltration
   * @param {Array} events - Network-related hook events (fetch, xhr, beacon, websocket)
   * @returns {Object} - { score: 0-100, threats: [] }
   */
  analyze(events) {
    const threats = [];
    let score = 0;

    const networkEvents = (events || []).filter(e =>
      ['fetch', 'xhr', 'beacon', 'websocket'].includes(e.hook)
    );

    if (networkEvents.length === 0) {
      return { agent: this.name, score: 0, threats: [], timestamp: Date.now() };
    }

    for (const event of networkEvents) {
      const body = event.data?.bodyPreview || event.data?.dataPreview || '';
      const url = event.data?.url || '';

      // 1. Check for base64-encoded payloads
      if (this._isBase64(body)) {
        const decoded = this._tryDecodeBase64(body);
        score += 20;
        threats.push({
          type: 'base64-exfil',
          detail: `Base64-encoded data sent via ${event.hook}`,
          decodedPreview: decoded ? decoded.substring(0, 100) : null
        });

        // Check if decoded content contains sensitive data patterns
        if (decoded && this._containsSensitiveData(decoded)) {
          score += 25;
          threats.push({ type: 'sensitive-data-exfil', detail: 'Decoded payload contains possible credentials/PII' });
        }
      }

      // 2. Check for hex-encoded payloads
      if (this._isHexEncoded(body)) {
        score += 15;
        threats.push({ type: 'hex-exfil', detail: `Hex-encoded data sent via ${event.hook}` });
      }

      // 3. Check URL for encoded data
      if (url.length > 500 && this._hasEncodedParams(url)) {
        score += 15;
        threats.push({ type: 'url-exfil', detail: 'Data exfiltrated via long encoded URL parameters' });
      }

      // 4. Check for credentials in body
      if (body && this._containsSensitiveData(body)) {
        score += 20;
        threats.push({ type: 'credential-exfil', detail: `Possible credentials sent via ${event.hook}` });
      }

      // 5. Third-party exfiltration
      if (event.data?.destination) {
        try {
          const destOrigin = new URL(event.data.destination).origin;
          if (destOrigin !== event.origin && event.data.bodyPreview) {
            score += 10;
            threats.push({ type: 'third-party-exfil', detail: `Data sent to third-party: ${destOrigin}` });
          }
        } catch(e) { /* ignore */ }
      }
    }

    return {
      agent: this.name,
      score: Math.min(score, 100),
      threats,
      timestamp: Date.now()
    };
  }

  _isBase64(str) {
    if (!str || str.length < 20) return false;
    return /^[A-Za-z0-9+/=]{20,}$/.test(str.trim());
  }

  _tryDecodeBase64(str) {
    try {
      return atob(str.trim());
    } catch(e) {
      return null;
    }
  }

  _isHexEncoded(str) {
    if (!str || str.length < 20) return false;
    return /^[0-9a-fA-F]{20,}$/.test(str.trim());
  }

  _hasEncodedParams(url) {
    return /%[0-9a-fA-F]{2}/.test(url) && url.split('%').length > 10;
  }

  _containsSensitiveData(text) {
    const patterns = [
      /password/i,
      /passwd/i,
      /credit.?card/i,
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // CC number
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,  // email
      /bearer\s+[a-zA-Z0-9\-._~+/]+=*/i, // Bearer token
      /api[_-]?key/i
    ];
    return patterns.some(p => p.test(text));
  }

  /**
   * Stub LLM call — would call Qwen2.5-1.5B for deep payload analysis
   */
  async analyzeLLM(events) {
    return this.analyze(events);
  }
}

if (typeof globalThis !== 'undefined') {
  globalThis.SentinelExfilAgent = ExfilAgent;
}
