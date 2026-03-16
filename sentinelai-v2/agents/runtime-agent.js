/**
 * SentinelAI v2.0 — Runtime Agent
 * Analyzes runtime hook events for threat signals.
 * Stub Phi-4-mini LLM call for advanced behavioral analysis.
 */

class RuntimeAgent {
  constructor() {
    this.name = 'runtime-agent';
  }

  /**
   * Analyze a batch of hook events
   * @param {Array} events - Hook events from content script
   * @param {string} hostname - The page hostname
   * @returns {Object} - { score: 0-100, threats: [] }
   */
  analyze(events, hostname) {
    const threats = [];
    let score = 0;

    if (!events || events.length === 0) {
      return { agent: this.name, score: 0, threats: [], timestamp: Date.now() };
    }

    // Categorize events by hook
    const hookCounts = {};
    events.forEach(e => {
      hookCounts[e.hook] = (hookCounts[e.hook] || 0) + 1;
    });

    // 1. Excessive network calls (potential exfiltration)
    const networkCalls = (hookCounts['fetch'] || 0) + (hookCounts['xhr'] || 0) + (hookCounts['beacon'] || 0);
    if (networkCalls > 20) {
      score += 15;
      threats.push({ type: 'excessive-network', detail: `${networkCalls} outbound network calls detected` });
    }

    // 2. Eval usage (code injection)
    if (hookCounts['eval'] > 0) {
      score += 20;
      threats.push({ type: 'eval-usage', detail: `${hookCounts['eval']} eval/Function calls detected` });

      // Check eval events for suspicious patterns
      events.filter(e => e.hook === 'eval').forEach(e => {
        if (e.data?.hasBase64) {
          score += 15;
          threats.push({ type: 'eval-base64', detail: 'Eval contains base64 decoding (possible obfuscated malware)' });
        }
        if (e.data?.hasNetworkCall) {
          score += 15;
          threats.push({ type: 'eval-network', detail: 'Eval contains network calls (possible exfiltration)' });
        }
      });
    }

    // 3. DOM injection (mutation observer events)
    const mutationEvents = events.filter(e => e.hook === 'mutation');
    const iframeInjections = mutationEvents.filter(e => e.data?.reason === 'iframe-injection');
    const overlayInjections = mutationEvents.filter(e => e.data?.reason === 'overlay-injection');
    const formInjections = mutationEvents.filter(e => e.data?.reason === 'form-injection');

    if (iframeInjections.length > 0) {
      score += 20;
      threats.push({ type: 'iframe-injection', detail: `${iframeInjections.length} iframe(s) dynamically injected` });
    }
    if (overlayInjections.length > 0) {
      score += 25;
      threats.push({ type: 'overlay-injection', detail: 'Full-screen overlay detected (possible clickjacking)' });
    }
    if (formInjections.length > 0) {
      score += 20;
      threats.push({ type: 'form-injection', detail: 'Form dynamically injected (possible credential phishing)' });
    }

    // 4. DOM write with scripts
    const domWriteEvents = events.filter(e => e.hook === 'dom-write');
    domWriteEvents.forEach(e => {
      if (e.data?.hasScript) {
        score += 15;
        threats.push({ type: 'script-injection', detail: 'Script injected via document.write/innerHTML' });
      }
    });

    // 5. WebSocket connections
    const wsConnections = events.filter(e => e.hook === 'websocket' && e.data?.action === 'connect');
    if (wsConnections.length > 3) {
      score += 10;
      threats.push({ type: 'excessive-websocket', detail: `${wsConnections.length} WebSocket connections opened` });
    }

    // 6. Canvas fingerprinting
    if (hookCounts['canvas'] > 0) {
      score += 10;
      threats.push({ type: 'fingerprinting', detail: 'Browser fingerprinting via canvas/WebGL detected' });
    }

    // 7. Clipboard access
    const clipboardReads = events.filter(e => e.hook === 'clipboard' && e.data?.action === 'read');
    if (clipboardReads.length > 0) {
      score += 15;
      threats.push({ type: 'clipboard-read', detail: 'Page attempted to read clipboard' });
    }

    // 8. Deferred suspicious timers
    const suspiciousTimers = events.filter(e => e.hook === 'timer' && e.data?.hasSuspiciousPatterns);
    if (suspiciousTimers.length > 0) {
      score += 15;
      threats.push({ type: 'deferred-malware', detail: `${suspiciousTimers.length} deferred suspicious timer(s) detected` });
    }

    // 9. Cross-origin form submissions
    const formEvents = events.filter(e => e.hook === 'form' && e.data?.actionIsCrossOrigin);
    if (formEvents.length > 0) {
      formEvents.forEach(e => {
        if (e.data?.hasPasswordField) {
          score += 30;
          threats.push({ type: 'credential-exfil', detail: 'Password submitted to cross-origin server' });
        }
      });
    }

    // 10. Beacon exfiltration patterns
    const beaconEvents = events.filter(e => e.hook === 'beacon');
    if (beaconEvents.length > 5) {
      score += 15;
      threats.push({ type: 'beacon-exfil', detail: `${beaconEvents.length} sendBeacon calls (possible tracking/exfiltration)` });
    }

    return {
      agent: this.name,
      score: Math.min(score, 100),
      threats,
      hookCounts,
      timestamp: Date.now()
    };
  }

  /**
   * Stub LLM call — would call Phi-4-mini for behavioral analysis
   */
  async analyzeLLM(events, hostname) {
    return this.analyze(events, hostname);
  }
}

if (typeof globalThis !== 'undefined') {
  globalThis.SentinelRuntimeAgent = RuntimeAgent;
}
