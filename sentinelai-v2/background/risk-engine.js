/**
 * SentinelAI v3.0 — Risk Engine
 * Weighted risk score calculator.
 * Aggregates scores from all 8 agents using the v3 architecture's weight matrix.
 */

importScripts('../agents/url-agent.js');
importScripts('../agents/content-agent.js');
importScripts('../agents/runtime-agent.js');
importScripts('../agents/visual-agent.js');
importScripts('../agents/exfil-agent.js');
importScripts('../agents/orchestrator-agent.js');

class RiskEngine {
  constructor() {
    this.urlAgent = new SentinelURLAgent();
    this.contentAgent = new SentinelContentAgent();
    this.runtimeAgent = new SentinelRuntimeAgent();
    this.visualAgent = new SentinelVisualAgent();
    this.exfilAgent = new SentinelExfilAgent();
    this.orchestrator = new SentinelOrchestratorAgent();
  }

  /**
   * Run full scan pipeline
   * @param {Object} params
   * @param {string} params.url - The page URL
   * @param {Object} params.pageSignals - Content extracted from page
   * @param {Array} params.hookEvents - Runtime hook events
   * @param {number} params.tabId - Chrome tab ID
   * @returns {Object} - Final orchestrated verdict
   */
  async runFullScan({ url, pageSignals, hookEvents, tabId }) {
    const results = {};

    // 1. URL Agent
    results['url-agent'] = this.urlAgent.analyze(url);

    // 2. Content Agent
    if (pageSignals) {
      results['content-agent'] = this.contentAgent.analyze(pageSignals);
    }

    // 3. Runtime Agent
    if (hookEvents && hookEvents.length > 0) {
      const hostname = pageSignals?.hostname || new URL(url).hostname;
      results['runtime-agent'] = this.runtimeAgent.analyze(hookEvents, hostname);
    }

    // 4. Visual Agent
    if (pageSignals) {
      results['visual-agent'] = this.visualAgent.analyze(pageSignals);
    }

    // 5. Exfil Agent
    if (hookEvents && hookEvents.length > 0) {
      results['exfil-agent'] = this.exfilAgent.analyze(hookEvents);
    }

    // 6. Orchestrator — aggregate all
    const verdict = this.orchestrator.aggregate(results);

    return {
      ...verdict,
      url,
      individualResults: results
    };
  }

  /**
   * Quick URL-only scan (for initial page load)
   */
  quickScan(url) {
    const urlResult = this.urlAgent.analyze(url);
    return {
      compositeScore: urlResult.score,
      level: urlResult.score < 30 ? 'safe' : urlResult.score < 40 ? 'low' : urlResult.score < 75 ? 'medium' : urlResult.score < 80 ? 'high' : 'critical',
      urlResult,
      timestamp: Date.now()
    };
  }
}

globalThis.SentinelRiskEngine = RiskEngine;
