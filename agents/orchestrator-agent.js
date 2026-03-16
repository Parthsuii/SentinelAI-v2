/**
 * SentinelAI v2.0 — Orchestrator Agent
 * Aggregates scores from all 5 analysis agents using weighted risk matrix.
 * Emits final verdict and threat level.
 */

const AGENT_WEIGHTS = {
  'url-agent': 0.20,
  'content-agent': 0.20,
  'runtime-agent': 0.30,
  'visual-agent': 0.15,
  'exfil-agent': 0.15
};

const LEVEL_THRESHOLDS = {
  safe: 15,
  low: 30,
  medium: 55,
  high: 80
  // >= 80 = critical
};

class OrchestratorAgent {
  constructor() {
    this.name = 'orchestrator-agent';
  }

  /**
   * Aggregate all agent results into a final verdict
   * @param {Object} results - Map of agent name to their analysis result
   * @returns {Object} - Final verdict with composite score, level, and all threats
   */
  aggregate(results) {
    let compositeScore = 0;
    const allThreats = [];
    const agentBreakdown = {};

    for (const [agentName, weight] of Object.entries(AGENT_WEIGHTS)) {
      const result = results[agentName];
      if (result) {
        const weightedScore = result.score * weight;
        compositeScore += weightedScore;
        agentBreakdown[agentName] = {
          rawScore: result.score,
          weight,
          weightedScore: Math.round(weightedScore * 10) / 10,
          threatCount: result.threats?.length || 0
        };
        if (result.threats) {
          result.threats.forEach(t => {
            allThreats.push({ ...t, source: agentName });
          });
        }
      } else {
        agentBreakdown[agentName] = { rawScore: 0, weight, weightedScore: 0, threatCount: 0 };
      }
    }

    compositeScore = Math.round(Math.min(compositeScore, 100) * 10) / 10;

    // Determine threat level
    let level;
    if (compositeScore < LEVEL_THRESHOLDS.safe) level = 'safe';
    else if (compositeScore < LEVEL_THRESHOLDS.low) level = 'low';
    else if (compositeScore < LEVEL_THRESHOLDS.medium) level = 'medium';
    else if (compositeScore < LEVEL_THRESHOLDS.high) level = 'high';
    else level = 'critical';

    // Sort threats by severity (source agent weight * raw score)
    allThreats.sort((a, b) => {
      const aWeight = AGENT_WEIGHTS[a.source] || 0;
      const bWeight = AGENT_WEIGHTS[b.source] || 0;
      return bWeight - aWeight;
    });

    return {
      agent: this.name,
      compositeScore,
      level,
      allThreats,
      agentBreakdown,
      recommendation: this._getRecommendation(level),
      timestamp: Date.now()
    };
  }

  _getRecommendation(level) {
    switch(level) {
      case 'safe': return 'This site appears safe. No threats detected.';
      case 'low': return 'Minor concerns detected. Proceed with normal caution.';
      case 'medium': return 'Moderate risk detected. Exercise caution with sensitive data.';
      case 'high': return 'High risk! Avoid entering credentials or personal information.';
      case 'critical': return 'CRITICAL THREAT! This site is likely malicious. Leave immediately.';
      default: return 'Unable to determine risk level.';
    }
  }
}

if (typeof globalThis !== 'undefined') {
  globalThis.SentinelOrchestratorAgent = OrchestratorAgent;
}
