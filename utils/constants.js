/**
 * SentinelAI v2.0 — Shared Constants
 */

// ── Threat Levels ──
const THREAT_LEVEL = {
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

const THREAT_COLORS = {
  [THREAT_LEVEL.SAFE]: '#00e676',
  [THREAT_LEVEL.LOW]: '#69f0ae',
  [THREAT_LEVEL.MEDIUM]: '#ffd740',
  [THREAT_LEVEL.HIGH]: '#ff6e40',
  [THREAT_LEVEL.CRITICAL]: '#ff1744'
};

// ── Hook Names ──
const HOOK_NAMES = {
  FETCH: 'fetch',
  XHR: 'xhr',
  EVAL: 'eval',
  DOM_WRITE: 'dom-write',
  MUTATION: 'mutation',
  BEACON: 'beacon',
  WEBSOCKET: 'websocket',
  POSTMESSAGE: 'postmessage',
  FORM: 'form',
  CLIPBOARD: 'clipboard',
  CANVAS: 'canvas',
  TIMER: 'timer'
};

// ── Agent Names ──
const AGENT_NAMES = {
  URL: 'url-agent',
  CONTENT: 'content-agent',
  RUNTIME: 'runtime-agent',
  VISUAL: 'visual-agent',
  EXFIL: 'exfil-agent',
  ORCHESTRATOR: 'orchestrator-agent'
};

// ── Risk Score Weights (from architecture) ──
const RISK_WEIGHTS = {
  [AGENT_NAMES.URL]: 0.25,
  [AGENT_NAMES.CONTENT]: 0.20,
  [AGENT_NAMES.RUNTIME]: 0.35,
  [AGENT_NAMES.VISUAL]: 0.05,
  [AGENT_NAMES.EXFIL]: 0.15
};

// ── AI Model Endpoints (Ollama) ──
const AI_ENDPOINTS = {
  OLLAMA: 'http://localhost:11434/api/generate'
};

const AI_MODELS = {
  PHI4_MINI: 'phi4-mini',
  QWEN_1_5B: 'qwen2.5:1.5b',
  SMOLLM2: 'smollm2:1.7b',
  ORCHESTRATOR: 'qwen2.5:3b'
};

// ── Scan Config ──
const SCAN_CONFIG = {
  SANDBOX_TIMEOUT_MS: 500,
  PRIVACY_WINDOW_MS: 300,
  MAX_EVENTS_STORED: 200,
  MAX_SCAN_HISTORY: 100,
  BADGE_UPDATE_INTERVAL_MS: 1000
};

// ── Suspicious Patterns ──
const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
  '.work', '.date', '.racing', '.win', '.bid', '.stream', '.click',
  '.link', '.loan', '.trade', '.cricket', '.science', '.party'
];

const SUSPICIOUS_URL_PATTERNS = [
  /login.*\.(?:tk|ml|ga|cf|gq)/i,
  /secure.*bank/i,
  /account.*verify/i,
  /paypal.*\.(?!com$)/i,
  /google.*\.(?!com$|co\.|com\.|org$)/i,
  /microsoft.*\.(?!com$)/i,
  /apple.*\.(?!com$)/i,
  /amazon.*\.(?!com$|co\.|com\.)/i
];

// ── Homoglyph Map ──
const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
  'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'ɡ': 'g', 'ɩ': 'l',
  '0': 'o', '1': 'l', 'rn': 'm'
};

// ── Phishing Content Patterns ──
const PHISHING_TEXT_PATTERNS = [
  /your account (?:has been|was) (?:suspended|locked|compromised)/i,
  /verify your (?:identity|account|email)/i,
  /unusual (?:activity|sign.?in|login)/i,
  /update your (?:payment|billing|credit card)/i,
  /confirm your (?:password|credentials)/i,
  /click (?:here|below) (?:to|within) (?:\d+\s*hours?)/i,
  /your (?:package|shipment|order) (?:could not|cannot) be delivered/i,
  /you have won/i,
  /congratulations.*prize/i,
  /limited time.*act now/i
];

// ── Message Types ──
const MSG = {
  HOOK_EVENT: 'SENTINEL_HOOK_EVENT',
  SCAN_REQUEST: 'SENTINEL_SCAN_REQUEST',
  SCAN_RESULT: 'SENTINEL_SCAN_RESULT',
  GET_STATUS: 'SENTINEL_GET_STATUS',
  STATUS_RESPONSE: 'SENTINEL_STATUS_RESPONSE',
  SANDBOX_RESULT: 'SENTINEL_SANDBOX_RESULT',
  BLOCK_SITE: 'SENTINEL_BLOCK_SITE',
  WHITELIST_SITE: 'SENTINEL_WHITELIST_SITE',
  GET_HISTORY: 'SENTINEL_GET_HISTORY',
  CLEAR_HISTORY: 'SENTINEL_CLEAR_HISTORY'
};

// Export for both content scripts and ES modules
if (typeof globalThis !== 'undefined') {
  globalThis.SENTINEL_CONSTANTS = {
    THREAT_LEVEL, THREAT_COLORS, HOOK_NAMES, AGENT_NAMES,
    RISK_WEIGHTS, AI_ENDPOINTS, AI_MODELS, SCAN_CONFIG,
    SUSPICIOUS_TLDS, SUSPICIOUS_URL_PATTERNS, HOMOGLYPHS,
    PHISHING_TEXT_PATTERNS, MSG
  };
}
