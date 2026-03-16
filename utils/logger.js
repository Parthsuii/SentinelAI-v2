/**
 * SentinelAI v2.0 — Structured Logger
 */

const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3, NONE: 4 };
let currentLevel = LOG_LEVELS.INFO;

const SentinelLogger = {
  setLevel(level) {
    currentLevel = LOG_LEVELS[level] ?? LOG_LEVELS.INFO;
  },

  _format(level, module, msg, data) {
    const ts = new Date().toISOString().slice(11, 23);
    const prefix = `%c[SentinelAI ${ts}] [${level}] [${module}]`;
    return { prefix, msg, data };
  },

  debug(module, msg, data) {
    if (currentLevel <= LOG_LEVELS.DEBUG) {
      const f = this._format('DBG', module, msg, data);
      console.debug(f.prefix, 'color:#8e8e8e', f.msg, f.data ?? '');
    }
  },

  info(module, msg, data) {
    if (currentLevel <= LOG_LEVELS.INFO) {
      const f = this._format('INF', module, msg, data);
      console.info(f.prefix, 'color:#00e5ff', f.msg, f.data ?? '');
    }
  },

  warn(module, msg, data) {
    if (currentLevel <= LOG_LEVELS.WARN) {
      const f = this._format('WRN', module, msg, data);
      console.warn(f.prefix, 'color:#ffd740', f.msg, f.data ?? '');
    }
  },

  error(module, msg, data) {
    if (currentLevel <= LOG_LEVELS.ERROR) {
      const f = this._format('ERR', module, msg, data);
      console.error(f.prefix, 'color:#ff1744', f.msg, f.data ?? '');
    }
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.SentinelLogger = SentinelLogger;
}
