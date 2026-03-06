/**
 * Tamper-Evident Audit Logger.
 *
 * Hash-chained append-only JSONL logs for EU AI Act Article 12 compliance.
 * Each entry's SHA-256 hash includes the previous entry's hash.
 * Any modification breaks the chain from that point forward.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const GENESIS_HASH = '0'.repeat(64);

class AuditLogger {
  /**
   * @param {import('./config').ShieldConfig} config
   */
  constructor(config) {
    this.config = config;
    this._seq = 0;
    this._prevHash = GENESIS_HASH;
    this._logDir = config.logDir;
    this._initialized = false;
  }

  _ensureInit() {
    if (this._initialized) return;

    fs.mkdirSync(this._logDir, { recursive: true });

    // Recover chain state from most recent log file
    const logFiles = this._getLogFiles();
    if (logFiles.length > 0) {
      const lastFile = logFiles[logFiles.length - 1];
      try {
        const content = fs.readFileSync(lastFile, 'utf-8');
        const lines = content.split('\n').filter(l => l.trim());
        if (lines.length > 0) {
          const lastEntry = JSON.parse(lines[lines.length - 1]);
          this._seq = lastEntry.seq + 1;
          this._prevHash = lastEntry.entry_hash;
        }
      } catch {
        // Start fresh if corrupted
      }
    }

    this._initialized = true;
  }

  _getLogFiles() {
    if (!fs.existsSync(this._logDir)) return [];
    return fs.readdirSync(this._logDir)
      .filter(f => f.startsWith('audit_') && f.endsWith('.jsonl'))
      .sort()
      .map(f => path.join(this._logDir, f));
  }

  _getLogFile() {
    const today = new Date().toISOString().split('T')[0];
    return path.join(this._logDir, `audit_${today}.jsonl`);
  }

  /**
   * Compute SHA-256 hash of entry data.
   * @param {Object} data
   * @returns {string}
   */
  static computeHash(data) {
    // Deterministic serialization: recursively sort keys at all levels
    const sorted = JSON.stringify(data, (_, v) => {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        return Object.keys(v).sort().reduce((o, k) => { o[k] = v[k]; return o; }, {});
      }
      return v;
    });
    return crypto.createHash('sha256').update(sorted).digest('hex');
  }

  /**
   * Append a new entry to the audit log.
   * @param {Object} options
   * @returns {Object|null}
   */
  log({
    eventType,
    originalText = '',
    sanitizedText = '',
    model = null,
    provider = null,
    entityCount = 0,
    categories = {},
    tokensUsed = [],
    latencyMs = 0,
    mode = null,
    entityDetails = [],
    metadata = {},
  }) {
    if (!this.config.auditEnabled) return null;

    this._ensureInit();

    const entryData = {
      seq: this._seq,
      event_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      event_type: eventType,
      model,
      provider,
      entity_count: entityCount,
      categories,
      tokens_used: tokensUsed,
      prompt_hash: originalText
        ? crypto.createHash('sha256').update(originalText).digest('hex')
        : '',
      sanitized_hash: sanitizedText
        ? crypto.createHash('sha256').update(sanitizedText).digest('hex')
        : '',
      latency_ms: Math.round(latencyMs * 100) / 100,
      mode,
      entity_details: entityDetails,
      prev_hash: this._prevHash,
      metadata,
    };

    const entryHash = AuditLogger.computeHash(entryData);
    entryData.entry_hash = entryHash;

    // Write to log file
    const logFile = this._getLogFile();
    fs.appendFileSync(logFile, JSON.stringify(entryData) + '\n');

    // Update chain state
    this._prevHash = entryHash;
    this._seq += 1;

    return entryData;
  }

  /**
   * Verify the integrity of the entire audit chain.
   * @param {string} [logFilePath] - Specific file, or all files in logDir
   * @returns {{ valid: boolean, errors: string[] }}
   */
  verifyChain(logFilePath = null) {
    const errors = [];
    const files = logFilePath ? [logFilePath] : this._getLogFiles();

    if (files.length === 0) return { valid: true, errors: [] };

    let prevHash = GENESIS_HASH;

    for (const fpath of files) {
      const content = fs.readFileSync(fpath, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim());
      const fname = path.basename(fpath);

      for (let i = 0; i < lines.length; i++) {
        let entry;
        try {
          entry = JSON.parse(lines[i]);
        } catch {
          errors.push(`${fname}:${i + 1} — Invalid JSON`);
          continue;
        }

        // Check chain link
        if (entry.prev_hash !== prevHash) {
          errors.push(
            `${fname}:${i + 1} seq=${entry.seq} — ` +
            `Chain broken: expected prev_hash=${prevHash.slice(0, 16)}..., ` +
            `got ${(entry.prev_hash || 'MISSING').slice(0, 16)}...`
          );
        }

        // Recompute entry hash
        const storedHash = entry.entry_hash;
        delete entry.entry_hash;
        const recomputed = AuditLogger.computeHash(entry);
        if (storedHash !== recomputed) {
          errors.push(
            `${fname}:${i + 1} seq=${entry.seq} — ` +
            `Entry tampered: stored_hash=${storedHash.slice(0, 16)}..., ` +
            `recomputed=${recomputed.slice(0, 16)}...`
          );
        }

        prevHash = storedHash;
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Get aggregate statistics from audit logs.
   * @returns {Object}
   */
  getStats() {
    this._ensureInit();
    const stats = {
      total_events: 0,
      total_entities_detected: 0,
      categories: {},
      models_used: new Set(),
      log_files: [],
    };

    for (const fpath of this._getLogFiles()) {
      stats.log_files.push(path.basename(fpath));
      const content = fs.readFileSync(fpath, 'utf-8');
      for (const line of content.split('\n').filter(l => l.trim())) {
        try {
          const entry = JSON.parse(line);
          stats.total_events += 1;
          stats.total_entities_detected += entry.entity_count || 0;
          for (const [cat, count] of Object.entries(entry.categories || {})) {
            stats.categories[cat] = (stats.categories[cat] || 0) + count;
          }
          if (entry.model) stats.models_used.add(entry.model);
        } catch { /* skip corrupt lines */ }
      }
    }

    stats.models_used = [...stats.models_used];
    return stats;
  }
}

module.exports = { AuditLogger, GENESIS_HASH };
