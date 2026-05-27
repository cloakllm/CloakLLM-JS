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
const { canonicalJson, _legacyCanonicalJson } = require('./_canonical');

const GENESIS_HASH = '0'.repeat(64);

const _PII_FORBIDDEN_KEYS = ['original_value', 'original_text', 'raw_text', 'plain_text', 'value'];

// v0.6.3 H9: Prototype-pollution vector keys. When user-controlled JSON flows
// into object key assignments via `obj[k] = v`, these three names trigger
// JS engine setters that mutate the prototype chain rather than creating own
// properties -- and the pollution affects every object in the runtime.
// Centralized here so all validation sites use the same definition.
const _PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function _isPrototypePollutionKey(k) {
  return _PROTOTYPE_POLLUTION_KEYS.has(k);
}

// v0.6.1 B3: allow-list schema validator. Always-on (not gated on complianceMode).
// See cloakllm-py/cloakllm/audit.py B3 docstring for full rationale.
const _ENTRY_ALLOWED_KEYS = new Set([
  'seq', 'event_id', 'timestamp', 'event_type', 'model', 'provider',
  'entity_count', 'categories', 'tokens_used', 'prompt_hash', 'sanitized_hash',
  'latency_ms', 'mode', 'entity_details', 'timing', 'certificate_hash',
  'key_id', 'prev_hash', 'entry_hash', 'metadata', 'risk_assessment',
  // v0.6.0 compliance-mode fields
  'compliance_version', 'article_ref', 'retention_hint_days', 'pii_in_log',
  // v0.7.0 A4a-3 -- Article 4a bias-detection context (only present on bias_* events)
  'bias_context',
  // v0.7.1 C7.1-1 / C7.1-2 -- Compliance-schema extensions
  'decision_id',
  'system_version_pin',
]);

// v0.7.0 A4a-3: bias_context schema. See cloakllm-py audit.py for full rationale.
// Wider per-string cap than `metadata` (necessity_justification is <= 2000 chars
// by design) -- kept on a per-key allow-list so the looser limit cannot be abused
// as a generic PII sink.
const _BIAS_CONTEXT_ALLOWED_KEYS = new Set([
  'session_id', 'purpose', 'necessity_justification', 'categories_allowed',
  'max_lifetime_seconds', 'categories_used', 'entity_count', 'exit_reason',
  'wipe_confirmed', 'entries_processed', 'duration_seconds', 'finding_summary',
  'bias_metrics',
]);
const _BIAS_CONTEXT_STR_MAX_LEN = {
  session_id: 64,
  purpose: 500,
  necessity_justification: 2000,
  exit_reason: 32,
  finding_summary: 500,
};
const _BIAS_CONTEXT_NUMERIC_FIELDS = new Set([
  'max_lifetime_seconds', 'entity_count', 'entries_processed', 'duration_seconds',
]);
const _BIAS_VALID_EVENT_TYPES = new Set([
  'bias_session_start', 'bias_pseudonymise', 'bias_finding', 'bias_session_end',
]);

function _validateBiasContext(ctx) {
  if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx)) {
    throw new Error(
      `AUDIT SCHEMA VIOLATION: bias_context must be a plain object ` +
      `(got ${Array.isArray(ctx) ? 'array' : typeof ctx}).`
    );
  }
  for (const k of Object.keys(ctx)) {
    if (typeof k !== 'string') {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: bias_context key ${JSON.stringify(k)} must be a string.`
      );
    }
    if (_isPrototypePollutionKey(k)) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: bias_context key ${JSON.stringify(k)} ` +
        `is a prototype-pollution vector.`
      );
    }
    if (!_BIAS_CONTEXT_ALLOWED_KEYS.has(k)) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: bias_context contains disallowed key ` +
        `${JSON.stringify(k)}. Allowed: ` +
        `${Array.from(_BIAS_CONTEXT_ALLOWED_KEYS).sort().join(', ')}.`
      );
    }
    if (_PII_FORBIDDEN_KEYS.includes(k)) {
      throw new Error(
        `COMPLIANCE VIOLATION: bias_context contains forbidden field ` +
        `${JSON.stringify(k)}. Audit logs must not contain original PII.`
      );
    }
    const v = ctx[k];
    if (k in _BIAS_CONTEXT_STR_MAX_LEN) {
      if (typeof v !== 'string') {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.${k} must be a string ` +
          `(got ${typeof v}).`
        );
      }
      const limit = _BIAS_CONTEXT_STR_MAX_LEN[k];
      if (v.length > limit) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.${k} exceeds ${limit} chars ` +
          `(got ${v.length}).`
        );
      }
    } else if (k === 'categories_allowed') {
      if (!Array.isArray(v)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.categories_allowed must be ` +
          `an array (got ${typeof v}).`
        );
      }
      if (v.length > 32) {
        throw new Error(
          'AUDIT SCHEMA VIOLATION: bias_context.categories_allowed exceeds 32 entries.'
        );
      }
      for (let i = 0; i < v.length; i++) {
        if (typeof v[i] !== 'string' || v[i].length > 32) {
          throw new Error(
            `AUDIT SCHEMA VIOLATION: bias_context.categories_allowed[${i}] ` +
            `must be a string <= 32 chars.`
          );
        }
      }
    } else if (k === 'categories_used') {
      if (!v || typeof v !== 'object' || Array.isArray(v)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.categories_used must be a ` +
          `plain object (got ${Array.isArray(v) ? 'array' : typeof v}).`
        );
      }
      const keys = Object.keys(v);
      if (keys.length > 64) {
        throw new Error(
          'AUDIT SCHEMA VIOLATION: bias_context.categories_used exceeds 64 entries.'
        );
      }
      for (const ck of keys) {
        if (typeof ck !== 'string' || ck.length > 32) {
          throw new Error(
            `AUDIT SCHEMA VIOLATION: bias_context.categories_used key ` +
            `${JSON.stringify(ck)} must be a string <= 32 chars.`
          );
        }
        if (typeof v[ck] !== 'number' || !Number.isInteger(v[ck])) {
          throw new Error(
            `AUDIT SCHEMA VIOLATION: bias_context.categories_used[${ck}] ` +
            `must be an integer (got ${typeof v[ck]}).`
          );
        }
      }
    } else if (_BIAS_CONTEXT_NUMERIC_FIELDS.has(k)) {
      if (typeof v !== 'number' || Number.isNaN(v) || !Number.isFinite(v)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.${k} must be a finite number ` +
          `(got ${typeof v}).`
        );
      }
    } else if (k === 'wipe_confirmed') {
      if (typeof v !== 'boolean') {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.wipe_confirmed must be a ` +
          `boolean (got ${typeof v}).`
        );
      }
    } else if (k === 'bias_metrics') {
      if (!v || typeof v !== 'object' || Array.isArray(v)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: bias_context.bias_metrics must be a ` +
          `plain object (got ${Array.isArray(v) ? 'array' : typeof v}).`
        );
      }
      // v0.7.0 SECURITY-13: per-entry key-count cap (log-volume DoS).
      // 64 matches the categories_used cap.
      const bkeys = Object.keys(v);
      if (bkeys.length > 64) {
        throw new Error(
          'AUDIT SCHEMA VIOLATION: bias_context.bias_metrics exceeds 64 keys.'
        );
      }
      for (const bk of bkeys) {
        if (typeof bk !== 'string') {
          throw new Error(
            `AUDIT SCHEMA VIOLATION: bias_metrics key ${JSON.stringify(bk)} ` +
            `must be a string.`
          );
        }
        if (_isPrototypePollutionKey(bk)) {
          throw new Error(
            `AUDIT SCHEMA VIOLATION: bias_metrics key ${JSON.stringify(bk)} ` +
            `is a prototype-pollution vector.`
          );
        }
        _validateMetadataValue(v[bk], 2, `.bias_metrics.${bk}`);
      }
    }
  }
}

// Verified against actual code (tokenizer.js:109-120 + Shield.sanitizeBatch
// adds text_index). 9 keys total.
const _ENTITY_DETAIL_ALLOWED_KEYS = new Set([
  'category', 'start', 'end', 'length', 'confidence',
  'source', 'token', 'entity_hash', 'text_index',
]);

const _METADATA_MAX_VALUE_LEN = 256;
const _METADATA_MAX_DEPTH = 3;

function _validateMetadataValue(value, depth, path) {
  if (depth > _METADATA_MAX_DEPTH) {
    throw new Error(
      `AUDIT SCHEMA VIOLATION: metadata${path} exceeds max nesting depth of ${_METADATA_MAX_DEPTH}.`
    );
  }
  if (value === null || value === undefined) return;
  const t = typeof value;
  if (t === 'string') {
    if (value.length > _METADATA_MAX_VALUE_LEN) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: metadata${path} string exceeds ` +
        `${_METADATA_MAX_VALUE_LEN} chars (got ${value.length}). ` +
        `Long strings risk leaking PII into audit logs.`
      );
    }
    return;
  }
  if (t === 'number' || t === 'boolean') return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      _validateMetadataValue(value[i], depth + 1, `${path}[${i}]`);
    }
    return;
  }
  if (t === 'object') {
    for (const k of Object.keys(value)) {
      if (typeof k !== 'string') {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: metadata${path} key ${JSON.stringify(k)} is not a string.`
        );
      }
      // v0.6.3 H9: REJECT prototype-pollution vectors instead of silently
      // skipping them. The previous `continue` hid the issue from callers,
      // which means downstream consumers of metadata couldn't rely on its
      // shape (and a malicious caller's `__proto__` payload silently passed
      // structural validation while leaving the rest of the dict intact for
      // pollution-based exploits in any later iterator). Hard error makes
      // callers strip these keys before passing JSON-parsed data as metadata.
      if (_isPrototypePollutionKey(k)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: metadata${path} key ${JSON.stringify(k)} ` +
          `is a prototype-pollution vector. Strip __proto__/constructor/prototype ` +
          `from metadata before passing.`
        );
      }
      _validateMetadataValue(value[k], depth + 1, `${path}.${k}`);
    }
    return;
  }
  throw new Error(
    `AUDIT SCHEMA VIOLATION: metadata${path} has disallowed type ${t}. ` +
    `Allowed: string, number, boolean, null, array of those, object of those.`
  );
}

/**
 * v0.6.1 B3: always-on allow-list validator for audit entries. Asserts:
 *  - top-level keys are in the allow-list (rejects unknown fields)
 *  - entity_details elements have only the 9 verified-allowed keys
 *  - metadata values are strict-typed and bounded
 * Throws if violated.
 */
function _validateAuditEntrySchema(entryData) {
  // Top-level keys
  for (const k of Object.keys(entryData)) {
    if (!_ENTRY_ALLOWED_KEYS.has(k)) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: top-level key ${JSON.stringify(k)} is not in ` +
        `the allow-list. This guard prevents arbitrary keys (which may ` +
        `contain PII) from being written to audit logs.`
      );
    }
  }

  // entity_details
  const details = entryData.entity_details || [];
  for (let i = 0; i < details.length; i++) {
    const detail = details[i];
    if (!detail || typeof detail !== 'object' || Array.isArray(detail)) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: entity_details[${i}] is not a plain object ` +
        `(got ${detail === null ? 'null' : typeof detail}).`
      );
    }
    // Check the legacy denylist FIRST so known-PII keys produce the
    // recognizable "COMPLIANCE VIOLATION" message.
    for (const forbidden of _PII_FORBIDDEN_KEYS) {
      if (forbidden in detail) {
        throw new Error(
          `COMPLIANCE VIOLATION: entity_details[${i}] contains forbidden ` +
          `field '${forbidden}'. Audit logs must not contain original PII.`
        );
      }
    }
    for (const k of Object.keys(detail)) {
      if (!_ENTITY_DETAIL_ALLOWED_KEYS.has(k)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: entity_details[${i}] contains disallowed ` +
          `key ${JSON.stringify(k)}. Allowed: ` +
          `${Array.from(_ENTITY_DETAIL_ALLOWED_KEYS).sort().join(', ')}.`
        );
      }
    }
  }

  // metadata
  const metadata = entryData.metadata;
  if (metadata !== null && metadata !== undefined && Object.keys(metadata).length > 0) {
    if (typeof metadata !== 'object' || Array.isArray(metadata)) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: metadata must be a plain object ` +
        `(got ${Array.isArray(metadata) ? 'array' : typeof metadata}).`
      );
    }
    for (const k of Object.keys(metadata)) {
      if (typeof k !== 'string') {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: metadata key ${JSON.stringify(k)} must be a string.`
        );
      }
      // v0.6.3 H9: see _validateMetadataValue for the rationale -- reject loudly.
      if (_isPrototypePollutionKey(k)) {
        throw new Error(
          `AUDIT SCHEMA VIOLATION: metadata key ${JSON.stringify(k)} is a ` +
          `prototype-pollution vector. Strip __proto__/constructor/prototype ` +
          `from metadata before passing.`
        );
      }
      _validateMetadataValue(metadata[k], 1, `.${k}`);
    }
  }

  // v0.7.1 C7.1-1: decision_id -- per-inference audit anchor. Loose validation;
  // accepts caller-supplied IDs from upstream systems too (UUID, integers,
  // opaque tokens). Rejects control bytes + bidi-formatting (SECURITY-13).
  const decisionId = entryData.decision_id;
  if (decisionId !== null && decisionId !== undefined) {
    if (typeof decisionId !== 'string') {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: decision_id must be a string ` +
        `(got ${typeof decisionId}).`
      );
    }
    if (decisionId.length < 1 || decisionId.length > 64) {
      throw new Error(
        'AUDIT SCHEMA VIOLATION: decision_id must be 1..64 chars.'
      );
    }
    for (let i = 0; i < decisionId.length; i++) {
      const c = decisionId.charCodeAt(i);
      if (c < 0x20 || c > 0x7E) {
        throw new Error(
          'AUDIT SCHEMA VIOLATION: decision_id contains a control byte ' +
          'or non-ASCII-printable character.'
        );
      }
    }
  }

  // v0.7.1 C7.1-2: system_version_pin -- composed model@deployment/instruction
  const systemVersionPin = entryData.system_version_pin;
  if (systemVersionPin !== null && systemVersionPin !== undefined) {
    if (typeof systemVersionPin !== 'string') {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: system_version_pin must be a string ` +
        `(got ${typeof systemVersionPin}).`
      );
    }
    if (systemVersionPin.length > 256) {
      throw new Error(
        'AUDIT SCHEMA VIOLATION: system_version_pin exceeds 256 chars.'
      );
    }
  }

  // v0.7.0 A4a-3: bias_context (Article 4a bias-detection events)
  const biasContext = entryData.bias_context;
  if (biasContext !== null && biasContext !== undefined) {
    _validateBiasContext(biasContext);
    // Event_type / bias_context coupling: arbitrary events can't smuggle
    // bias-detection metadata. Auditors must be able to trust that any
    // entry carrying bias_context IS an Article 4a workflow event.
    const ev = entryData.event_type;
    if (!_BIAS_VALID_EVENT_TYPES.has(ev)) {
      throw new Error(
        `AUDIT SCHEMA VIOLATION: bias_context requires event_type in ` +
        `${Array.from(_BIAS_VALID_EVENT_TYPES).sort().join(', ')} ` +
        `(got ${JSON.stringify(ev)}).`
      );
    }
  }
}

/**
 * Deprecated v0.6.1 alias for the validator. Use _validateAuditEntrySchema.
 */
function _assertNoPiiInEntry(entryData) {
  return _validateAuditEntrySchema(entryData);
}

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
    // v0.6.3 H4: When true, the next write prepends `\n`. Set during init
    // recovery if the target log file exists and ends mid-line (partial
    // crash write). Without this, the new entry concatenates onto the
    // truncation and is itself unparseable.
    this._needsLeadingNewline = false;
  }

  /**
   * v0.6.3 H4: Scan backward through log files looking for the last
   * well-formed entry (with both `seq` and `entry_hash`). Skips corrupt
   * trailing lines instead of treating them as evidence the whole file
   * is unusable -- that previously stranded earlier valid entries when
   * a write was partial at crash time.
   *
   * @param {string[]} logFiles
   * @returns {object|null}
   */
  _scanForLastValidEntry(logFiles) {
    for (let fi = logFiles.length - 1; fi >= 0; fi--) {
      let content;
      try {
        content = fs.readFileSync(logFiles[fi], 'utf-8');
      } catch {
        continue;
      }
      const lines = content.split('\n').filter(l => l.trim());
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const entry = JSON.parse(lines[i]);
          if (entry && typeof entry === 'object'
              && 'seq' in entry && 'entry_hash' in entry) {
            return entry;
          }
        } catch {
          // corrupt line -- keep scanning backward in this file
        }
      }
      // file had no valid entries -- try next-older
    }
    return null;
  }

  _ensureInit() {
    if (this._initialized) return;

    // v0.6.3 G7: create the audit dir mode 0o700 so other system users
    // can't list audit log filenames. On Windows the mode is largely
    // ignored -- operators must rely on NTFS ACLs.
    fs.mkdirSync(this._logDir, { recursive: true, mode: 0o700 });
    // If the dir already existed with looser permissions, tighten it.
    // POSIX-only; Windows chmod is a no-op for these bits.
    if (process.platform !== 'win32') {
      try {
        fs.chmodSync(this._logDir, 0o700);
      } catch { /* best effort */ }
    }

    // v0.6.3 H4: backward scan across all files (was: read trailing line of
    // most-recent file only and silently start fresh if it failed to parse).
    const logFiles = this._getLogFiles();
    // v0.6.3 H4: detect partial-write tail on today's file. If it exists and
    // doesn't end with `\n`, the next write prepends one to avoid concat-on-truncation.
    const todayFile = this._getLogFile();
    try {
      if (fs.existsSync(todayFile)) {
        const stat = fs.statSync(todayFile);
        if (stat.size > 0) {
          const fd = fs.openSync(todayFile, 'r');
          try {
            const buf = Buffer.alloc(1);
            fs.readSync(fd, buf, 0, 1, stat.size - 1);
            if (buf[0] !== 0x0a) {  // not '\n'
              this._needsLeadingNewline = true;
            }
          } finally {
            fs.closeSync(fd);
          }
        }
      }
    } catch {
      // best-effort -- if we can't probe, fall through; next write may concat.
    }
    const lastEntry = this._scanForLastValidEntry(logFiles);
    if (lastEntry !== null) {
      this._seq = lastEntry.seq + 1;
      this._prevHash = lastEntry.entry_hash;
    } else if (logFiles.length > 0 && this.config.auditStrictChain) {
      // v0.6.3 H4: refuse silent GENESIS restart when files exist but
      // recovery returned nothing -- that surface lets an attacker mask
      // tampering as a normal restart.
      throw new Error(
        `CloakLLM audit chain recovery failed: log dir '${this._logDir}' ` +
        `contains ${logFiles.length} file(s) but none have a recoverable ` +
        `trailing entry. Refusing to silently restart from GENESIS ` +
        `(auditStrictChain=true). Inspect the files for corruption -- a ` +
        `silent restart would let an attacker mask tampering as a restart.`
      );
    }
    // else: log dir empty OR all files empty AND strict mode off → start
    // from GENESIS (back-compat default).

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
   *
   * @param {Object} data - The audit entry dict.
   * @param {Object} [options]
   * @param {boolean} [options.legacyCanonical=false] - When true, use the
   *   v0.6.0-compatible canonicalizer (replacer-based JSON.stringify). Used
   *   ONLY by `verifyChain` when the caller opts in to verifying a pre-v0.6.1
   *   chain. Sunset in v0.7.0.
   * @returns {string}
   */
  static computeHash(data, options = null) {
    const legacy = options && options.legacyCanonical === true;
    const encoder = legacy ? _legacyCanonicalJson : canonicalJson;
    const canonical = encoder(data);
    return crypto.createHash('sha256').update(canonical).digest('hex');
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
    timing = null,
    metadata = {},
    certificateHash = null,
    keyId = null,
    riskAssessment = null,
    biasContext = null,
    decisionId = null,
    systemVersionPin = null,
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
      timing,
      certificate_hash: certificateHash,
      key_id: keyId,
      prev_hash: this._prevHash,
      metadata,
      risk_assessment: riskAssessment,
      // v0.7.0 A4a-3: bias_context -- only present on bias_* events
      bias_context: biasContext,
      // v0.7.1 C7.1-1 / C7.1-2: compliance-schema extensions
      decision_id: decisionId,
      system_version_pin: systemVersionPin,
    };

    // Compliance mode injection (v0.6.0) -- fields are part of the hash chain.
    if (this.config.complianceMode === 'eu_ai_act_article12') {
      entryData.compliance_version = 'eu_ai_act_article12_v1';
      const articleRefs = ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19'];
      // v0.7.0 A4a-3: bias events additionally satisfy Article 4a.
      if (_BIAS_VALID_EVENT_TYPES.has(eventType)) {
        articleRefs.push('EU_AI_Act_Art_4a');
      }
      entryData.article_ref = articleRefs;
      entryData.retention_hint_days = this.config.retentionHintDays;
      entryData.pii_in_log = false;
    }

    // v0.6.1 B3: ALWAYS-ON allow-list schema validation. The no-PII-in-logs
    // invariant is a project-wide guarantee, not a compliance-mode feature.
    _validateAuditEntrySchema(entryData);

    const entryHash = AuditLogger.computeHash(entryData);
    entryData.entry_hash = entryHash;

    // Write to log file
    const logFile = this._getLogFile();
    // NOTE: appendFileSync is atomic on POSIX for writes < PIPE_BUF (4096 bytes).
    // For multi-process deployments, use external coordination.
    // This module assumes single-process, single-writer access.
    let payload = JSON.stringify(entryData) + '\n';
    // v0.6.3 H4: prepend `\n` if recovery detected the target file ends
    // mid-line (partial-write tail from a prior crash). One-shot flag.
    if (this._needsLeadingNewline) {
      payload = '\n' + payload;
      this._needsLeadingNewline = false;
    }
    // v0.6.3 G7: ensure new audit logs are created with mode 0o600 so other
    // system users can't read entity hashes / token counts / categories.
    // appendFileSync's `mode` option is honoured ONLY when the file is being
    // CREATED -- existing files keep their current mode. To tighten existing
    // audit files we'd need to chmod every write, which is wasteful; we
    // instead chmod once after the first write that creates the file.
    const fileExisted = fs.existsSync(logFile);
    fs.appendFileSync(logFile, payload, { mode: 0o600 });
    if (!fileExisted && process.platform !== 'win32') {
      try { fs.chmodSync(logFile, 0o600); } catch { /* best effort */ }
    }

    // Update chain state
    this._prevHash = entryHash;
    this._seq += 1;

    return entryData;
  }

  /**
   * Verify the integrity of the entire audit chain.
   *
   * @param {Object} [options]
   * @param {string} [options.logFilePath] - Specific file, or all files in logDir
   * @param {'compliance_report'} [options.outputFormat] - When set, returns a
   *   structured compliance report dict instead of the default { valid, errors, finalSeq }.
   *   When omitted, the existing return shape is preserved (backward compatible).
   * @param {boolean} [options.legacyCanonical] - When true, recompute hashes
   *   using the v0.6.0-compatible canonicalizer (`ensure_ascii=true` /
   *   `\uXXXX`-escaped non-ASCII). Required to verify audit chains that were
   *   originally written by **Python v0.5.x or v0.6.0** and contain non-ASCII
   *   characters (names, addresses, etc.) -- Python escaped them, JS preserved
   *   UTF-8, so the canonical bytes diverged. v0.6.1+ chains use a unified
   *   canonicalizer and verify cross-SDK without this flag. **Sunset in v0.7.0
   *   with a deprecation warning whenever the flag is set.**
   *
   *   See `CloakLLM/COMPLIANCE.md` § Cross-Language Compatibility for the
   *   full asymmetry description and a per-SDK flag table.
   *
   * Backward-compat: passing a string (the old `logFilePath` positional argument)
   * is still accepted.
   *
   * @returns {{ valid: boolean, errors: string[], finalSeq: number } | Object}
   */
  verifyChain(options = null) {
    let logFilePath = null;
    let outputFormat = null;
    let legacyCanonical = false;
    if (typeof options === 'string') {
      logFilePath = options;
    } else if (options && typeof options === 'object') {
      logFilePath = options.logFilePath ?? null;
      outputFormat = options.outputFormat ?? null;
      legacyCanonical = options.legacyCanonical === true;
    }
    if (legacyCanonical) {
      // eslint-disable-next-line no-console
      console.warn(
        '[cloakllm] legacyCanonical=true is a backward-compat shim for ' +
        'v0.5.x / v0.6.0 audit chains; sunset in v0.7.0.'
      );
    }
    const reportEnabled = outputFormat === 'compliance_report';

    const errors = [];
    const files = logFilePath ? [logFilePath] : this._getLogFiles();

    // Compliance-report aggregates
    let firstTs = null;
    let lastTs = null;
    let totalEntries = 0;
    let complianceModeEntries = 0;
    let nonComplianceModeEntries = 0;
    let certificatesPresent = 0;
    const piiCategoriesDetected = {};
    let piiInLogs = false;

    if (files.length === 0) {
      if (reportEnabled) {
        return AuditLogger._buildComplianceReport({
          auditDir: this._logDir,
          firstTs: null,
          lastTs: null,
          totalEntries: 0,
          complianceModeEntries: 0,
          nonComplianceModeEntries: 0,
          certificatesPresent: 0,
          piiCategoriesDetected: {},
          piiInLogs: false,
          chainValid: true,
          anomalies: [],
        });
      }
      return { valid: true, errors: [], finalSeq: -1 };
    }

    let prevHash = GENESIS_HASH;
    let finalSeq = -1;

    for (const fpath of files) {
      const content = fs.readFileSync(fpath, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim());
      const fname = path.basename(fpath);

      for (let i = 0; i < lines.length; i++) {
        let entry;
        try {
          entry = JSON.parse(lines[i]);
        } catch {
          errors.push(`${fname}:${i + 1} -- Invalid JSON`);
          continue;
        }

        if (entry.seq !== undefined) {
          finalSeq = entry.seq;
        }

        // Check chain link
        if (entry.prev_hash !== prevHash) {
          errors.push(
            `${fname}:${i + 1} seq=${entry.seq} -- ` +
            `Chain broken: expected prev_hash=${prevHash.slice(0, 16)}..., ` +
            `got ${(entry.prev_hash || 'MISSING').slice(0, 16)}...`
          );
        }

        // Compliance-report aggregation (before deleting entry_hash)
        if (reportEnabled) {
          totalEntries += 1;
          const ts = entry.timestamp;
          if (ts) {
            if (firstTs === null || ts < firstTs) firstTs = ts;
            if (lastTs === null || ts > lastTs) lastTs = ts;
          }
          if (entry.compliance_version) {
            complianceModeEntries += 1;
            if (entry.pii_in_log === true) {
              piiInLogs = true;
              errors.push(
                `${fname}:${i + 1} seq=${entry.seq} -- ` +
                `COMPLIANCE VIOLATION: pii_in_log=true`
              );
            }
          } else {
            nonComplianceModeEntries += 1;
          }
          if (entry.certificate_hash) certificatesPresent += 1;
          for (const [cat, count] of Object.entries(entry.categories || {})) {
            piiCategoriesDetected[cat] = (piiCategoriesDetected[cat] || 0) + count;
          }
        }

        // Recompute entry hash (legacyCanonical thread-through)
        const storedHash = entry.entry_hash;
        delete entry.entry_hash;
        const recomputed = AuditLogger.computeHash(entry, { legacyCanonical });
        // v0.6.4 G8: timing-safe comparison via crypto.timingSafeEqual.
        // String !== short-circuits at first mismatched char -- an attacker
        // with many verifyChain calls could in principle infer hash bytes
        // by timing. Length pre-check is required (timingSafeEqual throws
        // on length mismatch) and is itself constant-time on length only.
        let tampered = true;
        if (typeof storedHash === 'string' && storedHash.length === recomputed.length) {
          try {
            tampered = !crypto.timingSafeEqual(
              Buffer.from(storedHash, 'hex'),
              Buffer.from(recomputed, 'hex'),
            );
          } catch {
            tampered = true;  // hex parse failure is always tampered
          }
        }
        if (tampered) {
          errors.push(
            `${fname}:${i + 1} seq=${entry.seq} -- ` +
            `Entry tampered: stored_hash=${(storedHash || '').slice(0, 16)}..., ` +
            `recomputed=${recomputed.slice(0, 16)}...`
          );
        }

        prevHash = storedHash;
      }
    }

    const chainValid = errors.length === 0;

    if (reportEnabled) {
      return AuditLogger._buildComplianceReport({
        auditDir: this._logDir,
        firstTs,
        lastTs,
        totalEntries,
        complianceModeEntries,
        nonComplianceModeEntries,
        certificatesPresent,
        piiCategoriesDetected,
        piiInLogs,
        chainValid,
        anomalies: errors,
      });
    }

    return { valid: chainValid, errors, finalSeq };
  }

  static _buildComplianceReport({
    auditDir, firstTs, lastTs, totalEntries,
    complianceModeEntries, nonComplianceModeEntries,
    certificatesPresent, piiCategoriesDetected, piiInLogs,
    chainValid, anomalies,
  }) {
    const verdict = (chainValid && !piiInLogs) ? 'COMPLIANT' : 'NON_COMPLIANT';
    return {
      audit_dir: auditDir,
      period: { from: firstTs, to: lastTs },
      total_entries: totalEntries,
      chain_integrity: chainValid ? 'verified' : 'broken',
      pii_in_logs: piiInLogs,
      compliance_mode_entries: complianceModeEntries,
      non_compliance_mode_entries: nonComplianceModeEntries,
      pii_categories_detected: piiCategoriesDetected,
      certificates_present: certificatesPresent,
      anomalies,
      generated_at: new Date().toISOString(),
      verdict,
    };
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
