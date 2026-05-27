/**
 * BiasDetectionSession -- EU AI Act Article 4a-compliant bias-detection workflow.
 *
 * JS mirror of cloakllm-py/cloakllm/bias_detection.py. See that module for full
 * regulatory rationale; this file mirrors the API surface and invariants so
 * the audit chains produced by the two SDKs canonicalize identically (extends
 * the I7 cross-SDK fixture pattern from v0.6.3).
 *
 * JS-specific notes:
 *  * No language-level context-manager protocol -- callers MUST use try/finally
 *    with explicit .end() or the static helper `BiasDetectionSession.run(...)`
 *    which mimics Python's `with` block.
 *  * Lifetime accounting uses `process.hrtime.bigint()` so NTP adjustments
 *    don't prematurely expire (or extend) the session.
 *  * Wipe semantics: Map.clear() + nulling references. JS strings are
 *    immutable like Python; we cannot zero memory, but the GC can reclaim
 *    once references are dropped.
 *
 * Usage:
 *   const { Shield, ShieldConfig, BiasDetectionSession } = require('cloakllm');
 *   const shield = new Shield(new ShieldConfig({ complianceMode: 'eu_ai_act_article12' }));
 *
 *   await BiasDetectionSession.run({
 *     shield,
 *     purpose: 'Pre-deployment fairness audit of credit-scoring model v3.2',
 *     necessityJustification: 'Synthetic data evaluated and rejected...',
 *     categoriesAllowed: ['RACE', 'ETHNICITY', 'RELIGION'],
 *     maxLifetimeSeconds: 86400,
 *   }, async (session) => {
 *     for (const record of dataset) {
 *       const [pseudo, counts] = session.pseudonymise(record.text, {
 *         forceCategories: record.spans,
 *       });
 *       // ...
 *     }
 *     session.recordFinding({
 *       findingSummary: 'No significant disparate impact detected.',
 *       biasMetrics: { demographic_parity_diff: 0.012 },
 *     });
 *   });
 *   // Token map wiped on `run` callback exit (success or throw).
 */

'use strict';

const crypto = require('crypto');

const { Tokenizer, TokenMap } = require('./tokenizer');
const { SPECIAL_CATEGORY_CATEGORIES } = require('./token-spec');

const MAX_LIFETIME_CEILING_SECONDS = 7 * 24 * 60 * 60;  // 604800

const PURPOSE_MAX = 500;
const NECESSITY_JUSTIFICATION_MAX = 2000;
const FINDING_SUMMARY_MAX = 500;

// v0.7.0 SECURITY-13: cap on the per-call `forceCategories` list (memory-DoS
// defense). Mirror of Python's _FORCE_CATEGORIES_MAX.
const FORCE_CATEGORIES_MAX = 1024;

// v0.7.0 SECURITY-13: reject Unicode bidi formatting characters in operator-
// supplied free-text fields (purpose, necessityJustification, findingSummary).
// These can visually reverse / re-render surrounding text in audit-log
// viewers, enabling auditor visual-spoofing on otherwise-truthful entries.
// Codepoints: U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO,
// U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI.
const BIDI_FORMATTING_RE = /[\u202a-\u202e\u2066-\u2069]/;

function rejectBidiFormatting(value, fieldName) {
  const m = BIDI_FORMATTING_RE.exec(value);
  if (m !== null) {
    const codepoint = m[0].codePointAt(0);
    const hex = codepoint.toString(16).toUpperCase().padStart(4, '0');
    throw new RangeError(
      `BiasDetectionSession.${fieldName} contains a Unicode bidi formatting ` +
      `character (U+${hex}). These can visually spoof audit-log reviewers ` +
      `and are refused in operator-supplied free-text fields.`
    );
  }
}

// --- Error classes ---

class BiasDetectionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BiasDetectionError';
  }
}

class BiasDetectionScopeError extends BiasDetectionError {
  constructor(message) {
    super(message);
    this.name = 'BiasDetectionScopeError';
  }
}

class BiasDetectionTimeoutError extends BiasDetectionError {
  constructor(message) {
    super(message);
    this.name = 'BiasDetectionTimeoutError';
  }
}

class BiasDetectionStateError extends BiasDetectionError {
  constructor(message) {
    super(message);
    this.name = 'BiasDetectionStateError';
  }
}

// --- Internals ---

function _nowSeconds() {
  // process.hrtime.bigint() returns nanoseconds since an arbitrary start
  // point. Convert to seconds as a Number for ease of arithmetic -- at
  // 7-day session ceilings the float precision is ample.
  return Number(process.hrtime.bigint()) / 1e9;
}

function _validateSpan(span) {
  if (!Array.isArray(span) || span.length !== 3) {
    throw new TypeError(
      `Span must be a [start, end, category] tuple (got ${JSON.stringify(span)}).`
    );
  }
  const [start, end, category] = span;
  if (!Number.isInteger(start) || start < 0) {
    throw new RangeError(`span.start must be a non-negative integer (got ${start}).`);
  }
  if (!Number.isInteger(end) || end <= start) {
    throw new RangeError(
      `span.end must be an integer > start (got start=${start}, end=${end}).`
    );
  }
  if (typeof category !== 'string' || !category) {
    throw new TypeError(`span.category must be a non-empty string (got ${JSON.stringify(category)}).`);
  }
  return { start, end, category };
}

// --- Public class ---

class BiasDetectionSession {
  /**
   * @param {Object} opts
   * @param {import('./shield').Shield} opts.shield
   * @param {string} opts.purpose
   * @param {string} opts.necessityJustification
   * @param {Iterable<string>} opts.categoriesAllowed
   * @param {number} opts.maxLifetimeSeconds  Required, no default. <= 604800.
   */
  constructor({
    shield,
    purpose,
    necessityJustification,
    categoriesAllowed,
    maxLifetimeSeconds,
  } = {}) {
    // Late-checked structural import -- avoids circular import bites.
    // We accept any object that exposes `.audit` and `.config` rather than
    // `instanceof Shield` so test fakes can pass through cleanly. The runtime
    // signature is documented; misuse surfaces as a TypeError when audit.log
    // is called.
    if (!shield || typeof shield !== 'object'
        || !shield.audit || !shield.config) {
      throw new TypeError(
        'BiasDetectionSession requires a Shield instance with .audit and .config.'
      );
    }

    // Article 4a builds on Article 12 -- refuse to start without it.
    if (shield.config.complianceMode !== 'eu_ai_act_article12') {
      throw new BiasDetectionError(
        "BiasDetectionSession requires the underlying Shield to be in " +
        "complianceMode='eu_ai_act_article12'. Article 4a workflows produce " +
        "audit-chain entries that Article 12 then verifies; running without " +
        "compliance mode would skip the article_ref and compliance_version " +
        "fields downstream auditors rely on."
      );
    }

    if (typeof purpose !== 'string' || purpose.trim().length === 0) {
      throw new RangeError('BiasDetectionSession.purpose must be a non-empty string.');
    }
    if (purpose.length > PURPOSE_MAX) {
      throw new RangeError(
        `BiasDetectionSession.purpose must be <= ${PURPOSE_MAX} chars (got ${purpose.length}).`
      );
    }
    rejectBidiFormatting(purpose, 'purpose');
    if (typeof necessityJustification !== 'string'
        || necessityJustification.trim().length === 0) {
      throw new RangeError(
        'BiasDetectionSession.necessityJustification must be a non-empty string. ' +
        'Article 4a safeguard #1 requires a recorded justification.'
      );
    }
    if (necessityJustification.length > NECESSITY_JUSTIFICATION_MAX) {
      throw new RangeError(
        `BiasDetectionSession.necessityJustification must be <= ` +
        `${NECESSITY_JUSTIFICATION_MAX} chars (got ${necessityJustification.length}).`
      );
    }
    rejectBidiFormatting(necessityJustification, 'necessityJustification');

    const cats = new Set(categoriesAllowed || []);
    if (cats.size === 0) {
      throw new RangeError(
        'BiasDetectionSession.categoriesAllowed must be a non-empty iterable.'
      );
    }
    const invalid = [...cats].filter(c => !SPECIAL_CATEGORY_CATEGORIES.has(c));
    if (invalid.length > 0) {
      invalid.sort();
      throw new RangeError(
        `BiasDetectionSession.categoriesAllowed contains non-special-category ` +
        `entries: ${JSON.stringify(invalid)}. Allowed: ` +
        `${JSON.stringify([...SPECIAL_CATEGORY_CATEGORIES].sort())}.`
      );
    }

    if (!Number.isInteger(maxLifetimeSeconds)) {
      throw new TypeError(
        `BiasDetectionSession.maxLifetimeSeconds must be an integer ` +
        `(got ${typeof maxLifetimeSeconds}).`
      );
    }
    if (maxLifetimeSeconds <= 0) {
      throw new RangeError(
        `BiasDetectionSession.maxLifetimeSeconds must be > 0 (got ${maxLifetimeSeconds}).`
      );
    }
    if (maxLifetimeSeconds > MAX_LIFETIME_CEILING_SECONDS) {
      throw new RangeError(
        `BiasDetectionSession.maxLifetimeSeconds must be <= ` +
        `${MAX_LIFETIME_CEILING_SECONDS} seconds (7 days). Got ${maxLifetimeSeconds}. ` +
        `Long-lived pseudonymisation maps violate Article 4a safeguard #5.`
      );
    }

    // --- State ---
    this._shield = shield;
    this._purpose = purpose;
    this._necessityJustification = necessityJustification;
    this._categoriesAllowed = cats;
    this._maxLifetimeSeconds = maxLifetimeSeconds;
    this._sessionId = crypto.randomUUID();
    this._tokenMap = new TokenMap({
      mode: 'tokenize',
      entityHashing: shield.config.entityHashing,
      entityHashKey: shield.config.entityHashKey,
    });
    this._tokenizer = new Tokenizer(shield.config);
    this._startedAt = null;
    this._closed = false;
    this._entriesProcessed = 0;
    this._entered = false;
  }

  // --- Read-only properties ---

  get sessionId() { return this._sessionId; }
  get purpose() { return this._purpose; }
  get necessityJustification() { return this._necessityJustification; }
  get categoriesAllowed() { return new Set(this._categoriesAllowed); }
  get maxLifetimeSeconds() { return this._maxLifetimeSeconds; }
  get closed() { return this._closed; }
  get entriesProcessed() { return this._entriesProcessed; }

  // --- Lifecycle ---

  /**
   * Enter the session. Must be called before any operations. Idempotent
   * for the lifetime of the session (but cannot be re-entered after end()).
   */
  start() {
    if (this._closed) {
      throw new BiasDetectionStateError(
        `BiasDetectionSession ${this._sessionId} is closed and cannot be restarted.`
      );
    }
    if (this._entered) return;
    this._entered = true;
    this._startedAt = _nowSeconds();
    this._logSessionStart();
  }

  /**
   * Static helper that mimics Python's `with` block: starts the session,
   * runs the callback (sync or async), and guarantees end() runs even on throw.
   * Returns whatever the callback returns.
   *
   * @template T
   * @param {Object} opts - Constructor options (see ctor).
   * @param {(session: BiasDetectionSession) => Promise<T>|T} fn
   * @returns {Promise<T>}
   */
  static async run(opts, fn) {
    const session = new BiasDetectionSession(opts);
    session.start();
    let threw = false;
    try {
      return await fn(session);
    } catch (e) {
      threw = true;
      throw e;
    } finally {
      if (!session._closed) {
        session._end(threw ? 'error' : 'clean');
      }
    }
  }

  /**
   * Pseudonymise text using caller-declared special-category spans.
   *
   * @param {string} text
   * @param {Object} options
   * @param {Array<[number, number, string]>} options.forceCategories
   * @returns {[string, Object<string, number>]} [pseudonymisedText, categoriesUsedCounts]
   */
  pseudonymise(text, { forceCategories } = {}) {
    this._assertOpen();
    this._assertWithinLifetime();

    if (!Array.isArray(forceCategories) || forceCategories.length === 0) {
      throw new RangeError(
        'BiasDetectionSession.pseudonymise requires at least one ' +
        '[start, end, category] entry in forceCategories.'
      );
    }
    // v0.7.0 SECURITY-13: per-call span cap (memory-DoS defense).
    if (forceCategories.length > FORCE_CATEGORIES_MAX) {
      throw new RangeError(
        `BiasDetectionSession.pseudonymise accepts at most ` +
        `${FORCE_CATEGORIES_MAX} spans per call (got ${forceCategories.length}). ` +
        `Chunk the input and call multiple times.`
      );
    }
    if (typeof text !== 'string') {
      throw new TypeError(`text must be a string (got ${typeof text}).`);
    }

    const spans = forceCategories.map(_validateSpan);

    for (const sp of spans) {
      if (!this._categoriesAllowed.has(sp.category)) {
        throw new BiasDetectionScopeError(
          `Category '${sp.category}' is not in this session's categoriesAllowed ` +
          `set (${JSON.stringify([...this._categoriesAllowed].sort())}). ` +
          `Article 4a safeguard #4 forbids re-use beyond the declared scope.`
        );
      }
      if (sp.end > text.length) {
        throw new RangeError(
          `Span (start=${sp.start}, end=${sp.end}, category='${sp.category}') ` +
          `exceeds text length ${text.length}.`
        );
      }
    }

    // Sort ascending by start. The Tokenizer iterates in reverse so high-offset
    // replacements don't shift low-offset ones; passing sorted-ascending matches
    // the rest of the SDK.
    spans.sort((a, b) => a.start - b.start);

    const detections = spans.map(sp => ({
      text: text.slice(sp.start, sp.end),
      category: sp.category,
      start: sp.start,
      end: sp.end,
      confidence: 1.0,  // caller-declared → maximally confident
      source: 'bias_detection_session',
    }));

    const t0 = _nowSeconds();
    const [pseudonymised, newMap] = this._tokenizer.tokenize(text, detections, this._tokenMap);
    this._tokenMap = newMap;
    const tokenizeMs = (_nowSeconds() - t0) * 1000;

    const counts = {};
    for (const det of detections) {
      counts[det.category] = (counts[det.category] || 0) + 1;
    }

    this._entriesProcessed += 1;
    this._logPseudonymise({
      entityCount: detections.length,
      categoriesUsed: counts,
      latencyMs: tokenizeMs,
    });
    return [pseudonymised, counts];
  }

  /**
   * Record a bias-detection finding to the audit chain.
   *
   * @param {Object} options
   * @param {string} options.findingSummary
   * @param {Object<string, number|boolean|string|null>} [options.biasMetrics]
   */
  recordFinding({ findingSummary, biasMetrics = null } = {}) {
    if (typeof findingSummary !== 'string' || findingSummary.trim().length === 0) {
      throw new RangeError('findingSummary must be a non-empty string.');
    }
    if (findingSummary.length > FINDING_SUMMARY_MAX) {
      throw new RangeError(
        `findingSummary must be <= ${FINDING_SUMMARY_MAX} chars (got ${findingSummary.length}).`
      );
    }
    rejectBidiFormatting(findingSummary, 'findingSummary');
    if (biasMetrics !== null && biasMetrics !== undefined) {
      if (typeof biasMetrics !== 'object' || Array.isArray(biasMetrics)) {
        throw new TypeError(
          `biasMetrics must be a plain object ` +
          `(got ${Array.isArray(biasMetrics) ? 'array' : typeof biasMetrics}).`
        );
      }
    }

    this._assertOpen();
    this._assertWithinLifetime();
    this._logFinding({
      findingSummary: findingSummary.trim(),
      biasMetrics: biasMetrics || {},
    });
  }

  /**
   * Explicit clean close. Idempotent. Required if not using `.run()`.
   */
  end() {
    if (this._closed) return;
    this._end('clean');
  }

  // --- Internals ---

  _assertOpen() {
    if (this._closed) {
      throw new BiasDetectionStateError(
        `BiasDetectionSession ${this._sessionId} is closed. Token map was ` +
        `wiped on session end -- no further operations are possible. ` +
        `Article 4a safeguard #5.`
      );
    }
    if (!this._entered) {
      throw new BiasDetectionStateError(
        'BiasDetectionSession used before .start(). Call .start() (or use ' +
        'BiasDetectionSession.run(...)) before operations.'
      );
    }
  }

  _assertWithinLifetime() {
    const elapsed = _nowSeconds() - (this._startedAt || 0);
    if (elapsed > this._maxLifetimeSeconds) {
      // Force-end before raising. The caller never gets back a session whose
      // lifetime has lapsed.
      this._end('timeout');
      throw new BiasDetectionTimeoutError(
        `BiasDetectionSession ${this._sessionId} exceeded its ` +
        `maxLifetimeSeconds=${this._maxLifetimeSeconds} cap ` +
        `(elapsed=${elapsed.toFixed(1)}s). Session has been wiped per ` +
        `Article 4a safeguard #5.`
      );
    }
  }

  _end(exitReason) {
    if (this._closed) return;
    const duration = _nowSeconds() - (this._startedAt || _nowSeconds());
    const wipeConfirmed = this._wipeTokenMap();
    this._closed = true;
    this._logSessionEnd({
      exitReason,
      wipeConfirmed,
      durationSeconds: Math.round(duration * 1000) / 1000,
    });
  }

  _wipeTokenMap() {
    const tm = this._tokenMap;
    if (!tm) return true;
    try {
      // Overwrite values before clearing (best effort -- JS strings are
      // immutable; the GC owns lifetime).
      for (const k of [...tm.forward.keys()]) tm.forward.set(k, '');
      for (const k of [...tm.reverse.keys()]) tm.reverse.set(k, '');
      tm.forward.clear();
      tm.reverse.clear();
      tm._counters.clear();
      tm.detections.length = 0;
      this._tokenMap = null;
      return true;
    } catch (e) {
      // Best-effort. Drop the reference regardless so the GC can reclaim.
      // eslint-disable-next-line no-console
      console.warn(
        `[cloakllm] BiasDetectionSession ${this._sessionId}: best-effort ` +
        `wipe threw ${e.name} -- session closed regardless.`
      );
      this._tokenMap = null;
      return false;
    }
  }

  // --- Audit-log helpers ---

  _biasContextBase() {
    return { session_id: this._sessionId };
  }

  _logSessionStart() {
    const ctx = this._biasContextBase();
    ctx.purpose = this._purpose;
    ctx.necessity_justification = this._necessityJustification;
    ctx.categories_allowed = [...this._categoriesAllowed].sort();
    ctx.max_lifetime_seconds = this._maxLifetimeSeconds;
    this._shield.audit.log({
      eventType: 'bias_session_start',
      latencyMs: 0,
      biasContext: ctx,
    });
  }

  _logPseudonymise({ entityCount, categoriesUsed, latencyMs }) {
    const ctx = this._biasContextBase();
    ctx.entity_count = entityCount;
    ctx.categories_used = categoriesUsed;
    this._shield.audit.log({
      eventType: 'bias_pseudonymise',
      entityCount,
      categories: categoriesUsed,
      latencyMs,
      biasContext: ctx,
    });
  }

  _logFinding({ findingSummary, biasMetrics }) {
    const ctx = this._biasContextBase();
    ctx.finding_summary = findingSummary;
    ctx.bias_metrics = biasMetrics;
    this._shield.audit.log({
      eventType: 'bias_finding',
      latencyMs: 0,
      biasContext: ctx,
    });
  }

  _logSessionEnd({ exitReason, wipeConfirmed, durationSeconds }) {
    const ctx = this._biasContextBase();
    ctx.exit_reason = exitReason;
    ctx.wipe_confirmed = wipeConfirmed;
    ctx.entries_processed = this._entriesProcessed;
    ctx.duration_seconds = durationSeconds;
    this._shield.audit.log({
      eventType: 'bias_session_end',
      latencyMs: 0,
      biasContext: ctx,
    });
  }
}

module.exports = {
  BiasDetectionSession,
  BiasDetectionError,
  BiasDetectionScopeError,
  BiasDetectionTimeoutError,
  BiasDetectionStateError,
};
