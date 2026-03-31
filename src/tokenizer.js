/**
 * Deterministic Tokenizer.
 *
 * Replaces sensitive entities with consistent, reversible tokens.
 * Same input always produces the same token within a session.
 * Tokens are descriptive: [PERSON_0], [EMAIL_1], etc.
 */

const crypto = require('crypto');

const {
  CLOAKLLM_TOKEN_REGEX: TOKEN_PATTERN,
  ESCAPED_OPEN,
  ESCAPED_CLOSE,
} = require('./token-spec');

const ESCAPED_PATTERN = new RegExp(`${ESCAPED_OPEN}([A-Z][A-Z0-9_]*_(?:\\d+|REDACTED))${ESCAPED_CLOSE}`, 'g');

class TokenMap {
  /**
   * @param {Object} [options]
   * @param {string} [options.mode] - "tokenize" or "redact"
   */
  constructor({ mode = 'tokenize', entityHashing = false, entityHashKey = '' } = {}) {
    /** @type {Map<string, string>} original -> token */
    this.forward = new Map();
    /** @type {Map<string, string>} token -> original */
    this.reverse = new Map();
    /** @type {Map<string, number>} category -> counter */
    this._counters = new Map();
    /** @type {import('./detector').Detection[]} */
    this.detections = [];
    /** @type {string} */
    this.mode = mode;
    /** @type {boolean} */
    this.entityHashing = entityHashing;
    /** @type {string} */
    this.entityHashKey = entityHashKey;
    /** @type {import('./attestation').SanitizationCertificate|null} */
    this.certificate = null;
    /** @type {import('./attestation').SanitizationCertificate|null} */
    this.batchCertificate = null;
    /** @type {Object|null} */
    this.merkleTree = null;
    /** @type {Object|null} Context risk assessment */
    this.riskAssessment = null;
  }

  /**
   * Compute HMAC-SHA256 hash: HMAC(key, "CATEGORY:normalized").
   * @param {string} category
   * @param {string} originalText
   * @returns {string} 64-char hex hash
   */
  _computeEntityHash(category, originalText) {
    const normalized = originalText.trim().toLowerCase();
    const message = `${category}:${normalized}`;
    return crypto.createHmac('sha256', this.entityHashKey).update(message).digest('hex');
  }

  /**
   * Get existing token for value, or create a new one.
   * @param {string} original
   * @param {string} category
   * @returns {string}
   */
  getOrCreate(original, category) {
    if (this.mode === 'redact') {
      return `[${category}_REDACTED]`;
    }

    const key = original.trim();
    if (this.forward.has(key)) {
      return this.forward.get(key);
    }

    const idx = this._counters.get(category) ?? 0;
    this._counters.set(category, idx + 1);
    const token = `[${category}_${idx}]`;

    this.forward.set(key, token);
    this.reverse.set(token, key);
    return token;
  }

  get entityCount() {
    return this.forward.size;
  }

  get categories() {
    const counts = {};
    for (const det of this.detections) {
      counts[det.category] = (counts[det.category] ?? 0) + 1;
    }
    return counts;
  }

  /** Per-entity metadata list (PII-safe — no original text). */
  get entityDetails() {
    const details = [];
    for (const det of this.detections) {
      let token;
      if (this.mode === 'redact') {
        token = `[${det.category}_REDACTED]`;
      } else {
        const key = det.text.trim();
        token = this.forward.get(key) ?? '';
      }
      const detail = {
        category: det.category,
        start: det.start,
        end: det.end,
        length: det.end - det.start,
        confidence: det.confidence,
        source: det.source,
        token,
      };
      if (this.entityHashing && this.entityHashKey) {
        detail.entity_hash = this._computeEntityHash(det.category, det.text);
      }
      details.push(detail);
    }
    details.sort((a, b) => a.start - b.start);
    return details;
  }

  /** Non-sensitive summary for logging. */
  toSummary() {
    return {
      entity_count: this.entityCount,
      categories: this.categories,
      tokens: [...this.reverse.keys()],
    };
  }

  /** Extended summary with per-entity details (PII-safe). */
  toReport() {
    return {
      entity_count: this.entityCount,
      categories: this.categories,
      tokens: [...this.reverse.keys()],
      mode: this.mode,
      entity_details: this.entityDetails,
    };
  }
}

class Tokenizer {
  /**
   * @param {import('./config').ShieldConfig} config
   */
  constructor(config) {
    this.config = config;
  }

  escapeExistingTokens(text) {
    return text.replace(TOKEN_PATTERN, (_, inner) => `${ESCAPED_OPEN}${inner}${ESCAPED_CLOSE}`);
  }

  unescapeTokens(text) {
    return text.replace(ESCAPED_PATTERN, (_, inner) => `[${inner}]`);
  }

  /**
   * Replace all detected entities in text with tokens.
   * @param {string} text
   * @param {import('./detector').Detection[]} detections - Must be sorted by start position
   * @param {TokenMap} [tokenMap]
   * @returns {[string, TokenMap]}
   */
  tokenize(text, detections, tokenMap = null) {
    if (!tokenMap) tokenMap = new TokenMap();

    // Escape any existing token-like patterns to prevent fake token injection
    let result = this.escapeExistingTokens(text);
    for (let i = detections.length - 1; i >= 0; i--) {
      const det = detections[i];
      const token = tokenMap.getOrCreate(det.text, det.category);
      result = result.slice(0, det.start) + token + result.slice(det.end);
      tokenMap.detections.push(det);
    }

    return [result, tokenMap];
  }

  /**
   * Replace all tokens in text with their original values.
   * Handles case-insensitive matching (LLMs may change casing).
   * @param {string} text
   * @param {TokenMap} tokenMap
   * @returns {string}
   */
  detokenize(text, tokenMap) {
    let result = text;

    // Sort tokens by length (longest first) to avoid partial replacements
    const sorted = [...tokenMap.reverse.entries()]
      .sort((a, b) => b[0].length - a[0].length);

    for (const [token, original] of sorted) {
      const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      result = result.replace(new RegExp(escaped, 'gi'), () => original);
    }

    // Restore any escaped token-like patterns from the original input
    result = this.unescapeTokens(result);

    return result;
  }
}

module.exports = { TokenMap, Tokenizer };
