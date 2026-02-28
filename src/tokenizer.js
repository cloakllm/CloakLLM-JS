/**
 * Deterministic Tokenizer.
 *
 * Replaces sensitive entities with consistent, reversible tokens.
 * Same input always produces the same token within a session.
 * Tokens are descriptive: [PERSON_0], [EMAIL_1], etc.
 */

class TokenMap {
  constructor() {
    /** @type {Map<string, string>} original -> token */
    this.forward = new Map();
    /** @type {Map<string, string>} token -> original */
    this.reverse = new Map();
    /** @type {Map<string, number>} category -> counter */
    this._counters = new Map();
    /** @type {import('./detector').Detection[]} */
    this.detections = [];
  }

  /**
   * Get existing token for value, or create a new one.
   * @param {string} original
   * @param {string} category
   * @returns {string}
   */
  getOrCreate(original, category) {
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

  /** Non-sensitive summary for logging. */
  toSummary() {
    return {
      entity_count: this.entityCount,
      categories: this.categories,
      tokens: [...this.reverse.keys()],
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

  /**
   * Replace all detected entities in text with tokens.
   * @param {string} text
   * @param {import('./detector').Detection[]} detections - Must be sorted by start position
   * @param {TokenMap} [tokenMap]
   * @returns {[string, TokenMap]}
   */
  tokenize(text, detections, tokenMap = null) {
    if (!tokenMap) tokenMap = new TokenMap();

    // Replace back-to-front so offsets stay valid
    let result = text;
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
      result = result.replace(new RegExp(escaped, 'gi'), original);
    }

    return result;
  }
}

module.exports = { TokenMap, Tokenizer };
