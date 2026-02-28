/**
 * Shield — the main CloakLLM engine.
 *
 * Usage:
 *   const { Shield } = require('cloakllm');
 *   const shield = new Shield();
 *
 *   const [sanitized, tokenMap] = shield.sanitize("Email john@acme.com about the deal");
 *   // sanitized: "Email [EMAIL_0] about the deal"
 *
 *   // Send sanitized to LLM, get response...
 *   const clean = shield.desanitize(responseText, tokenMap);
 */

const { ShieldConfig } = require('./config');
const { DetectionEngine } = require('./detector');
const { Tokenizer, TokenMap } = require('./tokenizer');
const { AuditLogger } = require('./audit');

class Shield {
  /**
   * @param {ShieldConfig} [config]
   */
  constructor(config = null) {
    this.config = config || new ShieldConfig();
    this.detector = new DetectionEngine(this.config);
    this.tokenizer = new Tokenizer(this.config);
    this.audit = new AuditLogger(this.config);
  }

  /**
   * Detect and replace sensitive entities in text.
   * @param {string} text
   * @param {Object} [options]
   * @param {TokenMap} [options.tokenMap] - Existing TokenMap for multi-turn
   * @param {string} [options.model] - LLM model name
   * @param {string} [options.provider] - LLM provider
   * @param {Object} [options.metadata] - Additional context
   * @returns {[string, TokenMap]}
   */
  sanitize(text, { tokenMap = null, model = null, provider = null, metadata = {} } = {}) {
    const startTime = performance.now();

    const detections = this.detector.detect(text);
    const [sanitized, map] = this.tokenizer.tokenize(text, detections, tokenMap);

    const elapsedMs = performance.now() - startTime;

    this.audit.log({
      eventType: 'sanitize',
      originalText: text,
      sanitizedText: sanitized,
      model,
      provider,
      entityCount: detections.length,
      categories: map.categories,
      tokensUsed: [...map.reverse.keys()],
      latencyMs: elapsedMs,
      metadata,
    });

    return [sanitized, map];
  }

  /**
   * Replace tokens in LLM response with original values.
   * @param {string} text
   * @param {TokenMap} tokenMap
   * @param {Object} [options]
   * @returns {string}
   */
  desanitize(text, tokenMap, { model = null, provider = null, metadata = {} } = {}) {
    const startTime = performance.now();

    const result = this.tokenizer.detokenize(text, tokenMap);

    const elapsedMs = performance.now() - startTime;

    this.audit.log({
      eventType: 'desanitize',
      originalText: text,
      sanitizedText: result,
      model,
      provider,
      entityCount: tokenMap.entityCount,
      categories: tokenMap.categories,
      tokensUsed: [...tokenMap.reverse.keys()],
      latencyMs: elapsedMs,
      metadata,
    });

    return result;
  }

  /**
   * Analyze text for sensitive data without modifying it.
   * @param {string} text
   * @returns {Object}
   */
  analyze(text) {
    const detections = this.detector.detect(text);
    return {
      entity_count: detections.length,
      entities: detections.map(d => ({
        text: d.text,
        category: d.category,
        start: d.start,
        end: d.end,
        confidence: d.confidence,
        source: d.source,
      })),
    };
  }

  /** Verify the integrity of all audit logs. */
  verifyAudit() {
    return this.audit.verifyChain();
  }

  /** Get aggregate audit statistics. */
  auditStats() {
    return this.audit.getStats();
  }
}

module.exports = { Shield };
