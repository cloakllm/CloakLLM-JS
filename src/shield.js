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

    // Ensure token_map has the correct mode
    if (!tokenMap) {
      tokenMap = new TokenMap({ mode: this.config.mode });
    }

    const [sanitized, map] = this.tokenizer.tokenize(text, detections, tokenMap);

    const elapsedMs = performance.now() - startTime;

    // Build tokens_used list — in redact mode, collect from detections
    let tokensUsed;
    if (this.config.mode === 'redact') {
      tokensUsed = [...new Set(detections.map(d => `[${d.category}_REDACTED]`))];
    } else {
      tokensUsed = [...map.reverse.keys()];
    }

    this.audit.log({
      eventType: 'sanitize',
      originalText: text,
      sanitizedText: sanitized,
      model,
      provider,
      entityCount: detections.length,
      categories: map.categories,
      tokensUsed,
      latencyMs: elapsedMs,
      mode: this.config.mode,
      entityDetails: map.entityDetails,
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
      mode: this.config.mode,
      entityDetails: tokenMap.entityDetails,
      metadata,
    });

    return result;
  }

  /**
   * Sanitize multiple texts with a shared token map and single audit entry.
   * @param {string[]} texts
   * @param {Object} [options]
   * @param {TokenMap} [options.tokenMap]
   * @param {string} [options.model]
   * @param {string} [options.provider]
   * @param {Object} [options.metadata]
   * @returns {[string[], TokenMap]}
   */
  sanitizeBatch(texts, { tokenMap = null, model = null, provider = null, metadata = {} } = {}) {
    const startTime = performance.now();

    if (!tokenMap) {
      tokenMap = new TokenMap({ mode: this.config.mode });
    }

    const sanitizedTexts = [];
    const allEntityDetails = [];
    let totalDetections = 0;

    for (let textIndex = 0; textIndex < texts.length; textIndex++) {
      const text = texts[textIndex];
      const detections = this.detector.detect(text);
      const [sanitized, map] = this.tokenizer.tokenize(text, detections, tokenMap);
      tokenMap = map;
      sanitizedTexts.push(sanitized);
      totalDetections += detections.length;

      for (const det of detections) {
        let token;
        if (this.config.mode === 'redact') {
          token = `[${det.category}_REDACTED]`;
        } else {
          const key = det.text.trim();
          token = tokenMap.forward.get(key) || '';
        }
        allEntityDetails.push({
          category: det.category,
          start: det.start,
          end: det.end,
          length: det.end - det.start,
          confidence: det.confidence,
          source: det.source,
          token,
          text_index: textIndex,
        });
      }
    }

    const elapsedMs = performance.now() - startTime;

    let tokensUsed;
    if (this.config.mode === 'redact') {
      tokensUsed = [...new Set(allEntityDetails.map(d => d.token))];
    } else {
      tokensUsed = [...tokenMap.reverse.keys()];
    }

    const crypto = require('crypto');
    const auditMetadata = { ...metadata };
    auditMetadata.prompt_hashes = texts.map(t =>
      crypto.createHash('sha256').update(t).digest('hex')
    );
    auditMetadata.sanitized_hashes = sanitizedTexts.map(t =>
      crypto.createHash('sha256').update(t).digest('hex')
    );

    this.audit.log({
      eventType: 'sanitize_batch',
      originalText: '',
      sanitizedText: '',
      model,
      provider,
      entityCount: totalDetections,
      categories: tokenMap.categories,
      tokensUsed,
      latencyMs: elapsedMs,
      mode: this.config.mode,
      entityDetails: allEntityDetails,
      metadata: auditMetadata,
    });

    return [sanitizedTexts, tokenMap];
  }

  /**
   * Desanitize multiple texts using a shared token map.
   * @param {string[]} texts
   * @param {TokenMap} tokenMap
   * @param {Object} [options]
   * @returns {string[]}
   */
  desanitizeBatch(texts, tokenMap, { model = null, provider = null, metadata = {} } = {}) {
    const startTime = performance.now();

    const results = texts.map(text => this.tokenizer.detokenize(text, tokenMap));

    const elapsedMs = performance.now() - startTime;

    this.audit.log({
      eventType: 'desanitize_batch',
      originalText: '',
      sanitizedText: '',
      model,
      provider,
      entityCount: tokenMap.entityCount,
      categories: tokenMap.categories,
      tokensUsed: [...tokenMap.reverse.keys()],
      latencyMs: elapsedMs,
      mode: this.config.mode,
      entityDetails: tokenMap.entityDetails,
      metadata,
    });

    return results;
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
