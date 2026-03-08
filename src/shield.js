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
    this._metrics = Shield._emptyMetrics();
  }

  static _emptyMetrics() {
    return {
      calls: { sanitize: 0, desanitize: 0, sanitizeBatch: 0, desanitizeBatch: 0 },
      total_ms: 0,
      detection: { regex_ms: 0, llm_ms: 0 },
      tokenization_ms: 0,
      entities_detected: 0,
      categories: {},
    };
  }

  _accumulate(callType, totalMs, detectionTiming, tokenizationMs, entityCount, categories) {
    this._metrics.calls[callType]++;
    this._metrics.total_ms += totalMs;
    for (const key of ['regex_ms', 'llm_ms']) {
      this._metrics.detection[key] += (detectionTiming[key] || 0);
    }
    this._metrics.tokenization_ms += tokenizationMs;
    this._metrics.entities_detected += entityCount;
    for (const [cat, count] of Object.entries(categories)) {
      this._metrics.categories[cat] = (this._metrics.categories[cat] || 0) + count;
    }
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

    let t0 = performance.now();
    const { detections, timing: detectionTiming } = this.detector.detect(text);
    const detectionMs = performance.now() - t0;

    // Ensure token_map has the correct mode
    if (!tokenMap) {
      tokenMap = new TokenMap({ mode: this.config.mode });
    }

    t0 = performance.now();
    const [sanitized, map] = this.tokenizer.tokenize(text, detections, tokenMap);
    const tokenizationMs = performance.now() - t0;

    const elapsedMs = performance.now() - startTime;

    const timing = {
      total_ms: +elapsedMs.toFixed(2),
      detection_ms: +detectionMs.toFixed(2),
      ...detectionTiming,
      tokenization_ms: +tokenizationMs.toFixed(2),
    };

    // Build tokens_used list — in redact mode, collect from detections
    let tokensUsed;
    if (this.config.mode === 'redact') {
      tokensUsed = [...new Set(detections.map(d => `[${d.category}_REDACTED]`))];
    } else {
      tokensUsed = [...map.reverse.keys()];
    }

    this._accumulate('sanitize', elapsedMs, detectionTiming, tokenizationMs, detections.length, map.categories);

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
      timing,
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

    const t0 = performance.now();
    const result = this.tokenizer.detokenize(text, tokenMap);
    const tokenizationMs = performance.now() - t0;

    const elapsedMs = performance.now() - startTime;

    const timing = {
      total_ms: +elapsedMs.toFixed(2),
      tokenization_ms: +tokenizationMs.toFixed(2),
    };

    this._metrics.calls.desanitize++;
    this._metrics.total_ms += elapsedMs;
    this._metrics.tokenization_ms += tokenizationMs;

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
      timing,
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
    const combinedDetectionTiming = { regex_ms: 0, llm_ms: 0 };
    let totalDetectionMs = 0;
    let totalTokenizationMs = 0;

    for (let textIndex = 0; textIndex < texts.length; textIndex++) {
      const text = texts[textIndex];

      let t0 = performance.now();
      const { detections, timing: detTiming } = this.detector.detect(text);
      totalDetectionMs += performance.now() - t0;
      for (const key of ['regex_ms', 'llm_ms']) {
        combinedDetectionTiming[key] += (detTiming[key] || 0);
      }

      t0 = performance.now();
      const [sanitized, map] = this.tokenizer.tokenize(text, detections, tokenMap);
      totalTokenizationMs += performance.now() - t0;

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

    const timing = {
      total_ms: +elapsedMs.toFixed(2),
      detection_ms: +totalDetectionMs.toFixed(2),
      regex_ms: +combinedDetectionTiming.regex_ms.toFixed(2),
      llm_ms: +combinedDetectionTiming.llm_ms.toFixed(2),
      tokenization_ms: +totalTokenizationMs.toFixed(2),
    };

    let tokensUsed;
    if (this.config.mode === 'redact') {
      tokensUsed = [...new Set(allEntityDetails.map(d => d.token))];
    } else {
      tokensUsed = [...tokenMap.reverse.keys()];
    }

    this._accumulate('sanitizeBatch', elapsedMs, combinedDetectionTiming, totalTokenizationMs, totalDetections, tokenMap.categories);

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
      timing,
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

    const t0 = performance.now();
    const results = texts.map(text => this.tokenizer.detokenize(text, tokenMap));
    const tokenizationMs = performance.now() - t0;

    const elapsedMs = performance.now() - startTime;

    const timing = {
      total_ms: +elapsedMs.toFixed(2),
      tokenization_ms: +tokenizationMs.toFixed(2),
    };

    this._metrics.calls.desanitizeBatch++;
    this._metrics.total_ms += elapsedMs;
    this._metrics.tokenization_ms += tokenizationMs;

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
      timing,
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
    const { detections } = this.detector.detect(text);
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

  /**
   * Return accumulated performance metrics for this Shield instance.
   * @returns {Object}
   */
  metrics() {
    const totalCalls = Object.values(this._metrics.calls).reduce((a, b) => a + b, 0);
    return {
      calls: { ...this._metrics.calls },
      total_ms: +this._metrics.total_ms.toFixed(2),
      avg_ms: totalCalls ? +(this._metrics.total_ms / totalCalls).toFixed(2) : 0,
      detection: {
        regex_ms: +this._metrics.detection.regex_ms.toFixed(2),
        llm_ms: +this._metrics.detection.llm_ms.toFixed(2),
      },
      tokenization_ms: +this._metrics.tokenization_ms.toFixed(2),
      entities_detected: this._metrics.entities_detected,
      categories: { ...this._metrics.categories },
    };
  }

  /** Reset accumulated performance metrics. */
  resetMetrics() {
    this._metrics = Shield._emptyMetrics();
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
