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

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ShieldConfig } = require('./config');
const { DetectionEngine } = require('./detector');
const { Tokenizer, TokenMap } = require('./tokenizer');
const { AuditLogger } = require('./audit');
const { DeploymentKeyPair, SanitizationCertificate, MerkleTree } = require('./attestation');
const { ContextAnalyzer } = require('./context-analyzer');
const { generateUlid } = require('./_ulid');
const { version: CLOAKLLM_VERSION } = require('../package.json');

/**
 * v0.7.1 C7.1-2: compose system_version_pin from three components.
 * Returns the composed string only when ALL three components are present
 * (no partial pins). Mirror of cloakllm-py shield.py.
 *
 * @param {string|null} model
 * @param {string|null} deploymentVersion
 * @param {string|null} instructionVersion
 * @returns {string|null}
 */
function _composeSystemVersionPin(model, deploymentVersion, instructionVersion) {
  if (!model || !deploymentVersion || !instructionVersion) return null;
  return `${model}@${deploymentVersion}/${instructionVersion}`;
}

class Shield {
  /**
   * @param {ShieldConfig} [config]
   * @param {Object} [options]
   * @param {Array<import('./backends/base').DetectorBackend>} [options.backends] - Custom detection pipeline
   */
  constructor(config = null, { backends = null } = {}) {
    this.config = config || new ShieldConfig();
    this.detector = new DetectionEngine(this.config, backends);
    this.tokenizer = new Tokenizer(this.config);
    this.audit = new AuditLogger(this.config);
    this._metrics = this._emptyMetrics();
    // Auto-generate entity hash key if hashing enabled but no key provided
    if (this.config.entityHashing && !this.config.entityHashKey) {
      this.config.entityHashKey = crypto.randomBytes(32).toString('hex');
    }
    // Load attestation keypair
    this._attestationKey = null;
    if (this.config.attestationKey) {
      this._attestationKey = this.config.attestationKey;
    } else if (this.config.attestationKeyPath) {
      this._attestationKey = DeploymentKeyPair.fromFile(this.config.attestationKeyPath);
    }
    // Context analyzer (opt-in)
    this._contextAnalyzer = this.config.contextAnalysis ? new ContextAnalyzer() : null;
    // Detection gap warning (only for default pipeline)
    const hasNer = this.detector._backends.some(b => b.name === 'ner' && b.available !== false);
    const hasLlm = this.detector._backends.some(b => b.name === 'llm');
    if (!hasNer && !hasLlm) {
      if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'test') {
        console.warn(
          '[cloakllm] Running regex-only detection. ' +
          'PERSON, ORG, and GPE entities may be missed. ' +
          'Install "compromise" for NER or configure Ollama for LLM detection.'
        );
      }
    }
  }

  _emptyMetrics() {
    const detection = {};
    if (this.detector && this.detector._backends) {
      for (const b of this.detector._backends) {
        detection[`${b.name}_ms`] = 0;
      }
    }
    if (Object.keys(detection).length === 0) {
      detection.regex_ms = 0;
      detection.ner_ms = 0;
      detection.llm_ms = 0;
    }
    return {
      calls: { sanitize: 0, desanitize: 0, sanitizeBatch: 0, desanitizeBatch: 0 },
      total_ms: 0,
      detection,
      tokenization_ms: 0,
      entities_detected: 0,
      categories: {},
    };
  }

  _accumulate(callType, totalMs, detectionTiming, tokenizationMs, entityCount, categories) {
    this._metrics.calls[callType]++;
    this._metrics.total_ms += totalMs;
    for (const [key, value] of Object.entries(detectionTiming)) {
      // v0.6.3 H9: skip prototype-pollution vector keys. detectionTiming
      // keys come from backend `Detection.category` values; those are
      // validated upstream by CATEGORY_NAME_PATTERN, but defense-in-depth
      // here means a misbehaving custom backend can't silently lose metrics
      // (write to `__proto__` is a no-op since Object.prototype rejects
      // non-object assignment) or pollute the prototype chain.
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      if (!Object.prototype.hasOwnProperty.call(this._metrics.detection, key)) {
        this._metrics.detection[key] = 0;
      }
      this._metrics.detection[key] += value;
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
  /**
   * v0.6.1 H1.4: refuse oversized inputs to limit ReDoS exposure.
   * @private
   */
  _checkInputLength(text) {
    const cap = this.config.maxInputLength;
    if (cap > 0 && text.length > cap) {
      throw new Error(
        `Input length ${text.length} exceeds maxInputLength=${cap}. ` +
        `Set ShieldConfig({ maxInputLength: ... }) to raise the cap, or chunk the input.`
      );
    }
  }

  sanitize(text, { tokenMap = null, model = null, provider = null, metadata = {}, decisionId = null } = {}) {
    this._checkInputLength(text);
    const startTime = performance.now();

    let t0 = performance.now();
    const { detections, timing: detectionTiming } = this.detector.detect(text);
    const detectionMs = performance.now() - t0;

    // Ensure token_map has the correct mode
    if (!tokenMap) {
      tokenMap = new TokenMap({
        mode: this.config.mode,
        entityHashing: this.config.entityHashing,
        entityHashKey: this.config.entityHashKey,
      });
    }

    // v0.7.1 C7.1-1: decision_id resolution + propagation via token_map.
    const resolvedDecisionId = decisionId || generateUlid();
    tokenMap.decisionId = resolvedDecisionId;

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

    // Create attestation certificate if signing key is configured
    let certHash = null;
    let certKeyId = null;
    if (this._attestationKey) {
      const detectionPasses = this.detector._backends.map(b => b.name);
      const cert = SanitizationCertificate.create({
        originalText: text,
        sanitizedText: sanitized,
        entityCount: detections.length,
        categories: map.categories,
        detectionPasses: detectionPasses,
        mode: this.config.mode,
        keypair: this._attestationKey,
      });
      map.certificate = cert;
      certHash = crypto.createHash('sha256').update(cert.signature).digest('hex');
      certKeyId = cert.key_id;
    }

    // Context risk analysis (opt-in)
    let riskAssessment = null;
    if (this._contextAnalyzer) {
      const risk = this._contextAnalyzer.analyze(sanitized);
      riskAssessment = risk;
      map.riskAssessment = risk;
      if (risk.risk_score > this.config.contextRiskThreshold) {
        console.warn(
          `[cloakllm] Context risk ${risk.risk_score.toFixed(2)} (${risk.risk_level}) exceeds threshold ${this.config.contextRiskThreshold}`
        );
      }
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
      timing,
      metadata,
      certificateHash: certHash,
      keyId: certKeyId,
      riskAssessment,
      // v0.7.1 C7.1-1 / C7.1-2
      decisionId: resolvedDecisionId,
      systemVersionPin: _composeSystemVersionPin(
        model, this.config.deploymentVersion, this.config.instructionVersion,
      ),
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
  desanitize(text, tokenMap, { model = null, provider = null, metadata = {}, decisionId = null } = {}) {
    const startTime = performance.now();

    // v0.6.3 H3: Pre-compute which tokens actually appear in `text`. Logged
    // (instead of the full map) to close the desanitize-time disclosure
    // oracle — see Python shield.py for the full rationale. Mirrors
    // cloakllm-py exactly so audit-log readers see the same shape across SDKs.
    const presentTokens = [...tokenMap.reverse.keys()]
      .filter(t => text.includes(t))
      .sort();

    const t0 = performance.now();
    const result = this.tokenizer.detokenize(text, tokenMap);
    const tokenizationMs = performance.now() - t0;

    const elapsedMs = performance.now() - startTime;

    // v0.6.3 H3: Bucket timing in audit log to 10ms granularity. Microsecond
    // precision lets an audit-log reader correlate "which tokens hit" with
    // timing variance — a side-channel for token presence. Full-precision
    // values still flow into .metrics() for performance debugging.
    const _bucketMs = (ms) => Math.round(ms / 10) * 10;

    const timing = {
      total_ms: _bucketMs(elapsedMs),
      tokenization_ms: _bucketMs(tokenizationMs),
    };

    this._metrics.calls.desanitize++;
    this._metrics.total_ms += elapsedMs;
    this._metrics.tokenization_ms += tokenizationMs;

    // v0.6.3 H3: filter entity_details to the present subset.
    const presentTokenSet = new Set(presentTokens);
    const presentEntityDetails = (tokenMap.entityDetails || [])
      .filter(ed => presentTokenSet.has(ed.token));

    // v0.6.3 G2 (PII hash oracle fix): pass `text` (the tokenized input) for
    // BOTH originalText AND sanitizedText. Previously sanitizedText was
    // `result` — the restored PII — so `sanitized_hash` equaled
    // sha256(restored_PII). An attacker with audit log read access could
    // hash candidate PII (sha256("123-45-6789") for SSNs, common email
    // formats) and confirm matches. Direct PII oracle in production logs.
    //
    // New semantics for desanitize entries:
    //   prompt_hash    = sha256(tokenized_input_text)
    //   sanitized_hash = sha256(tokenized_input_text)  (equal to prompt_hash)
    //
    // The `result` (restored PII) is NEVER hashed and NEVER in the log.
    // Pre-v0.6.3 chains: shield.verifyAudit({ legacyDesanitizeHash: true }).
    // Sunset in v0.7.0.
    // v0.7.1 C7.1-1: decision_id propagation. Caller override wins; otherwise
    // inherit from token_map (set during the matching sanitize).
    const resolvedDecisionId = decisionId || tokenMap.decisionId || null;

    this.audit.log({
      eventType: 'desanitize',
      originalText: text,
      sanitizedText: text,  // G2: was `result` (the oracle); now tokenized input
      model,
      provider,
      entityCount: presentTokens.length,  // H3: present-only, not full map
      categories: tokenMap.categories,
      tokensUsed: presentTokens,  // H3
      latencyMs: _bucketMs(elapsedMs),  // H3: bucketed
      mode: this.config.mode,
      entityDetails: presentEntityDetails,  // H3
      timing,
      metadata,
      // v0.7.1 C7.1-1 / C7.1-2
      decisionId: resolvedDecisionId,
      systemVersionPin: _composeSystemVersionPin(
        model, this.config.deploymentVersion, this.config.instructionVersion,
      ),
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
  sanitizeBatch(texts, { tokenMap = null, model = null, provider = null, metadata = {}, decisionId = null } = {}) {
    // v0.6.1 H1.4 — per-text length cap
    for (let i = 0; i < texts.length; i++) {
      try {
        this._checkInputLength(texts[i]);
      } catch (e) {
        throw new Error(`texts[${i}]: ${e.message}`);
      }
    }
    const startTime = performance.now();

    if (!tokenMap) {
      tokenMap = new TokenMap({
        mode: this.config.mode,
        entityHashing: this.config.entityHashing,
        entityHashKey: this.config.entityHashKey,
      });
    }

    // v0.7.1 C7.1-1: decision_id resolution + propagation.
    const resolvedDecisionId = decisionId || generateUlid();
    tokenMap.decisionId = resolvedDecisionId;

    const sanitizedTexts = [];
    const allEntityDetails = [];
    let totalDetections = 0;
    const combinedDetectionTiming = {};
    let totalDetectionMs = 0;
    let totalTokenizationMs = 0;

    for (let textIndex = 0; textIndex < texts.length; textIndex++) {
      const text = texts[textIndex];

      let t0 = performance.now();
      const { detections, timing: detTiming } = this.detector.detect(text);
      totalDetectionMs += performance.now() - t0;
      for (const [key, value] of Object.entries(detTiming)) {
        // v0.6.3 H9: same defense as _accumulate — skip prototype-pollution
        // vector keys so a misbehaving backend can't silently lose batch
        // metrics or affect the runtime's Object.prototype.
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        combinedDetectionTiming[key] = (combinedDetectionTiming[key] || 0) + value;
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
        const detail = {
          category: det.category,
          start: det.start,
          end: det.end,
          length: det.end - det.start,
          confidence: det.confidence,
          source: det.source,
          token,
          text_index: textIndex,
        };
        if (tokenMap.entityHashing && tokenMap.entityHashKey) {
          detail.entity_hash = tokenMap._computeEntityHash(det.category, det.text);
        }
        allEntityDetails.push(detail);
      }
    }

    const elapsedMs = performance.now() - startTime;

    const timing = {
      total_ms: +elapsedMs.toFixed(2),
      detection_ms: +totalDetectionMs.toFixed(2),
      ...Object.fromEntries(
        Object.entries(combinedDetectionTiming).map(([k, v]) => [k, +v.toFixed(2)])
      ),
      tokenization_ms: +totalTokenizationMs.toFixed(2),
    };

    let tokensUsed;
    if (this.config.mode === 'redact') {
      tokensUsed = [...new Set(allEntityDetails.map(d => d.token))];
    } else {
      tokensUsed = [...tokenMap.reverse.keys()];
    }

    this._accumulate('sanitizeBatch', elapsedMs, combinedDetectionTiming, totalTokenizationMs, totalDetections, tokenMap.categories);

    // Create batch attestation certificate with Merkle roots
    let certHash = null;
    let certKeyId = null;
    if (this._attestationKey) {
      const inputHashes = texts.map(t =>
        crypto.createHash('sha256').update(t).digest('hex')
      );
      const outputHashes = sanitizedTexts.map(t =>
        crypto.createHash('sha256').update(t).digest('hex')
      );
      const inputTree = new MerkleTree(inputHashes);
      const outputTree = new MerkleTree(outputHashes);

      const detectionPasses = this.detector._backends.map(b => b.name);

      const cert = SanitizationCertificate.create({
        entityCount: totalDetections,
        categories: tokenMap.categories,
        detectionPasses: detectionPasses,
        mode: this.config.mode,
        keypair: this._attestationKey,
        inputMerkleRoot: inputTree.root,
        outputMerkleRoot: outputTree.root,
      });
      tokenMap.certificate = cert;
      tokenMap.batchCertificate = cert;
      tokenMap.merkleTree = { input: inputTree, output: outputTree };
      certHash = crypto.createHash('sha256').update(cert.signature).digest('hex');
      certKeyId = cert.key_id;
    }

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
      certificateHash: certHash,
      keyId: certKeyId,
      // v0.7.1 C7.1-1 / C7.1-2
      decisionId: resolvedDecisionId,
      systemVersionPin: _composeSystemVersionPin(
        model, this.config.deploymentVersion, this.config.instructionVersion,
      ),
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
  desanitizeBatch(texts, tokenMap, { model = null, provider = null, metadata = {}, decisionId = null } = {}) {
    const startTime = performance.now();

    // v0.6.3 H3: union of tokens present across the batch (mirrors Python).
    const allText = texts.join('\n');
    const presentTokens = [...tokenMap.reverse.keys()]
      .filter(t => allText.includes(t))
      .sort();

    const t0 = performance.now();
    const results = texts.map(text => this.tokenizer.detokenize(text, tokenMap));
    const tokenizationMs = performance.now() - t0;

    const elapsedMs = performance.now() - startTime;

    // v0.6.3 H3: bucket timing in audit log; full precision in .metrics().
    const _bucketMs = (ms) => Math.round(ms / 10) * 10;

    const timing = {
      total_ms: _bucketMs(elapsedMs),
      tokenization_ms: _bucketMs(tokenizationMs),
    };

    this._metrics.calls.desanitizeBatch++;
    this._metrics.total_ms += elapsedMs;
    this._metrics.tokenization_ms += tokenizationMs;

    const presentTokenSet = new Set(presentTokens);
    const presentEntityDetails = (tokenMap.entityDetails || [])
      .filter(ed => presentTokenSet.has(ed.token));

    // v0.7.1 C7.1-1: decision_id propagation (override -> token_map -> null).
    const resolvedDecisionId = decisionId || tokenMap.decisionId || null;

    this.audit.log({
      eventType: 'desanitize_batch',
      originalText: '',
      sanitizedText: '',
      model,
      provider,
      entityCount: presentTokens.length,  // H3
      categories: tokenMap.categories,
      tokensUsed: presentTokens,  // H3
      latencyMs: _bucketMs(elapsedMs),  // H3
      mode: this.config.mode,
      entityDetails: presentEntityDetails,  // H3
      timing,
      metadata,
      // v0.7.1 C7.1-1 / C7.1-2
      decisionId: resolvedDecisionId,
      systemVersionPin: _composeSystemVersionPin(
        model, this.config.deploymentVersion, this.config.instructionVersion,
      ),
    });

    return results;
  }

  /**
   * Analyze text for sensitive data without modifying it.
   *
   * WARNING (v0.6.x): By default, output contains raw PII in the 'text' field.
   * Set redactValues: true to replace with '[redacted]'.
   *
   * v0.7.0 will flip the default to true. To silence the deprecation warning,
   * pass `redactValues` explicitly.
   *
   * @param {string} text
   * @param {Object} [options]
   * @param {boolean} [options.redactValues=false] - Replace PII text with '[redacted]'
   * @returns {Object}
   */
  analyze(text, options) {
    this._checkInputLength(text);
    let redactValues;
    if (!options || !('redactValues' in options)) {
      // F4 deprecation: user did not pass an explicit value.
      // eslint-disable-next-line no-console
      console.warn(
        '[cloakllm] Shield.analyze() default for `redactValues` will change ' +
        'from false to true in v0.7.0. The current default RETURNS RAW PII in ' +
        'the response. Pass `redactValues: false` explicitly to keep current ' +
        'behaviour, or `redactValues: true` to redact (recommended).'
      );
      redactValues = false;
    } else {
      redactValues = options.redactValues;
    }
    const { detections } = this.detector.detect(text);
    return {
      entity_count: detections.length,
      entities: detections.map(d => ({
        text: redactValues ? '[redacted]' : d.text,
        category: d.category,
        start: d.start,
        end: d.end,
        confidence: d.confidence,
        source: d.source,
      })),
    };
  }

  /**
   * Analyze sanitized text for context-based PII leakage risk.
   * @param {string} sanitizedText - Text containing [CATEGORY_N] tokens
   * @returns {Object} RiskAssessment
   */
  analyzeContextRisk(sanitizedText) {
    const analyzer = new ContextAnalyzer();
    return analyzer.analyze(sanitizedText);
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
      detection: Object.fromEntries(
        Object.entries(this._metrics.detection).map(([k, v]) => [k, +v.toFixed(2)])
      ),
      tokenization_ms: +this._metrics.tokenization_ms.toFixed(2),
      entities_detected: this._metrics.entities_detected,
      categories: { ...this._metrics.categories },
    };
  }

  /** Reset accumulated performance metrics. */
  resetMetrics() {
    this._metrics = this._emptyMetrics();
  }

  /**
   * Verify the integrity of all audit logs.
   *
   * @param {Object} [options]
   * @param {string} [options.logDir] - Alternate audit dir to verify.
   * @param {'compliance_report'} [options.outputFormat] - When set, returns
   *   a structured EU AI Act Article 12 compliance report dict instead of
   *   the default { valid, errors, finalSeq } shape.
   * @param {boolean} [options.legacyCanonical] - v0.6.1 (F5): when true, use
   *   the v0.6.0-compatible canonical JSON encoding to verify pre-v0.6.1
   *   audit chains containing non-ASCII data. Sunset in v0.7.0.
   *
   *   **Cross-SDK limitation (v0.6.3 I3):** the legacyCanonical flag restores
   *   the v0.6.0 hashing behavior PER-SDK. Python v0.6.0 escaped non-ASCII
   *   characters (e.g. `é` → `\\u00e9`); JavaScript v0.6.0 preserved UTF-8.
   *   A Python v0.6.0 audit chain containing non-ASCII data in `categories`,
   *   `metadata`, or `entity_details` CANNOT be re-verified by this JS
   *   verifier with `legacyCanonical: true`, and vice versa. There is no
   *   migration path for those specific cross-SDK chains. Same-SDK chains
   *   (Python verified by Python, JS by JS) are unaffected.
   */
  verifyAudit(options = null) {
    let logDir = null;
    let outputFormat = null;
    let legacyCanonical = false;
    if (options && typeof options === 'object') {
      logDir = options.logDir ?? null;
      outputFormat = options.outputFormat ?? null;
      legacyCanonical = options.legacyCanonical === true;
    }
    let audit = this.audit;
    if (logDir) {
      const cfg = new ShieldConfig({ logDir, auditEnabled: true });
      audit = new AuditLogger(cfg);
    }
    if (outputFormat === 'compliance_report') {
      return audit.verifyChain({ outputFormat: 'compliance_report', legacyCanonical });
    }
    return audit.verifyChain({ legacyCanonical });
  }

  /** Get aggregate audit statistics. */
  auditStats() {
    return this.audit.getStats();
  }

  /**
   * Return a structured map of EU AI Act and GDPR articles addressed by the
   * current Shield configuration. Designed for auditors and DPOs.
   */
  complianceSummary() {
    const cfg = this.config;
    const attestationEnabled =
      cfg.attestationKey !== null && cfg.attestationKey !== undefined
        || (cfg.attestationKeyPath !== null && cfg.attestationKeyPath !== undefined);
    return {
      compliance_mode: cfg.complianceMode,
      articles_addressed: [
        {
          article: 'EU_AI_Act_Art_12',
          status: 'satisfied',
          notes: 'Automatic logging enabled, zero PII in logs',
        },
        {
          article: 'EU_AI_Act_Art_19',
          status: 'satisfied',
          notes: 'Hash-chained tamper-evident audit trail',
        },
        {
          article: 'GDPR_Art_5_data_minimisation',
          status: 'satisfied',
          notes: 'Tokenization removes PII before logging',
        },
        {
          article: 'GDPR_Art_5_storage_limitation',
          status: 'satisfied',
          notes: 'Logs contain no personal data',
        },
        {
          article: 'GDPR_Art_25_privacy_by_design',
          status: 'satisfied',
          notes: 'PII removed at input layer before any downstream processing',
        },
        {
          article: 'EU_AI_Act_Art_4a',
          status: 'satisfied',
          notes:
            'BiasDetectionSession workflow available (v0.7.0+) with all six Article 4a safeguards: recorded justification, pseudonymisation, in-memory-only token map, categories_allowed scope cap, hard-bounded max_lifetime_seconds with auto-wipe, full audit-chain recording.',
        },
      ],
      config_snapshot: {
        audit: cfg.auditEnabled,
        compliance_mode: cfg.complianceMode,
        mode: cfg.mode,
        entity_hashing: cfg.entityHashing,
        attestation_enabled: attestationEnabled,
        retention_hint_days: cfg.retentionHintDays,
        // v0.8.0 CR8-9: surface decision_id (always-on since v0.7.1) and the
        // composed system_version_pin so compliance_summary() reflects the
        // post-v0.7.1 capability set without auditors having to inspect the
        // full audit chain.
        decision_id_enabled: true,
        system_version_pin_configured:
          Boolean(cfg.deploymentVersion && cfg.instructionVersion),
        compliance_reporting_available: true,
      },
      generated_at: new Date().toISOString(),
      cloakllm_version: CLOAKLLM_VERSION,
    };
  }

  /**
   * v0.8.0 CR8: generate an end-to-end compliance report from the audit chain.
   *
   * @param {Object} [opts]
   * @param {string|null} [opts.periodFrom]    ISO 8601 UTC, inclusive
   * @param {string|null} [opts.periodTo]      ISO 8601 UTC, inclusive
   * @param {string[]|null} [opts.articles]    optional whitelist
   * @param {string} [opts.format]             'json' | 'markdown'
   * @param {string|null} [opts.outPath]       write to file if set
   * @param {boolean} [opts.includeDecisions]  expand per-decision rollup
   * @returns {Object|string} JSON report dict or Markdown string
   */
  generateComplianceReport({
    periodFrom = null,
    periodTo = null,
    articles = null,
    format = 'json',
    outPath = null,
    includeDecisions = false,
  } = {}) {
    const { buildReport, renderMarkdown } = require('./compliance-report');

    const fmt = String(format || 'json').toLowerCase();
    if (!['json', 'markdown'].includes(fmt)) {
      throw new Error(
        `generateComplianceReport: unsupported format '${format}'. ` +
        `JS SDK supports 'json' and 'markdown' only. ` +
        `PDF is Python-only (reportlab dependency).`
      );
    }

    // Read audit chain from logDir. v0.7.0 lesson: explicit utf-8.
    const auditDir = this.config.logDir;
    const entries = [];
    if (auditDir && fs.existsSync(auditDir)) {
      const files = fs.readdirSync(auditDir)
        .filter(f => f.startsWith('audit_') && f.endsWith('.jsonl'))
        .sort();
      for (const f of files) {
        const p = path.join(auditDir, f);
        const text = fs.readFileSync(p, { encoding: 'utf-8' });
        for (const line of text.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try { entries.push(JSON.parse(trimmed)); } catch (_) { /* skip */ }
        }
      }
    }

    const report = buildReport({
      auditEntries: entries,
      periodFrom,
      periodTo,
      articles,
      cloakllmVersion: CLOAKLLM_VERSION,
      auditDir: auditDir || null,
      includeDecisions,
    });

    if (fmt === 'json') {
      if (outPath) {
        const dir = path.dirname(outPath);
        if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(outPath, JSON.stringify(report, null, 2), { encoding: 'utf-8' });
      }
      return report;
    }
    // markdown
    const md = renderMarkdown(report);
    if (outPath) {
      const dir = path.dirname(outPath);
      if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(outPath, md, { encoding: 'utf-8' });
    }
    return md;
  }

  /**
   * Write the compliance summary to a JSON file. Artifact for auditors.
   *
   * v0.6.3 SEC-3: the `outPath` argument is validated through the same
   * helper that protects `logDir` and `attestationKeyPath` at construction
   * time (`config.js::_validatePath`). Always rejects symlinks and NUL
   * bytes; honors `auditStrictPaths` for outside-CWD writes.
   *
   * On POSIX, the file is opened with `O_NOFOLLOW` (best-effort —
   * defends against TOCTOU symlink swap between the validate check and
   * the open). File mode is 0o600 (matches G7 audit log perms).
   *
   * @param {string} [outPath]
   * @returns {string} Resolved path written.
   */
  exportComplianceConfig(outPath = './cloakllm_compliance_config.json') {
    // v0.6.3 SEC-3: validate at runtime — same rules as ShieldConfig.logDir.
    // Lazy-require avoids a config.js → shield.js circular import.
    const { _validatePath } = require('./config');
    _validatePath(outPath, 'exportComplianceConfig(outPath)', {
      strictPaths: this.config.auditStrictPaths === true,
    });

    const summary = this.complianceSummary();
    summary.note =
      'This configuration snapshot was generated by CloakLLM. ' +
      'Verify audit log integrity using: cloakllm verify <audit_dir>';
    const dir = path.dirname(outPath);
    if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });

    // v0.6.3 SEC-3: open with O_NOFOLLOW + 0o600 on POSIX. Windows lacks
    // O_NOFOLLOW; the constant fallback (|| 0) gracefully degrades to
    // standard open semantics there. O_TRUNC overwrites existing files.
    const O_NOFOLLOW = (fs.constants.O_NOFOLLOW || 0);
    const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_TRUNC | O_NOFOLLOW;
    let fd;
    try {
      fd = fs.openSync(outPath, flags, 0o600);
    } catch (err) {
      // ELOOP fires if the path is (now) a symlink — race window after
      // _validatePath. Re-raise with a clearer message.
      if (err.code === 'ELOOP') {
        throw new Error(
          `CloakLLM: exportComplianceConfig(outPath) refused — ` +
          `target ${outPath} became a symlink between validation and open. ` +
          `Possible TOCTOU attack.`
        );
      }
      throw err;
    }
    try {
      fs.writeSync(fd, JSON.stringify(summary, null, 2));
    } finally {
      fs.closeSync(fd);
    }
    return outPath;
  }

  /**
   * Verify a sanitization certificate's signature.
   * @param {SanitizationCertificate|Object} certificate
   * @param {Buffer} [publicKey] - If null, uses Shield's attestation key
   * @returns {boolean}
   */
  verifyCertificate(certificate, publicKey = null) {
    if (!(certificate instanceof SanitizationCertificate)) {
      certificate = SanitizationCertificate.fromDict(certificate);
    }
    if (!publicKey) {
      if (this._attestationKey) {
        publicKey = this._attestationKey.publicKey;
      } else {
        throw new Error('No public key provided and no attestation key configured');
      }
    }
    return certificate.verify(publicKey);
  }

  /**
   * Generate a new Ed25519 deployment keypair for attestation.
   * @returns {DeploymentKeyPair}
   */
  static generateAttestationKey() {
    return DeploymentKeyPair.generate();
  }
}

module.exports = { Shield };
