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
const { version: CLOAKLLM_VERSION } = require('../package.json');

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
      if (!(key in this._metrics.detection)) {
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
  sanitize(text, { tokenMap = null, model = null, provider = null, metadata = {} } = {}) {
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
      tokenMap = new TokenMap({
        mode: this.config.mode,
        entityHashing: this.config.entityHashing,
        entityHashKey: this.config.entityHashKey,
      });
    }

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
   *
   * WARNING: By default, output contains raw PII in the 'text' field.
   * Set redactValues: true to replace with '[redacted]'.
   *
   * @param {string} text
   * @param {Object} [options]
   * @param {boolean} [options.redactValues=false] - Replace PII text with '[redacted]'
   * @returns {Object}
   */
  analyze(text, { redactValues = false } = {}) {
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
   */
  verifyAudit(options = null) {
    let logDir = null;
    let outputFormat = null;
    if (options && typeof options === 'object') {
      logDir = options.logDir ?? null;
      outputFormat = options.outputFormat ?? null;
    }
    let audit = this.audit;
    if (logDir) {
      const cfg = new ShieldConfig({ logDir, auditEnabled: true });
      audit = new AuditLogger(cfg);
    }
    if (outputFormat === 'compliance_report') {
      return audit.verifyChain({ outputFormat: 'compliance_report' });
    }
    return audit.verifyChain();
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
          status: 'partial',
          notes:
            'Tokenization qualifies as pseudonymisation; BiasDetectionSession not yet implemented (v0.7)',
        },
      ],
      config_snapshot: {
        audit: cfg.auditEnabled,
        compliance_mode: cfg.complianceMode,
        mode: cfg.mode,
        entity_hashing: cfg.entityHashing,
        attestation_enabled: attestationEnabled,
        retention_hint_days: cfg.retentionHintDays,
      },
      generated_at: new Date().toISOString(),
      cloakllm_version: CLOAKLLM_VERSION,
    };
  }

  /**
   * Write the compliance summary to a JSON file. Artifact for auditors.
   * @param {string} [outPath]
   * @returns {string} Resolved path written.
   */
  exportComplianceConfig(outPath = './cloakllm_compliance_config.json') {
    const summary = this.complianceSummary();
    summary.note =
      'This configuration snapshot was generated by CloakLLM. ' +
      'Verify audit log integrity using: cloakllm verify <audit_dir>';
    const dir = path.dirname(outPath);
    if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(summary, null, 2), 'utf-8');
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
