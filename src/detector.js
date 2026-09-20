/**
 * PII Detection Engine.
 *
 * Orchestrates a pipeline of DetectorBackend instances for comprehensive
 * sensitive data detection. Default pipeline: regex -> NER -> LLM.
 *
 * Custom backends can be injected via the `backends` parameter.
 */

// NerDetector and LOCALE_PATTERNS moved to backends/ner.js and backends/regex.js

/**
 * @typedef {Object} Detection
 * @property {string} text - The original text matched
 * @property {string} category - e.g., "EMAIL", "SSN", "API_KEY"
 * @property {number} start - Start character offset
 * @property {number} end - End character offset
 * @property {number} confidence - 0.0-1.0 confidence score
 * @property {string} source - "regex", "ner", or "llm"
 */

// Built-in patterns now live in patterns.js (their single source of truth) so
// that PATTERNS can be imported without loading this module's pipeline builder,
// which reaches backends/llm.js -> llm-detector.js -> child_process/net.
// Re-exported here for backward compatibility.
const { PATTERNS } = require('./patterns');

class DetectionEngine {
  /**
   * @param {import('./config').ShieldConfig} config
   * @param {Array<import('./backends/base').DetectorBackend>} [backends] - Custom pipeline
   */
  constructor(config, backends = null) {
    this.config = config;
    /** @type {Array<import('./backends/base').DetectorBackend>} */
    this._backends = [];

    if (backends !== null) {
      // Custom pipeline
      this._backends = [...backends];
    } else {
      // Default pipeline: regex -> NER -> LLM
      this._buildDefaultPipeline();
    }
  }

  _buildDefaultPipeline() {
    const { RegexBackend } = require('./backends/regex');
    const { NerBackend } = require('./backends/ner');
    const { LlmBackend } = require('./backends/llm');

    // Order is precedence: a pass that claims a span first keeps it.
    //
    // regex -> LLM -> NER, and the LLM pass moved ahead of NER on 2026-09-20.
    // It used to run last, so a generic NER guess could take a span out from
    // under a category the USER had explicitly defined:
    //
    //     customLlmCategories: [{ name: 'PATIENT_ID', ... }]
    //     "Patient PAT-12345 was admitted"
    //         -> "Patient [PERSON_0]-12345 was admitted"
    //
    // Not a leak -- the value is still tokenised -- but the person asked for
    // PATIENT_ID and silently got PERSON, which corrupts entity_details and
    // anything downstream keyed on the category.
    //
    // Regex stays first: it is structural and the most certain. An explicitly
    // configured category is a stronger statement of intent than a
    // probabilistic name guess, so it outranks NER. NER is the fuzziest pass
    // and now goes last.
    //
    // Safe because the two do not compete: when NER is available the LLM is
    // told to skip PERSON/ORG/GPE, so it cannot steal them by going first;
    // when NER is unavailable the LLM keeps them, which is the only way they
    // get detected at all. The Python SDK carries the same ordering and the
    // same fix -- it had the identical latent flaw, exposed by a different
    // input (spaCy claims "John Smith-99" whole).

    // Pass 1: Regex (always)
    this._backends.push(new RegexBackend(this.config));

    const nerBackend = new NerBackend();

    // Pass 2: LLM (opt-in)
    if (this.config.llmDetection) {
      const llmBackend = new LlmBackend(this.config);

      // NER/LLM coordination: if NER handles PERSON/ORG/GPE, tell LLM to skip
      // them. Must be set BEFORE the backend runs, which is why it is here
      // rather than after the push.
      if (nerBackend.available) {
        llmBackend.addExcludedCategories(['PERSON', 'ORG', 'GPE']);
      }
      this._backends.push(llmBackend);
    }

    // Pass 3: NER (always -- uses compromise if available)
    this._backends.push(nerBackend);
  }

  // --- Backward compatibility properties ---

  /** @returns {NerDetector|null} */
  get _nerDetector() {
    for (const backend of this._backends) {
      if (backend.name === 'ner' && backend._nerDetector) {
        return backend._nerDetector;
      }
    }
    return null;
  }

  /** @returns {import('./llm-detector').LlmDetector|null} */
  get _llmDetector() {
    for (const backend of this._backends) {
      if (backend.name === 'llm') {
        return backend._detector;
      }
    }
    return null;
  }

  get _compiledPatterns() {
    for (const backend of this._backends) {
      if (backend.name === 'regex') {
        return backend._compiledPatterns;
      }
    }
    return [];
  }

  /** Backward compat: delegates to RegexBackend instance in pipeline. */
  _testRegexSafety(regex) {
    for (const backend of this._backends) {
      if (typeof backend._testRegexSafety === 'function') {
        return backend._testRegexSafety(regex);
      }
    }
    return true;
  }

  /**
   * Detect all sensitive entities in text.
   * @param {string} text
   * @returns {{ detections: Detection[], timing: Object }}
   */
  detect(text) {
    /** @type {Detection[]} */
    const detections = [];
    /** @type {Array<[number, number]>} */
    const coveredSpans = [];
    const timing = {};

    for (const backend of this._backends) {
      const t0 = performance.now();
      const backendDetections = backend.detect(text, coveredSpans);
      timing[`${backend.name}_ms`] = +(performance.now() - t0).toFixed(2);
      detections.push(...backendDetections);
    }

    // Sort by start position
    detections.sort((a, b) => a.start - b.start);
    return { detections, timing };
  }
}

module.exports = { DetectionEngine, PATTERNS };
