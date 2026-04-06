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

// Ordered by specificity (most specific first)
// Re-exported for backward compatibility
const PATTERNS = {
  EMAIL: {
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    configKey: 'detectEmails',
  },
  SSN: {
    pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    configKey: 'detectSsns',
  },
  CREDIT_CARD: {
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    configKey: 'detectCreditCards',
  },
  PHONE: {
    pattern: /(?:\+\d{1,3}[-.\s])?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b/g,
    configKey: 'detectPhones',
  },
  IP_ADDRESS: {
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    configKey: 'detectIpAddresses',
  },
  API_KEY: {
    pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9]{20,}\b/g,
    configKey: 'detectApiKeys',
  },
  AWS_KEY: {
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    configKey: 'detectApiKeys',
  },
  JWT: {
    pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    configKey: 'detectApiKeys',
  },
  IBAN: {
    pattern: /\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?(?:[\dA-Z]{4}\s?){2,7}[\dA-Z]{1,4}\b/g,
    configKey: 'detectIban',
  },
};

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

    // Pass 1: Regex (always)
    this._backends.push(new RegexBackend(this.config));

    // Pass 2: NER (always — uses compromise if available)
    const nerBackend = new NerBackend();
    this._backends.push(nerBackend);

    // Pass 3: LLM (opt-in)
    if (this.config.llmDetection) {
      const llmBackend = new LlmBackend(this.config);
      this._backends.push(llmBackend);

      // NER/LLM coordination: if NER handles PERSON/ORG/GPE, tell LLM to skip them
      if (nerBackend.available) {
        llmBackend.addExcludedCategories(['PERSON', 'ORG', 'GPE']);
      }
    }
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
