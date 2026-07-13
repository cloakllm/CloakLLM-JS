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
    // v0.11.2: detect SPACE/DASH-grouped cards (the normal way they're written),
    // not just contiguous digits. Before this "4111 1111 1111 1111" was missed
    // by CC and partially eaten by PHONE, leaking the trailing group. A back-
    // referenced separator (\1 / \2) keeps grouping consistent. Precedes PHONE
    // so the full card span is claimed first via coveredSpans.
    pattern: /(?<!\d)(?:(?:4\d{3}|5[1-5]\d{2}|6011|65\d{2})([ -]?)\d{4}\1\d{4}\1\d{4}|3[47]\d{2}([ -]?)\d{6}\2\d{5})(?!\d)/g,
    configKey: 'detectCreditCards',
  },
  IBAN: {
    // v0.11.2: MUST precede PHONE. In the old order IBAN came after PHONE, so
    // PHONE claimed the IBAN's digit groups first (coveredSpans), fragmenting
    // "DE89 3704 0044 0532 0130 00" + leaking the country code. Matches compact
    // + spaced forms.
    pattern: /\b[A-Z]{2}\d{2}(?:\s?[\dA-Z]{4}){2,7}(?:\s?[\dA-Z]{1,4})?\b/g,
    configKey: 'detectIban',
  },
  PHONE: {
    // v0.6.1 H1.3: tightened. Parens REQUIRE both, bare area code REQUIRES
    // trailing separator. Eliminates ambiguity but still matches `+1-555-0142`.
    // v0.12.1: added a 2-digit-grouped alternative (e.g. French/European
    // "06 12 34 56 78", 8-10 digits) -- the prior pattern assumed 3-4 digit
    // groups, so that shape leaked on the default (non-locale) config.
    // Byte-identical to the Python PHONE pattern (cross-SDK differential = 0).
    pattern: /(?<!\d)(?:(?:\+\d{1,3}[-.\s])?(?:\(\d{2,4}\)[-.\s]?|\d{2,4}[-.\s])?\d{3,4}[-.\s]?\d{3,4}|\d{2}(?:[-.\s]\d{2}){3,4})(?!\d)/g,
    configKey: 'detectPhones',
  },
  IP_ADDRESS: {
    // v0.11.2: IPv4 + IPv6. IPv6 was undetected before, so a whole address
    // leaked verbatim. Standard fully-bounded IPv6 alternation (ReDoS-safe),
    // gated by non-word/non-colon lookarounds.
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|(?<![\w:])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?::[A-Fa-f0-9]{1,4}){1,7})(?![\w:])/g,
    configKey: 'detectIpAddresses',
  },
  API_KEY: {
    // v0.6.1 F1: bounded upper at 512. Body includes - and _ so multi-segment
    // keys (Anthropic sk-ant-api03-, GitHub fine-grained github_pat_X_Y) match.
    pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9_-]{20,512}\b/g,
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
