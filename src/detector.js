/**
 * PII Detection Engine.
 *
 * Multi-pass detection for structured and contextual sensitive data.
 * Pass 1: Regex (built-in + locale + custom patterns)
 * Pass 2: NER via compromise (optional, English only)
 * Pass 3: Local LLM via Ollama (opt-in, any language)
 */

const { LOCALE_PATTERNS } = require('./locale-patterns');
const { NerDetector, isNerAvailable } = require('./ner-detector');

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
    pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9_]{20,}\b/g,
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
   */
  constructor(config) {
    this.config = config;
    this._compiledPatterns = this._buildPatterns();

    // --- NER detector (optional, via compromise) ---
    this._nerDetector = null;
    if (isNerAvailable()) {
      try {
        this._nerDetector = new NerDetector();
      } catch {
        // compromise load failed
      }
    }

    // --- LLM detector (opt-in Pass 3) ---
    this._llmDetector = null;
    if (config.llmDetection) {
      const { LlmDetector } = require('./llm-detector');
      this._llmDetector = new LlmDetector(config);
    }

    // NER/LLM coordination: if NER handles PERSON/ORG/GPE, tell LLM to skip them
    if (this._nerDetector && this._llmDetector) {
      this._llmDetector.addExcludedCategories(['PERSON', 'ORG', 'GPE']);
    }
  }

  _buildPatterns() {
    const compiled = [];

    // Custom patterns first — user-defined patterns take priority
    for (const { name, pattern: patternStr } of this.config.customPatterns) {
      try {
        const regex = new RegExp(patternStr, 'g');
        if (!this._testRegexSafety(regex)) {
          console.warn(`CloakLLM: Custom pattern '${name}' failed safety check (potential ReDoS) — skipped`);
          continue;
        }
        compiled.push({ name, pattern: regex });
      } catch (err) {
        console.warn(`CloakLLM: Invalid custom pattern '${name}': ${err.message} — skipped`);
      }
    }

    // Locale patterns second — before built-in so locale-specific patterns
    // (e.g., PHONE_DE) take priority over universal patterns (e.g., PHONE)
    // via covered-span overlap checks.
    const localePatterns = LOCALE_PATTERNS[this.config.locale] || [];
    for (const [name, pattern] of localePatterns) {
      if (this._testRegexSafety(pattern)) {
        compiled.push({ name, pattern: new RegExp(pattern.source, pattern.flags) });
      }
    }

    // Built-in patterns third
    for (const [name, { pattern, configKey }] of Object.entries(PATTERNS)) {
      if (this.config[configKey] !== false) {
        compiled.push({ name, pattern });
      }
    }

    // Safety-check all patterns (including built-in)
    for (const { name, pattern } of compiled) {
      if (!this._testRegexSafety(pattern)) {
        console.warn(`CloakLLM: Pattern '${name}' failed ReDoS safety check — this is a bug`);
      }
    }

    return compiled;
  }

  _testRegexSafety(regex) {
    const inputs = [
      'a'.repeat(25) + '!',
      '1'.repeat(25) + '!',
      ' '.repeat(25) + '!',
      'a1 '.repeat(8) + '!',
      '@'.repeat(25) + '!',
    ];
    for (const input of inputs) {
      const start = performance.now();
      new RegExp(regex.source, regex.flags).exec(input);
      if ((performance.now() - start) >= 20) return false;
    }
    return true;
  }

  /**
   * Detect all sensitive entities in text.
   * @param {string} text
   * @returns {{ detections: Detection[], timing: Object }} Sorted by start position, with per-pass timing
   */
  detect(text) {
    /** @type {Detection[]} */
    const detections = [];
    /** @type {Array<[number, number]>} */
    const coveredSpans = [];
    const timing = {};

    // --- Pass 1: Regex (fast, high precision for structured data) ---
    let t0 = performance.now();
    for (const { name, pattern } of this._compiledPatterns) {
      // Reset regex state (global flag)
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = regex.exec(text)) !== null) {
        const start = match.index;
        const end = start + match[0].length;

        // Skip if overlapping with existing detection
        if (coveredSpans.some(([s, e]) => start < e && end > s)) {
          continue;
        }

        // Skip short phone-like matches
        if (name === 'PHONE') {
          const digits = match[0].replace(/[-.\s()+]/g, '');
          if (digits.length < 7) continue;
        }

        detections.push({
          text: match[0],
          category: name,
          start,
          end,
          confidence: 0.95,
          source: 'regex',
        });
        coveredSpans.push([start, end]);
      }
    }
    timing.regex_ms = +(performance.now() - t0).toFixed(2);

    // --- Pass 2: NER via compromise (optional) ---
    t0 = performance.now();
    if (this._nerDetector) {
      const nerDetections = this._nerDetector.detect(text, coveredSpans);
      detections.push(...nerDetections);
    }
    timing.ner_ms = +(performance.now() - t0).toFixed(2);

    // --- Pass 3: Local LLM (semantic/contextual PII, opt-in) ---
    t0 = performance.now();
    if (this._llmDetector !== null) {
      const llmDetections = this._llmDetector.detect(text, coveredSpans);
      detections.push(...llmDetections);
    }
    timing.llm_ms = +(performance.now() - t0).toFixed(2);

    // Sort by start position
    detections.sort((a, b) => a.start - b.start);
    return { detections, timing };
  }
}

module.exports = { DetectionEngine, PATTERNS };
