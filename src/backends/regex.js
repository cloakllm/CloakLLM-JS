/**
 * RegexBackend — regex-based PII detection.
 *
 * Handles custom patterns, locale patterns, and built-in patterns.
 * This is always the first pass in the default detection pipeline.
 */

const { DetectorBackend } = require('./base');
const { LOCALE_PATTERNS } = require('../locale-patterns');
// PATTERNS is the single source of truth in detector.js.
// No circular dependency: detector.js lazy-requires this module inside
// _buildDefaultPipeline(), so detector.js is always fully loaded first.
const { PATTERNS } = require('../detector');

class RegexBackend extends DetectorBackend {
  /**
   * @param {import('../config').ShieldConfig} config
   */
  constructor(config) {
    super();
    this.config = config;
    this._compiledPatterns = this._buildPatterns();
  }

  get name() {
    return 'regex';
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

  _buildPatterns() {
    const compiled = [];

    // Custom patterns first
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

    // Locale patterns second
    const localePatterns = LOCALE_PATTERNS[this.config.locale] || [];
    for (const [name, pattern] of localePatterns) {
      if (this._testRegexSafety(pattern)) {
        compiled.push({ name, pattern: new RegExp(pattern.source, pattern.flags) });
      }
    }

    // Built-in patterns third (hardcoded, pre-validated — no safety check needed)
    for (const [name, { pattern, configKey }] of Object.entries(PATTERNS)) {
      if (this.config[configKey] !== false) {
        compiled.push({ name, pattern });
      }
    }

    return compiled;
  }

  /**
   * @param {string} text
   * @param {Array<[number, number]>} coveredSpans
   * @returns {Array<import('../detector').Detection>}
   */
  detect(text, coveredSpans) {
    const detections = [];

    for (const { name, pattern } of this._compiledPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = regex.exec(text)) !== null) {
        const start = match.index;
        const end = start + match[0].length;

        if (coveredSpans.some(([s, e]) => start < e && end > s)) {
          continue;
        }

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

    return detections;
  }
}

module.exports = { RegexBackend };
