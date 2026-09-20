/**
 * RegexBackend -- regex-based PII detection.
 *
 * Handles custom patterns, locale patterns, and built-in patterns.
 * This is always the first pass in the default detection pipeline.
 */

const { DetectorBackend } = require('./base');
const { LOCALE_PATTERNS } = require('../locale-patterns');
// PATTERNS comes from patterns.js, not detector.js. Importing it from
// detector.js used to pull in that module's pipeline builder, whose
// require('./backends/llm') reaches llm-detector.js and its child_process/net
// dependencies -- bundlers follow requires inside function bodies, so a
// detection-only browser/worker build dragged in the whole Ollama path.
// This also removes the former detector.js <-> regex.js circular dependency.
const { PATTERNS, luhnValid } = require('../patterns');

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
    // v0.6.1 H1.2: expanded corpus for previously-skipped built-ins.
    //
    // v0.12.3: measured in CPU time, not wall clock. Catastrophic
    // backtracking is CPU burn, so CPU time is what characterises it; wall
    // clock additionally measures whatever else the machine is doing. That
    // matters because failing this check SKIPS the pattern -- detection for
    // that category is silently switched off -- so on a wall-clock
    // threshold a busy machine could quietly stop detecting. EMAIL had only
    // ~6x of headroom where other patterns had 100x-1300x.
    const inputs = [
      'a'.repeat(25) + '!',
      '1'.repeat(25) + '!',
      ' '.repeat(25) + '!',
      'a1 '.repeat(8) + '!',
      '@'.repeat(25) + '!',
      '1'.repeat(5000),               // PHONE / locale phones
      'A1'.repeat(2500),              // API_KEY / IBAN
      'AAAA'.repeat(100),             // IBAN
      '1234-'.repeat(1000),           // PHONE separators
      'sk_' + 'a'.repeat(1000),       // API_KEY long bearer
    ];
    for (const input of inputs) {
      // process.cpuUsage() is microseconds of user+system CPU.
      const start = process.cpuUsage();
      new RegExp(regex.source, regex.flags).exec(input);
      const used = process.cpuUsage(start);
      if ((used.user + used.system) / 1000 >= 100) return false;
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
          console.warn(`CloakLLM: Custom pattern '${name}' failed safety check (potential ReDoS) - skipped`);
          continue;
        }
        compiled.push({ name, pattern: regex });
      } catch (err) {
        console.warn(`CloakLLM: Invalid custom pattern '${name}': ${err.message} - skipped`);
      }
    }

    // Locale patterns second
    const localePatterns = LOCALE_PATTERNS[this.config.locale] || [];
    for (const [name, pattern] of localePatterns) {
      if (this._testRegexSafety(pattern)) {
        compiled.push({ name, pattern: new RegExp(pattern.source, pattern.flags) });
      }
    }

    // Built-in patterns third.
    // v0.6.1 H1.1: built-in patterns are now also gated by the safety check
    // (previously skipped). This caught real bugs in PHONE/IBAN that had
    // been shipping since v0.1.0.
    for (const [name, { pattern, configKey }] of Object.entries(PATTERNS)) {
      if (this.config[configKey] === false) continue;
      if (!this._testRegexSafety(pattern)) {
        console.warn(
          `CloakLLM: built-in pattern '${name}' failed ReDoS safety check ` +
          `(potential catastrophic backtracking) - skipped. This indicates ` +
          `a regression. Please file a bug.`
        );
        continue;
      }
      compiled.push({ name, pattern });
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

        // v0.12.3: prefix alone is not enough. Rejecting here rather than in
        // the regex also leaves the span UNCOVERED, so a number that merely
        // looked like a card stays available to the patterns that follow.
        if (name === 'CREDIT_CARD' && !luhnValid(match[0])) continue;

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
