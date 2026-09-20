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
const { PATTERNS, luhnValid, hasPhoneContext } = require('../patterns');

/**
 * A BUILT-IN pattern failed the ReDoS safety check.
 *
 * Thrown rather than skipped. A built-in failing here cannot be caused by
 * user input -- it means one of our own patterns regressed -- and the
 * alternative is to carry on with that category's detection silently
 * switched off, which in a PII tool is the worst available outcome.
 *
 * Custom and locale patterns are still skipped with a warning: a user's
 * own regex should not be able to stop the SDK from starting.
 */
class PatternSafetyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PatternSafetyError';
  }
}

// Two budgets, because the check means two different things (v0.12.4).
// For a CUSTOM or locale pattern it is a real boundary against a regex we
// did not write, so it stays tight. For a BUILT-IN it is a regression
// canary -- a user cannot change our patterns -- and since a failing
// built-in now THROWS, a tight budget would turn a merely slow machine
// into one where the SDK refuses to start. Catastrophic backtracking is
// exponential and blows past a second on these probes, so 1s still
// catches the thing this is for while leaving room for slow hardware.
const SAFETY_BUDGET_MS = 100;
const BUILTIN_SAFETY_BUDGET_MS = 1000;

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

  _measureRegexSafety(regex) {
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
    // v0.12.5: `process` does not exist in a browser or a service worker,
    // and this is a cross-platform library. v0.12.4 called
    // process.cpuUsage() unconditionally, so merely CONSTRUCTING a
    // RegexBackend threw ReferenceError anywhere outside Node -- which
    // took down the CloakLLM Guard extension, whose service worker could
    // no longer build a detector at all.
    //
    // CPU time where it exists, wall clock where it does not. Browsers
    // expose no CPU-time API, so the fallback reintroduces the contention
    // sensitivity that v0.12.3 removed -- but only there, and only against
    // the 1-second built-in budget, where real patterns sit ~60x clear.
    const hasCpuClock = typeof process !== 'undefined'
      && typeof process.cpuUsage === 'function';

    let worst = 0;
    for (const input of inputs) {
      // process.cpuUsage() is microseconds of user+system CPU.
      const start = hasCpuClock ? process.cpuUsage() : performance.now();
      new RegExp(regex.source, regex.flags).exec(input);
      const elapsed = hasCpuClock
        ? (() => { const u = process.cpuUsage(start); return (u.user + u.system) / 1000; })()
        : performance.now() - start;
      worst = Math.max(worst, elapsed);
    }
    return worst;
  }

  _testRegexSafety(regex) {
    return this._measureRegexSafety(regex) < SAFETY_BUDGET_MS;
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
      } else {
        // v0.12.4: this branch used to be silent, which is the same
        // fail-open with the volume turned all the way down -- a locale's
        // detection would just quietly not happen. Not thrown, because a
        // locale pack is data rather than core code, but no longer invisible.
        console.warn(
          `CloakLLM: locale pattern '${name}' for locale '${this.config.locale}' ` +
          `failed the ReDoS safety check - skipped. That category will NOT be detected.`
        );
      }
    }

    // Built-in patterns third.
    // v0.6.1 H1.1: built-in patterns are now also gated by the safety check
    // (previously skipped). This caught real bugs in PHONE/IBAN that had
    // been shipping since v0.1.0.
    for (const [name, { pattern, configKey }] of Object.entries(PATTERNS)) {
      if (this.config[configKey] === false) continue;
      // v0.12.4: THROW, do not skip. Skipping left the process running with
      // this category's detection silently switched off, which is fail-open
      // in a tool whose entire job is not to miss things. A built-in failing
      // here cannot be provoked by user input -- it is our own regression,
      // exactly as the message has always said -- so refusing to start is
      // the honest response, and CI catches it long before a user does.
      const worst = this._measureRegexSafety(pattern);
      if (worst >= BUILTIN_SAFETY_BUDGET_MS) {
        throw new PatternSafetyError(
          `CloakLLM: built-in pattern '${name}' failed the ReDoS safety check ` +
          `(${worst.toFixed(0)} ms of CPU against a ${BUILTIN_SAFETY_BUDGET_MS} ms ` +
          `budget). This is a regression in CloakLLM, not in your input. ` +
          `Refusing to start rather than run with '${name}' detection silently ` +
          `disabled. Please file a bug.`
        );
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
          // v0.12.4: a CONTIGUOUS digit run is only a phone number if
          // something nearby says so. Separated forms and E.164 have
          // already declared themselves and are not gated. Verified purely
          // additive: the only all-digit match the previous pattern made
          // anywhere in the corpora was "14159265", the digits of pi,
          // which was itself a false positive.
          if (/^\d+$/.test(match[0]) && !hasPhoneContext(text, start)) continue;
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

module.exports = { RegexBackend, PatternSafetyError };
