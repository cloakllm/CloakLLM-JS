/**
 * NerBackend — NER detection via compromise (optional).
 *
 * Detects PERSON, ORG, and GPE entities using compromise's rule-based NLP.
 * This is the second pass in the default detection pipeline.
 */

const { DetectorBackend } = require('./base');
const { NerDetector, isNerAvailable } = require('../ner-detector');

class NerBackend extends DetectorBackend {
  constructor(config) {
    super();
    this._config = config || {};
    this._nerDetector = null;
    if (isNerAvailable()) {
      try {
        this._nerDetector = new NerDetector();
      } catch {
        // compromise load failed -> degrade (handled in detect())
      }
    }
  }

  get name() {
    return 'ner';
  }

  /**
   * Whether NER is actually available (compromise installed).
   * @returns {boolean}
   */
  get available() {
    return this._nerDetector !== null;
  }

  /**
   * @param {string} text
   * @param {Array<[number, number]>} coveredSpans
   * @returns {Array<import('../detector').Detection>}
   */
  detect(text, coveredSpans) {
    if (!this._nerDetector) {
      // v0.11.3: fail-closed only when the deployment requires NER.
      if (this._config.nerRequired) {
        throw new Error(
          'CloakLLM: NER is required (nerRequired=true) but unavailable '
          + '(compromise not installed or failed to load).');
      }
      return [];  // best-effort: regex pass already ran
    }
    return this._nerDetector.detect(text, coveredSpans);
  }
}

module.exports = { NerBackend };
