/**
 * NerBackend — NER detection via compromise (optional).
 *
 * Detects PERSON, ORG, and GPE entities using compromise's rule-based NLP.
 * This is the second pass in the default detection pipeline.
 */

const { DetectorBackend } = require('./base');
const { NerDetector, isNerAvailable } = require('../ner-detector');

class NerBackend extends DetectorBackend {
  constructor() {
    super();
    this._nerDetector = null;
    if (isNerAvailable()) {
      try {
        this._nerDetector = new NerDetector();
      } catch {
        // compromise load failed
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
    if (!this._nerDetector) return [];
    return this._nerDetector.detect(text, coveredSpans);
  }
}

module.exports = { NerBackend };
