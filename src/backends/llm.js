/**
 * LlmBackend — LLM-based semantic PII detection via Ollama.
 *
 * Wraps the existing LlmDetector as a DetectorBackend.
 * This is the third pass in the default detection pipeline (opt-in).
 */

const { DetectorBackend } = require('./base');

class LlmBackend extends DetectorBackend {
  /**
   * @param {import('../config').ShieldConfig} config
   */
  constructor(config) {
    super();
    const { LlmDetector } = require('../llm-detector');
    this._detector = new LlmDetector(config);
  }

  get name() {
    return 'llm';
  }

  /**
   * @param {string} text
   * @param {Array<[number, number]>} coveredSpans
   * @returns {Array<import('../detector').Detection>}
   */
  detect(text, coveredSpans) {
    return this._detector.detect(text, coveredSpans);
  }

  /**
   * Forward to underlying LlmDetector for NER/LLM coordination.
   * @param {string[]} categories
   */
  addExcludedCategories(categories) {
    this._detector.addExcludedCategories(categories);
  }
}

module.exports = { LlmBackend };
