/**
 * DetectorBackend — base class for pluggable detection backends.
 *
 * All detection backends (regex, NER, LLM, custom) extend this class.
 * The DetectionEngine orchestrates a pipeline of backends in order.
 *
 * Usage:
 *   const { DetectorBackend } = require('cloakllm');
 *
 *   class MyBackend extends DetectorBackend {
 *     get name() { return 'my_backend'; }
 *     detect(text, coveredSpans) { ... }
 *   }
 */

class DetectorBackend {
  /**
   * Unique name for this backend (used in timing keys and detection_passes).
   * @returns {string}
   */
  get name() {
    throw new Error('DetectorBackend subclass must implement get name()');
  }

  /**
   * Detect sensitive entities in text.
   *
   * @param {string} text - The input text to scan.
   * @param {Array<[number, number]>} coveredSpans - Spans already detected by prior backends.
   *   Backends MUST push new spans to this array.
   * @returns {Array<import('../detector').Detection>} Detected entities.
   */
  detect(text, coveredSpans) {
    throw new Error('DetectorBackend subclass must implement detect()');
  }
}

module.exports = { DetectorBackend };
