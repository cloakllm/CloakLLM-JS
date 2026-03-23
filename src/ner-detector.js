/**
 * NER Detector via compromise (optional dependency).
 *
 * Detects PERSON, ORG, and GPE entities using compromise's
 * rule-based NLP. English only.
 *
 * Install: npm install compromise
 */

let nlp = null;
try {
  nlp = require('compromise');
} catch {
  // compromise not installed — NER disabled
}

const MAX_NER_TEXT_LENGTH = 100_000;

class NerDetector {
  constructor() {
    if (!nlp) {
      throw new Error(
        'compromise is required for NER detection: npm install compromise'
      );
    }
  }

  /**
   * Detect named entities in text.
   * @param {string} text - Input text
   * @param {Array<[number, number]>} coveredSpans - Already-detected spans
   * @returns {Array<import('./detector').Detection>} Detected entities
   */
  detect(text, coveredSpans = []) {
    if (text.length > MAX_NER_TEXT_LENGTH) {
      console.warn(`CloakLLM: NER input truncated from ${text.length} to ${MAX_NER_TEXT_LENGTH} chars`);
      text = text.slice(0, MAX_NER_TEXT_LENGTH);
    }
    const doc = nlp(text);
    const detections = [];

    // People → PERSON
    this._extractEntities(doc.people(), text, 'PERSON', 0.80, coveredSpans, detections);
    // Organizations → ORG
    this._extractEntities(doc.organizations(), text, 'ORG', 0.75, coveredSpans, detections);
    // Places → GPE
    this._extractEntities(doc.places(), text, 'GPE', 0.75, coveredSpans, detections);

    return detections;
  }

  /**
   * Extract entities from a compromise View, computing character offsets.
   * @private
   */
  _extractEntities(view, text, category, confidence, coveredSpans, detections) {
    const matches = view.json({ offset: true });
    for (const match of matches) {
      const value = match.text;
      if (!value || value.length < 2) continue;

      // Compute span from first term to last term
      const terms = match.terms || [];
      if (terms.length === 0) continue;

      const firstTerm = terms[0];
      const lastTerm = terms[terms.length - 1];

      if (!firstTerm.offset || !lastTerm.offset) {
        // Fallback: find by text search
        this._findByText(text, value, category, confidence, coveredSpans, detections);
        continue;
      }

      const start = firstTerm.offset.start;
      const end = lastTerm.offset.start + lastTerm.offset.length;

      // Skip if overlapping with already-detected spans
      if (coveredSpans.some(([s, e]) => start < e && end > s)) continue;

      detections.push({
        text: text.slice(start, end),
        category,
        start,
        end,
        confidence,
        source: 'ner',
      });
      coveredSpans.push([start, end]);
    }
  }

  /**
   * Fallback: find entity by text search when offsets unavailable.
   * @private
   */
  _findByText(text, value, category, confidence, coveredSpans, detections) {
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escaped, 'gi');
    let match;
    while ((match = regex.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      if (coveredSpans.some(([s, e]) => start < e && end > s)) continue;
      detections.push({
        text: match[0], category, start, end, confidence, source: 'ner',
      });
      coveredSpans.push([start, end]);
    }
  }
}

/**
 * Check if compromise is installed and NER is available.
 * @returns {boolean}
 */
function isNerAvailable() {
  return nlp !== null;
}

module.exports = { NerDetector, isNerAvailable };
