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
  // compromise not installed -- NER disabled
}

const MAX_NER_TEXT_LENGTH = 100_000;

// Characters that can sit at the edge of a NER span but are never part of a
// name. The period is deliberately absent: "Acme Inc." ends in one.
const NER_EDGE_CHARS = new Set("'\"`()[]{}<>,;: \t\r\n");
// A NER span containing any of these is code, not a name: a call such as
// ObjectId( -- a letter directly followed by "(" -- braces, angle brackets,
// "=", or a run of five or more digits. "John (Jack) Smith" is unaffected:
// its bracket follows a space. Square brackets are deliberately NOT here:
// "jane[at]example[dot]org" is how people obfuscate an email, and a NER tag
// on it is what keeps it from leaking -- the hard corpus caught a first
// version of this rule that let it through.
const NER_CODE_RE = /[A-Za-z_]\(|[{}<>=]|\d{5,}/;

/**
 * Tidy a NER span, or reject it. Returns [start, end] or null.
 *
 * v0.12.7 (cloakllm/CloakLLM#10). spaCy, reading a Python dict printed as
 * text, returned the name AND its closing quote, and returned
 * ObjectId('68cfeb61...') as a place. compromise was not affected on that
 * input, but both SDKs apply the same rule so they cannot drift apart.
 * Mirrors cloakllm-py's detector.clean_ner_span exactly.
 *
 * @param {string} text
 * @param {number} start
 * @param {number} end
 * @returns {[number, number] | null}
 */
function cleanNerSpan(text, start, end) {
  while (start < end && NER_EDGE_CHARS.has(text[start])) start += 1;
  while (end > start && NER_EDGE_CHARS.has(text[end - 1])) end -= 1;
  if (end - start < 2 || NER_CODE_RE.test(text.slice(start, end))) return null;
  return [start, end];
}

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

    // People -> PERSON
    this._extractEntities(doc.people(), text, 'PERSON', 0.80, coveredSpans, detections);
    // Organizations -> ORG
    this._extractEntities(doc.organizations(), text, 'ORG', 0.75, coveredSpans, detections);
    // Places -> GPE
    this._extractEntities(doc.places(), text, 'GPE', 0.75, coveredSpans, detections);

    // Organizations named only by COORDINATION: "Microsoft and Amazon".
    //
    // compromise tags Amazon there as a proper noun but not an organisation,
    // so the second half of the pair was missed while the first was caught.
    // Coordination shares type -- that is what "and" is doing in the
    // sentence -- so an unrecognised proper noun conjoined to a recognised
    // organisation is one too.
    //
    // Anchored on a confirmed #Organization, which is what keeps it safe.
    // The obvious alternatives are not: treating every #Acronym as an org
    // would swallow DNS, API, JWT and UUID, and treating every #ProperNoun
    // as one would swallow every capitalised word in the corpus. Measured:
    // this adds Amazon and changes nothing else -- person coordinations
    // ("Alice Chen and Bob Martinez") do not fire, because no organisation
    // anchors them.
    //
    // Confidence is below a directly-recognised org: this is inferred from
    // a neighbour rather than from the term itself.
    this._extractEntities(
      doc.match('#Organization+ (and|&|or|,) #ProperNoun+')
        .match('(and|&|or|,) #ProperNoun+')
        .match('#ProperNoun+'),
      text, 'ORG', 0.65, coveredSpans, detections,
    );

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

      // v0.12.7 (#10): trim quotes/brackets off the edges, drop code.
      const span = cleanNerSpan(
        text, firstTerm.offset.start, lastTerm.offset.start + lastTerm.offset.length,
      );
      if (!span) continue;
      const [start, end] = span;

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
      const span = cleanNerSpan(text, match.index, match.index + match[0].length);
      if (!span) continue;
      const [start, end] = span;
      if (coveredSpans.some(([s, e]) => start < e && end > s)) continue;
      detections.push({
        text: text.slice(start, end), category, start, end, confidence, source: 'ner',
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

module.exports = { NerDetector, isNerAvailable, cleanNerSpan };
