/**
 * Built-in PII regex patterns -- the single source of truth.
 *
 * Extracted from detector.js so that consumers needing ONLY the patterns
 * (RegexBackend, and any detection-only build) do not have to load the
 * detection pipeline builder. detector.js._buildDefaultPipeline() requires
 * backends/llm.js, which reaches llm-detector.js and its child_process/net
 * dependencies -- a bundler follows requires inside function bodies, so
 * importing PATTERNS from detector.js dragged the whole Ollama path into any
 * browser/worker bundle. Keeping the patterns standalone also removes the
 * detector.js <-> backends/regex.js circular dependency.
 *
 * detector.js re-exports PATTERNS, so `require('./detector').PATTERNS`
 * keeps working unchanged.
 *
 * Ordered by specificity (most specific first). Patterns are byte-identical
 * to cloakllm-py's PATTERNS (cross-SDK detection differential = 0).
 */

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
    // v0.11.2: detect SPACE/DASH-grouped cards (the normal way they're written),
    // not just contiguous digits. Before this "4111 1111 1111 1111" was missed
    // by CC and partially eaten by PHONE, leaking the trailing group. A back-
    // referenced separator (\1 / \2) keeps grouping consistent. Precedes PHONE
    // so the full card span is claimed first via coveredSpans.
    //
    // v0.12.3: the issuer list had stopped at Visa / 5-series Mastercard /
    // Amex / Discover, so Luhn-valid cards on three live ranges were MISSED
    // ENTIRELY -- a leak, not a false positive:
    //   * Mastercard 2-series (2221-2720), issued since 2017
    //   * JCB (3528-3589)
    //   * UnionPay (62), the largest network in the world by volume
    // Discover's 644-649 range was missing too. The recall benchmark could
    // not have caught any of it: its corpus only held Visa, 5-series
    // Mastercard and Amex.
    //
    // The prefixes stay explicit rather than becoming "any 13-19 digit run
    // validated by Luhn". Luhn alone passes one in ten random digit runs,
    // which on a developer's order ids and timestamps is a false-positive
    // engine. Prefix AND checksum, not either alone.
    // Maestro (50, 56-69, 12-19 digits) is deliberately NOT covered. Its
    // range is so broad it overlaps most of the others and a great many
    // ordinary numbers, and Luhn alone admits one in ten candidates -- so
    // adding it would buy a little recall for a lot of false positives.
    // The test suite asserts the gap so it stays a decision.
    pattern: /(?<!\d)(?:(?:4\d{3}|5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720|352[89]|35[3-8]\d|6011|62\d{2}|64[4-9]\d|65\d{2})([ -]?)\d{4}\1\d{4}\1\d{4}|3[47]\d{2}([ -]?)\d{6}\2\d{5}|3(?:0[0-5]\d|6\d{2}|8\d{2})([ -]?)\d{6}\3\d{4}|62\d{15,17})(?!\d)/g,
    configKey: 'detectCreditCards',
  },
  IBAN: {
    // v0.11.2: MUST precede PHONE. In the old order IBAN came after PHONE, so
    // PHONE claimed the IBAN's digit groups first (coveredSpans), fragmenting
    // "DE89 3704 0044 0532 0130 00" + leaking the country code. Matches compact
    // + spaced forms.
    pattern: /\b[A-Z]{2}\d{2}(?:\s?[\dA-Z]{4}){2,7}(?:\s?[\dA-Z]{1,4})?\b/g,
    configKey: 'detectIban',
  },
  PHONE: {
    // v0.6.1 H1.3: tightened. Parens REQUIRE both, bare area code REQUIRES
    // trailing separator. Eliminates ambiguity but still matches `+1-555-0142`.
    // v0.12.1: added a 2-digit-grouped alternative (e.g. French/European
    // "06 12 34 56 78", 8-10 digits) -- the prior pattern assumed 3-4 digit
    // groups, so that shape leaked on the default (non-locale) config.
    // Byte-identical to the Python PHONE pattern (cross-SDK differential = 0).
    // KNOWN GAP (2026-09-10, tracked in PLAN_v0130_detection.md): contiguous
    // no-separator runs of 9+ digits (e.g. "5550104422", "+33145678901") match
    // NOTHING -- without separators this alternation covers at most 8 digits
    // and the \d boundaries force whole-run coverage. Deliberately not patched
    // here; the fix trades against the bare-digit-run false-positive class.
    pattern: /(?<!\d)(?:(?:\+\d{1,3}[-.\s])?(?:\(\d{2,4}\)[-.\s]?|\d{2,4}[-.\s])?\d{3,4}[-.\s]?\d{3,4}|\d{2}(?:[-.\s]\d{2}){3,4})(?!\d)/g,
    configKey: 'detectPhones',
  },
  IP_ADDRESS: {
    // v0.11.2: IPv4 + IPv6. IPv6 was undetected before, so a whole address
    // leaked verbatim. Standard fully-bounded IPv6 alternation (ReDoS-safe),
    // gated by non-word/non-colon lookarounds.
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|(?<![\w:])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?::[A-Fa-f0-9]{1,4}){1,7})(?![\w:])/g,
    configKey: 'detectIpAddresses',
  },
  API_KEY: {
    // v0.6.1 F1: bounded upper at 512. Body includes - and _ so multi-segment
    // keys (Anthropic sk-ant-api03-, GitHub fine-grained github_pat_X_Y) match.
    pattern: /\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9_-]{20,512}\b/g,
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
};

/**
 * Does this digit run pass the Luhn checksum every card issuer uses?
 *
 * Applied to CREDIT_CARD matches so that a number which merely looks like a
 * card is not reported as one. Without it the standard test Visa with a
 * deliberately broken check digit (4111111111111112) was flagged, and the
 * first warning that fires on something obviously not a card is what makes
 * a user stop believing the next one.
 *
 * Separators are ignored, so it works on "4111 1111 1111 1111" as written.
 * Mirrors cloakllm-py's detector.luhn_valid exactly.
 *
 * @param {string} number
 * @returns {boolean}
 */
function luhnValid(number) {
  const digits = [];
  for (const ch of String(number)) {
    if (ch >= '0' && ch <= '9') digits.push(ch.charCodeAt(0) - 48);
  }
  if (digits.length < 12) return false;
  // Double every second digit counting from the RIGHT. Indexing from the
  // left instead, that is every index congruent to length % 2.
  const parity = digits.length % 2;
  let total = 0;
  for (let i = 0; i < digits.length; i += 1) {
    let digit = digits[i];
    if (i % 2 === parity) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    total += digit;
  }
  return total % 10 === 0;
}

module.exports = { PATTERNS, luhnValid };
