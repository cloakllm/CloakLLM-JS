/**
 * Clinical date and age detection (v0.13.0, health edition).
 *
 * Under HIPAA Safe Harbor (45 CFR 164.514(b)(2)(i)(C)), every element of a
 * date more specific than the year is an identifier, and so is any age over
 * 89. Both categories are OFF by default (ShieldConfig.detectDates,
 * detectAgesOver89) and OPT-IN: a config object that does not mention them
 * -- such as the plain object the Guard extension passes -- keeps them off.
 *
 * The regex proposes, code disposes: a match is accepted only if it is a real
 * calendar date, a year-less "3/14" has a date word right before it, and it is
 * not a clinical ratio ("5/5 strength", "4/10 pain"). Ages are matched only in
 * age context and only when 90 or more.
 *
 * Mirrors cloakllm-py's cloakllm/clinical_dates.py exactly.
 */

const MONTH = String.raw`(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|`
  + String.raw`Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)`;
const DAY = String.raw`(?:0?[1-9]|[12]\d|3[01])`;
const MON = String.raw`(?:0?[1-9]|1[0-2])`;
const YEAR4 = String.raw`(?:19|20)\d{2}`;
const YEAR = String.raw`(?:(?:19|20)\d{2}|\d{2})`;
const ORD = String.raw`(?:st|nd|rd|th)?`;
const NB = String.raw`(?<![\w/.-])`;
const NA = String.raw`(?![\w/-])`;

const DATE_PATTERN = [
  NB + MON + '/' + DAY + '/' + YEAR + NA,
  NB + MON + '-' + DAY + '-' + YEAR + NA,
  NB + YEAR4 + String.raw`[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])` + NA,
  NB + MON + '/' + YEAR4 + NA,
  String.raw`\b` + MONTH + String.raw`\.?\s` + DAY + ORD + String.raw`(?:,?\s` + YEAR4 + String.raw`)?\b`,
  String.raw`\b` + DAY + ORD + String.raw`\s(?:of\s)?` + MONTH + String.raw`\.?(?:,?\s` + YEAR4 + String.raw`)?\b`,
  String.raw`\b` + MONTH + String.raw`\.?,?\s` + YEAR4 + String.raw`\b`,
  NB + MON + '/' + DAY + String.raw`(?![\w/%-])(?!\.\d)`,
].join('|');

const AGE_NUM = String.raw`(?:9\d|1[01]\d)`;
const AGE_PATTERN = [
  String.raw`\b` + AGE_NUM + String.raw`(?:\s?-\s?|\s)?(?:years?[\s-]old|yrs?(?:\s?old)?|y/o|y\.o\.|yo)(?![A-Za-z])`,
  String.raw`\b[Aa]ge[d]?\s?:?\s?` + AGE_NUM + String.raw`\b`,
  String.raw`\b` + AGE_NUM + String.raw`(?:yo|y/o)?[MF]\b`,
  String.raw`\b` + AGE_NUM + String.raw`\s(?:yo|y/o)\s?[MF]\b`,
  String.raw`\bin\s(?:his|her|their)\s(?:early\s|mid\s|mid-|late\s)?(?:90|100)s\b`,
  String.raw`\b[Nn]onagenarian\b|\b[Cc]entenarian\b`,
].join('|');

const DATE_CONTEXT_RE = new RegExp(
  String.raw`(?:\bon|\bsince|\bfrom|\buntil|\btill|\bby|\bdated?|\bseen|\badmitted|\badm|`
  + String.raw`\bdischarged|\bd/c|\bDOS|\bDOB|\bLMP|\bEDD|\bscheduled|\bappt|\bf/u|`
  + String.raw`\bfollow[- ]?up|\bvisit|\bsurgery|\bprocedure|\blast|\bnext|\bstart(?:ed|ing)?|`
  + String.raw`\bbegan|\bdue)\W{0,3}$`,
  'i',
);
const DATE_CONTEXT_WINDOW = 22;

// Sticky: must match exactly at the end of the date (Python re.match(text, end)).
const RATIO_AFTER_RE = new RegExp(
  String.raw`\s?(?:strength|pain|tab|tabs|tablet|of\b|dose|scale|ratio|split|units?\b|ml\b|mg\b|`
  + String.raw`cm\b|mm\b|hpf\b|lpf\b|vision|murmur|systolic|diastolic)`,
  'iy',
);

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const DAYS_IN_MONTH = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function parseMonthDay(match) {
  const word = /[A-Za-z]{3,}/.exec(match);
  const nums = (match.match(/\d+/g) || []).map(Number);
  if (word) {
    const month = MONTHS[word[0].slice(0, 3).toLowerCase()] ?? null;
    const day = nums.find((n) => n <= 31 && !(n >= 1900 && n <= 2099));
    return [month, day ?? null];
  }
  if (/^(?:19|20)\d{2}[-/]/.test(match)) return [nums[1], nums[2]];
  if (nums.length === 2 && nums[1] >= 1900) return [nums[0], null];
  return [nums[0], nums[1]];
}

/**
 * Accept a DATE pattern match only if it is really a date.
 * Mirrors clinical_dates.is_valid_date.
 */
function isValidDate(text, start, end) {
  const match = text.slice(start, end);
  const [month, day] = parseMonthDay(match);
  if (month == null || month < 1 || month > 12) return false;
  if (day != null && (day < 1 || day > DAYS_IN_MONTH[month - 1])) return false;
  const numeric = !/[A-Za-z]/.test(match);
  const hasYear = /\d+\D+\d+\D+\d+|(?:19|20)\d{2}/.test(match);
  if (numeric) {
    RATIO_AFTER_RE.lastIndex = end;
    if (RATIO_AFTER_RE.test(text)) return false;
  }
  if (numeric && !hasYear) {
    const before = text.slice(Math.max(0, start - DATE_CONTEXT_WINDOW), start);
    if (!DATE_CONTEXT_RE.test(before)) return false;
  }
  return true;
}

// \b matters: without it any word ending in "t" ("Lindqvist, 95-year-old")
// looked like a temperature label and hid the age.
const TEMPERATURE_BEFORE_RE = /(?:\btemp|\bt|\u00b0)\W{0,3}$/i;

/** Accept an AGE_90PLUS match only in a real age context. Mirrors is_age_over_89. */
function isAgeOver89(text, start, end) {
  if (TEMPERATURE_BEFORE_RE.test(text.slice(Math.max(0, start - 8), start))) return false;
  const nums = (text.slice(start, end).match(/\d+/g) || []).map(Number);
  return nums.length === 0 || nums[0] >= 90;
}

/**
 * Safe Harbor form of a detected date or age: the date's four-digit year (or
 * [DATE_REDACTED] if it has none), and "90+" for an age. Mirrors generalize.
 */
function generalize(category, value) {
  if (category === 'DATE') {
    const m = /(?<!\d)((?:19|20)\d{2})(?!\d)/.exec(value);
    return m ? m[1] : '[DATE_REDACTED]';
  }
  if (category === 'AGE_90PLUS') {
    return /\d/.test(value) ? value.replace(/\d+/, '90+') : 'aged 90+';
  }
  throw new Error(`no Safe Harbor generalization for category '${category}'`);
}

const GENERALIZED_CATEGORIES = new Set(['DATE', 'AGE_90PLUS']);

module.exports = {
  DATE_PATTERN, AGE_PATTERN, isValidDate, isAgeOver89, generalize, GENERALIZED_CATEGORIES,
};
