/**
 * US healthcare identifiers (v0.13.0, health edition).
 *
 * Off by default and OPT-IN: ShieldConfig.detectUsHealthIds must be `true`.
 * Label-gated categories (MRN, ACCOUNT_NUMBER, HEALTH_PLAN_ID,
 * LICENSE_NUMBER, NPI, SSN_PARTIAL) match LABEL + VALUE and detect only the
 * value -- the pattern's single capture group, which always ends the match.
 * Structural categories (MEDICARE_MBI, HICN, DEA, NPI) are checked in code.
 *
 * Mirrors cloakllm-py's cloakllm/clinical_ids.py exactly; see that module for
 * the sources and the reasoning behind each rule.
 */

const SEP = String.raw`\s{0,3}(?:[:#=]\s{0,3})?(?:(?:[Nn]o\.?|[Nn]umber|#)\s{0,3}[:#]?\s{0,3})?`;
const ID_VALUE = String.raw`([A-Za-z]{0,4}-?\d[\dA-Za-z]{2,15}(?:-\d{1,6})?)(?![\w-])`;
const NPI_VALUE = String.raw`([12]\d{9})(?!\d)`;

const MRN_LABELS = String.raw`(?:[Mm]edical\s[Rr]ecord(?:\s(?:[Nn]umber|[Nn]o\.?|#))?|[Mm]ed\.?\s?[Rr]ec\.?|`
  + String.raw`MRN|MR#|[Pp]atient\s(?:ID|[Nn]umber|[Nn]o\.?|#)|[Pp]t\.?\s?(?:ID|#)|PID|`
  + String.raw`[Cc]hart\s?(?:#|[Nn]o\.?|[Nn]umber)|CSN|FIN|[Ee]ncounter\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|`
  + String.raw`[Vv]isit\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|[Aa]ccession\s?(?:#|[Nn]o\.?|[Nn]umber)?)`;
const ACCOUNT_LABELS = String.raw`(?:[Aa]ccount\s?(?:#|[Nn]o\.?|[Nn]umber)|[Aa]cct\.?|HAR|`
  + String.raw`[Cc]laim\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|(?:[Pp]rior\s)?[Aa]uth(?:orization)?\s?(?:#|[Nn]o\.?|[Nn]umber)|`
  + String.raw`[Rr]ef(?:erence)?\s?(?:#|[Nn]o\.?|[Nn]umber))`;
const PLAN_LABELS = String.raw`(?:[Mm]ember\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|[Ss]ubscriber\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|`
  + String.raw`[Pp]olicy\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|[Ii]nsurance\s(?:ID|#|[Nn]o\.?|[Nn]umber)|`
  + String.raw`[Mm]edicaid(?:\s(?:ID|#|[Nn]o\.?|[Nn]umber))?|CIN|R[Xx]\s?ID|`
  + String.raw`[Bb]eneficiary\s(?:ID|#|[Nn]o\.?|[Nn]umber)|[Pp]lan\sID)`;
const LICENSE_LABELS = String.raw`(?:[Dd]river'?s\s[Ll]icen[cs]e(?:\s(?:#|[Nn]o\.?|[Nn]umber))?|`
  + String.raw`[Ll]icen[cs]e\s?(?:#|[Nn]o\.?|[Nn]umber)|[Ll]ic\.?\s?(?:#|[Nn]o\.?)|DL\s?#)`;
const NPI_LABELS = String.raw`(?:NPI)`;
const B = String.raw`(?<![A-Za-z0-9])`;

const MRN_PATTERN = B + MRN_LABELS + SEP + ID_VALUE;
const ACCOUNT_PATTERN = B + ACCOUNT_LABELS + SEP + ID_VALUE;
const HEALTH_PLAN_PATTERN = B + PLAN_LABELS + SEP + ID_VALUE;
const LICENSE_PATTERN = B + LICENSE_LABELS + SEP + ID_VALUE;
const NPI_PATTERN = B + NPI_LABELS + SEP + NPI_VALUE;

const A = '[AC-HJKMNP-RT-Y]';
const AN = '[AC-HJKMNP-RT-Y0-9]';
const MBI_PATTERN = String.raw`(?<![A-Za-z0-9-])[1-9]` + A + AN + String.raw`\d-?` + A + AN
  + String.raw`\d-?` + A + A + String.raw`\d\d(?![A-Za-z0-9-])`;

const HICN_PATTERN = String.raw`(?<![\w-])(?!000|666|9\d\d)\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}-?[A-Z][A-Z0-9]?(?![\w-])`;

const DEA_PATTERN = String.raw`(?<![A-Za-z0-9])[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}(?![A-Za-z0-9])`;

const SSN_PARTIAL_PATTERN = String.raw`(?:(?<![A-Za-z0-9])(?:SSN|SS#|[Ss]ocial\s[Ss]ecurity(?:\s[Nn]umber)?)\s{0,3}(?:#|[Nn]o\.?)?\s{0,3}:?\s{0,3}`
  + String.raw`(?:[Ee]nding(?:\s[Ii]n)?|[Ll]ast\s(?:4|[Ff]our)(?:\s[Dd]igits)?|[Xx*]{3}-?[Xx*]{2}-?)\s{0,3}:?\s{0,3}|`
  + String.raw`(?<![A-Za-z0-9])[Ll]ast\s(?:4|[Ff]our)(?:\s[Dd]igits)?\sof\s(?:(?:his|her|their|the|[Pp]t'?s|[Pp]atient'?s)\s){0,2}`
  + String.raw`(?:SSN|SS#|[Ss]ocial\s[Ss]ecurity(?:\s[Nn]umber)?)\s{0,3}(?:is\s)?:?\s{0,3}|`
  + String.raw`(?<![A-Za-z0-9])(?:[Xx]{3}|\*{3})-(?:[Xx]{2}|\*{2})-)(\d{4})(?!\d)`;

const VALUE_GROUP_CATEGORIES = new Set([
  'MRN', 'ACCOUNT_NUMBER', 'HEALTH_PLAN_ID', 'LICENSE_NUMBER', 'NPI', 'SSN_PARTIAL',
]);
const US_HEALTH_ID_CATEGORIES = new Set([
  'MRN', 'ACCOUNT_NUMBER', 'HEALTH_PLAN_ID', 'LICENSE_NUMBER', 'NPI',
  'MEDICARE_MBI', 'HICN', 'DEA', 'SSN_PARTIAL',
]);

const MEDICARE_CONTEXT_RE = /(?:[Mm]edicare|MBI|HICN|[Bb]eneficiary)\W{0,12}(?:\w+\W{1,3}){0,2}$/;
const MEDICARE_CONTEXT_WINDOW = 40;

/** CMS NPI check digit: Luhn with the 80840 prefix (plain Luhn plus 24). */
function npiValid(value) {
  if (!/^[12]\d{9}$/.test(value)) return false;
  let total = 24;
  const base = value.slice(0, 9).split('').reverse();
  base.forEach((ch, i) => {
    let d = Number(ch);
    if (i % 2 === 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  });
  return (10 - (total % 10)) % 10 === Number(value[9]);
}

/** DEA registration number check digit. */
function deaValid(value) {
  if (!/^[A-Z][A-Z9]\d{7}$/.test(value)) return false;
  const d = value.slice(2).split('').map(Number);
  const total = d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5]);
  return total % 10 === d[6];
}

/** Dashed MBI stands alone; undashed needs a Medicare word shortly before. */
function mbiAccepted(text, start, end) {
  if ((text.slice(start, end).match(/-/g) || []).length === 2) return true;
  return MEDICARE_CONTEXT_RE.test(text.slice(Math.max(0, start - MEDICARE_CONTEXT_WINDOW), start));
}

/** Code-side gate (regex proposes, code disposes). start/end span the value. */
function accept(name, text, start, end) {
  const value = text.slice(start, end);
  if (name === 'MRN' || name === 'ACCOUNT_NUMBER' || name === 'HEALTH_PLAN_ID' || name === 'LICENSE_NUMBER') {
    return (value.match(/\d/g) || []).length >= 5;
  }
  if (name === 'NPI') return npiValid(value);
  if (name === 'DEA') return deaValid(value);
  if (name === 'MEDICARE_MBI') return mbiAccepted(text, start, end);
  return true;
}

module.exports = {
  MRN_PATTERN, ACCOUNT_PATTERN, HEALTH_PLAN_PATTERN, LICENSE_PATTERN, NPI_PATTERN,
  MBI_PATTERN, HICN_PATTERN, DEA_PATTERN, SSN_PARTIAL_PATTERN,
  VALUE_GROUP_CATEGORIES, US_HEALTH_ID_CATEGORIES,
  npiValid, deaValid, accept,
};
