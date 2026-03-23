/**
 * Locale-specific PII regex patterns.
 *
 * Each locale defines additional regex patterns that supplement the
 * universal patterns (EMAIL, SSN, CREDIT_CARD, etc.). Patterns are
 * designed for low false-positive rates with validation where possible.
 */

const LOCALE_PATTERNS = {
  de: [
    ['PHONE_DE', /(?:\+49\s?|0)[1][5-7]\d[\s\-]?\d{3,4}[\s\-]?\d{4}/g],
    ['PHONE_DE_LAND', /(?:\+49\s?|0)[2-9]\d{1,4}[\s\-\/]?\d{3,8}/g],
    ['VAT_DE', /\bDE\d{9}\b/g],
  ],
  fr: [
    ['PHONE_FR', /(?:\+33\s?|0)[1-9](?:[\s\.\-]?\d{2}){4}/g],
    ['NIR_FR', /\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}\s?\d{2}\b/g],
  ],
  es: [
    ['PHONE_ES', /(?:\+34\s?)?[6-9]\d{2}[\s\-]?\d{2,3}[\s\-]?\d{2,3}[\s\-]?\d{2,3}/g],
    ['DNI_ES', /\b\d{8}[A-HJ-NP-TV-Z]\b/g],
    ['NIE_ES', /\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b/g],
  ],
  nl: [
    ['PHONE_NL', /(?:\+31\s?[1-9]\d|06)[\s\-]?\d{4}[\s\-]?\d{4}/g],
    ['POSTAL_NL', /\b\d{4}\s?[A-Z]{2}\b/g],
    ['BSN_NL', /(?:bsn|burgerservicenummer|sofi)[\s:]*(\d{9})\b/gi],
  ],
  he: [
    ['PHONE_IL', /(?:\+972[\s\-]?|0)5[0-9][\s\-]?\d{3}[\s\-]?\d{4}/g],
    ['PHONE_IL_LAND', /(?:\+972[\s\-]?|0)[2-489][\s\-]?\d{7}/g],
  ],
  zh: [
    // National ID must come before PHONE_CN to prevent partial matches on IDs
    ['NATIONAL_ID_CN', /\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g],
    ['PHONE_CN', /(?:\+86\s?)?1[3-9]\d[\s\-]?\d{4}[\s\-]?\d{4}/g],
  ],
  ja: [
    ['PHONE_JP', /(?:\+81\s?|0)[789]0[\s\-]?\d{4}[\s\-]?\d{4}/g],
    ['PHONE_JP_LAND', /(?:\+81\s?|0)[1-9]\d{0,3}[\s\-]?\d{2,4}[\s\-]?\d{4}/g],
    ['MY_NUMBER_JP', /(?:マイナンバー|my\s?number)[\s:]*(\d{12})\b/gi],
  ],
  ru: [
    ['PHONE_RU', /(?:\+7|8)[\s\-]?\(?9\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}/g],
    ['PHONE_RU_LAND', /(?:\+7|8)[\s\-]?\(?[3-8]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}/g],
    ['SNILS_RU', /\b\d{3}-\d{3}-\d{3}\s\d{2}\b/g],
    ['INN_RU', /(?:инн|inn)[\s:]*(\d{10}(?:\d{2})?)\b/gi],
  ],
  ko: [
    ['PHONE_KR', /(?:\+82[\s\-]?)?0?1[016789][\s\-]?\d{3,4}[\s\-]?\d{4}/g],
    ['PHONE_KR_LAND', /(?:\+82[\s\-]?)?0[2-6]\d?[\s\-]?\d{3,4}[\s\-]?\d{4}/g],
    ['RRN_KR', /\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[\s\-]\d{7}\b/g],
  ],
  it: [
    ['PHONE_IT', /(?:\+39[\s\-]?)?3\d{2}[\s\-]?\d{6,7}/g],
    ['PHONE_IT_LAND', /(?:\+39[\s\-]?)?0\d{1,3}[\s\-]?\d{4,8}/g],
    ['CODICE_FISCALE_IT', /\b[A-Z]{6}\d{2}[ABCDEHLMPRST](?:[0-4]\d|[5-7][01])[A-Z]\d{3}[A-Z]\b/g],
  ],
  pl: [
    ['PHONE_PL', /(?:\+48[\s\-]?)?\d{3}[\s\-]?\d{3}[\s\-]?\d{3}/g],
    ['PESEL_PL', /(?:pesel)[\s:]*(\d{2}(?:[02468][1-9]|[13579][012])(?:0[1-9]|[12]\d|3[01])\d{5})\b/gi],
    ['NIP_PL', /(?:nip)[\s:]*(\d{3}-?\d{3}-?\d{2}-?\d{2})\b/gi],
  ],
  pt: [
    ['PHONE_PT', /(?:\+351[\s\-]?)?9[1236]\d[\s\-]?\d{3}[\s\-]?\d{3}/g],
    ['PHONE_BR', /(?:\+55[\s\-]?)?\(?[1-9]\d\)?[\s\-]?9?\d{4}[\s\-]?\d{4}/g],
    ['CPF_BR', /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g],
  ],
  hi: [
    ['PHONE_IN', /(?:\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}/g],
    ['PAN_IN', /\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b/g],
    ['AADHAAR_IN', /(?:aadhaar|आधार|uidai)[\s:]*([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b/gi],
  ],
};

module.exports = { LOCALE_PATTERNS };
