/**
 * CloakLLM Token Specification — canonical constants and validation.
 *
 * This module is the single source of truth for token format, category
 * registry, and validation logic. Other modules (tokenizer, stream,
 * config) import from here instead of defining their own constants.
 *
 * See TOKEN_SPEC.md in the hub repo for the full formal specification.
 */

// --- Token format ---

/** Canonical regex pattern string for matching CloakLLM tokens. */
const CLOAKLLM_TOKEN_PATTERN = '\\[([A-Z][A-Z0-9_]*_(?:\\d+|REDACTED))\\]';

/** Compiled regex (global) for matching CloakLLM tokens. */
const CLOAKLLM_TOKEN_REGEX = /\[([A-Z][A-Z0-9_]*_(?:\d+|REDACTED))\]/g;

/** Parsing regex with named groups. */
const _PARSE_RE = /^\[(?<category>[A-Z][A-Z0-9_]*)_(?<suffix>\d+|REDACTED)\]$/;

/** Maximum token length (including brackets), used for streaming buffer. */
const MAX_TOKEN_LENGTH = 40;

// --- Escaping ---

const ESCAPED_OPEN = '\uFF3B';
const ESCAPED_CLOSE = '\uFF3D';

// --- Category name validation ---

const CATEGORY_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;

// --- Built-in category registry ---

/** Regex categories (Pass 1). */
const REGEX_CATEGORIES = new Set([
  'EMAIL', 'SSN', 'CREDIT_CARD', 'PHONE', 'IP_ADDRESS',
  'API_KEY', 'AWS_KEY', 'JWT', 'IBAN', 'IL_ID',
]);

/** NER categories (Pass 2). */
const NER_CATEGORIES = new Set([
  'PERSON', 'ORG', 'GPE', 'FAC', 'NORP', 'MISC',
]);

/** LLM categories (Pass 3). */
const LLM_CATEGORIES = new Set([
  'ADDRESS', 'DATE_OF_BIRTH', 'MEDICAL', 'FINANCIAL',
  'NATIONAL_ID', 'BIOMETRIC', 'USERNAME', 'PASSWORD', 'VEHICLE',
]);

/** Locale-specific categories. */
const LOCALE_CATEGORIES = new Set([
  'PHONE_DE', 'PHONE_DE_LAND', 'VAT_DE',
  'PHONE_FR', 'NIR_FR',
  'PHONE_ES', 'DNI_ES', 'NIE_ES',
  'PHONE_NL', 'BSN_NL', 'POSTAL_NL',
  'PHONE_IL', 'PHONE_IL_LAND',
  'PHONE_CN', 'NATIONAL_ID_CN',
  'PHONE_JP', 'PHONE_JP_LAND', 'MY_NUMBER_JP',
  'PHONE_RU', 'PHONE_RU_LAND', 'INN_RU', 'SNILS_RU',
  'PHONE_KR', 'PHONE_KR_LAND', 'RRN_KR',
  'PHONE_IT', 'PHONE_IT_LAND', 'CODICE_FISCALE_IT',
  'PHONE_PL', 'NIP_PL', 'PESEL_PL',
  'PHONE_PT', 'PHONE_BR', 'CPF_BR',
  'PHONE_IN', 'AADHAAR_IN', 'PAN_IN',
]);

/** All built-in categories combined. */
const BUILTIN_CATEGORIES = new Set([
  ...REGEX_CATEGORIES, ...NER_CATEGORIES,
  ...LLM_CATEGORIES, ...LOCALE_CATEGORIES,
]);

/** Reserved categories that custom patterns must not use. */
const RESERVED_CATEGORIES = BUILTIN_CATEGORIES;

// --- Validation functions ---

/**
 * Return true if the string is a valid CloakLLM token.
 * @param {string} token
 * @returns {boolean}
 */
function validateToken(token) {
  if (token.length > MAX_TOKEN_LENGTH) return false;
  return _PARSE_RE.test(token);
}

/**
 * Parse a token string into { category, suffix } or null.
 * @param {string} token
 * @returns {{ category: string, suffix: string } | null}
 */
function parseToken(token) {
  const m = _PARSE_RE.exec(token);
  if (!m) return null;
  return { category: m.groups.category, suffix: m.groups.suffix };
}

/**
 * Return true if the token is a redacted token ([CATEGORY_REDACTED]).
 * @param {string} token
 * @returns {boolean}
 */
function isRedactedToken(token) {
  const result = parseToken(token);
  if (!result) return false;
  return result.suffix === 'REDACTED';
}

/**
 * Check if a category name is valid (format only, no collision check).
 * @param {string} name
 * @returns {boolean}
 */
function validateCategoryName(name) {
  return CATEGORY_NAME_PATTERN.test(name);
}

module.exports = {
  CLOAKLLM_TOKEN_PATTERN,
  CLOAKLLM_TOKEN_REGEX,
  MAX_TOKEN_LENGTH,
  ESCAPED_OPEN,
  ESCAPED_CLOSE,
  CATEGORY_NAME_PATTERN,
  REGEX_CATEGORIES,
  NER_CATEGORIES,
  LLM_CATEGORIES,
  LOCALE_CATEGORIES,
  BUILTIN_CATEGORIES,
  RESERVED_CATEGORIES,
  validateToken,
  parseToken,
  isRedactedToken,
  validateCategoryName,
};
