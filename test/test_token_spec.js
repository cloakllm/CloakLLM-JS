const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  BUILTIN_CATEGORIES,
  CATEGORY_NAME_PATTERN,
  CLOAKLLM_TOKEN_PATTERN,
  CLOAKLLM_TOKEN_REGEX,
  ESCAPED_OPEN,
  ESCAPED_CLOSE,
  LOCALE_CATEGORIES,
  LLM_CATEGORIES,
  MAX_TOKEN_LENGTH,
  NER_CATEGORIES,
  REGEX_CATEGORIES,
  RESERVED_CATEGORIES,
  // v0.7.0 A4a-2 — special-category PII (GDPR Art. 9 / EU AI Act Art. 4a)
  SPECIAL_CATEGORY_CATEGORIES,
  isRedactedToken,
  parseToken,
  validateCategoryName,
  validateToken,
} = require('../src/token-spec');

const { ShieldConfig } = require('../src/config');

describe('validateToken', () => {
  it('accepts simple tokens', () => {
    assert.ok(validateToken('[EMAIL_0]'));
    assert.ok(validateToken('[PERSON_1]'));
    assert.ok(validateToken('[CREDIT_CARD_99]'));
    assert.ok(validateToken('[SSN_0]'));
  });

  it('accepts redacted tokens', () => {
    assert.ok(validateToken('[EMAIL_REDACTED]'));
    assert.ok(validateToken('[PERSON_REDACTED]'));
    assert.ok(validateToken('[CREDIT_CARD_REDACTED]'));
  });

  it('accepts multi-word categories', () => {
    assert.ok(validateToken('[DATE_OF_BIRTH_0]'));
    assert.ok(validateToken('[IP_ADDRESS_3]'));
    assert.ok(validateToken('[API_KEY_REDACTED]'));
  });

  it('accepts category with digits', () => {
    assert.ok(validateToken('[PHONE2_0]'));
    assert.ok(validateToken('[V1_0]'));
  });

  it('rejects lowercase', () => {
    assert.ok(!validateToken('[email_0]'));
    assert.ok(!validateToken('[Person_1]'));
  });

  it('rejects missing brackets', () => {
    assert.ok(!validateToken('EMAIL_0'));
    assert.ok(!validateToken('[EMAIL_0'));
    assert.ok(!validateToken('EMAIL_0]'));
  });

  it('rejects empty and no-suffix', () => {
    assert.ok(!validateToken(''));
    assert.ok(!validateToken('[]'));
    assert.ok(!validateToken('[EMAIL]'));
  });

  it('rejects starts with digit or underscore', () => {
    assert.ok(!validateToken('[1EMAIL_0]'));
    assert.ok(!validateToken('[_EMAIL_0]'));
  });

  it('rejects special characters', () => {
    assert.ok(!validateToken('[EMAIL-ADDR_0]'));
    assert.ok(!validateToken('[EMAIL.ADDR_0]'));
  });

  it('rejects tokens exceeding max length', () => {
    const longCat = 'A'.repeat(38);
    assert.ok(!validateToken(`[${longCat}_0]`));
  });

  it('accepts tokens at max length boundary', () => {
    const cat = 'A'.repeat(36); // [A*36_0] = 40
    assert.ok(validateToken(`[${cat}_0]`));
    const cat2 = 'A'.repeat(37); // 41
    assert.ok(!validateToken(`[${cat2}_0]`));
  });
});

describe('parseToken', () => {
  it('parses basic tokens', () => {
    assert.deepStrictEqual(parseToken('[EMAIL_0]'), { category: 'EMAIL', suffix: '0' });
    assert.deepStrictEqual(parseToken('[PERSON_42]'), { category: 'PERSON', suffix: '42' });
  });

  it('parses redacted tokens', () => {
    assert.deepStrictEqual(parseToken('[SSN_REDACTED]'), { category: 'SSN', suffix: 'REDACTED' });
  });

  it('parses multi-word categories', () => {
    assert.deepStrictEqual(parseToken('[DATE_OF_BIRTH_3]'), { category: 'DATE_OF_BIRTH', suffix: '3' });
    assert.deepStrictEqual(parseToken('[IP_ADDRESS_REDACTED]'), { category: 'IP_ADDRESS', suffix: 'REDACTED' });
  });

  it('returns null for invalid tokens', () => {
    assert.strictEqual(parseToken('not a token'), null);
    assert.strictEqual(parseToken('[email_0]'), null);
    assert.strictEqual(parseToken(''), null);
    assert.strictEqual(parseToken('[EMAIL]'), null);
  });
});

describe('isRedactedToken', () => {
  it('identifies redacted tokens', () => {
    assert.ok(isRedactedToken('[EMAIL_REDACTED]'));
    assert.ok(isRedactedToken('[PERSON_REDACTED]'));
  });

  it('rejects non-redacted tokens', () => {
    assert.ok(!isRedactedToken('[EMAIL_0]'));
    assert.ok(!isRedactedToken('[PERSON_1]'));
  });

  it('rejects invalid strings', () => {
    assert.ok(!isRedactedToken('not a token'));
    assert.ok(!isRedactedToken(''));
  });
});

describe('validateCategoryName', () => {
  it('accepts valid names', () => {
    assert.ok(validateCategoryName('EMAIL'));
    assert.ok(validateCategoryName('CREDIT_CARD'));
    assert.ok(validateCategoryName('DATE_OF_BIRTH'));
    assert.ok(validateCategoryName('V2'));
    assert.ok(validateCategoryName('A'));
  });

  it('rejects invalid names', () => {
    assert.ok(!validateCategoryName('email'));
    assert.ok(!validateCategoryName('Email'));
    assert.ok(!validateCategoryName('1EMAIL'));
    assert.ok(!validateCategoryName('_EMAIL'));
    assert.ok(!validateCategoryName('EMAIL-ADDR'));
    assert.ok(!validateCategoryName(''));
  });
});

describe('Category Registry', () => {
  it('BUILTIN_CATEGORIES is the union of all sets', () => {
    // v0.7.0: union now includes SPECIAL_CATEGORY_CATEGORIES (Art. 4a).
    const union = new Set([
      ...REGEX_CATEGORIES, ...NER_CATEGORIES,
      ...LLM_CATEGORIES, ...SPECIAL_CATEGORY_CATEGORIES,
      ...LOCALE_CATEGORIES,
    ]);
    assert.deepStrictEqual(BUILTIN_CATEGORIES, union);
  });

  it('RESERVED_CATEGORIES equals BUILTIN_CATEGORIES', () => {
    assert.deepStrictEqual(RESERVED_CATEGORIES, BUILTIN_CATEGORIES);
  });

  it('no overlap between regex and NER', () => {
    for (const cat of REGEX_CATEGORIES) {
      assert.ok(!NER_CATEGORIES.has(cat), `${cat} in both regex and NER`);
    }
  });

  it('no overlap between regex and LLM', () => {
    for (const cat of REGEX_CATEGORIES) {
      assert.ok(!LLM_CATEGORIES.has(cat), `${cat} in both regex and LLM`);
    }
  });

  it('no overlap between NER and LLM', () => {
    for (const cat of NER_CATEGORIES) {
      assert.ok(!LLM_CATEGORIES.has(cat), `${cat} in both NER and LLM`);
    }
  });

  it('all names are valid category names', () => {
    for (const cat of BUILTIN_CATEGORIES) {
      assert.ok(validateCategoryName(cat), `${cat} is not valid`);
    }
  });

  it('known categories present', () => {
    assert.ok(REGEX_CATEGORIES.has('EMAIL'));
    assert.ok(NER_CATEGORIES.has('PERSON'));
    assert.ok(LLM_CATEGORIES.has('ADDRESS'));
    assert.ok(LOCALE_CATEGORIES.has('PHONE_DE'));
  });
});

describe('Token Regex', () => {
  it('finds tokens in text', () => {
    const text = 'Hello [PERSON_0], your email is [EMAIL_1].';
    const matches = [...text.matchAll(new RegExp(CLOAKLLM_TOKEN_REGEX.source, 'g'))].map(m => m[1]);
    assert.deepStrictEqual(matches, ['PERSON_0', 'EMAIL_1']);
  });

  it('finds redacted tokens', () => {
    const text = 'Contact [EMAIL_REDACTED] for info.';
    const matches = [...text.matchAll(new RegExp(CLOAKLLM_TOKEN_REGEX.source, 'g'))].map(m => m[1]);
    assert.deepStrictEqual(matches, ['EMAIL_REDACTED']);
  });

  it('does not match lowercase tokens', () => {
    const text = 'This [email_0] is not a token.';
    const matches = [...text.matchAll(new RegExp(CLOAKLLM_TOKEN_REGEX.source, 'g'))].map(m => m[1]);
    assert.deepStrictEqual(matches, []);
  });
});

describe('Constants', () => {
  it('MAX_TOKEN_LENGTH is 40', () => {
    assert.strictEqual(MAX_TOKEN_LENGTH, 40);
  });

  it('escaped brackets are fullwidth', () => {
    assert.strictEqual(ESCAPED_OPEN, '\uFF3B');
    assert.strictEqual(ESCAPED_CLOSE, '\uFF3D');
  });
});

describe('Config Integration', () => {
  it('rejects reserved category name', () => {
    assert.throws(
      () => new ShieldConfig({ customLlmCategories: [{ name: 'EMAIL', description: 'emails' }] }),
      /conflicts with built-in/
    );
  });

  it('rejects invalid format', () => {
    assert.throws(
      () => new ShieldConfig({ customLlmCategories: [{ name: 'lowercase', description: 'bad' }] }),
      /Must match/
    );
  });

  it('accepts valid custom name', () => {
    const config = new ShieldConfig({ customLlmCategories: [{ name: 'MY_CUSTOM_TYPE', description: 'custom' }] });
    assert.strictEqual(config.customLlmCategories.length, 1);
  });
});
