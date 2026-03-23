const { describe, it } = require('node:test');
const assert = require('node:assert');
const { Shield, ShieldConfig, isNerAvailable } = require('../src');

describe('Locale Config', () => {
  it('default locale is en', () => {
    const config = new ShieldConfig({ auditEnabled: false });
    assert.strictEqual(config.locale, 'en');
  });

  it('locale can be set via constructor', () => {
    const config = new ShieldConfig({ locale: 'de', auditEnabled: false });
    assert.strictEqual(config.locale, 'de');
  });
});

describe('Locale Regex Patterns', () => {
  it('German phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'de', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Rufen Sie an: +49 171 1234567');
    assert.ok(sanitized.includes('[PHONE_DE_0]'), `Expected [PHONE_DE_0] in: ${sanitized}`);
  });

  it('German VAT detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'de', auditEnabled: false }));
    const [sanitized] = shield.sanitize('USt-IdNr: DE123456789');
    assert.ok(sanitized.includes('[VAT_DE_0]'), `Expected [VAT_DE_0] in: ${sanitized}`);
  });

  it('French phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'fr', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Appelez le +33 1 23 45 67 89');
    assert.ok(sanitized.includes('[PHONE_FR_0]'), `Expected [PHONE_FR_0] in: ${sanitized}`);
  });

  it('French NIR detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'fr', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Mon NIR: 1 85 01 75 123 456 78');
    assert.ok(sanitized.includes('[NIR_FR_0]'), `Expected [NIR_FR_0] in: ${sanitized}`);
  });

  it('Spanish DNI detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'es', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Mi DNI es 12345678A');
    assert.ok(sanitized.includes('[DNI_ES_0]'), `Expected [DNI_ES_0] in: ${sanitized}`);
  });

  it('Spanish NIE detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'es', auditEnabled: false }));
    const [sanitized] = shield.sanitize('NIE: X1234567A');
    assert.ok(sanitized.includes('[NIE_ES_0]'), `Expected [NIE_ES_0] in: ${sanitized}`);
  });

  it('Dutch phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'nl', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Bel 06 1234 5678');
    assert.ok(sanitized.includes('[PHONE_NL_0]'), `Expected [PHONE_NL_0] in: ${sanitized}`);
  });

  it('Dutch postal code detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'nl', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Adres: 1234 AB Amsterdam');
    assert.ok(sanitized.includes('[POSTAL_NL_0]'), `Expected [POSTAL_NL_0] in: ${sanitized}`);
  });

  it('Israeli mobile detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'he', auditEnabled: false }));
    const [sanitized] = shield.sanitize('טלפון: 054-123-4567');
    assert.ok(sanitized.includes('[PHONE_IL_0]'), `Expected [PHONE_IL_0] in: ${sanitized}`);
  });

  it('Chinese mobile detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'zh', auditEnabled: false }));
    const [sanitized] = shield.sanitize('手机号: 13912345678');
    assert.ok(sanitized.includes('[PHONE_CN_0]'), `Expected [PHONE_CN_0] in: ${sanitized}`);
  });

  it('Chinese national ID detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'zh', auditEnabled: false }));
    const [sanitized] = shield.sanitize('身份证号: 110101199001011234');
    assert.ok(sanitized.includes('[NATIONAL_ID_CN_0]'), `Expected [NATIONAL_ID_CN_0] in: ${sanitized}`);
  });

  it('Japanese mobile detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'ja', auditEnabled: false }));
    const [sanitized] = shield.sanitize('電話番号: 090-1234-5678');
    assert.ok(sanitized.includes('[PHONE_JP_0]'), `Expected [PHONE_JP_0] in: ${sanitized}`);
  });

  it('Russian phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'ru', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Позвоните: +7 (912) 345-67-89');
    assert.ok(sanitized.includes('[PHONE_RU_0]'), `Expected [PHONE_RU_0] in: ${sanitized}`);
  });

  it('Russian SNILS detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'ru', auditEnabled: false }));
    const [sanitized] = shield.sanitize('СНИЛС: 123-456-789 01');
    assert.ok(sanitized.includes('[SNILS_RU_0]'), `Expected [SNILS_RU_0] in: ${sanitized}`);
  });

  it('Korean phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'ko', auditEnabled: false }));
    const [sanitized] = shield.sanitize('전화번호: 010-1234-5678');
    assert.ok(sanitized.includes('[PHONE_KR_0]'), `Expected [PHONE_KR_0] in: ${sanitized}`);
  });

  it('Korean RRN detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'ko', auditEnabled: false }));
    const [sanitized] = shield.sanitize('주민등록번호: 900315-1234567');
    assert.ok(sanitized.includes('[RRN_KR_0]'), `Expected [RRN_KR_0] in: ${sanitized}`);
  });

  it('Italian Codice Fiscale detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'it', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Codice Fiscale: RSSMRA85M01H501U');
    assert.ok(sanitized.includes('[CODICE_FISCALE_IT_0]'), `Expected [CODICE_FISCALE_IT_0] in: ${sanitized}`);
  });

  it('Italian phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'it', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Telefono: +39 320 1234567');
    assert.ok(sanitized.includes('[PHONE_IT_0]'), `Expected [PHONE_IT_0] in: ${sanitized}`);
  });

  it('Polish phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'pl', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Telefon: +48 512 345 678');
    assert.ok(sanitized.includes('[PHONE_PL_0]'), `Expected [PHONE_PL_0] in: ${sanitized}`);
  });

  it('Brazilian CPF detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'pt', auditEnabled: false }));
    const [sanitized] = shield.sanitize('CPF: 123.456.789-09');
    assert.ok(sanitized.includes('[CPF_BR_0]'), `Expected [CPF_BR_0] in: ${sanitized}`);
  });

  it('Portuguese phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'pt', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Telefone: +351 912 345 678');
    assert.ok(sanitized.includes('[PHONE_PT_0]'), `Expected [PHONE_PT_0] in: ${sanitized}`);
  });

  it('Indian PAN detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'hi', auditEnabled: false }));
    const [sanitized] = shield.sanitize('PAN: ABCPD1234E');
    assert.ok(sanitized.includes('[PAN_IN_0]'), `Expected [PAN_IN_0] in: ${sanitized}`);
  });

  it('Indian phone detected', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'hi', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Phone: +91 98765 43210');
    assert.ok(sanitized.includes('[PHONE_IN_0]'), `Expected [PHONE_IN_0] in: ${sanitized}`);
  });

  it('English locale does not add locale patterns', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'en', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Code 12345678A');
    assert.ok(!sanitized.includes('[DNI_ES'), `Should not detect DNI_ES in English locale: ${sanitized}`);
  });

  it('universal patterns still work with locale', () => {
    const shield = new Shield(new ShieldConfig({ locale: 'de', auditEnabled: false }));
    const [sanitized] = shield.sanitize('Email: hans@example.de, Phone: +49 171 1234567');
    assert.ok(sanitized.includes('[EMAIL_0]'), `Expected [EMAIL_0] in: ${sanitized}`);
    assert.ok(sanitized.includes('[PHONE_DE_0]'), `Expected [PHONE_DE_0] in: ${sanitized}`);
  });

  it('ner_ms timing is reported', () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const { timing } = shield.detector.detect('Test text');
    assert.ok('ner_ms' in timing, 'timing should have ner_ms');
    assert.ok(timing.ner_ms >= 0, 'ner_ms should be >= 0');
  });
});

describe('JS NER via compromise', () => {
  const skip = !isNerAvailable();

  it('detects person names', { skip }, () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const [sanitized] = shield.sanitize('Meeting with John Smith tomorrow');
    assert.ok(sanitized.includes('[PERSON_0]'), `Should tokenize PERSON entity: ${sanitized}`);
  });

  it('detects organizations', { skip }, () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const [sanitized] = shield.sanitize('She works at Microsoft in Seattle');
    assert.ok(sanitized.includes('[ORG_0]'), `Should tokenize ORG entity: ${sanitized}`);
  });

  it('detects places', { skip }, () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const [sanitized] = shield.sanitize('He traveled from Paris to Tokyo');
    assert.ok(sanitized.includes('[GPE_0]'), `Should tokenize GPE entity: ${sanitized}`);
  });

  it('NER does not overlap with regex detections', { skip }, () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const [sanitized] = shield.sanitize('Contact John Smith at john@example.com');
    assert.ok(sanitized.includes('[EMAIL_0]'), `Email should be detected by regex: ${sanitized}`);
    assert.ok(sanitized.includes('[PERSON_0]'), `Person should be detected by NER: ${sanitized}`);
  });

  it('NER uses analyze for source verification', { skip }, () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const result = shield.analyze('Contact John Smith at john@example.com');
    const emails = result.entities.filter(e => e.source === 'regex' && e.category === 'EMAIL');
    const persons = result.entities.filter(e => e.source === 'ner' && e.category === 'PERSON');
    assert.ok(emails.length >= 1, 'Should have at least 1 email from regex');
    assert.ok(persons.length >= 1, 'Should have at least 1 person from NER');
  });

  it('NER timing is reported', { skip }, () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const { timing } = shield.detector.detect('Meeting with John Smith');
    assert.ok('ner_ms' in timing);
    assert.ok(timing.ner_ms >= 0);
  });
});
