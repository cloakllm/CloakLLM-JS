// Regressions from cloakllm/CloakLLM#10 (v0.12.7). Mirrors cloakllm-py's
// tests/test_issue10_numeric_and_ner_spans.py -- same cases, same literal
// expectations, so the two SDKs cannot drift apart on them.
//
// A user's MongoDB payload came out with a name's closing quote swallowed
// into the token (spaCy, Python only) and, in both SDKs, parts of ordinary
// decimal numbers detected as personal data: 1,152 of 6,016 plain decimals
// were tagged SSN, PHONE or CREDIT_CARD, so numeric payloads reached the
// model corrupted.
const test = require('node:test');
const assert = require('node:assert/strict');

const { RegexBackend } = require('../src/backends/regex');
const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');
const { inDecimalNumber } = require('../src/patterns');
const { LOCALE_PATTERNS } = require('../src/locale-patterns');
const { cleanNerSpan, isNerAvailable } = require('../src/ner-detector');

const USER_PAYLOAD = "[{'_id': ObjectId('68cfeb6153dc447c8de27511'), 'market_value': 20042839.001880005, "
  + "'name': 'Shawn Hardin'}, {'_id': ObjectId('68cfeb6e53dc447c8de27523'), "
  + "'name': 'Maria Lopez', 'market_value': 17246256.599931788}]";

const regex = () => new RegexBackend(new ShieldConfig({ auditEnabled: false }));

// ------------------------------------------------------------ decimals --

test('decimal numbers are not personal data', () => {
  const b = regex();
  for (const n of [
    '20042839.001880005', '17246256.599931788', '764623112.909', '237.07924402',
    '51350.4754678208288285', '6943335.6574100425578441',
    '47.6062095', '-122.3320708', '0.123456789',
  ]) {
    for (const text of [`value ${n}`, `{'market_value': ${n}}`]) {
      assert.deepEqual(b.detect(text, []), [], text);
    }
  }
});

test('random decimals are never tagged', () => {
  // Deterministic LCG so the run is reproducible without a seeded RNG.
  let seed = 7;
  const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  const b = regex();
  for (let k = 0; k < 3000; k += 1) {
    const intPart = String(rand(10 ** (1 + rand(9))));
    let frac = '';
    for (let j = 0, len = 1 + rand(17); j < len; j += 1) frac += String(rand(10));
    const text = `value ${intPart}.${frac}`;
    assert.deepEqual(b.detect(text, []), [], text);
  }
});

test('real values next to dots are still caught', () => {
  const b = regex();
  for (const [text, category, value] of [
    ['My SSN is 123-45-6789.', 'SSN', '123-45-6789'],
    ['ssn: 123456789.', 'SSN', '123456789'],
    ['Call 555.123.4567 today', 'PHONE', '555.123.4567'],
    ['Toll free 1.800.555.1234.', 'PHONE', '800.555.1234'],
    ['Reach me at +1.555.123.4567', 'PHONE', '+1.555.123.4567'],
    ['phone: 555.1234567', 'PHONE', '555.1234567'],
    ['call me on 2125551234.', 'PHONE', '2125551234'],
    ['My card is 4111111111111111.', 'CREDIT_CARD', '4111111111111111'],
    ['Paid 12.50 with 4111111111111111', 'CREDIT_CARD', '4111111111111111'],
    ['IBAN DE89370400440532013000.', 'IBAN', 'DE89370400440532013000'],
  ]) {
    const found = b.detect(text, []).map((d) => [d.category, d.text]);
    assert.ok(found.some(([c, v]) => c === category && v === value), `${text}: ${JSON.stringify(found)}`);
  }
});

test('custom patterns are matched as written', () => {
  const b = new RegexBackend(new ShieldConfig({
    auditEnabled: false,
    customPatterns: [{ name: 'ACCOUNT', pattern: '\\d{9}' }],
  }));
  const found = b.detect('v 1.123456789', []).map((d) => [d.category, d.text]);
  assert.ok(found.some(([c, v]) => c === 'ACCOUNT' && v === '123456789'), JSON.stringify(found));
});

test('inDecimalNumber looks at the whole number around the match', () => {
  for (const [text, value, expected] of [
    ['value 764623112.909', '764623112', true],         // integer part
    ['value 20042839.001880005', '001880005', true],    // fraction
    ['value 1.61318609139099', '09139099', true],       // from the middle
    ['value 4303163444.116372651676', '03163444.11', true], // across the dot
    ['Toll free 1.800.555.1234', '800.555.1234', false],    // 3 dots: phone
    ['version 1.2.3456789', '3456789', false],              // 2 dots
    ['ssn: 123456789.', '123456789', false],                // sentence period
    ['ip 10.0.0.123456', '123456', false],
  ]) {
    const start = text.indexOf(value);
    assert.equal(inDecimalNumber(text, start, start + value.length), expected, text);
  }
});

test('decimals are not tagged under any locale', () => {
  // Several locale phone patterns have no digit boundary and matched from
  // the middle of a number. All must now be 0.
  let seed = 11;
  const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (const locale of Object.keys(LOCALE_PATTERNS).sort()) {
    const b = new RegexBackend(new ShieldConfig({ auditEnabled: false, locale }));
    for (let k = 0; k < 400; k += 1) {
      const intPart = String(rand(10 ** (1 + rand(9))));
      let frac = '';
      for (let j = 0, len = 1 + rand(17); j < len; j += 1) frac += String(rand(10));
      const text = `value ${intPart}.${frac}`;
      assert.deepEqual(b.detect(text, []), [], `${locale}: ${text}`);
    }
  }
});

// ----------------------------------------------------------- NER spans --

test('NER span edges are trimmed', () => {
  for (const [raw, expected] of [
    ["'Shawn Hardin'", 'Shawn Hardin'],
    ["Shawn Hardin'", 'Shawn Hardin'],
    ['"Maria Lopez",', 'Maria Lopez'],
    ['(Acme Inc.)', 'Acme Inc.'],
    ['John (Jack) Smith', 'John (Jack) Smith'],
    // An obfuscated email is not code. A first version of the rule rejected
    // square brackets and the hard corpus showed this leaking as a result.
    ['jane[at]example[dot]org', 'jane[at]example[dot]org'],
  ]) {
    const span = cleanNerSpan(raw, 0, raw.length);
    assert.ok(span, raw);
    assert.equal(raw.slice(span[0], span[1]), expected);
  }
});

test('NER spans that are code are dropped', () => {
  for (const raw of [
    "ObjectId('68cfeb6153dc447c8de27511",
    "ObjectId('68cfeb6153dc447c8de27511')",
    'user_id=42',
    'Order 1234567',
    "'",
  ]) {
    assert.equal(cleanNerSpan(raw, 0, raw.length), null, raw);
  }
});

// ------------------------------------------------------------ end to end --

test('the user payload, end to end', { skip: !isNerAvailable() && 'compromise not installed' }, () => {
  const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
  const [clean, tokenMap] = shield.sanitize(USER_PAYLOAD);
  assert.equal(clean,
    "[{'_id': ObjectId('68cfeb6153dc447c8de27511'), 'market_value': 20042839.001880005, "
    + "'name': '[PERSON_1]'}, {'_id': ObjectId('68cfeb6e53dc447c8de27523'), "
    + "'name': '[PERSON_0]', 'market_value': 17246256.599931788}]");
  assert.equal(shield.desanitize(clean, tokenMap), USER_PAYLOAD);
});
