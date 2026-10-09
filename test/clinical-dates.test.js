// v0.13.0 health edition: clinical dates and ages over 89 (HIPAA Safe Harbor).
// Mirrors cloakllm-py tests/test_clinical_dates.py -- same cases, same literal
// expectations -- plus two JS-only checks: the opt-in rule (a plain config
// object such as Guard's must never enable dates) and running without
// `process`, as in a browser.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { RegexBackend } = require('../src/backends/regex');
const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');

const backend = () => new RegexBackend(new ShieldConfig({
  auditEnabled: false, detectDates: true, detectAgesOver89: true,
}));
const found = (b, text) => b.detect(text, [])
  .sort((x, y) => x.start - y.start).map((d) => [d.category, d.text]);

test('dates are detected', () => {
  const b = backend();
  for (const [text, expected] of [
    ['Admitted 03/14/2026, discharged 3/21/26.', [['DATE', '03/14/2026'], ['DATE', '3/21/26']]],
    ['Seen 2026-03-14; f/u 4/2.', [['DATE', '2026-03-14'], ['DATE', '4/2']]],
    ['DOB: March 14, 1961. Surgery on 14 March 2026.', [['DATE', 'March 14, 1961'], ['DATE', '14 March 2026']]],
    ['Symptoms since Feb 2026, last visit Jan 5th.', [['DATE', 'Feb 2026'], ['DATE', 'Jan 5th']]],
    ['dated 12-31-1999, LMP 1/15', [['DATE', '12-31-1999'], ['DATE', '1/15']]],
    ['On 2/29/2024 and Sept. 3rd, 2025', [['DATE', '2/29/2024'], ['DATE', 'Sept. 3rd, 2025']]],
    ['started 03/2026', [['DATE', '03/2026']]],
  ]) {
    assert.deepEqual(found(b, text), expected, text);
  }
});

test('clinical look-alikes are left alone', () => {
  const b = backend();
  for (const text of [
    'BP 120/80, strength 5/5 in all limbs, pain 4/10, take 1/2 tab, vision 20/20.',
    'HbA1c 8.9%, eGFR 52.4, version 1.2.3, order 2026091712.',
    'The patient may need it; March forward. 2/2 PNA.',
    'Feb 30 2026 is not a date, nor is 13/14/2026.',
    'f/u 4/2.5 mg',
    's/p CABG 2019',
    '3/14 of patients improved',
  ]) {
    assert.deepEqual(found(b, text), [], text);
  }
});

test('ages over 89 in every form', () => {
  assert.deepEqual(found(backend(), '93-year-old woman, aged 95, 92M, 91 yo F, in her late 90s, a nonagenarian.'), [
    ['AGE_90PLUS', '93-year-old'], ['AGE_90PLUS', 'aged 95'], ['AGE_90PLUS', '92M'],
    ['AGE_90PLUS', '91 yo'], ['AGE_90PLUS', 'in her late 90s'], ['AGE_90PLUS', 'nonagenarian'],
  ]);
});

test('ages under 90 and temperatures are left alone', () => {
  const b = backend();
  for (const text of ['45-year-old man, aged 67.', '89 yo F', 'temp 98 F', 'T 99F']) {
    assert.deepEqual(found(b, text), [], text);
  }
});

test('a surname ending in t does not hide an age', () => {
  assert.deepEqual(found(backend(), 'Ellen Lindqvist, 95-year-old'), [['AGE_90PLUS', '95-year-old']]);
});

// ------------------------------------------------------------ output modes --

const NOTE = '93-year-old admitted 03/14/2026, discharged 3/21/26, DOB March 14, 1931.';
const shield = (extra = {}) => new Shield(new ShieldConfig({
  auditEnabled: false, detectDates: true, detectAgesOver89: true, ...extra,
}));

test('tokenize mode round-trips', () => {
  const s = shield();
  const [clean, tm] = s.sanitize(NOTE);
  assert.equal(clean, '[AGE_90PLUS_0] admitted [DATE_2], discharged [DATE_1], DOB [DATE_0].');
  assert.equal(s.desanitize(clean, tm), NOTE);
});

test('generalize_year mode is the Safe Harbor form', () => {
  const s = shield({ dateMode: 'generalize_year' });
  const [clean, tm] = s.sanitize(NOTE);
  assert.equal(clean, '90+-year-old admitted 2026, discharged [DATE_REDACTED], DOB 1931.');
  assert.equal(tm.reverse.size, 0);
  assert.equal(s.desanitize(clean, tm), clean);
  assert.deepEqual(new Set(tm.entityDetails.map((e) => e.token)),
    new Set(['[DATE_GENERALIZED]', '[AGE_90PLUS_GENERALIZED]']));
});

test('redact mode wins over generalize', () => {
  const [clean] = shield({ dateMode: 'generalize_year', mode: 'redact' }).sanitize('admitted 03/14/2026');
  assert.equal(clean, 'admitted [DATE_REDACTED]');
});

test('date shifting is refused with the reason', () => {
  assert.throws(() => new ShieldConfig({ dateMode: 'shift' }), /Safe Harbor/);
});

// ------------------------------------------------------------- compatibility --

test('off by default', () => {
  const [clean] = new Shield(new ShieldConfig({ auditEnabled: false })).sanitize(NOTE);
  assert.equal(clean, NOTE);
});

test('opt-in: a plain config object that does not mention dates keeps them off', () => {
  // The Guard extension builds its detector from a plain object listing only
  // the categories it wants. Every older built-in is on unless set false;
  // dates must need an explicit true, or Guard would start flagging them.
  const b = new RegexBackend({
    customPatterns: [], locale: 'en', detectEmails: true, detectSsns: true,
    detectCreditCards: true, detectPhones: true, detectIban: true, detectApiKeys: true,
    detectIpAddresses: false,
  });
  assert.deepEqual(found(b, 'admitted 03/14/2026, 93-year-old'), []);
});

test('custom names DATE and AGE_90PLUS are still allowed', () => {
  new ShieldConfig({ customPatterns: [{ name: 'DATE', pattern: '\\d{8}' }] });
  new ShieldConfig({ customLlmCategories: [{ name: 'AGE_90PLUS', description: 'an age over 89' }] });
});

test('runs without process (browser, worker)', () => {
  const real = globalThis.process;
  delete globalThis.process;
  let out;
  try {
    const b = new RegexBackend({ customPatterns: [], locale: 'en', detectDates: true, detectAgesOver89: true });
    out = found(b, 'admitted 03/14/2026, 93-year-old');
  } finally {
    globalThis.process = real;
  }
  assert.deepEqual(out, [['DATE', '03/14/2026'], ['AGE_90PLUS', '93-year-old']]);
});

test('no dates or ages in the audit log', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-dates-'));
  try {
    const s = new Shield(new ShieldConfig({ logDir: dir, detectDates: true, detectAgesOver89: true }));
    s.sanitize('93-year-old admitted 03/14/2026, DOB March 14, 1931, f/u 4/2.');
    const raw = fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl'))
      .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('');
    assert.ok(raw.length > 0, 'expected an audit entry');
    for (const planted of ['03/14/2026', 'March 14, 1931', '4/2', '93-year-old']) {
      assert.ok(!raw.includes(planted), planted);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
