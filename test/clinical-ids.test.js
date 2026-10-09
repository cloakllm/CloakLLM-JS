// v0.13.0 health edition: US healthcare identifiers. Mirrors cloakllm-py
// tests/test_clinical_ids.py (same cases, same literal expectations) plus the
// JS opt-in rule. Test values are published examples or voided numbers only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { RegexBackend } = require('../src/backends/regex');
const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');
const { npiValid, deaValid } = require('../src/clinical-ids');
const { OPT_IN_CATEGORIES } = require('../src/token-spec');

const backend = () => new RegexBackend(new ShieldConfig({ auditEnabled: false, detectUsHealthIds: true }));
const found = (b, text) => b.detect(text, []).sort((x, y) => x.start - y.start).map((d) => [d.category, d.text]);

test('identifiers are detected, value only', () => {
  const b = backend();
  for (const [text, expected] of [
    ['MRN: 00482913, Med Rec No. H4875819, Patient ID 7734512, Chart # 5512345, CSN 223344556',
      [['MRN', '00482913'], ['MRN', 'H4875819'], ['MRN', '7734512'], ['MRN', '5512345'], ['MRN', '223344556']]],
    ['Member ID: XJH448812934, Subscriber ID W123456789, Policy #MBR3708473355, Medicaid ID 12345678901',
      [['HEALTH_PLAN_ID', 'XJH448812934'], ['HEALTH_PLAN_ID', 'W123456789'],
        ['HEALTH_PLAN_ID', 'MBR3708473355'], ['HEALTH_PLAN_ID', '12345678901']]],
    ['Acct # 88812345, Claim # 2026091712, Prior auth # PA4455661',
      [['ACCOUNT_NUMBER', '88812345'], ['ACCOUNT_NUMBER', '2026091712'], ['ACCOUNT_NUMBER', 'PA4455661']]],
    ['License # A123456, DL # D1234567, NPI 1234567893',
      [['LICENSE_NUMBER', 'A123456'], ['LICENSE_NUMBER', 'D1234567'], ['NPI', '1234567893']]],
    ['Medicare MBI 1EG4-TE5-MK73; Medicare number 1EG4TE5MK73; card 1EG4-TE5-MK73',
      [['MEDICARE_MBI', '1EG4-TE5-MK73'], ['MEDICARE_MBI', '1EG4TE5MK73'], ['MEDICARE_MBI', '1EG4-TE5-MK73']]],
    ['HICN 078051120A and 078-05-1120-B1; DEA AB1234563',
      [['HICN', '078051120A'], ['HICN', '078-05-1120-B1'], ['DEA', 'AB1234563']]],
    ["SSN ending in 6789; last 4 of SSN: 4321; last four of the patient's SSN is 9876; XXX-XX-5555",
      [['SSN_PARTIAL', '6789'], ['SSN_PARTIAL', '4321'], ['SSN_PARTIAL', '9876'], ['SSN_PARTIAL', '5555']]],
  ]) {
    assert.deepEqual(found(b, text), expected, text);
  }
});

test('look-alikes are left alone', () => {
  const b = backend();
  for (const text of [
    'per chart review 2019, encounter today, claim denied, account of events, Medicaid 2024',
    'hash 1AC4DE5FA73 and sha 1EG4TE5MK73 without context',
    'NPI 1234567890',
    'DEA AB1234567',
    'MRN pending; Policy # unknown; NPI 12345; last 4 visits 2024',
    'ICD-10 E11.65; CPT 99213',
  ]) {
    assert.deepEqual(found(b, text), [], text);
  }
});

test('check digits against published examples', () => {
  assert.ok(npiValid('1234567893') && !npiValid('1234567890'));
  assert.ok(deaValid('AB1234563') && !deaValid('AB1234567'));
});

test('label stays readable', () => {
  const s = new Shield(new ShieldConfig({ auditEnabled: false, detectUsHealthIds: true }));
  const text = 'MRN: 00482913, Member ID XJH448812934, NPI 1234567893';
  const [clean, tm] = s.sanitize(text);
  assert.equal(clean, 'MRN: [MRN_0], Member ID [HEALTH_PLAN_ID_0], NPI [NPI_0]');
  assert.equal(s.desanitize(clean, tm), text);
});

test('off by default', () => {
  // Scoped to the pack: default name detection (compromise) may still tag a
  // word like "Medicare" as ORG, which is unrelated existing behaviour.
  const text = 'MRN: 00482913, Member ID XJH448812934, Medicare 1EG4-TE5-MK73';
  const [clean, tm] = new Shield(new ShieldConfig({ auditEnabled: false })).sanitize(text);
  for (const value of ['00482913', 'XJH448812934', '1EG4-TE5-MK73']) {
    assert.ok(clean.includes(value), value);
  }
  const packCategories = new Set(['MRN', 'HEALTH_PLAN_ID', 'MEDICARE_MBI']);
  assert.deepEqual(tm.detections.filter((d) => packCategories.has(d.category)), []);
});

test('opt-in: a plain config object (Guard) never enables the pack', () => {
  const b = new RegexBackend({ customPatterns: [], locale: 'en', detectEmails: true, detectSsns: true });
  assert.deepEqual(found(b, 'MRN: 00482913, Medicare 1EG4-TE5-MK73, DEA AB1234563'), []);
});

test('all new categories are opt-in and unreserved', () => {
  for (const c of ['MRN', 'ACCOUNT_NUMBER', 'HEALTH_PLAN_ID', 'LICENSE_NUMBER', 'NPI',
    'MEDICARE_MBI', 'HICN', 'DEA', 'SSN_PARTIAL']) {
    assert.ok(OPT_IN_CATEGORIES.has(c), c);
  }
  new ShieldConfig({ customPatterns: [{ name: 'MRN', pattern: 'MRN\\d{6}' }] });
});

test('runs without process (browser, worker)', () => {
  const real = globalThis.process;
  delete globalThis.process;
  let out;
  try {
    out = found(new RegexBackend({ customPatterns: [], locale: 'en', detectUsHealthIds: true }),
      'MRN: 00482913 and Medicare 1EG4-TE5-MK73');
  } finally {
    globalThis.process = real;
  }
  assert.deepEqual(out, [['MRN', '00482913'], ['MEDICARE_MBI', '1EG4-TE5-MK73']]);
});

test('no identifiers in the audit log', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-ids-'));
  try {
    const s = new Shield(new ShieldConfig({ logDir: dir, detectUsHealthIds: true }));
    s.sanitize('MRN: 00482913, Member ID XJH448812934, MBI 1EG4-TE5-MK73, HICN 078051120A, '
      + 'NPI 1234567893, DEA AB1234563, SSN ending in 6789');
    const raw = fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl'))
      .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('');
    assert.ok(raw.length > 0);
    for (const planted of ['00482913', 'XJH448812934', '1EG4-TE5-MK73', '078051120A', '1234567893', 'AB1234563', '6789']) {
      assert.ok(!raw.includes(planted), planted);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
