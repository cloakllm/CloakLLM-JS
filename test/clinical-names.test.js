// v0.13.0 health edition: role-gated and header-line names, and surname
// completion for one-word NER names. Mirrors cloakllm-py
// tests/test_clinical_names.py (same cases, same literal expectations) plus
// the JS opt-in rule.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { RegexBackend } = require('../src/backends/regex');
const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');
const { extendFirstName } = require('../src/clinical-names');

const backend = () => new RegexBackend(new ShieldConfig({ auditEnabled: false, detectRoleNames: true }));
const found = (b, text) => b.detect(text, []).sort((x, y) => x.start - y.start).map((d) => [d.category, d.text]);

test('names are detected', () => {
  const b = backend();
  for (const [text, expected] of [
    ['Patient Hector Vance. Mother Aisha Sato called.', [['PERSON', 'Hector Vance'], ['PERSON', 'Aisha Sato']]],
    ['Lucia Pruitt 876701408 11/02/1950 seen today.', [['PERSON', 'Lucia Pruitt'], ['SSN', '876701408']]],
    ['PRUITT, LUCIA DOB 11/02/1950', [['PERSON', 'PRUITT, LUCIA']]],
    ['Thomas Halvorsen F8437807 1941-07-23 - hypothyroid', [['PERSON', 'Thomas Halvorsen']]],
    ['Draft a letter for Aisha Vance (Date of birth: 03/09/1985)', [['PERSON', 'Aisha Vance']]],
    ['Seen: Mary Ann Smith DOB 1/2/1960', [['PERSON', 'Mary Ann Smith']]],
    ["Pt name: Mary-Ann O'Neil", [['PERSON', "Mary-Ann O'Neil"]]],
    ['Father Angus McDonald visited', [['PERSON', 'Angus McDonald']]],
    ["Patient Ann Parkinson's daughter", [['PERSON', 'Ann Parkinson']]],
    ['Name: John Q. Public', [['PERSON', 'John Q. Public']]],
    ['Dr. Smith MD reviewed.', [['PERSON', 'Smith']]],
    ['Signed by Dr. Ana Ruiz, MD', [['PERSON', 'Ana Ruiz']]],
    ['Emergency contact: Raj Patel (son)', [['PERSON', 'Raj Patel']]],
  ]) {
    assert.deepEqual(found(b, text), expected, text);
  }
});

test('template words are left alone', () => {
  const b = backend();
  for (const text of [
    'Patient Reports Chest Pain. Patient Portal access. Patient Education given.',
    'Brand Name Lipitor Tablets',
    'Follow Up 11/02/2025 with labs',
    'Discharge Date 10/02/2025',
    '2 Dr visits; patient tolerated the procedure',
    'Mason Jar Lid 12345',
    'started Heart Failure DOBUTAMINE drip',
  ]) {
    assert.deepEqual(found(b, text), [], text);
  }
});

test('extendFirstName', () => {
  for (const [text, start, end, expected] of [
    ['Thomas Parkinson asks', 0, 6, 16],
    ["Thomas Parkinson's disease", 0, 6, 6],
    ['Thomas Monday', 0, 6, 6],
    ['Thomas MD', 0, 6, 6],
    ['Thomas Reports pain', 0, 6, 6],
    ['Thomas Smith Jones', 0, 12, 12],
    ['Thomas, Smith', 0, 6, 6],
  ]) {
    assert.equal(extendFirstName(text, start, end), expected, text);
  }
});

test('round trip, and off by default (and never on from a plain config object)', () => {
  const text = 'Lucia Pruitt 876701408. Mother Aisha Sato called.';
  const s = new Shield(new ShieldConfig({ auditEnabled: false, detectRoleNames: true }));
  const [clean, tm] = s.sanitize(text);
  assert.ok(!clean.includes('Pruitt') && !clean.includes('Aisha'), clean);
  assert.equal(s.desanitize(clean, tm), text);
  const b = new RegexBackend({ customPatterns: [], locale: 'en', detectEmails: true });
  assert.deepEqual(found(b, 'Mother Aisha Sato called.'), []);
});

test('NER surname completion through a Shield', (t) => {
  const s = new Shield(new ShieldConfig({ auditEnabled: false, detectRoleNames: true }));
  const ner = s.detector._backends.find((b) => b.name === 'ner');
  if (!ner || !ner.available) return t.skip('compromise not installed');
  const [clean] = s.sanitize("Thomas Parkinson asks whether his Parkinson's disease is worse.");
  assert.ok(!clean.includes('Parkinson asks'), clean);
  assert.ok(clean.includes("Parkinson's disease"), clean);
});

test('surname completion never drops the first name', (t) => {
  // If an earlier pass already claimed the next word, the NER name stays
  // short; extending into it would drop the WHOLE detection.
  const { NerDetector, isNerAvailable } = require('../src/ner-detector');
  if (!isNerAvailable()) return t.skip('compromise not installed');
  const text = 'Thomas Parkinson asks';
  const view = { json: () => [{ text: 'Thomas', terms: [{ offset: { start: 0, length: 6 } }] }] };
  const run = (opts, covered) => {
    const out = [];
    new NerDetector(opts)._extractEntities(view, text, 'PERSON', 0.8, covered, out);
    return out.map((d) => d.text);
  };
  assert.deepEqual(run({ extendSurnames: true }, [[7, 16]]), ['Thomas']);
  assert.deepEqual(run({ extendSurnames: true }, []), ['Thomas Parkinson']);
  assert.deepEqual(run({}, []), ['Thomas']);
});

test('no name in the audit log', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-names-'));
  try {
    new Shield(new ShieldConfig({ logDir: dir, detectRoleNames: true }))
      .sanitize('Lucia Pruitt 876701408. Patient Hector Vance. Thomas Parkinson asks.');
    const raw = fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl'))
      .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('');
    assert.ok(raw.length > 0);
    for (const planted of ['Pruitt', 'Vance', 'Hector', 'Parkinson']) assert.ok(!raw.includes(planted), planted);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
