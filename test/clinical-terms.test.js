// v0.13.0 health edition: the clinical-term veto for NER. The per-case
// behaviour is diffed against the Python SDK from cloakllm-py
// tests/test_clinical_terms.py; these cover the JS paths.
const test = require('node:test');
const assert = require('node:assert/strict');

const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');
const { NerDetector, isNerAvailable } = require('../src/ner-detector');
const { isClinicalSpan } = require('../src/clinical-terms');

test('a few cases, including the fail-closed ones', () => {
  const at = (text, span, expected) => {
    const s = text.indexOf(span);
    assert.equal(isClinicalSpan(text, s, s + span.length), expected, `${text} / ${span}`);
  };
  at('My INR was 3.5 yesterday', 'INR', true);
  at("History of Crohn's disease", 'Crohn', true);
  at('Mr. Parkinson asks', 'Parkinson', false);
  at('ED SMITH 12345', 'ED', false);
  at('INR Zoë', 'INR Zoë', false);
});

test('the NER detector vetoes only when asked', (t) => {
  if (!isNerAvailable()) return t.skip('compromise not installed');
  const text = 'Janet Novak. My INR was 3.5';
  const view = { json: () => [{ text: 'INR', terms: [{ offset: { start: 16, length: 3 } }] }] };
  const run = (opts) => {
    const out = [];
    new NerDetector(opts)._extractEntities(view, text, 'ORG', 0.75, [], out);
    return out.map((d) => d.text);
  };
  assert.deepEqual(run({ protectClinicalTerms: true }), []);
  assert.deepEqual(run({}), ['INR']);
  assert.deepEqual(run({ protectClinicalTerms: 'yes' }), ['INR']); // opt-in means === true
});

test('through a Shield; off by default; never on from a plain object', (t) => {
  const text = "Hi, this is Janet Novak. My INR was 3.5 and my Crohn's disease is worse.";
  const on = new Shield(new ShieldConfig({ auditEnabled: false, protectClinicalTerms: true }));
  if (!on.detector._backends.find((b) => b.name === 'ner').available) return t.skip('compromise not installed');
  const [clean] = on.sanitize(text);
  assert.ok(!clean.includes('Janet') && !clean.includes('Novak'), clean);
  assert.ok(clean.includes('INR') && clean.includes("Crohn's disease"), clean);
  const ner = new Shield(new ShieldConfig({ auditEnabled: false })).detector._backends.find((b) => b.name === 'ner');
  assert.equal(ner._nerDetector._protectClinicalTerms, false);
  const plain = new (require('../src/backends/ner').NerBackend)({ protectClinicalTerms: 'yes' });
  assert.equal(plain._nerDetector._protectClinicalTerms, false);
});
