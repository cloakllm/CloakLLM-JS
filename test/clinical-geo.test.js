// v0.13.0 health edition: US ZIP codes in address context. Mirrors cloakllm-py
// tests/test_clinical_geo.py (same cases, same literal expectations) plus the
// JS opt-in rule.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { RegexBackend } = require('../src/backends/regex');
const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');

const backend = () => new RegexBackend(new ShieldConfig({ auditEnabled: false, detectZipCodes: true }));
const found = (b, text) => b.detect(text, []).sort((x, y) => x.start - y.start).map((d) => [d.category, d.text]);

test('ZIP in address context', () => {
  const b = backend();
  for (const [text, expected] of [
    ['Lives at 418 Maple Ave, Springfield, IL 62704.', [['ZIP', '62704']]],
    ['Address: 12 Oak St, Riverside, CA  92501-1234', [['ZIP', '92501-1234']]],
    ['Mail to Salem, Oregon 97301 or New York 10001', [['ZIP', '97301'], ['ZIP', '10001']]],
    ['ZIP: 30303; Zip code 60614; zip 02115; postal code 94110; ZIP+4 20500-0003',
      [['ZIP', '30303'], ['ZIP', '60614'], ['ZIP', '02115'], ['ZIP', '94110'], ['ZIP', '20500-0003']]],
  ]) {
    assert.deepEqual(found(b, text), expected, text);
  }
});

test('no ZIP without address context', () => {
  const b = backend();
  for (const text of [
    'Patient ID 12345, IN 47401 visits, OR 97201 cases, OK 73101',
    'CPT 99213, order 2026091712, BNP 12345 pg/mL',
    'Springfield IL 62704',
  ]) {
    assert.deepEqual(found(b, text), [], text);
  }
});

// Label-only text: no city names, so name detection (on by default in JS)
// plays no part. 893 (Elko, NV) is on the HHS restricted list.
const TEXT = 'ZIP: 92501-1234; zip code 97301; postal code 89301';
const shield = (extra = {}) => new Shield(new ShieldConfig({ auditEnabled: false, detectZipCodes: true, ...extra }));

test('tokenize round-trips', () => {
  const s = shield();
  const [clean, tm] = s.sanitize(TEXT);
  assert.equal(clean, 'ZIP: [ZIP_2]; zip code [ZIP_1]; postal code [ZIP_0]');
  assert.equal(s.desanitize(clean, tm), TEXT);
});

test('zip3 is the Safe Harbor form', () => {
  const [clean, tm] = shield({ zipMode: 'zip3' }).sanitize(TEXT);
  assert.equal(clean, 'ZIP: 925XX; zip code 973XX; postal code 000XX');
  assert.equal(tm.reverse.size, 0);
  assert.deepEqual(new Set(tm.entityDetails.map((e) => e.token)), new Set(['[ZIP_GENERALIZED]']));
});

test('restricted list is configurable', () => {
  const [clean] = shield({ zipMode: 'zip3', zip3Restricted: ['925'] }).sanitize(TEXT);
  assert.equal(clean, 'ZIP: 000XX; zip code 973XX; postal code 893XX');
});

test('invalid settings are refused', () => {
  assert.throws(() => new ShieldConfig({ zipMode: 'zip5' }));
  assert.throws(() => new ShieldConfig({ zip3Restricted: ['93'] }));
});

test('off by default, and a plain config object (Guard) never enables it', () => {
  const [clean] = new Shield(new ShieldConfig({ auditEnabled: false })).sanitize('Springfield, IL 62704');
  assert.ok(clean.includes('62704'));
  const b = new RegexBackend({ customPatterns: [], locale: 'en', detectEmails: true });
  assert.deepEqual(found(b, 'Springfield, IL 62704'), []);
});

test('no ZIP in the audit log', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-zip-'));
  try {
    new Shield(new ShieldConfig({ logDir: dir, detectZipCodes: true })).sanitize('Springfield, IL 62704 and ZIP: 30303');
    const raw = fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl'))
      .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('');
    assert.ok(raw.length > 0);
    for (const planted of ['62704', '30303']) assert.ok(!raw.includes(planted), planted);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
