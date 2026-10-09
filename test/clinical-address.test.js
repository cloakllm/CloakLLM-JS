// v0.13.0 health edition: US street addresses and PO boxes. Mirrors
// cloakllm-py tests/test_clinical_address.py (same cases, same literal
// expectations) plus the JS opt-in rule.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { RegexBackend } = require('../src/backends/regex');
const { ShieldConfig } = require('../src/config');
const { Shield } = require('../src/index');

const backend = () => new RegexBackend(new ShieldConfig({ auditEnabled: false, detectStreetAddresses: true }));
const found = (b, text) => b.detect(text, []).sort((x, y) => x.start - y.start).map((d) => [d.category, d.text]);

test('addresses are detected', () => {
  const b = backend();
  for (const [text, expected] of [
    ['Lives at 418 Maple Ave, Springfield, IL 62704.', [['STREET_ADDRESS', '418 Maple Ave']]],
    ['Address: 12 Oak Street, Apt 4B, Riverside', [['STREET_ADDRESS', '12 Oak Street, Apt 4B']]],
    ['1600 Pennsylvania Avenue NW, 350 5th Ave, Suite 300 and 22B Baker St.',
      [['STREET_ADDRESS', '1600 Pennsylvania Avenue NW'], ['STREET_ADDRESS', '350 5th Ave, Suite 300'],
        ['STREET_ADDRESS', '22B Baker St.']]],
    ['Moved to 77 W Cedar Ct #12; mail to P.O. Box 1234 or PO Box 98',
      [['STREET_ADDRESS', '77 W Cedar Ct #12'], ['STREET_ADDRESS', 'P.O. Box 1234'], ['STREET_ADDRESS', 'PO Box 98']]],
    ['Send to 4500 MARTIN LUTHER KING JR BLVD and 10 1/2 Elm Rd',
      [['STREET_ADDRESS', '4500 MARTIN LUTHER KING JR BLVD'], ['STREET_ADDRESS', '10 1/2 Elm Rd']]],
  ]) {
    assert.deepEqual(found(b, text), expected, text);
  }
});

test('non-addresses are left alone', () => {
  const b = backend();
  for (const text of [
    'walk 3 blocks down the road, take 2 tabs a day, 5 mg twice daily',
    'follow up in 2 weeks at the Main St clinic',
    'seen by Dr. Smith on Main; 2 Dr visits; level 3 trauma; room 12',
    'BP 120/80, I-95, Route 66, Highway 1',
    "HbA1c 8.9 St. Mary's Hospital",
    '418 maple ave',
  ]) {
    assert.deepEqual(found(b, text), [], text);
  }
});

test('round trip, and off by default (and never on from a plain config object)', () => {
  const text = 'Lives at 418 Maple Ave, Apt 2';
  const s = new Shield(new ShieldConfig({ auditEnabled: false, detectStreetAddresses: true }));
  const [clean, tm] = s.sanitize(text);
  assert.equal(clean, 'Lives at [STREET_ADDRESS_0]');
  assert.equal(s.desanitize(clean, tm), text);
  const b = new RegexBackend({ customPatterns: [], locale: 'en', detectEmails: true });
  assert.deepEqual(found(b, text), []);
});

test('no address in the audit log', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-addr-'));
  try {
    new Shield(new ShieldConfig({ logDir: dir, detectStreetAddresses: true }))
      .sanitize('Lives at 418 Maple Ave and P.O. Box 1234');
    const raw = fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl'))
      .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('');
    assert.ok(raw.length > 0);
    for (const planted of ['418 Maple', 'Box 1234']) assert.ok(!raw.includes(planted), planted);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
