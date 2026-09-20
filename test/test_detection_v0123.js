/**
 * v0.12.3 credit-card issuer coverage and Luhn validation (mirror of
 * cloakllm-py/tests/test_detection_v0123.py).
 *
 * Two defects, found by pulling on one external review finding.
 *
 * The serious one was a LEAK: the issuer list stopped at Visa, 5-series
 * Mastercard, Amex and Discover, so Luhn-valid Mastercard 2-series
 * (2221-2720, issued since 2017), JCB (3528-3589) and UnionPay (62, the
 * largest network in the world by volume) went through untouched. The
 * recall benchmark could not have caught it -- its corpus held only Visa,
 * 5-series Mastercard and Amex.
 *
 * The second was the reported one: no Luhn check, so a number that merely
 * looked like a card was reported as one.
 *
 * Numbers here are published test values or constructed to be Luhn-valid.
 * None is a real card.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Shield, ShieldConfig } = require('../src');
const { luhnValid } = require('../src/patterns');

// Regex only: this is about the card pattern, and an NER hit would make the
// assertions mean something else.
const sh = new Shield(new ShieldConfig({ auditEnabled: false, nerEnabled: false }));

function san(text) {
  const r = sh.sanitize(text);
  return Array.isArray(r) ? r[0] : (r.sanitized || r.sanitizedText || r.sanitized_text);
}

function caught(number) {
  return san(`card ${number} here`).includes('[CREDIT_CARD_');
}

describe('v0.12.3 Luhn', () => {
  for (const n of ['4111111111111111', '5500000000000004', '378282246310005',
    '2221000000000009', '3530111333300000', '6212345678901232',
    '4111 1111 1111 1111', '4111-1111-1111-1111']) {
    it(`accepts ${n}`, () => assert.equal(luhnValid(n), true));
  }

  for (const n of ['4111111111111112', '5500000000000005', '378282246310006',
    '2221000000000008']) {
    it(`rejects broken check digit ${n}`, () => assert.equal(luhnValid(n), false));
  }

  it('ignores separators', () => {
    assert.equal(luhnValid('4111 1111 1111 1111'), luhnValid('4111111111111111'));
  });

  it('rejects runs too short to be a card', () => {
    // 12 is the shortest card in circulation; below that a passing checksum
    // is just arithmetic.
    assert.equal(luhnValid('00000000000'), false);
    assert.equal(luhnValid(''), false);
  });
});

describe('v0.12.3 issuer coverage (the leak)', () => {
  for (const [issuer, number] of [
    ['Visa 16', '4111111111111111'],
    ['Mastercard 5-series', '5500000000000004'],
    ['Mastercard 2-series', '2221000000000009'],
    ['Amex', '378282246310005'],
    ['Discover 6011', '6011111111111117'],
    ['Discover 65', '6511111111111112'],
    ['Discover 644', '6441111111111117'],
    ['JCB', '3530111333300000'],
    ['UnionPay 16', '6212345678901232'],
    ['UnionPay 19', '6212345678901234569'],
    ['Diners 36, 14 digits', '36011111111113'],
    ['Diners 38, 14 digits', '38123456789011'],
    ['Diners 300-305', '30011111111119'],
  ]) {
    it(`catches ${issuer}`, () => {
      // Each is Luhn-valid, so a miss is a card reaching the provider.
      assert.equal(luhnValid(number), true, `fixture not Luhn-valid: ${number}`);
      assert.ok(caught(number), `${issuer} leaked: ${number}`);
    });
  }

  for (const n of ['2221000000000009', '2720990000000007',
    '3528000000000007', '3589000000000003']) {
    it(`range edge ${n} is inside`, () => assert.ok(caught(n)));
  }

  it('just outside the Mastercard range is not a card', () => {
    // 2220 is below 2221-2720. Luhn-valid, still not a card: the boundary
    // has to be exact or the prefix check means nothing.
    assert.equal(luhnValid('2220000000000000'), true);
    assert.equal(caught('2220000000000000'), false);
  });

  it('spaced and dashed forms still work', () => {
    for (const t of ['4111 1111 1111 1111', '4111-1111-1111-1111',
      '2221 0000 0000 0009', '3782 822463 10005']) {
      assert.ok(caught(t), t);
    }
  });

  it('mixed separators are not a card', () => {
    // The backreferenced separator is what stops arbitrary digit runs from
    // matching; keep it honest.
    assert.equal(caught('4111 1111-1111 1111'), false);
  });
});

describe('v0.12.3 Luhn as a gate (the false positive)', () => {
  for (const n of ['4111111111111112', '5500000000000005',
    '2221000000000008', '6212345678901233']) {
    it(`rejects card-shaped ${n}`, () => {
      assert.equal(luhnValid(n), false);
      assert.equal(caught(n), false);
    });
  }

  it('a rejected card is not relabelled as something else', () => {
    // Rejecting on Luhn leaves the span uncovered, so a later pattern could
    // claim it. Turning a false CREDIT_CARD into a false PHONE is not a fix.
    assert.equal(san('ref 4111111111111112 here'), 'ref 4111111111111112 here');
  });
});

// Things a developer has in a chat window all day. The project measures
// character-level scrub (recall) and had no false-positive measurement at
// all, which is why a missing Luhn check was invisible to every gate.
const NOT_PII = [
  ['ISBN-13', 'see isbn 9780306406157'],
  ['ISBN-13 hyphenated', 'isbn 978-0-306-40615-7'],
  ['non-Luhn 16 digit', 'ref 4111111111111112'],
  ['order id, 16 digit', 'order 1234567890123456'],
  ['order id, 14 digit', 'order 12345678901234'],
  ['two ms timestamps', 'window 1726660800000 to 1726747200000'],
  ['big int in json', '{"id": 4532015112830367}'],
  ['IMEI', 'imei 490154203237518'],
  ['UPS tracking', 'tracking 1Z999AA10123456784'],
  ['long account number', 'acct 12345678901234567'],
  ['git sha', 'sha a1b2c3d4e5f6'],
  ['uuid', 'id 550e8400-e29b-41d4-a716-446655440000'],
  ['semver-ish build', 'build 20260919.1234567890123'],
];

describe('v0.12.3 false positives, as a number', () => {
  for (const [label, text] of NOT_PII) {
    it(`${label} is not a card`, () => {
      assert.ok(!san(text).includes('[CREDIT_CARD_'), label);
    });
  }

  it('credit-card false-positive rate is zero on the corpus', () => {
    // Stated as a number so a regression shows up as one. The first warning
    // that fires on something obviously not a card is what makes a user stop
    // believing the next one.
    //
    // Read the scope honestly: this counts CREDIT_CARD false positives, and
    // this shield is regex-only. It is not the rate a user experiences --
    // with NER on, a git SHA comes back as a PERSON and a bare word as an
    // ORG, and a build number is read as a PHONE even regex-only. None of
    // that is new; it is visible only because the corpus now exists.
    const hits = NOT_PII.filter(([, t]) => san(t).includes('[CREDIT_CARD_'))
      .map(([l]) => l);
    assert.deepEqual(hits, []);
  });

  it('records the other categories this corpus trips, regex-only', () => {
    // Pinned so the next person to work on false positives starts from a
    // measured number instead of rediscovering it.
    //
    // v0.12.4 emptied this list: "semver-ish build" was here because its
    // 8-digit prefix read as a PHONE, and the contiguous-phone context
    // gate drops bare digit runs with no keyword near them. The list
    // shrinking is the gate working -- and this assertion going red is it
    // being noticed rather than absorbed.
    const hits = NOT_PII.filter(([, t]) => /\[[A-Z_]+_\d+\]/.test(san(t)))
      .map(([l]) => l).sort();
    assert.deepEqual(hits, []);
  });
});

describe('v0.12.3 documented gaps', () => {
  for (const n of ['5018111111111112', '6718111111111113']) {
    it(`Maestro ${n} is deliberately not covered`, () => {
      // Maestro spans 50 and 56-69 at 12-19 digits, overlapping most other
      // issuers and a great many ordinary numbers. Luhn alone admits one in
      // ten candidates, so covering it would buy a little recall for a lot
      // of false positives. Asserted so it stays a decision.
      assert.equal(luhnValid(n), true);
      assert.equal(caught(n), false);
    });
  }
});
