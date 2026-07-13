/**
 * v0.11.2 detection-hardening regression tests (mirror of
 * cloakllm-py/tests/test_detection_v0112.py).
 *
 * Guards the leak fixes the hard-corpus benchmark found: spaced/dashed credit
 * cards and IBANs were partially leaking (mistyped as PHONE) and IPv6 was
 * undetected -- all no-PII-in-logs violations. Asserted on sanitize() output.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Shield, ShieldConfig } = require('../src');

const sh = new Shield(new ShieldConfig({ auditEnabled: false }));
function san(text) {
  const r = sh.sanitize(text);
  return Array.isArray(r) ? r[0] : (r.sanitized || r.sanitizedText || r.sanitized_text);
}

describe('v0.11.2 credit-card variants', () => {
  for (const [text, card] of [
    ['Pay 4111 1111 1111 1111 now', '4111 1111 1111 1111'],
    ['card 4111-1111-1111-1111 ok', '4111-1111-1111-1111'],
    ['contiguous 4111111111111111 end', '4111111111111111'],
    ['mc 5500 0000 0000 0004 done', '5500 0000 0000 0004'],
    ['Amex 3782 822463 10005 charged', '3782 822463 10005'],
    ['disc 6011 1111 1111 1117 ok', '6011 1111 1111 1117'],
  ]) {
    it(`detects + fully scrubs ${card}`, () => {
      const out = san(text);
      assert.ok(out.includes('[CREDIT_CARD_'), out);
      const last4 = card.replace(/\D/g, '').slice(-4);
      assert.ok(!out.includes(last4), `leaked trailing digits: ${out}`);
    });
  }
});

describe('v0.11.2 IBAN spaced forms', () => {
  for (const iban of ['DE89 3704 0044 0532 0130 00', 'GB29 NWBK 6016 1331 9268 19', 'DE89370400440532013000']) {
    it(`detects ${iban} as one IBAN, not PHONE`, () => {
      const out = san(`wire ${iban} ok`);
      assert.ok(out.includes('[IBAN_') && !out.includes('PHONE'), out);
    });
  }
});

describe('v0.11.2 IPv6', () => {
  for (const ip of ['2001:0db8:85a3::8a2e:0370:7334', '2001:db8::1', 'fe80::1', '::1', '2001:db8:0:0:0:0:2:1']) {
    it(`detects + scrubs ${ip}`, () => {
      const out = san(`host ${ip} up`);
      assert.ok(out.includes('[IP_ADDRESS_'), out);
      assert.ok(!out.includes(ip), `IPv6 leaked: ${out}`);
    });
  }
  it('IPv4 still detected', () => {
    assert.ok(san('from 192.168.0.14 ok').includes('[IP_ADDRESS_'));
  });
});

describe('v0.11.2 headline + precision', () => {
  it('spaced card does not leak into the sanitized log', () => {
    assert.equal(san('Pay with 4111 1111 1111 1111 please'), 'Pay with [CREDIT_CARD_0] please');
  });
  for (const text of ['PO 1111-1111-1111-1111 internal', 'ref 1234 5678 9012 3456 note']) {
    it(`does not flag non-card group: ${text}`, () => {
      assert.ok(!san(text).includes('[CREDIT_CARD_'), san(text));
    });
  }
});

describe('v0.12.1 spaced/grouped phone leak fix', () => {
  for (const text of [
    'call 06 12 34 56 78 now',
    'call 06.12.34.56.78 now',
    'call 06-12-34-56-78 now',
  ]) {
    it(`does not leak: ${text}`, () => {
      assert.equal(san(text), 'call [PHONE_0] now');
    });
  }
  it('spaced date is not flagged as a phone', () => {
    assert.equal(san('meeting 12 25 2024 agenda'), 'meeting 12 25 2024 agenda');
  });
});
