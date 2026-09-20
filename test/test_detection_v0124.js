/**
 * v0.12.4: contiguous phone numbers, and a detection guard that fails
 * closed (mirror of cloakllm-py/tests/test_detection_v0124.py).
 *
 * Contiguous numbers -- written without separators -- were completely
 * undetected, including every bare US 10-digit number. The naive fix is to
 * match bare digit runs, and it is a trap: roughly 64% of random 10-digit
 * ids satisfy NANP shape, so "2026091912" is simultaneously a plausible
 * Washington DC number and a plausible invoice id.
 *
 * What works, measured: E.164 ungated (a leading "+" is a declaration, not
 * an inference) plus NANP-shaped runs gated on a nearby keyword.
 *
 * Separately, failing the ReDoS safety check used to SKIP the pattern,
 * leaving the process running with that category's detection switched off.
 * For a built-in that is fail-open, so it now throws.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Shield, ShieldConfig } = require('../src');
const { PATTERNS, hasPhoneContext } = require('../src/patterns');
const { RegexBackend, PatternSafetyError } = require('../src/backends/regex');

const sh = new Shield(new ShieldConfig({ auditEnabled: false, nerEnabled: false }));

function san(text) {
  const r = sh.sanitize(text);
  return Array.isArray(r) ? r[0] : (r.sanitized || r.sanitizedText || r.sanitized_text);
}

const isPhone = (t) => san(t).includes('[PHONE_');

describe('v0.12.4 contiguous phones', () => {
  for (const t of [
    'call 4155550199 tomorrow',
    'phone: 2125551234',
    'dial 14155550199 now',
    'contact 4155550199',
    'reach me on 2125551234',
    'call him at 4155550199',
    'contact us on 2125551234',
    'mobile is 4155550199',
    'text me at 4155550199',
    'phone number is 2125551234',
    'my cell number 4155550199',
  ]) {
    it(`catches ${JSON.stringify(t)}`, () => assert.ok(isPhone(t), t));
  }

  for (const t of ['the number is +442071838750', 'reachable at +14155550199',
    '+61291234567 is the Sydney office']) {
    it(`E.164 needs no keyword: ${t}`, () => assert.ok(isPhone(t), t));
  }
});

describe('v0.12.4 no regressions on separated forms', () => {
  for (const t of ['call 555 010 4422 today', 'call 415-555-0199 today',
    '06 12 34 56 78 is French', '(415) 555-0199 x42', '415.555.0199',
    'tel +1-415-555-0199']) {
    it(`still catches ${JSON.stringify(t)}`, () => assert.ok(isPhone(t), t));
  }
});

const NOT_PHONES = [
  ['order id 10', 'order 1234567890 shipped'],
  ['order id, high lead', 'order 9876543210 shipped'],
  ['order id 12', 'order 123456789012 shipped'],
  ['unix seconds', 'ts 1726660800 utc'],
  ['unix millis', 'ts 1726660800000 utc'],
  ['account 17', 'acct 12345678901234567 closed'],
  ['build number', 'build 20260919123456 ok'],
  ['ISBN-13', 'isbn 9780306406157 here'],
  ['card', 'card 4111111111111111 ok'],
  ['tracking', 'tracking 9400110200881234567890'],
  ['invoice, DC-shaped', 'invoice 2026091912 paid'],
  ['ticket, phone-shaped', 'ticket 5551234567 closed'],
  ['pi digits', 'Pi is 3.14159265 and so on'],
  // The strings that make allowing the "number" connector safe or unsafe.
  ['order number', 'order number 1234567890 shipped'],
  ['invoice number', 'invoice number 2026091912 paid'],
  ['ticket number', 'ticket number 5551234567 closed'],
  ['reference number', 'reference number 9876543210 filed'],
  ['tracking number', 'tracking number 9400110200881234'],
  ['keyword, distant number', 'call about order 9876543210'],
  ['keyword, longer sentence', 'we had to call the supplier and quote 9876543210'],
];

describe('v0.12.4 the false-positive corpus', () => {
  for (const [label, text] of NOT_PHONES) {
    it(`${label} is not a phone`, () => assert.ok(!isPhone(text), text));
  }

  it('phone false-positive rate is zero on the corpus', () => {
    assert.deepEqual(NOT_PHONES.filter(([, t]) => isPhone(t)).map(([l]) => l), []);
  });

  it('the gate also removed an existing false positive', () => {
    // "Pi is 3.14159265" used to be reported as a PHONE.
    assert.ok(!isPhone('Pi is 3.14159265 and the ratio was 16:9'));
  });
});

describe('v0.12.4 the context gate', () => {
  it('the keyword must be near the number, not merely in the sentence', () => {
    const far = 'call about order 9876543210';
    assert.equal(hasPhoneContext(far, far.indexOf('9876543210')), false);
    const near = 'call 9876543210';
    assert.equal(hasPhoneContext(near, near.indexOf('9876543210')), true);
  });

  for (const kw of ['call', 'called', 'calling', 'phone', 'telephone', 'tel',
    'mobile', 'cell', 'fax', 'contact', 'reach', 'dial', 'ring', 'whatsapp', 'sms']) {
    it(`"${kw}" opens the gate`, () => {
      const t = `${kw} 4155550199`;
      assert.ok(hasPhoneContext(t, t.indexOf('4155550199')));
    });
  }

  it('punctuation between keyword and number is allowed', () => {
    for (const t of ['phone: 4155550199', 'tel. 4155550199', 'mobile - 4155550199']) {
      assert.ok(hasPhoneContext(t, t.indexOf('4155550199')), t);
    }
  });
});

describe('v0.12.4 documented limits', () => {
  for (const [label, text] of [
    ['bare US 10 with no keyword', '4155550199'],
    ['international, contiguous, no +', 'call 442071838750 please'],
  ]) {
    it(`${label} is still missed, deliberately`, () => assert.ok(!isPhone(text)));
  }

  it('an invalid NANP exchange is correctly rejected', () => {
    // 555-010-4422 cannot exist: an exchange may not start with 0. This
    // number was carried for a while as an example of the gap, and
    // rejecting it is correct rather than a miss.
    assert.ok(!isPhone('call 5550104422 today'));
  });
});

describe('v0.12.4 the guard fails closed', () => {
  const real = RegexBackend.prototype._measureRegexSafety;

  it('a catastrophic built-in throws instead of being skipped', () => {
    RegexBackend.prototype._measureRegexSafety = () => 2000;
    try {
      assert.throws(() => new RegexBackend(new ShieldConfig()), PatternSafetyError);
    } finally {
      RegexBackend.prototype._measureRegexSafety = real;
    }
  });

  it('a merely slow machine can still start', () => {
    // The built-in budget is 1s, not 100ms, so fail-closed does not turn
    // slow hardware into an install that cannot start.
    RegexBackend.prototype._measureRegexSafety = () => 500;
    try {
      assert.ok(new RegexBackend(new ShieldConfig())._compiledPatterns.length > 0);
    } finally {
      RegexBackend.prototype._measureRegexSafety = real;
    }
  });

  it('real built-ins have real headroom', () => {
    const backend = new RegexBackend(new ShieldConfig());
    const worst = Math.max(...backend._compiledPatterns.map(
      ({ pattern }) => real.call(backend, pattern)));
    assert.ok(worst < 100, `worst built-in is ${worst.toFixed(0)} ms of CPU`);
  });

  it("a user's own regex cannot stop the SDK starting", () => {
    RegexBackend.prototype._measureRegexSafety = function (rx) {
      return rx.source === 'SLOWCUSTOM' ? 500 : real.call(this, rx);
    };
    try {
      const cfg = new ShieldConfig({ customPatterns: [{ name: 'X', pattern: 'SLOWCUSTOM' }] });
      const backend = new RegexBackend(cfg);
      assert.ok(!backend._compiledPatterns.some(({ name }) => name === 'X'));
    } finally {
      RegexBackend.prototype._measureRegexSafety = real;
    }
  });
});

describe('v0.12.4 ReDoS safety', () => {
  it('the new phone pattern is cheap', () => {
    const backend = new RegexBackend(new ShieldConfig());
    const worst = backend._measureRegexSafety(PATTERNS.PHONE.pattern);
    assert.ok(worst < 10, `${worst.toFixed(1)} ms of CPU`);
  });
});
