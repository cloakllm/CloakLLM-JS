/**
 * v0.7.0 A4a-7: BiasDetectionSession test suite (JS).
 *
 * Mirrors cloakllm-py/tests/test_bias_detection_session.py — covers
 * lifecycle, constructor validation, scope enforcement, lifetime
 * enforcement, audit-chain shape, and the special-category registry.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  Shield, ShieldConfig,
  BiasDetectionSession,
  BiasDetectionError,
  BiasDetectionScopeError,
  BiasDetectionStateError,
  BiasDetectionTimeoutError,
  SPECIAL_CATEGORY_CATEGORIES,
  BUILTIN_CATEGORIES,
  validateCategoryName,
  validateToken,
} = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-bias-test-'));
}

function makeShield() {
  return new Shield(new ShieldConfig({
    logDir: tmpDir(),
    complianceMode: 'eu_ai_act_article12',
  }));
}

const SESSION_KWARGS = {
  purpose: 'Pre-deployment fairness audit of credit-scoring model v3.2',
  necessityJustification: (
    'Synthetic data evaluated and rejected — covariance between protected ' +
    'characteristics and credit history not preserved. See report XYZ-2026-04.'
  ),
  categoriesAllowed: ['RACE', 'ETHNICITY', 'RELIGION'],
  maxLifetimeSeconds: 3600,
};

function readEntries(logDir) {
  const files = fs.readdirSync(logDir).filter(f => f.startsWith('audit_')).sort();
  const entries = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(logDir, f), 'utf-8');
    for (const line of text.split('\n').filter(l => l.trim())) {
      entries.push(JSON.parse(line));
    }
  }
  return entries;
}

// --- Lifecycle ---

describe('BiasDetectionSession lifecycle', () => {
  it('full workflow — chain verifies', async () => {
    const shield = makeShield();
    let counts;
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        const [pseudo, c] = session.pseudonymise(
          'Patient identifies as Asian and practices Buddhism.',
          { forceCategories: [[22, 27, 'RACE'], [42, 50, 'RELIGION']] },
        );
        assert.match(pseudo, /\[RACE_0\]/);
        assert.match(pseudo, /\[RELIGION_0\]/);
        counts = c;
        session.recordFinding({
          findingSummary: 'No disparate impact detected.',
          biasMetrics: { demographic_parity_diff: 0.012, n: 5000 },
        });
      },
    );
    assert.deepEqual(counts, { RACE: 1, RELIGION: 1 });
    const result = shield.audit.verifyChain();
    assert.equal(result.valid, true);
    assert.equal(result.finalSeq, 3);  // 4 entries 0..3
  });

  it('deterministic tokens within session', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        const [pseudo, counts] = session.pseudonymise(
          'Asian. Asian. Asian.',
          { forceCategories: [[0, 5, 'RACE'], [7, 12, 'RACE'], [14, 19, 'RACE']] },
        );
        assert.equal(pseudo, '[RACE_0]. [RACE_0]. [RACE_0].');
        assert.deepEqual(counts, { RACE: 3 });
      },
    );
  });

  it('explicit .end() is idempotent and does not double-log', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({ shield, ...SESSION_KWARGS });
    s.start();
    s.end();
    s.end();  // second call is no-op
    s.end();
    assert.equal(s.closed, true);
    const r = shield.audit.verifyChain();
    assert.equal(r.valid, true);
    assert.equal(r.finalSeq, 1);  // start + end
  });

  it('start() is idempotent', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({ shield, ...SESSION_KWARGS });
    s.start();
    s.start();
    s.start();
    s.end();
    const r = shield.audit.verifyChain();
    assert.equal(r.finalSeq, 1);  // only one start logged
  });

  it('pseudonymise before start raises', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({ shield, ...SESSION_KWARGS });
    assert.throws(
      () => s.pseudonymise('x', { forceCategories: [[0, 1, 'RACE']] }),
      BiasDetectionStateError,
    );
  });

  it('operations after end raise', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({ shield, ...SESSION_KWARGS });
    s.start();
    s.end();
    assert.throws(
      () => s.pseudonymise('x', { forceCategories: [[0, 1, 'RACE']] }),
      BiasDetectionStateError,
    );
    assert.throws(
      () => s.recordFinding({ findingSummary: 'x' }),
      BiasDetectionStateError,
    );
  });

  it('cannot restart a closed session', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({ shield, ...SESSION_KWARGS });
    s.start();
    s.end();
    assert.throws(() => s.start(), BiasDetectionStateError);
  });
});

// --- Constructor validation ---

describe('BiasDetectionSession constructor validation', () => {
  it('rejects shield missing audit/config', () => {
    assert.throws(
      () => new BiasDetectionSession({ shield: {}, ...SESSION_KWARGS }),
      TypeError,
    );
  });

  it('requires compliance_mode=eu_ai_act_article12', () => {
    const shield = new Shield(new ShieldConfig({ logDir: tmpDir() }));
    assert.throws(
      () => new BiasDetectionSession({ shield, ...SESSION_KWARGS }),
      /complianceMode/,
    );
  });

  it('rejects empty purpose', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({ shield, ...SESSION_KWARGS, purpose: '' }),
      RangeError,
    );
  });

  it('rejects oversized purpose', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS, purpose: 'x'.repeat(501),
      }),
      /500/,
    );
  });

  it('rejects oversized necessity_justification', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS, necessityJustification: 'x'.repeat(2001),
      }),
      /2000/,
    );
  });

  it('rejects empty categoriesAllowed', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS, categoriesAllowed: [],
      }),
      /non-empty/,
    );
  });

  it('rejects non-special-category entries', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS, categoriesAllowed: ['RACE', 'EMAIL'],
      }),
      /non-special-category/,
    );
  });

  it('rejects missing maxLifetimeSeconds', () => {
    const shield = makeShield();
    const { maxLifetimeSeconds: _, ...rest } = SESSION_KWARGS;
    assert.throws(
      () => new BiasDetectionSession({ shield, ...rest }),
      TypeError,
    );
  });

  for (const bad of [0, -1, 1.5, '3600', true, null]) {
    it(`rejects invalid maxLifetimeSeconds: ${JSON.stringify(bad)}`, () => {
      const shield = makeShield();
      assert.throws(
        () => new BiasDetectionSession({
          shield, ...SESSION_KWARGS, maxLifetimeSeconds: bad,
        }),
      );
    });
  }

  it('rejects maxLifetimeSeconds > 7d', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS,
        maxLifetimeSeconds: 7 * 24 * 60 * 60 + 1,
      }),
      /7 days/,
    );
  });
});

// --- Scope enforcement (safeguard #4) ---

describe('BiasDetectionSession scope enforcement', () => {
  it('rejects out-of-set category and leaves state unchanged', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS, categoriesAllowed: ['RACE'] },
      (session) => {
        assert.throws(
          () => session.pseudonymise('Buddhist patient.', {
            forceCategories: [[0, 8, 'RELIGION']],
          }),
          BiasDetectionScopeError,
        );
        // State unchanged: token map empty.
        assert.equal(session._tokenMap.forward.size, 0);
        assert.equal(session.entriesProcessed, 0);
      },
    );
    const r = shield.audit.verifyChain();
    assert.equal(r.valid, true);
    assert.equal(r.finalSeq, 1);  // start + end only
  });

  it('rejects span beyond text length', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        assert.throws(
          () => session.pseudonymise('abc', {
            forceCategories: [[0, 10, 'RACE']],
          }),
          RangeError,
        );
      },
    );
  });
});

// --- Lifetime enforcement (safeguard #5) ---

describe('BiasDetectionSession lifetime enforcement', () => {
  it('timeout force-ends and raises', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({
      shield, ...SESSION_KWARGS, maxLifetimeSeconds: 1,
    });
    s.start();
    // Spoof the started-at to 10 s in the past.
    s._startedAt -= 10;
    assert.throws(
      () => s.pseudonymise('Asian.', { forceCategories: [[0, 5, 'RACE']] }),
      BiasDetectionTimeoutError,
    );
    assert.equal(s.closed, true);
    assert.equal(s._tokenMap, null);
  });

  it('timeout logs exit_reason=timeout', () => {
    const shield = makeShield();
    const s = new BiasDetectionSession({
      shield, ...SESSION_KWARGS, maxLifetimeSeconds: 1,
    });
    s.start();
    s._startedAt -= 10;
    assert.throws(
      () => s.recordFinding({ findingSummary: 'any' }),
      BiasDetectionTimeoutError,
    );
    const entries = readEntries(shield.config.logDir);
    const last = entries[entries.length - 1];
    assert.equal(last.event_type, 'bias_session_end');
    assert.equal(last.bias_context.exit_reason, 'timeout');
    assert.equal(last.bias_context.wipe_confirmed, true);
  });
});

// --- Audit-chain shape ---

describe('BiasDetectionSession audit chain', () => {
  it('all four event types appear in order', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        session.pseudonymise('Asian.', {
          forceCategories: [[0, 5, 'RACE']],
        });
        session.recordFinding({ findingSummary: 'ok' });
      },
    );
    const entries = readEntries(shield.config.logDir);
    assert.deepEqual(
      entries.map(e => e.event_type),
      ['bias_session_start', 'bias_pseudonymise', 'bias_finding', 'bias_session_end'],
    );
  });

  it('bias_* entries get EU_AI_Act_Art_4a in article_ref', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => session.pseudonymise('Asian.', {
        forceCategories: [[0, 5, 'RACE']],
      }),
    );
    const entries = readEntries(shield.config.logDir);
    for (const e of entries) {
      if (e.event_type.startsWith('bias_')) {
        assert.ok(e.article_ref.includes('EU_AI_Act_Art_4a'),
          `missing 4a in ${JSON.stringify(e.article_ref)}`);
        assert.ok(e.article_ref.includes('EU_AI_Act_Art_12'));
        assert.equal(e.pii_in_log, false);
        assert.equal(e.compliance_version, 'eu_ai_act_article12_v1');
      }
    }
  });

  it('bias_context carries session_id on every event', async () => {
    const shield = makeShield();
    let sid;
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        sid = session.sessionId;
        session.pseudonymise('Asian.', { forceCategories: [[0, 5, 'RACE']] });
        session.recordFinding({ findingSummary: 'ok' });
      },
    );
    const entries = readEntries(shield.config.logDir);
    for (const e of entries) {
      if (e.event_type.startsWith('bias_')) {
        assert.equal(e.bias_context.session_id, sid);
      }
    }
  });

  it('start entry carries purpose and necessity_justification', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run({ shield, ...SESSION_KWARGS }, () => {});
    const start = readEntries(shield.config.logDir)[0];
    assert.equal(start.bias_context.purpose, SESSION_KWARGS.purpose);
    assert.equal(
      start.bias_context.necessity_justification,
      SESSION_KWARGS.necessityJustification,
    );
    assert.deepEqual(
      start.bias_context.categories_allowed,
      [...SESSION_KWARGS.categoriesAllowed].sort(),
    );
    assert.equal(
      start.bias_context.max_lifetime_seconds,
      SESSION_KWARGS.maxLifetimeSeconds,
    );
  });

  it('end entry records wipe + entries_processed + exit_reason', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        session.pseudonymise('Asian.', { forceCategories: [[0, 5, 'RACE']] });
        session.pseudonymise('Asian.', { forceCategories: [[0, 5, 'RACE']] });
      },
    );
    const entries = readEntries(shield.config.logDir);
    const end = entries[entries.length - 1];
    assert.equal(end.bias_context.wipe_confirmed, true);
    assert.equal(end.bias_context.entries_processed, 2);
    assert.equal(end.bias_context.exit_reason, 'clean');
  });

  it('exception inside .run() callback yields exit_reason=error', async () => {
    const shield = makeShield();
    await assert.rejects(
      BiasDetectionSession.run({ shield, ...SESSION_KWARGS }, (session) => {
        session.pseudonymise('Asian.', { forceCategories: [[0, 5, 'RACE']] });
        throw new Error('boom');
      }),
      /boom/,
    );
    const entries = readEntries(shield.config.logDir);
    const end = entries[entries.length - 1];
    assert.equal(end.bias_context.exit_reason, 'error');
    assert.equal(end.bias_context.wipe_confirmed, true);
  });

  it('bias_context does not contain source PII', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => session.pseudonymise('Asian patient', {
        forceCategories: [[0, 5, 'RACE']],
      }),
    );
    const serialized = JSON.stringify(readEntries(shield.config.logDir));
    assert.equal(serialized.includes('Asian patient'), false);
  });

  it('chain verifies across sanitize / bias_* / sanitize boundary', async () => {
    const shield = makeShield();
    shield.sanitize('Contact john@example.com.');
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        session.pseudonymise('Asian.', { forceCategories: [[0, 5, 'RACE']] });
        session.recordFinding({ findingSummary: 'fine' });
      },
    );
    shield.sanitize('Contact jane@example.com.');
    const r = shield.audit.verifyChain();
    assert.equal(r.valid, true);
  });
});

// --- Special-category registry (A4a-2 invariants) ---

describe('Special-category registry', () => {
  const EXPECTED = new Set([
    'RACE', 'ETHNICITY', 'RELIGION', 'POLITICAL_OPINION',
    'HEALTH_BIOMETRIC', 'SEXUAL_ORIENTATION', 'TRADE_UNION', 'GENETIC',
  ]);

  it('exactly 8 categories registered', () => {
    assert.deepEqual(
      [...SPECIAL_CATEGORY_CATEGORIES].sort(),
      [...EXPECTED].sort(),
    );
  });

  it('all included in BUILTIN_CATEGORIES', () => {
    for (const c of EXPECTED) {
      assert.ok(BUILTIN_CATEGORIES.has(c), `${c} missing from BUILTIN`);
    }
  });

  it('category names validate', () => {
    for (const c of EXPECTED) {
      assert.ok(validateCategoryName(c), `${c} fails name validation`);
    }
  });

  it('tokens validate', () => {
    for (const c of EXPECTED) {
      assert.ok(validateToken(`[${c}_0]`));
      assert.ok(validateToken(`[${c}_REDACTED]`));
    }
  });

  it('regex pass does not auto-detect special categories', () => {
    const shield = new Shield(new ShieldConfig({ logDir: tmpDir() }));
    const [sanitized] = shield.sanitize(
      'Asian Buddhist Catholic Jewish Democrat Republican'
    );
    for (const c of EXPECTED) {
      assert.equal(
        sanitized.includes(`[${c}_`), false,
        `Regex auto-detected ${c}: ${sanitized}`,
      );
    }
  });
});

// --- v0.7.0 SECURITY-13: new-code security hardenings ---

describe('SECURITY-13 hardenings (JS)', () => {
  it('rejects bidi RLO in purpose', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS, purpose: 'audit‮evil',
      }),
      /bidi formatting/,
    );
  });

  it('rejects bidi LRO in necessityJustification', () => {
    const shield = makeShield();
    assert.throws(
      () => new BiasDetectionSession({
        shield, ...SESSION_KWARGS,
        necessityJustification: 'approve‭reject. ' + 'x'.repeat(30),
      }),
      /bidi formatting/,
    );
  });

  it('rejects bidi in findingSummary', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (session) => {
        assert.throws(
          () => session.recordFinding({ findingSummary: 'finding‮text' }),
          /bidi formatting/,
        );
      },
    );
  });

  it('clean ASCII passes (no false positives)', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      {
        shield, ...SESSION_KWARGS,
        purpose: 'Pre-deployment fairness audit (clean ASCII)',
        necessityJustification: 'Synthetic data evaluated and rejected.',
      },
      (s) => s.recordFinding({ findingSummary: 'No disparate impact.' }),
    );
  });

  it('forceCategories > 1024 rejected (memory DoS defense)', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (s) => {
        const spans = Array.from({ length: 1025 }, (_, i) => [i, i + 1, 'RACE']);
        assert.throws(
          () => s.pseudonymise('x'.repeat(2000), { forceCategories: spans }),
          /1024 spans/,
        );
      },
    );
  });

  it('forceCategories at cap (1024) accepted', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (s) => {
        const spans = Array.from({ length: 1024 }, (_, i) => [i, i + 1, 'RACE']);
        const [, counts] = s.pseudonymise('x'.repeat(2000), { forceCategories: spans });
        assert.equal(counts.RACE, 1024);
      },
    );
  });

  it('biasMetrics > 64 keys rejected (log-volume DoS defense)', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (s) => {
        const big = {};
        for (let i = 0; i < 65; i++) big[`k${i}`] = i;
        assert.throws(
          () => s.recordFinding({ findingSummary: 'too many', biasMetrics: big }),
          /64 keys/,
        );
      },
    );
  });

  it('biasMetrics at cap (64) accepted', async () => {
    const shield = makeShield();
    await BiasDetectionSession.run(
      { shield, ...SESSION_KWARGS },
      (s) => {
        const big = {};
        for (let i = 0; i < 64; i++) big[`k${i}`] = i;
        s.recordFinding({ findingSummary: 'at cap', biasMetrics: big });
      },
    );
  });
});
