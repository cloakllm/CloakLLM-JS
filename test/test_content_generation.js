/**
 * v0.10.0 A50-* JS test suite: EU AI Act Article 50 content-labeling
 * record-keeping. Mirror of cloakllm-py/tests/test_content_generation.py.
 *
 * Covers A50-1 (content_generation event + content_context validation via
 * the Shield/AuditLogger write path, closed whitelists, bool/hash types,
 * NUL/oversize, no-content invariant, event_type coupling), A50-2 (Shield
 * .recordContentGeneration), A50-3 (Article 50 rollup + Art-50-only
 * invariant + coverage int-when-whole), A50-4 (verdict flip), A50-6
 * (backward compatibility).
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');
const { buildReport } = require('../src/compliance-report');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-a50-js-'));
}

function makeShield() {
  const dir = tmpDir();
  const cfg = new ShieldConfig({
    auditEnabled: true,
    logDir: dir,
    complianceMode: 'eu_ai_act_article12',
  });
  return new Shield(cfg);
}

function entries(shield) {
  const dir = shield.config.logDir;
  const out = [];
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith('.jsonl'))) {
    for (const line of fs.readFileSync(path.join(dir, f), 'utf-8').split('\n')) {
      if (line.trim()) out.push(JSON.parse(line));
    }
  }
  return out;
}


// ===================================================================
// A50-1: content_context validation (via the Shield write path)
// ===================================================================

describe('A50-1 content_context validation', () => {
  function write(cc, eventType = 'content_generation') {
    const sh = makeShield();
    sh.audit.log({ eventType, contentContext: cc });
    return sh;
  }

  const validCc = (over = {}) => ({
    modality: 'text', synthetic: true, labeled: true,
    disclosure_method: 'c2pa', deepfake: false,
    c2pa_manifest_hash: null, content_hash: null, ...over,
  });

  it('accepts a valid content_context', () => {
    assert.doesNotThrow(() => write(validCc()));
  });

  for (const mod of ['text', 'image', 'audio', 'video']) {
    it(`accepts modality=${mod}`, () => {
      assert.doesNotThrow(() => write(validCc({ modality: mod })));
    });
  }

  for (const disc of ['c2pa', 'watermark', 'metadata', 'visible_notice', 'none']) {
    it(`accepts disclosure_method=${disc}`, () => {
      assert.doesNotThrow(() => write(validCc({ disclosure_method: disc })));
    });
  }

  it('rejects a bad modality', () => {
    assert.throws(() => write(validCc({ modality: 'hologram' })), /modality/);
  });

  it('rejects a bad disclosure_method', () => {
    assert.throws(() => write(validCc({ disclosure_method: 'vibes' })), /disclosure_method/);
  });

  for (const field of ['synthetic', 'labeled', 'deepfake']) {
    it(`rejects non-bool ${field}`, () => {
      assert.throws(() => write(validCc({ [field]: 'yes' })), /must be a boolean/);
    });
  }

  it('rejects a missing required field', () => {
    const cc = validCc();
    delete cc.deepfake;
    assert.throws(() => write(cc), /missing required field/);
  });

  it('rejects a null required field', () => {
    assert.throws(() => write(validCc({ modality: null })), /must not be null/);
  });

  it('rejects a disallowed key', () => {
    assert.throws(() => write(validCc({ extra: 'nope' })), /disallowed/);
  });

  it('rejects an oversize hash', () => {
    assert.throws(() => write(validCc({ content_hash: 'a'.repeat(200) })), /exceeds/);
  });

  it('rejects a NUL byte in a hash', () => {
    assert.throws(() => write(validCc({ content_hash: 'a\x00b' })), /NUL byte/);
  });

  // --- no-content-in-logs invariant ---
  for (const forbidden of ['content', 'text', 'output', 'payload', 'body', 'data', 'asset']) {
    it(`rejects forbidden content key '${forbidden}'`, () => {
      assert.throws(
        () => write(validCc({ [forbidden]: 'the secret prompt' })),
        /COMPLIANCE VIOLATION/,
      );
    });
  }

  // --- event_type coupling ---
  it('rejects content_context on a sanitize event', () => {
    assert.throws(() => write(validCc(), 'sanitize'), /content_context requires/);
  });

  it('rejects content_context on a key_registered event', () => {
    assert.throws(() => write(validCc(), 'key_registered'), /content_context requires/);
  });
});


// ===================================================================
// A50-2: Shield.recordContentGeneration
// ===================================================================

describe('A50-2 recordContentGeneration', () => {
  it('writes a content_generation event', () => {
    const sh = makeShield();
    sh.recordContentGeneration({
      modality: 'image', labeled: true, disclosureMethod: 'c2pa',
      contentHash: 'a'.repeat(64),
    });
    const es = entries(sh);
    assert.equal(es.length, 1);
    assert.equal(es[0].event_type, 'content_generation');
    assert.equal(es[0].content_context.modality, 'image');
    assert.equal(es[0].content_context.content_hash, 'a'.repeat(64));
  });

  it('article_ref includes Art_50', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', labeled: true });
    assert.deepEqual(entries(sh)[0].article_ref,
      ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19', 'EU_AI_Act_Art_50']);
  });

  it('chain verifies', () => {
    const sh = makeShield();
    for (let i = 0; i < 3; i++) sh.recordContentGeneration({ modality: 'text', labeled: true });
    const r = sh.audit.verifyChain();
    assert.equal(r.valid, true, JSON.stringify(r.errors));
  });

  it('rejects a bad modality', () => {
    const sh = makeShield();
    assert.throws(() => sh.recordContentGeneration({ modality: 'hologram' }), /modality/);
  });

  it('rejects a bad disclosureMethod', () => {
    const sh = makeShield();
    assert.throws(
      () => sh.recordContentGeneration({ modality: 'text', disclosureMethod: 'vibes' }),
      /disclosureMethod/);
  });

  it('threads decisionId', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', labeled: true, decisionId: 'my-decision-1' });
    assert.equal(entries(sh)[0].decision_id, 'my-decision-1');
  });

  it('never writes the content, only a hash', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', labeled: true, contentHash: 'deadbeef'.repeat(8) });
    const raw = JSON.stringify(entries(sh)[0]);
    assert.ok(raw.includes('deadbeef'));
    assert.ok(!raw.includes('"content"') && !raw.includes('"output"'));
  });
});


// ===================================================================
// A50-3 + A50-4: report rollup, Art-50-only invariant, verdict
// ===================================================================

describe('A50-3/A50-4 Article 50 rollup', () => {
  function gen(sh, nLabeled, nUnlabeled, modalities = ['text'], deepfakes = 0) {
    let i = 0;
    for (let k = 0; k < nLabeled; k++) {
      sh.recordContentGeneration({
        modality: modalities[i % modalities.length], labeled: true,
        disclosureMethod: 'c2pa', deepfake: i < deepfakes,
      });
      i++;
    }
    for (let k = 0; k < nUnlabeled; k++) {
      sh.recordContentGeneration({
        modality: modalities[i % modalities.length], labeled: false,
        disclosureMethod: 'none',
      });
      i++;
    }
  }

  it('rollup fields', () => {
    const sh = makeShield();
    gen(sh, 4, 1, ['text', 'text', 'text', 'image', 'audio']);
    const a50 = sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50;
    assert.equal(a50.generation_events, 5);
    assert.equal(a50.labeled_events, 4);
    assert.equal(a50.label_coverage_pct, 80);
    assert.deepEqual(a50.modality_distribution, { audio: 1, image: 1, text: 3 });
  });

  it('coverage int when whole', () => {
    const sh = makeShield();
    gen(sh, 2, 0);
    const cov = sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50.label_coverage_pct;
    assert.equal(cov, 100);
    assert.ok(Number.isInteger(cov));
  });

  it('coverage two dp', () => {
    const sh = makeShield();
    gen(sh, 1, 2); // 1/3
    const cov = sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50.label_coverage_pct;
    assert.equal(cov, 33.33);
  });

  it('deepfake count', () => {
    const sh = makeShield();
    gen(sh, 3, 0, ['text'], 2);
    const a50 = sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50;
    assert.equal(a50.deepfake_events, 2);
  });

  it('Art-50-only invariant (no content stats on Art_12/Art_19)', () => {
    const sh = makeShield();
    gen(sh, 3, 0);
    const rep = sh.generateComplianceReport({ format: 'json' });
    const contentKeys = ['generation_events', 'labeled_events', 'label_coverage_pct',
      'deepfake_events', 'modality_distribution'];
    for (const art of ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19']) {
      const stats = rep.per_article[art];
      for (const k of contentKeys) {
        assert.ok(!(k in stats), `${art} leaked content key ${k}`);
      }
    }
    for (const k of contentKeys) {
      assert.ok(k in rep.per_article.EU_AI_Act_Art_50);
    }
  });

  it('rollup merges, not replaces (evidence/decision counts survive)', () => {
    const sh = makeShield();
    gen(sh, 2, 0);
    const a50 = sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50;
    assert.equal(a50.evidence_event_count, 2);
    assert.equal(a50.decision_count, 2);
    assert.equal(a50.generation_events, 2);
  });

  it('verdict COMPLIANT when all labeled', () => {
    const sh = makeShield();
    gen(sh, 5, 0);
    assert.equal(sh.generateComplianceReport({ format: 'json' }).verdict, 'COMPLIANT');
  });

  it('verdict NON_COMPLIANT on unlabeled', () => {
    const sh = makeShield();
    gen(sh, 4, 1);
    const rep = sh.generateComplianceReport({ format: 'json' });
    assert.equal(rep.verdict, 'NON_COMPLIANT');
    assert.ok(rep.verdict_reasons.some(r => r.includes('EU_AI_Act_Art_50') && r.includes('unlabeled')));
  });

  it('markdown renders Art_50', () => {
    const sh = makeShield();
    gen(sh, 2, 0);
    const md = sh.generateComplianceReport({ format: 'markdown' });
    assert.ok(md.includes('Article 50 generation events'));
    assert.ok(md.includes('Label coverage'));
  });
});


// ===================================================================
// A50-6: backward compatibility
// ===================================================================

describe('A50-6 backward compatibility', () => {
  it('pre-v0.10.0 chain has no Art_50 row', () => {
    const sh = makeShield();
    sh.sanitize('Email me at john@acme.com');
    const rep = sh.generateComplianceReport({ format: 'json' });
    assert.ok(!('EU_AI_Act_Art_50' in rep.per_article));
    assert.equal(rep.verdict, 'COMPLIANT');
  });

  it('report byte-identical when no content events (Art_50 absent)', () => {
    // A buildReport run over only sanitize-class entries must produce no
    // Art_50 fields anywhere (additive-only guarantee).
    const e = {
      seq: 0, event_id: 'e', timestamp: '2026-01-01T00:00:00.000000+00:00',
      event_type: 'sanitize', model: null, provider: null, entity_count: 0,
      categories: {}, tokens_used: [], prompt_hash: '', sanitized_hash: '',
      latency_ms: 0, mode: null, entity_details: [], timing: null,
      certificate_hash: null, key_id: null, prev_hash: '0'.repeat(64),
      entry_hash: 'x', metadata: {}, risk_assessment: null,
      article_ref: ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19'],
    };
    const rep = buildReport({
      auditEntries: [e], periodFrom: null, periodTo: null,
      chainValid: true, chainAnomalies: [], cloakllmVersion: '0.10.0',
    });
    assert.ok(!('EU_AI_Act_Art_50' in rep.per_article));
    assert.equal(rep.verdict, 'COMPLIANT');
  });
});


// ===================================================================
// v0.10.2 C1: cross-SDK _pct rounding parity (regression guard)
// ===================================================================

describe('C1 _pct rounding parity', () => {
  function coverageFor(nLabeled, nTotal) {
    const sh = makeShield();
    for (let i = 0; i < nLabeled; i++) sh.recordContentGeneration({ modality: 'text', labeled: true });
    for (let i = 0; i < nTotal - nLabeled; i++) sh.recordContentGeneration({ modality: 'text', labeled: false });
    return sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50.label_coverage_pct;
  }

  it('half-way boundary (1 of 800) rounds half up to 0.13 (matches Python)', () => {
    // Was 0.13 in JS but 0.12 in Python under the old float path -> divergence.
    assert.equal(coverageFor(1, 800), 0.13);
  });

  it('contract values match the Python _pct table exactly', () => {
    // Same (n,d)->pct table asserted in the Python suite.
    const cases = [[1, 3, 33.33], [2, 3, 66.67], [4, 5, 80], [1, 8, 12.5],
      [7, 9, 77.78], [1, 16, 6.25], [3, 7, 42.86], [1, 1, 100]];
    for (const [n, d, expected] of cases) {
      assert.equal(coverageFor(n, d), expected, `${n}/${d}`);
    }
  });

  it('whole percentage serializes as int (no trailing .0)', () => {
    const cov = coverageFor(5, 5);
    assert.equal(cov, 100);
    assert.ok(Number.isInteger(cov));
  });
});


// ===================================================================
// v0.10.2 H1: Article 50 obligation applies to SYNTHETIC content only
// ===================================================================

describe('H1 synthetic-only scoping', () => {
  it('non-synthetic unlabeled event is COMPLIANT (no labeling duty)', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', synthetic: false, labeled: false, disclosureMethod: 'none' });
    const rep = sh.generateComplianceReport({ format: 'json' });
    assert.equal(rep.verdict, 'COMPLIANT');
    assert.ok(!('generation_events' in (rep.per_article.EU_AI_Act_Art_50 || {})));
  });

  it('synthetic unlabeled event is still NON_COMPLIANT', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', synthetic: true, labeled: false, disclosureMethod: 'none' });
    assert.equal(sh.generateComplianceReport({ format: 'json' }).verdict, 'NON_COMPLIANT');
  });

  it('mixed chain counts synthetic events only', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'image', synthetic: true, labeled: true, disclosureMethod: 'c2pa' });
    sh.recordContentGeneration({ modality: 'text', synthetic: false, labeled: false, disclosureMethod: 'none' });
    const a50 = sh.generateComplianceReport({ format: 'json' }).per_article.EU_AI_Act_Art_50;
    assert.equal(a50.generation_events, 1);
    assert.equal(a50.label_coverage_pct, 100);
  });
});
