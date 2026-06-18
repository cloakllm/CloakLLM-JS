/**
 * v0.10.3 regression suite (JS mirror): the six bugs found by the deep audit
 * of the compliance-report / audit engine. Each test fails without its fix.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');
const { buildReport } = require('../src/compliance-report');
const { canonicalJson } = require('../src/_canonical');
const { ContextAnalyzer } = require('../src/context-analyzer');

function makeShield() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cl-v0103-'));
  return new Shield(new ShieldConfig({
    auditEnabled: true, logDir: dir, complianceMode: 'eu_ai_act_article12',
  }));
}

function tamperFirst(logDir) {
  const f = fs.readdirSync(logDir).filter(x => x.endsWith('.jsonl')).sort()[0];
  const fp = path.join(logDir, f);
  const lines = fs.readFileSync(fp, 'utf-8').trim().split('\n');
  const e0 = JSON.parse(lines[0]); e0.entity_count = 999; lines[0] = JSON.stringify(e0);
  fs.writeFileSync(fp, lines.join('\n') + '\n');
}

function baseEntry(extra) {
  return {
    seq: 0, event_id: 'e', timestamp: '2026-01-01T00:00:00+00:00',
    event_type: 'sanitize', model: null, provider: null, entity_count: 0,
    tokens_used: [], prompt_hash: '', sanitized_hash: '', latency_ms: 0,
    mode: null, entity_details: [], timing: null, certificate_hash: null,
    key_id: null, prev_hash: '0'.repeat(64), entry_hash: 'x', metadata: {},
    risk_assessment: null, article_ref: ['EU_AI_Act_Art_12'], ...extra,
  };
}

// ---- CRITICAL-1 ----
describe('CRITICAL-1 chain actually verified', () => {
  it('tampered chain is NON_COMPLIANT / broken', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', labeled: true });
    sh.recordContentGeneration({ modality: 'text', labeled: true });
    tamperFirst(sh.config.logDir);
    const rep = sh.generateComplianceReport({ format: 'json' });
    assert.equal(rep.verdict, 'NON_COMPLIANT');
    assert.equal(rep.chain_integrity.verdict, 'broken');
    assert.ok(rep.chain_integrity.anomalies.length >= 1);
  });

  it('clean chain is verified / COMPLIANT', () => {
    const sh = makeShield();
    sh.recordContentGeneration({ modality: 'text', labeled: true });
    const rep = sh.generateComplianceReport({ format: 'json' });
    assert.equal(rep.verdict, 'COMPLIANT');
    assert.equal(rep.chain_integrity.verdict, 'verified');
  });
});

// ---- HIGH-3 ----
describe('HIGH-3 malformed categories do not crash', () => {
  for (const categories of ['notadict', ['a', 'b'], { EMAIL: '5' },
    { EMAIL: null }, { EMAIL: 3.5 }, { EMAIL: true }]) {
    it(`categories=${JSON.stringify(categories)}`, () => {
      const rep = buildReport({
        auditEntries: [baseEntry({ categories })], periodFrom: null, periodTo: null,
        cloakllmVersion: 'x', chainValid: true,
      });
      const cats = rep.per_article.EU_AI_Act_Art_12.categories_detected;
      for (const [k, v] of Object.entries(cats)) {
        assert.ok(typeof k === 'string' && Number.isInteger(v));
      }
    });
  }

  it('valid int counts still aggregate', () => {
    const rep = buildReport({
      auditEntries: [baseEntry({ categories: { EMAIL: 3, SSN: 2 } })],
      periodFrom: null, periodTo: null, cloakllmVersion: 'x', chainValid: true,
    });
    assert.deepEqual(rep.per_article.EU_AI_Act_Art_12.categories_detected, { EMAIL: 3, SSN: 2 });
  });
});

// ---- MEDIUM-6 ----
describe('MEDIUM-6 pii_in_log is a global invariant', () => {
  it('filtered-out pii still flips verdict', () => {
    const rep = buildReport({
      auditEntries: [baseEntry({ pii_in_log: true })],
      periodFrom: null, periodTo: null, cloakllmVersion: 'x',
      articles: ['EU_AI_Act_Art_50'], chainValid: true,
    });
    assert.equal(rep.verdict, 'NON_COMPLIANT');
    assert.ok(rep.verdict_reasons.some(r => r.includes('pii_in_log')));
  });

  it('empty article_ref pii still flips verdict', () => {
    const rep = buildReport({
      auditEntries: [baseEntry({ article_ref: [], pii_in_log: true })],
      periodFrom: null, periodTo: null, cloakllmVersion: 'x', chainValid: true,
    });
    assert.equal(rep.verdict, 'NON_COMPLIANT');
  });
});

// ---- HIGH-4 ----
describe('HIGH-4 risk_assessment canonical (cross-SDK)', () => {
  it('empty text emits int 0', () => {
    const ra = new ContextAnalyzer().analyze('   ');
    assert.equal(canonicalJson({ v: ra.token_density }), '{"v":0}');
    assert.equal(canonicalJson({ v: ra.risk_score }), '{"v":0}');
  });

  it('whole risk_score emits int 1', () => {
    const ra = new ContextAnalyzer().analyze('[A_0] [B_0] [C_0] [D_0]');
    assert.equal(canonicalJson({ v: ra.risk_score }), '{"v":1}');
    assert.equal(canonicalJson({ v: ra.token_density }), '{"v":1}');
  });
});

// ---- HIGH-5 ----
describe('HIGH-5 canonical rejects prototype-pollution keys', () => {
  it('rejects own __proto__ / constructor / prototype', () => {
    assert.throws(() => canonicalJson(JSON.parse('{"__proto__":1}')), /disallowed object key/);
    assert.throws(() => canonicalJson({ constructor: 2 }), /disallowed object key/);
    assert.throws(() => canonicalJson({ prototype: 3 }), /disallowed object key/);
    assert.throws(() => canonicalJson({ a: JSON.parse('{"constructor":9}') }), /disallowed object key/);
  });

  it('normal keys unaffected', () => {
    assert.equal(canonicalJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
  });
});

// ---- CRITICAL-2 ----
describe('CRITICAL-2 honest attestation', () => {
  it('no false "signatures valid" verdict reason', () => {
    const sh = makeShield();
    sh.audit.log({ eventType: 'sanitize', certificateHash: 'a'.repeat(64), keyId: 'k1' });
    const rep = sh.generateComplianceReport({ format: 'json' });
    assert.ok(!rep.verdict_reasons.some(r => r.includes('signatures valid')));
    assert.ok(rep.attestation.entries_with_certificates >= 1);
  });
});
