/**
 * Detection benchmark threshold tests.
 *
 * These tests run the full PII corpus through the detection engine
 * and assert minimum recall/precision thresholds are met.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { evaluate, loadCorpus } = require('../benchmarks/evaluate');
const { Shield, ShieldConfig } = require('../src');

const corpusPath = path.join(__dirname, '..', 'benchmarks', 'corpus.json');

describe('Detection Benchmark', () => {
  const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
  const corpus = loadCorpus(corpusPath);
  const results = evaluate(shield, corpus);

  it('overall recall >= 95%', () => {
    assert.ok(
      results.overall.recall >= 0.95,
      `Overall recall ${(results.overall.recall * 100).toFixed(1)}% < 95%`
    );
  });

  it('overall precision >= 80%', () => {
    assert.ok(
      results.overall.precision >= 0.80,
      `Overall precision ${(results.overall.precision * 100).toFixed(1)}% < 80%`
    );
  });

  it('no category below 80% recall', () => {
    for (const [cat, m] of Object.entries(results.perCategory)) {
      if ((m.tp + m.fn) > 0) {
        assert.ok(
          m.recall >= 0.80,
          `${cat} recall ${(m.recall * 100).toFixed(1)}% < 80%`
        );
      }
    }
  });

  it('no false positives on negative samples', () => {
    for (const s of results.samples) {
      if (s.tags && s.tags.includes('negative')) {
        assert.strictEqual(
          s.fp,
          0,
          `False positive on negative sample ${s.id}`
        );
      }
    }
  });
});
