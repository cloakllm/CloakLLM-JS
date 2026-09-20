/**
 * Detection Benchmark Harness -- measures recall/precision/F1 per category.
 *
 * Usage:
 *   node benchmarks/evaluate.js [--json]
 *
 * PERSON/ORG/GPE ground truth is scored only when a NER backend is actually
 * available (compromise installed). Otherwise it is filtered out of the
 * EXPECTED entities -- not out of the samples, so regex entities in mixed
 * samples are still tested.
 *
 * That conditional matters, and getting it wrong produced a false alarm.
 * This harness used to strip NER ground truth UNCONDITIONALLY, on the
 * premise -- true when it was written -- that "JS has no NER". Detections
 * were never filtered to match. So the moment compromise was installed,
 * every PERSON/ORG/GPE detection was scored against ground truth that had
 * been deleted: 32 guaranteed false positives, 0 possible true positives,
 * and an overall precision of 72% that said nothing about detection quality.
 *
 * A benchmark whose premise has silently expired reports a defect in the
 * code instead of in itself.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { Shield, ShieldConfig } = require('../src');

const NER_CATEGORIES = new Set(['PERSON', 'ORG', 'GPE']);

const CORPUS_PATH = path.join(__dirname, 'corpus.json');

class Metrics {
  constructor() {
    this.tp = 0;
    this.fp = 0;
    this.fn = 0;
  }

  get precision() {
    return (this.tp + this.fp) > 0 ? this.tp / (this.tp + this.fp) : 0;
  }

  get recall() {
    return (this.tp + this.fn) > 0 ? this.tp / (this.tp + this.fn) : 0;
  }

  get f1() {
    const p = this.precision;
    const r = this.recall;
    return (p + r) > 0 ? (2 * p * r) / (p + r) : 0;
  }
}

/**
 * Check if two spans overlap by at least `threshold` of the smaller span.
 */
function overlaps(aStart, aEnd, bStart, bEnd, threshold = 0.5) {
  const overlap = Math.max(0, Math.min(aEnd, bEnd) - Math.max(aStart, bStart));
  const smaller = Math.min(aEnd - aStart, bEnd - bStart);
  return smaller > 0 ? overlap / smaller >= threshold : false;
}

/**
 * Is a NER backend actually usable in this process?
 *
 * Asked of the real module rather than assumed, because the assumption is
 * exactly what went stale here.
 */
function nerAvailable() {
  try {
    const { NerBackend } = require('../src/backends/ner');
    return new NerBackend().available === true;
  } catch {
    return false;
  }
}

/**
 * Load corpus from JSON file.
 *
 * @param {string} [corpusPath]
 * @param {{ includeNer?: boolean }} [opts] when includeNer is false (the
 *   default is to decide by asking the NER backend), PERSON/ORG/GPE ground
 *   truth is dropped so that an engine which cannot detect those categories
 *   is not marked down for missing them.
 */
function loadCorpus(corpusPath, opts = {}) {
  if (!corpusPath) corpusPath = CORPUS_PATH;
  const includeNer = opts.includeNer === undefined ? nerAvailable() : opts.includeNer;
  const data = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));
  for (const sample of data.samples) {
    sample.entities = includeNer
      ? sample.entities
      : sample.entities.filter((e) => !NER_CATEGORIES.has(e.category));
  }
  return data.samples;
}

/**
 * Run detection on every corpus sample and compute metrics.
 * @param {import('../src').Shield} shield
 * @param {Array} corpus
 * @returns {{ overall, perCategory, samples }}
 */
function evaluate(shield, corpus) {
  const perCat = {};
  const overall = new Metrics();
  const sampleResults = [];

  for (const sample of corpus) {
    const all = shield.detector.detect(sample.text).detections;
    const groundTruth = sample.entities;

    // Score a NER-category detection only where the corpus actually makes a
    // claim about names, orgs and places.
    //
    // Each sample annotates the entity it is TESTING, not everything it
    // contains. "Old Visa: 4222222222222." is tagged `regex` and labels only
    // the card -- but Visa is a real organisation, and so are Google, UK and
    // Berlin in other regex samples. Counting those detections as false
    // positives punishes the engine for being right about something nobody
    // wrote down, which is how NER precision came out at 72%.
    //
    // `ner` and `multi` samples annotate NER entities properly, so they are
    // scored. `negative` samples are scored too: they contain no PII of any
    // kind and assert that nothing is found, so a NER hit there is a true
    // false positive. `regex` and `adversarial` samples are silent about
    // names, so their NER detections are neither credited nor penalised.
    const scored = new Set(['ner', 'multi', 'negative']);
    const nerScored = (sample.tags || []).some((t) => scored.has(t));
    const detections = nerScored
      ? all
      : all.filter((d) => !NER_CATEGORIES.has(d.category));

    const matchedGt = new Set();
    const matchedDet = new Set();

    // Greedy 1:1 matching -- first match wins
    for (let di = 0; di < detections.length; di++) {
      const det = detections[di];
      for (let gi = 0; gi < groundTruth.length; gi++) {
        if (matchedGt.has(gi)) continue;
        const gt = groundTruth[gi];
        if (
          det.category === gt.category &&
          overlaps(det.start, det.end, gt.start, gt.end)
        ) {
          matchedGt.add(gi);
          matchedDet.add(di);
          if (!perCat[gt.category]) perCat[gt.category] = new Metrics();
          perCat[gt.category].tp += 1;
          overall.tp += 1;
          break;
        }
      }
    }

    // False positives
    let sampleFp = 0;
    for (let di = 0; di < detections.length; di++) {
      if (!matchedDet.has(di)) {
        const cat = detections[di].category;
        if (!perCat[cat]) perCat[cat] = new Metrics();
        perCat[cat].fp += 1;
        overall.fp += 1;
        sampleFp++;
      }
    }

    // False negatives
    let sampleFn = 0;
    for (let gi = 0; gi < groundTruth.length; gi++) {
      if (!matchedGt.has(gi)) {
        const cat = groundTruth[gi].category;
        if (!perCat[cat]) perCat[cat] = new Metrics();
        perCat[cat].fn += 1;
        overall.fn += 1;
        sampleFn++;
      }
    }

    sampleResults.push({
      id: sample.id,
      tags: sample.tags || [],
      expected: groundTruth.length,
      detected: detections.length,
      tp: matchedGt.size,
      fp: sampleFp,
      fn: sampleFn,
    });
  }

  // Build sorted per-category results
  const perCategoryResult = {};
  for (const cat of Object.keys(perCat).sort()) {
    const m = perCat[cat];
    perCategoryResult[cat] = {
      precision: +m.precision.toFixed(4),
      recall: +m.recall.toFixed(4),
      f1: +m.f1.toFixed(4),
      tp: m.tp,
      fp: m.fp,
      fn: m.fn,
    };
  }

  return {
    overall: {
      precision: +overall.precision.toFixed(4),
      recall: +overall.recall.toFixed(4),
      f1: +overall.f1.toFixed(4),
      tp: overall.tp,
      fp: overall.fp,
      fn: overall.fn,
    },
    perCategory: perCategoryResult,
    samples: sampleResults,
  };
}

/**
 * CLI entry point.
 */
function main() {
  const useJson = process.argv.includes('--json');

  const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
  const corpus = loadCorpus();
  const results = evaluate(shield, corpus);

  if (useJson) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  const o = results.overall;
  console.log(
    `\nOverall: P=${(o.precision * 100).toFixed(1)}%  ` +
    `R=${(o.recall * 100).toFixed(1)}%  ` +
    `F1=${(o.f1 * 100).toFixed(1)}%  ` +
    `(TP=${o.tp} FP=${o.fp} FN=${o.fn})`
  );
  console.log();
  for (const [cat, m] of Object.entries(results.perCategory)) {
    console.log(
      `  ${cat.padEnd(15)}  P=${(m.precision * 100).toFixed(1)}%  ` +
      `R=${(m.recall * 100).toFixed(1)}%  ` +
      `F1=${(m.f1 * 100).toFixed(1)}%  ` +
      `(TP=${m.tp} FP=${m.fp} FN=${m.fn})`
    );
  }

  // Threshold checks
  let failed = false;
  if (o.recall < 0.95) {
    console.log(`\n  FAIL: Overall recall ${(o.recall * 100).toFixed(1)}% < 95% target`);
    failed = true;
  }
  if (o.precision < 0.80) {
    console.log(`\n  FAIL: Overall precision ${(o.precision * 100).toFixed(1)}% < 80% target`);
    failed = true;
  }
  for (const [cat, m] of Object.entries(results.perCategory)) {
    if (m.recall < 0.80 && (m.tp + m.fn) > 0) {
      console.log(`\n  FAIL: ${cat} recall ${(m.recall * 100).toFixed(1)}% < 80% target`);
      failed = true;
    }
  }

  if (failed) {
    process.exit(1);
  } else {
    console.log('\n  All thresholds passed.');
  }
}

module.exports = { Metrics, overlaps, loadCorpus, evaluate };

if (require.main === module) {
  main();
}
