// Cross-SDK detection differential helper: read a JSON array of input strings
// on argv[2], emit each string's REGEX-source detections as JSON to stdout.
// Compared against the Python dump to catch divergence in the hand-mirrored
// regexes (a divergence = one SDK leaks where the other doesn't).
'use strict';
const fs = require('fs');
const { Shield, ShieldConfig } = require('../src');
const sh = new Shield(new ShieldConfig({ auditEnabled: false }));
const inputs = JSON.parse(fs.readFileSync(process.argv[2], 'utf-8'));
const out = inputs.map((text) => {
  const { detections } = sh.detector.detect(text);
  const reg = detections
    .filter((d) => d.source === 'regex')
    .map((d) => [d.category, d.start, d.end])
    .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]));
  return { text, reg };
});
process.stdout.write(JSON.stringify(out));
