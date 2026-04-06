const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  Shield,
  ShieldConfig,
  DetectionEngine,
  DetectorBackend,
  RegexBackend,
  NerBackend,
  LlmBackend,
} = require('../src');

// ---- DetectorBackend base class ----

describe('DetectorBackend', () => {
  it('throws if name not implemented', () => {
    class Bad extends DetectorBackend {}
    const b = new Bad();
    assert.throws(() => b.name, /must implement/);
  });

  it('throws if detect not implemented', () => {
    class Bad extends DetectorBackend {}
    const b = new Bad();
    assert.throws(() => b.detect('text', []), /must implement/);
  });

  it('valid subclass works', () => {
    class Good extends DetectorBackend {
      get name() { return 'good'; }
      detect(text, coveredSpans) { return []; }
    }
    const b = new Good();
    assert.equal(b.name, 'good');
    assert.deepEqual(b.detect('hello', []), []);
  });
});

// ---- RegexBackend ----

describe('RegexBackend', () => {
  it('has name "regex"', () => {
    const backend = new RegexBackend(new ShieldConfig());
    assert.equal(backend.name, 'regex');
  });

  it('detects email', () => {
    const backend = new RegexBackend(new ShieldConfig());
    const spans = [];
    const results = backend.detect('Contact john@acme.com today', spans);
    assert.equal(results.length, 1);
    assert.equal(results[0].category, 'EMAIL');
    assert.equal(results[0].text, 'john@acme.com');
    assert.equal(results[0].source, 'regex');
    assert.equal(spans.length, 1);
  });

  it('detects SSN', () => {
    const backend = new RegexBackend(new ShieldConfig());
    const results = backend.detect('SSN: 123-45-6789', []);
    assert.ok(results.some(d => d.category === 'SSN'));
  });

  it('respects config flags', () => {
    const config = new ShieldConfig({ detectEmails: false });
    const backend = new RegexBackend(config);
    const results = backend.detect('Contact john@acme.com', []);
    assert.ok(!results.some(d => d.category === 'EMAIL'));
  });

  it('supports custom patterns', () => {
    const config = new ShieldConfig({ customPatterns: [{ name: 'TICKET', pattern: 'TICK-\\d+' }] });
    const backend = new RegexBackend(config);
    const results = backend.detect('See TICK-1234', []);
    assert.equal(results.length, 1);
    assert.equal(results[0].category, 'TICKET');
  });

  it('respects covered spans', () => {
    const backend = new RegexBackend(new ShieldConfig());
    const spans = [[8, 21]];
    const results = backend.detect('Contact john@acme.com today', spans);
    assert.ok(!results.some(d => d.category === 'EMAIL'));
  });

  it('mutates covered spans', () => {
    const backend = new RegexBackend(new ShieldConfig());
    const spans = [];
    backend.detect('Contact john@acme.com today', spans);
    assert.ok(spans.length > 0);
  });
});

// ---- NerBackend ----

describe('NerBackend', () => {
  it('has name "ner"', () => {
    const backend = new NerBackend();
    assert.equal(backend.name, 'ner');
  });

  it('returns array from detect', () => {
    const backend = new NerBackend();
    const results = backend.detect('John Smith went to the store', []);
    assert.ok(Array.isArray(results));
  });

  it('respects covered spans', () => {
    const backend = new NerBackend();
    const spans = [[0, 100]];
    const results = backend.detect('John Smith works at Google', spans);
    assert.equal(results.length, 0);
  });
});

// ---- Custom Backend ----

describe('Custom Backend', () => {
  it('custom backend in pipeline', () => {
    class UppercaseDetector extends DetectorBackend {
      get name() { return 'uppercase'; }
      detect(text, coveredSpans) {
        const detections = [];
        const regex = /\b[A-Z]{3,}\b/g;
        let match;
        while ((match = regex.exec(text)) !== null) {
          const start = match.index;
          const end = start + match[0].length;
          if (coveredSpans.some(([s, e]) => start < e && end > s)) continue;
          detections.push({
            text: match[0],
            category: 'UPPERCASE_WORD',
            start,
            end,
            confidence: 0.9,
            source: 'uppercase',
          });
          coveredSpans.push([start, end]);
        }
        return detections;
      }
    }

    const config = new ShieldConfig();
    const engine = new DetectionEngine(config, [new UppercaseDetector()]);
    const { detections, timing } = engine.detect('Check the NASA report');
    assert.equal(detections.length, 1);
    assert.equal(detections[0].category, 'UPPERCASE_WORD');
    assert.equal(detections[0].text, 'NASA');
    assert.ok('uppercase_ms' in timing);
  });

  it('custom backend with Shield', () => {
    class AlwaysDetector extends DetectorBackend {
      get name() { return 'always'; }
      detect(text, coveredSpans) {
        coveredSpans.push([0, 4]);
        return [{
          text: 'test',
          category: 'TEST',
          start: 0,
          end: 4,
          confidence: 1.0,
          source: 'always',
        }];
      }
    }

    const shield = new Shield(null, { backends: [new AlwaysDetector()] });
    const [sanitized] = shield.sanitize('test input');
    assert.ok(sanitized.includes('[TEST_0]'));
  });
});

// ---- DetectionEngine with backends ----

describe('DetectionEngine pipeline', () => {
  it('default pipeline has regex and ner', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const names = engine._backends.map(b => b.name);
    assert.ok(names.includes('regex'));
    assert.ok(names.includes('ner'));
  });

  it('default pipeline has no llm by default', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const names = engine._backends.map(b => b.name);
    assert.ok(!names.includes('llm'));
  });

  it('custom backends replace default', () => {
    const config = new ShieldConfig();
    const regex = new RegexBackend(config);
    const engine = new DetectionEngine(config, [regex]);
    assert.equal(engine._backends.length, 1);
    assert.equal(engine._backends[0].name, 'regex');
  });

  it('timing keys match backend names', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { timing } = engine.detect('john@acme.com');
    for (const backend of engine._backends) {
      assert.ok(`${backend.name}_ms` in timing);
    }
  });

  it('backward compat: _compiledPatterns', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    assert.ok(engine._compiledPatterns.length > 0);
  });
});

// ---- Shield with backends ----

describe('Shield with backends', () => {
  it('default pipeline', () => {
    const shield = new Shield();
    const names = shield.detector._backends.map(b => b.name);
    assert.ok(names.includes('regex'));
    assert.ok(names.includes('ner'));
  });

  it('custom backends', () => {
    const config = new ShieldConfig();
    const regex = new RegexBackend(config);
    const shield = new Shield(config, { backends: [regex] });
    assert.equal(shield.detector._backends.length, 1);
  });

  it('metrics have dynamic keys', () => {
    const shield = new Shield();
    shield.sanitize('Email john@acme.com');
    const m = shield.metrics();
    for (const backend of shield.detector._backends) {
      assert.ok(`${backend.name}_ms` in m.detection);
    }
  });

  it('sanitizeBatch has dynamic timing', () => {
    const shield = new Shield();
    const [sanitized] = shield.sanitizeBatch(['Email john@acme.com', 'Call 555-123-4567']);
    assert.equal(sanitized.length, 2);
    const m = shield.metrics();
    for (const backend of shield.detector._backends) {
      assert.ok(`${backend.name}_ms` in m.detection);
    }
  });
});
