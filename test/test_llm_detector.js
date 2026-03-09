const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { LlmDetector } = require('../src/llm-detector');
const { ShieldConfig } = require('../src/config');

function makeConfig(overrides = {}) {
  return new ShieldConfig({
    llmDetection: true,
    llmModel: 'llama3.2',
    llmOllamaUrl: 'http://localhost:11434',
    llmTimeout: 10000,
    llmConfidence: 0.85,
    ...overrides,
  });
}

function ollamaResponse(entities) {
  return JSON.stringify({
    message: { content: JSON.stringify({ entities }) },
  });
}

/**
 * Create a detector with mocked _execFileSync.
 * The mockFn receives (cmd, args, options) like execFileSync.
 */
function makeDetector(mockFn) {
  const detector = new LlmDetector(makeConfig());
  detector._execFileSync = mockFn;
  return detector;
}

function makeDetectorWithConfig(configOverrides, mockFn) {
  const detector = new LlmDetector(makeConfig(configOverrides));
  detector._execFileSync = mockFn;
  return detector;
}

// ─── Availability Tests ─────────────────────────────────────────

describe('LlmDetector — availability', () => {
  it('returns [] when Ollama is unavailable', () => {
    const warnings = [];
    const origWarn = console.warn;
    console.warn = (msg) => warnings.push(msg);
    try {
      const detector = makeDetector(() => { throw new Error('Connection refused'); });
      const result = detector.detect('My address is 123 Main St', []);
      assert.deepEqual(result, []);
      assert.ok(warnings.some(w => w.includes('not available')));
    } finally {
      console.warn = origWarn;
    }
  });

  it('caches availability — no second exec call after failure', () => {
    let callCount = 0;
    const origWarn = console.warn;
    console.warn = () => {};
    try {
      const detector = makeDetector(() => { callCount++; throw new Error('down'); });
      detector.detect('text1', []);
      detector.detect('text2', []);
      assert.equal(callCount, 1);
    } finally {
      console.warn = origWarn;
    }
  });
});

// ─── Successful Detection Tests ─────────────────────────────────

describe('LlmDetector — successful detection', () => {
  it('detects ADDRESS entity', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: '742 Evergreen Terrace', category: 'ADDRESS' }]);
    });
    const text = 'Ship to 742 Evergreen Terrace please';
    const results = detector.detect(text, []);
    assert.equal(results.length, 1);
    assert.equal(results[0].text, '742 Evergreen Terrace');
    assert.equal(results[0].category, 'ADDRESS');
    assert.equal(results[0].source, 'llm');
    assert.equal(results[0].confidence, 0.85);
    assert.equal(results[0].start, 8);
    assert.equal(results[0].end, 29);
  });

  it('detects PERSON entity (JS includes NER categories)', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: 'John Smith', category: 'PERSON' }]);
    });
    const results = detector.detect('Meeting with John Smith tomorrow', []);
    assert.equal(results.length, 1);
    assert.equal(results[0].category, 'PERSON');
  });

  it('detects multiple entities', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([
        { value: '1990-01-15', category: 'DATE_OF_BIRTH' },
        { value: '123 Oak Ave', category: 'ADDRESS' },
      ]);
    });
    const text = 'Born 1990-01-15 lives at 123 Oak Ave';
    const results = detector.detect(text, []);
    assert.equal(results.length, 2);
    const cats = new Set(results.map(r => r.category));
    assert.ok(cats.has('DATE_OF_BIRTH'));
    assert.ok(cats.has('ADDRESS'));
  });
});

// ─── Filtering Tests ────────────────────────────────────────────

describe('LlmDetector — filtering', () => {
  it('drops hallucinated values not in text', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: 'nonexistent value', category: 'MEDICAL' }]);
    });
    const results = detector.detect('The patient is healthy', []);
    assert.deepEqual(results, []);
  });

  it('skips entities overlapping with covered spans', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: '123 Main St', category: 'ADDRESS' }]);
    });
    const text = 'Visit 123 Main St today';
    const results = detector.detect(text, [[6, 17]]);
    assert.deepEqual(results, []);
  });

  it('skips short values (<2 chars)', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: 'X', category: 'PERSON' }]);
    });
    const results = detector.detect('Patient X has condition', []);
    assert.deepEqual(results, []);
  });

  it('skips excluded categories (EMAIL)', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: 'john@acme.com', category: 'EMAIL' }]);
    });
    const results = detector.detect('Contact john@acme.com', []);
    assert.deepEqual(results, []);
  });

  it('detects multiple occurrences of same value', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return ollamaResponse([{ value: '123 Main St', category: 'ADDRESS' }]);
    });
    const text = 'Visit 123 Main St or call about 123 Main St';
    const results = detector.detect(text, []);
    assert.equal(results.length, 2);
    assert.notEqual(results[0].start, results[1].start);
  });
});

// ─── Cache Tests ────────────────────────────────────────────────

describe('LlmDetector — cache', () => {
  it('uses cache on second call — no second curl to /api/chat', () => {
    let chatCalls = 0;
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      chatCalls++;
      return ollamaResponse([{ value: '742 Evergreen Terrace', category: 'ADDRESS' }]);
    });
    detector.detect('Ship to 742 Evergreen Terrace', []);
    detector.detect('Ship to 742 Evergreen Terrace', []);
    assert.equal(chatCalls, 1);
  });
});

// ─── Error Handling Tests ───────────────────────────────────────

describe('LlmDetector — error handling', () => {
  it('returns [] on malformed JSON from Ollama', () => {
    const origWarn = console.warn;
    console.warn = () => {};
    try {
      const detector = makeDetector((cmd, args) => {
        const url = args[args.length - 1];
        if (url.includes('/api/tags')) return '200';
        return '{"message":{"content":"not valid json{{{"}}';
      });
      const results = detector.detect('Some text', []);
      assert.deepEqual(results, []);
    } finally {
      console.warn = origWarn;
    }
  });

  it('returns [] on curl timeout', () => {
    const origWarn = console.warn;
    console.warn = () => {};
    try {
      const detector = makeDetector((cmd, args) => {
        const url = args[args.length - 1];
        if (url.includes('/api/tags')) return '200';
        throw new Error('Command timed out');
      });
      const results = detector.detect('Some text', []);
      assert.deepEqual(results, []);
    } finally {
      console.warn = origWarn;
    }
  });

  it('returns [] when entities is not an array', () => {
    const detector = makeDetector((cmd, args) => {
      const url = args[args.length - 1];
      if (url.includes('/api/tags')) return '200';
      return JSON.stringify({ message: { content: JSON.stringify({ entities: 'not array' }) } });
    });
    const results = detector.detect('Some text', []);
    assert.deepEqual(results, []);
  });
});

// ─── Custom Categories Tests ─────────────────────────────────────

describe('LlmDetector — custom categories', () => {
  it('detects custom category from LLM response', () => {
    const detector = makeDetectorWithConfig(
      { customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }] },
      (cmd, args) => {
        const url = args[args.length - 1];
        if (url.includes('/api/tags')) return '200';
        return ollamaResponse([{ value: 'PAT-12345', category: 'PATIENT_ID' }]);
      }
    );
    const results = detector.detect('Patient PAT-12345 was admitted', []);
    assert.equal(results.length, 1);
    assert.equal(results[0].category, 'PATIENT_ID');
    assert.equal(results[0].text, 'PAT-12345');
  });

  it('prompt includes custom category name', () => {
    const detector = new LlmDetector(makeConfig({
      customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }],
    }));
    const prompt = detector._systemPrompt();
    assert.ok(prompt.includes('PATIENT_ID'));
  });

  it('category without description: in list but not in hints', () => {
    const detector = new LlmDetector(makeConfig({
      customLlmCategories: [{ name: 'CASE_NUMBER' }],
    }));
    const prompt = detector._systemPrompt();
    assert.ok(prompt.includes('CASE_NUMBER'));
    assert.ok(!prompt.includes('Category hints'));
  });

  it('excluded category (EMAIL) rejected with warning', () => {
    const warnings = [];
    const origWarn = console.warn;
    console.warn = (msg) => warnings.push(msg);
    try {
      const detector = new LlmDetector(makeConfig({
        customLlmCategories: [{ name: 'EMAIL', description: 'Custom email' }],
      }));
      assert.ok(!detector._customCategories.has('EMAIL'));
      assert.ok(warnings.some(w => w.includes('conflicts')));
    } finally {
      console.warn = origWarn;
    }
  });

  it('custom + built-in coexist', () => {
    const detector = makeDetectorWithConfig(
      { customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }] },
      (cmd, args) => {
        const url = args[args.length - 1];
        if (url.includes('/api/tags')) return '200';
        return ollamaResponse([
          { value: 'PAT-12345', category: 'PATIENT_ID' },
          { value: '742 Evergreen Terrace', category: 'ADDRESS' },
        ]);
      }
    );
    const text = 'Patient PAT-12345 lives at 742 Evergreen Terrace';
    const results = detector.detect(text, []);
    assert.equal(results.length, 2);
    const cats = new Set(results.map(r => r.category));
    assert.ok(cats.has('PATIENT_ID'));
    assert.ok(cats.has('ADDRESS'));
  });

  it('unknown category from LLM filtered out', () => {
    const detector = makeDetectorWithConfig(
      { customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }] },
      (cmd, args) => {
        const url = args[args.length - 1];
        if (url.includes('/api/tags')) return '200';
        return ollamaResponse([
          { value: 'PAT-12345', category: 'PATIENT_ID' },
          { value: '1990-01-15', category: 'INVENTED_CATEGORY' },
        ]);
      }
    );
    const results = detector.detect('Patient PAT-12345 born 1990-01-15', []);
    assert.equal(results.length, 1);
    assert.equal(results[0].category, 'PATIENT_ID');
  });
});
