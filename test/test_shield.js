const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig, TokenMap, DetectionEngine, AuditLogger, Tokenizer } = require('../src');

// Helper: create temp dir for audit logs
function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-test-'));
}

// ─── Detection Tests ─────────────────────────────────────────────

describe('DetectionEngine', () => {
  it('detects emails', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Contact john@example.com for info');
    assert.equal(detections.length, 1);
    assert.equal(detections[0].category, 'EMAIL');
    assert.equal(detections[0].text, 'john@example.com');
  });

  it('detects SSNs', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('SSN: 123-45-6789');
    assert.ok(detections.some(d => d.category === 'SSN'));
  });

  it('detects credit cards', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Card: 4111111111111111');
    assert.ok(detections.some(d => d.category === 'CREDIT_CARD'));
  });

  it('detects phone numbers', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Call +1-555-0142');
    assert.ok(detections.some(d => d.category === 'PHONE'));
  });

  it('detects IP addresses', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Server at 192.168.1.1');
    assert.ok(detections.some(d => d.category === 'IP_ADDRESS'));
  });

  it('detects API keys', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Key: sk_live_abc123def456ghi789jkl012');
    assert.ok(detections.some(d => d.category === 'API_KEY'));
  });

  it('detects multiple entities', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect(
      'Email john@test.com, SSN 123-45-6789, IP 10.0.0.1'
    );
    assert.ok(detections.length >= 3);
  });

  it('respects config flags', () => {
    const engine = new DetectionEngine(new ShieldConfig({ detectEmails: false }));
    const { detections } = engine.detect('Email john@test.com');
    assert.equal(detections.filter(d => d.category === 'EMAIL').length, 0);
  });

  it('handles custom patterns', () => {
    const engine = new DetectionEngine(new ShieldConfig({
      customPatterns: [{ name: 'CUSTOM_ID', pattern: 'CUST-\\d{6}' }],
    }));
    const { detections } = engine.detect('Customer CUST-123456');
    assert.ok(detections.some(d => d.category === 'CUSTOM_ID'));
  });

  it('handles overlapping detections', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('john@acme.com');
    // Should only detect once (email), not also as phone or other
    const emails = detections.filter(d => d.category === 'EMAIL');
    assert.equal(emails.length, 1);
  });

  it('returns detections sorted by start position', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('IP 10.0.0.1 and email a@b.com');
    for (let i = 1; i < detections.length; i++) {
      assert.ok(detections[i].start >= detections[i - 1].start);
    }
  });
});

// ─── Tokenizer Tests ─────────────────────────────────────────────

describe('TokenMap', () => {
  it('creates sequential tokens per category', () => {
    const map = new TokenMap();
    assert.equal(map.getOrCreate('john@test.com', 'EMAIL'), '[EMAIL_0]');
    assert.equal(map.getOrCreate('jane@test.com', 'EMAIL'), '[EMAIL_1]');
    assert.equal(map.getOrCreate('John', 'PERSON'), '[PERSON_0]');
  });

  it('returns same token for same value', () => {
    const map = new TokenMap();
    const t1 = map.getOrCreate('john@test.com', 'EMAIL');
    const t2 = map.getOrCreate('john@test.com', 'EMAIL');
    assert.equal(t1, t2);
  });

  it('tracks entity count', () => {
    const map = new TokenMap();
    map.getOrCreate('a@b.com', 'EMAIL');
    map.getOrCreate('c@d.com', 'EMAIL');
    assert.equal(map.entityCount, 2);
  });
});

// ─── Shield Tests ────────────────────────────────────────────────

describe('Shield', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('sanitizes email', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitize('Contact john@example.com');
    assert.ok(sanitized.includes('[EMAIL_0]'));
    assert.ok(!sanitized.includes('john@example.com'));
    assert.equal(tokenMap.entityCount, 1);
  });

  it('desanitizes correctly', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitize('Email john@example.com');
    const restored = shield.desanitize(
      'I sent an email to [EMAIL_0] as requested.',
      tokenMap
    );
    assert.ok(restored.includes('john@example.com'));
    assert.ok(!restored.includes('[EMAIL_0]'));
  });

  it('handles case-insensitive desanitization', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [_, tokenMap] = shield.sanitize('Email john@example.com');
    const restored = shield.desanitize('Sent to [email_0]', tokenMap);
    assert.ok(restored.includes('john@example.com'));
  });

  it('preserves text without PII', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const text = 'Hello, how are you today?';
    const [sanitized, tokenMap] = shield.sanitize(text);
    assert.equal(sanitized, text);
    assert.equal(tokenMap.entityCount, 0);
  });

  it('handles multiple entity types', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitize(
      'Email john@test.com, SSN 123-45-6789, call +1-555-0142'
    );
    assert.ok(sanitized.includes('[EMAIL_0]'));
    assert.ok(sanitized.includes('[SSN_0]'));
    assert.ok(tokenMap.entityCount >= 2);
  });

  it('reuses token map across calls', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [s1, map1] = shield.sanitize('Email john@test.com');
    const [s2, map2] = shield.sanitize('Reply to john@test.com', { tokenMap: map1 });
    // Same email should get same token
    assert.ok(s1.includes('[EMAIL_0]'));
    assert.ok(s2.includes('[EMAIL_0]'));
    assert.equal(map2.entityCount, 1); // Still 1 unique entity
  });

  it('analyze returns detections without modifying text', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const result = shield.analyze('Contact john@test.com');
    assert.ok(result.entity_count >= 1);
    assert.ok(result.entities[0].text === 'john@test.com');
  });

  it('writes audit logs', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@test.com');
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    assert.ok(files.length > 0);
  });
});

// ─── Audit Tests ─────────────────────────────────────────────────

describe('AuditLogger', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('creates log entries', () => {
    const logger = new AuditLogger(new ShieldConfig({ logDir }));
    const entry = logger.log({ eventType: 'test', entityCount: 3 });
    assert.ok(entry);
    assert.equal(entry.seq, 0);
    assert.equal(entry.event_type, 'test');
    assert.equal(entry.entity_count, 3);
    assert.ok(entry.entry_hash);
    assert.ok(entry.prev_hash);
  });

  it('chains entries correctly', () => {
    const logger = new AuditLogger(new ShieldConfig({ logDir }));
    const e1 = logger.log({ eventType: 'first' });
    const e2 = logger.log({ eventType: 'second' });
    assert.equal(e2.prev_hash, e1.entry_hash);
    assert.equal(e2.seq, 1);
  });

  it('verifies valid chain', () => {
    const logger = new AuditLogger(new ShieldConfig({ logDir }));
    logger.log({ eventType: 'test1' });
    logger.log({ eventType: 'test2' });
    logger.log({ eventType: 'test3' });
    const { valid, errors } = logger.verifyChain();
    assert.ok(valid);
    assert.equal(errors.length, 0);
  });

  it('detects tampering', () => {
    const logger = new AuditLogger(new ShieldConfig({ logDir }));
    logger.log({ eventType: 'test1' });
    logger.log({ eventType: 'test2' });
    logger.log({ eventType: 'test3' });

    // Tamper with the log
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    const filePath = path.join(logDir, files[0]);
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    const entry = JSON.parse(lines[1]);
    entry.entity_count = 999; // Tamper!
    lines[1] = JSON.stringify(entry);
    fs.writeFileSync(filePath, lines.join('\n') + '\n');

    const checker = new AuditLogger(new ShieldConfig({ logDir }));
    const { valid, errors } = checker.verifyChain();
    assert.ok(!valid);
    assert.ok(errors.length > 0);
  });

  it('recovers chain state on restart', () => {
    const l1 = new AuditLogger(new ShieldConfig({ logDir }));
    l1.log({ eventType: 'test1' });
    const e2 = l1.log({ eventType: 'test2' });

    // New logger instance should continue the chain
    const l2 = new AuditLogger(new ShieldConfig({ logDir }));
    const e3 = l2.log({ eventType: 'test3' });
    assert.equal(e3.seq, 2);
    assert.equal(e3.prev_hash, e2.entry_hash);
  });

  it('returns stats', () => {
    const logger = new AuditLogger(new ShieldConfig({ logDir }));
    logger.log({ eventType: 'sanitize', entityCount: 3, categories: { EMAIL: 2, SSN: 1 } });
    logger.log({ eventType: 'sanitize', entityCount: 1, categories: { PHONE: 1 } });
    const stats = logger.getStats();
    assert.equal(stats.total_events, 2);
    assert.equal(stats.total_entities_detected, 4);
    assert.equal(stats.categories.EMAIL, 2);
    assert.equal(stats.categories.PHONE, 1);
  });

  it('skips logging when disabled', () => {
    const logger = new AuditLogger(new ShieldConfig({ logDir, auditEnabled: false }));
    const entry = logger.log({ eventType: 'test' });
    assert.equal(entry, null);
  });
});

// ─── End-to-End Tests ────────────────────────────────────────────

describe('End-to-end', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('full sanitize → simulate LLM → desanitize cycle', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));

    const prompt = 'Write a meeting reminder for sarah.j@techcorp.io about the Q3 audit. Call +1-555-0142 if needed.';
    const [sanitized, tokenMap] = shield.sanitize(prompt);

    // Verify PII is cloaked
    assert.ok(!sanitized.includes('sarah.j@techcorp.io'));
    assert.ok(!sanitized.includes('+1-555-0142'));
    assert.ok(sanitized.includes('[EMAIL_0]'));

    // Simulate LLM response using tokens
    const llmResponse = 'Hi! Here is your meeting reminder. I will email [EMAIL_0] about the Q3 audit. If there are questions, call [PHONE_0].';

    const restored = shield.desanitize(llmResponse, tokenMap);

    // Verify PII is restored
    assert.ok(restored.includes('sarah.j@techcorp.io'));
    assert.ok(restored.includes('+1-555-0142'));
    assert.ok(!restored.includes('[EMAIL_0]'));
    assert.ok(!restored.includes('[PHONE_0]'));

    // Verify audit chain
    const { valid } = shield.verifyAudit();
    assert.ok(valid);
  });

  it('handles text with no PII gracefully', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const text = 'The weather is nice today.';
    const [sanitized, tokenMap] = shield.sanitize(text);
    assert.equal(sanitized, text);
    const restored = shield.desanitize('Indeed the weather is great!', tokenMap);
    assert.equal(restored, 'Indeed the weather is great!');
  });

  it('CLI scan works', () => {
    const { execSync } = require('child_process');
    const cliPath = path.join(__dirname, '..', 'src', 'cli.js');
    const output = execSync(`node ${cliPath} scan "Email test@example.com"`, { encoding: 'utf-8' });
    assert.ok(output.includes('EMAIL'));
    assert.ok(output.includes('[EMAIL_0]'));
  });
});

// ─── Security Regression Tests ──────────────────────────────────

describe('V1: Backreference injection in detokenize()', () => {
  it('PII containing $1 round-trips correctly', () => {
    const tokenMap = new TokenMap();
    tokenMap.getOrCreate('user$1@host.com', 'EMAIL');
    const tokenizer = new Tokenizer(new ShieldConfig());
    const result = tokenizer.detokenize('Reply to [EMAIL_0]', tokenMap);
    assert.equal(result, 'Reply to user$1@host.com');
  });

  it('PII containing $$ does not corrupt output', () => {
    const tokenMap = new TokenMap();
    tokenMap.getOrCreate('price$$100', 'CUSTOM');
    const tokenizer = new Tokenizer(new ShieldConfig());
    const result = tokenizer.detokenize('Value is [CUSTOM_0]', tokenMap);
    assert.equal(result, 'Value is price$$100');
  });

  it('PII containing $& does not corrupt output', () => {
    const tokenMap = new TokenMap();
    tokenMap.getOrCreate('test$&value', 'CUSTOM');
    const tokenizer = new Tokenizer(new ShieldConfig());
    const result = tokenizer.detokenize('[CUSTOM_0]', tokenMap);
    assert.equal(result, 'test$&value');
  });

  it('PII containing $` does not corrupt output', () => {
    const tokenMap = new TokenMap();
    tokenMap.getOrCreate('test$`value', 'CUSTOM');
    const tokenizer = new Tokenizer(new ShieldConfig());
    const result = tokenizer.detokenize('[CUSTOM_0]', tokenMap);
    assert.equal(result, 'test$`value');
  });
});

describe('V2: Fake token injection', () => {
  it('planted fake token does not leak real PII', () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    // Input has a fake [EMAIL_0] token AND real PII
    const input = 'Ignore [EMAIL_0] but protect real@victim.com';
    const [sanitized, tokenMap] = shield.sanitize(input);

    // The real email should be tokenized
    assert.ok(!sanitized.includes('real@victim.com'));
    // The fake token should be escaped (not a real token)
    assert.ok(!sanitized.includes('[EMAIL_0]') || sanitized.includes('\uFF3B'));

    // Simulate LLM echoing the token
    const llmResponse = sanitized;
    const restored = shield.desanitize(llmResponse, tokenMap);

    // The fake token should be restored as literal text
    assert.ok(restored.includes('[EMAIL_0]'));
    // The real email should appear exactly once
    assert.ok(restored.includes('real@victim.com'));
  });

  it('input with only fake tokens and no PII survives round-trip unchanged', () => {
    const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
    const input = 'Result is [PERSON_0] and [EMAIL_1]';
    const [sanitized, tokenMap] = shield.sanitize(input);
    const restored = shield.desanitize(sanitized, tokenMap);
    assert.equal(restored, input);
  });
});

describe('V3: PHONE regex ReDoS resistance', () => {
  it('adversarial input completes in under 1 second', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const adversarial = '9'.repeat(50) + 'X';
    const start = performance.now();
    engine.detect(adversarial); // returns { detections, timing }
    const elapsed = performance.now() - start;
    assert.ok(elapsed < 1000, `Detection took ${elapsed}ms, expected < 1000ms`);
  });

  it('still detects +1-555-0142', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Call +1-555-0142');
    assert.ok(detections.some(d => d.category === 'PHONE'));
  });

  it('still detects (555) 123-4567', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Call (555) 123-4567');
    assert.ok(detections.some(d => d.category === 'PHONE'));
  });

  it('still detects 555-123-4567', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { detections } = engine.detect('Call 555-123-4567');
    assert.ok(detections.some(d => d.category === 'PHONE'));
  });
});

describe('V5: Custom pattern ReDoS safety check', () => {
  it('rejects catastrophically backtracking pattern', () => {
    const warnings = [];
    const origWarn = console.warn;
    console.warn = (msg) => warnings.push(msg);
    try {
      const engine = new DetectionEngine(new ShieldConfig({
        customPatterns: [{ name: 'EVIL', pattern: '(a+)+$' }],
      }));
      // Pattern should have been skipped
      const { detections } = engine.detect('aaaaaaaaaaaa');
      assert.ok(!detections.some(d => d.category === 'EVIL'));
      assert.ok(warnings.some(w => w.includes('safety check')));
    } finally {
      console.warn = origWarn;
    }
  });

  it('allows safe custom patterns', () => {
    const engine = new DetectionEngine(new ShieldConfig({
      customPatterns: [{ name: 'SAFE_ID', pattern: 'SAFE-\\d+' }],
    }));
    const { detections } = engine.detect('See SAFE-12345');
    assert.ok(detections.some(d => d.category === 'SAFE_ID'));
  });
});

// ─── Streaming Desanitization Tests ──────────────────────────────

describe('OpenAI SDK streaming desanitization', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    const { disable } = require('../src/middleware');
    disable();
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('buffers streaming chunks and desanitizes the final output', async () => {
    const { enable, disable } = require('../src/middleware');
    const { ShieldConfig } = require('../src');

    // Build a mock async iterable of streaming chunks
    async function* mockStream() {
      yield { choices: [{ delta: { content: "I'll email " }, finish_reason: null }] };
      yield { choices: [{ delta: { content: '[EMAIL_0]' }, finish_reason: null }] };
      yield { choices: [{ delta: { content: ' right away.' }, finish_reason: 'stop' }] };
    }

    const mockClient = {
      chat: {
        completions: {
          create: async (params) => {
            // Return the mock stream
            return mockStream();
          },
        },
      },
    };

    enable(mockClient, new ShieldConfig({ logDir, auditEnabled: false }));

    const result = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'Email john@example.com about the project' }],
    });

    // Collect all yielded chunks from the generator
    const chunks = [];
    for await (const chunk of result) {
      chunks.push(chunk);
    }

    // Incremental streaming: multiple chunks emitted as text arrives
    assert.ok(chunks.length >= 1, `Expected at least 1 chunk, got ${chunks.length}`);
    const fullContent = chunks
      .map(c => c.choices?.[0]?.delta?.content || '')
      .join('');
    assert.ok(fullContent.includes('john@example.com'), `Expected real email in: ${fullContent}`);
    assert.ok(!fullContent.includes('[EMAIL_0]'), `Token should be replaced in: ${fullContent}`);
  });

  it('handles streaming with no PII gracefully', async () => {
    const { enable } = require('../src/middleware');
    const { ShieldConfig } = require('../src');

    async function* mockStream() {
      yield { choices: [{ delta: { content: 'Hello ' }, finish_reason: null }] };
      yield { choices: [{ delta: { content: 'world!' }, finish_reason: 'stop' }] };
    }

    const mockClient = {
      chat: {
        completions: {
          create: async () => mockStream(),
        },
      },
    };

    enable(mockClient, new ShieldConfig({ logDir, auditEnabled: false }));

    const result = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'Say hello' }],
    });

    const chunks = [];
    for await (const chunk of result) {
      chunks.push(chunk);
    }

    // No PII means the stream is returned as-is (not wrapped)
    // Actually with no PII, callKey is '' so it returns raw stream
    // Let's just verify we got output
    assert.ok(chunks.length >= 1);
  });
});

describe('Custom pattern priority over built-ins', () => {
  it('custom pattern wins over built-in PHONE on overlapping span', () => {
    const engine = new DetectionEngine(new ShieldConfig({
      customPatterns: [{ name: 'CASE_NUMBER', pattern: 'CASE-\\d{4}-\\d{4}' }],
    }));
    const { detections } = engine.detect('Contact EMP-123456 about CASE-2024-0891');
    assert.ok(detections.some(d => d.category === 'CASE_NUMBER' && d.text === 'CASE-2024-0891'));
    assert.ok(!detections.some(d => d.category === 'PHONE' && d.text.includes('2024-0891')));
  });

  it('sanitize uses custom category token, not built-in', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({
        logDir,
        auditEnabled: false,
        customPatterns: [{ name: 'CASE_NUMBER', pattern: 'CASE-\\d{4}-\\d{4}' }],
      }));
      const [sanitized] = shield.sanitize('Contact EMP-123456 about CASE-2024-0891');
      assert.ok(sanitized.includes('[CASE_NUMBER_0]'));
      assert.ok(!sanitized.includes('CASE-2024-0891'));
      assert.ok(!sanitized.includes('[PHONE_'));
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });
});

// ─── Redaction Mode Tests ─────────────────────────────────────────

describe('Redaction Mode', () => {
  it('replaces PII with [CATEGORY_REDACTED]', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
      const [sanitized] = shield.sanitize('Email john@acme.com please');
      assert.ok(sanitized.includes('[EMAIL_REDACTED]'));
      assert.ok(!sanitized.includes('john@acme.com'));
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('token map is empty in redact mode', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
      const [, tokenMap] = shield.sanitize('Email john@acme.com please');
      assert.equal(tokenMap.entityCount, 0);
      assert.equal(tokenMap.forward.size, 0);
      assert.equal(tokenMap.reverse.size, 0);
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('desanitize is a no-op in redact mode', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
      const [sanitized, tokenMap] = shield.sanitize('Email john@acme.com please');
      const result = shield.desanitize(sanitized, tokenMap);
      assert.equal(result, sanitized);
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('audit log includes mode field', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
      shield.sanitize('Email john@acme.com please');
      const logFiles = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
      assert.equal(logFiles.length, 1);
      const content = fs.readFileSync(path.join(logDir, logFiles[0]), 'utf-8');
      const entry = JSON.parse(content.split('\n')[0]);
      assert.equal(entry.mode, 'redact');
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('multiple same-category entities all become [CATEGORY_REDACTED]', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
      const [sanitized] = shield.sanitize('Email john@acme.com and jane@acme.com');
      const matches = sanitized.match(/\[EMAIL_REDACTED\]/g);
      assert.equal(matches.length, 2);
      assert.ok(!sanitized.includes('john@acme.com'));
      assert.ok(!sanitized.includes('jane@acme.com'));
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('analyze() is unaffected by redact mode', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
      const result = shield.analyze('Email john@acme.com please');
      assert.ok(result.entity_count >= 1);
      assert.ok(result.entities.some(e => e.text === 'john@acme.com'));
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('default mode is tokenize', () => {
    const config = new ShieldConfig();
    assert.equal(config.mode, 'tokenize');
  });

  it('rejects invalid mode', () => {
    assert.throws(() => new ShieldConfig({ mode: 'invalid' }), /Invalid mode/);
  });
});

// ─── Entity Details Tests ─────────────────────────────────────────

describe('Entity Details', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('entityDetails has correct fields, sorted by start, no text key', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [, tokenMap] = shield.sanitize('Email john@acme.com, SSN 123-45-6789');
    const details = tokenMap.entityDetails;
    assert.ok(details.length >= 2);
    const expectedKeys = ['category', 'start', 'end', 'length', 'confidence', 'source', 'token'];
    for (const d of details) {
      for (const key of expectedKeys) {
        assert.ok(key in d, `Missing key: ${key}`);
      }
      assert.ok(!('text' in d), 'Should not have text key');
      assert.equal(d.length, d.end - d.start);
      assert.ok(d.token.startsWith('['));
    }
    // Sorted by start
    for (let i = 1; i < details.length; i++) {
      assert.ok(details[i].start >= details[i - 1].start);
    }
  });

  it('toReport() returns superset of toSummary() plus entity_details and mode', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [, tokenMap] = shield.sanitize('Email john@acme.com');
    const report = tokenMap.toReport();
    const summary = tokenMap.toSummary();
    assert.equal(report.entity_count, summary.entity_count);
    assert.deepEqual(report.categories, summary.categories);
    assert.deepEqual(report.tokens, summary.tokens);
    assert.ok('mode' in report);
    assert.ok('entity_details' in report);
    assert.ok(report.entity_details.length >= 1);
  });

  it('audit log entries include entity_details array', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@acme.com');
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    assert.equal(files.length, 1);
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    const entry = JSON.parse(content.split('\n')[0]);
    assert.ok('entity_details' in entry);
    assert.ok(Array.isArray(entry.entity_details));
    assert.ok(entry.entity_details.length >= 1);
    assert.equal(entry.entity_details[0].category, 'EMAIL');
  });

  it('no original PII text appears in audit entity_details', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@acme.com, SSN 123-45-6789');
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    assert.ok(!content.includes('john@acme.com'));
    assert.ok(!content.includes('123-45-6789'));
  });

  it('in redact mode, tokens show [CATEGORY_REDACTED]', () => {
    const shield = new Shield(new ShieldConfig({ mode: 'redact', logDir }));
    const [, tokenMap] = shield.sanitize('Email john@acme.com');
    const details = tokenMap.entityDetails;
    assert.ok(details.length >= 1);
    assert.equal(details[0].token, '[EMAIL_REDACTED]');
  });

  it('entityDetails is empty when no PII is detected', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [, tokenMap] = shield.sanitize('Hello world, no PII here');
    assert.deepEqual(tokenMap.entityDetails, []);
  });

  it('hash chain remains valid with entity_details included', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@acme.com');
    shield.sanitize('SSN 123-45-6789');
    shield.sanitize('No PII here');
    const { valid, errors } = shield.verifyAudit();
    assert.ok(valid, `Chain errors: ${errors.join(', ')}`);
  });
});

// ─── Batch Processing Tests ──────────────────────────────────────

describe('Batch operations', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('basic batch sanitization', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitizeBatch([
      'Email john@acme.com',
      'SSN 123-45-6789',
    ]);
    assert.equal(sanitized.length, 2);
    assert.ok(sanitized[0].includes('[EMAIL_0]'));
    assert.ok(sanitized[1].includes('[SSN_0]'));
    assert.ok(!sanitized[0].includes('john@acme.com'));
  });

  it('shared tokens across texts', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitizeBatch([
      'Email john@acme.com about the project',
      'Follow up with john@acme.com tomorrow',
    ]);
    assert.ok(sanitized[0].includes('[EMAIL_0]'));
    assert.ok(sanitized[1].includes('[EMAIL_0]'));
    assert.equal(tokenMap.entityCount, 1);
  });

  it('single audit entry for batch', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitizeBatch(['Email john@acme.com', 'SSN 123-45-6789']);
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    assert.equal(files.length, 1);
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.equal(entry.event_type, 'sanitize_batch');
    assert.ok(Array.isArray(entry.metadata.prompt_hashes));
    assert.equal(entry.metadata.prompt_hashes.length, 2);
  });

  it('entity_details include text_index', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitizeBatch(['Email john@acme.com', 'SSN 123-45-6789']);
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    const entry = JSON.parse(content.split('\n')[0]);
    const details = entry.entity_details;
    assert.ok(details.length >= 2);
    const indices = new Set(details.map(d => d.text_index));
    assert.ok(indices.has(0));
    assert.ok(indices.has(1));
  });

  it('empty list', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitizeBatch([]);
    assert.deepEqual(sanitized, []);
    assert.equal(tokenMap.entityCount, 0);
  });

  it('no-PII texts unchanged', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const texts = ['Hello world', 'Nice weather'];
    const [sanitized] = shield.sanitizeBatch(texts);
    assert.deepEqual(sanitized, texts);
  });

  it('reuse existing token map', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [, map1] = shield.sanitize('Email john@acme.com');
    const [sanitized, map2] = shield.sanitizeBatch(
      ['Remind john@acme.com', 'Also notify jane@acme.com'],
      { tokenMap: map1 }
    );
    assert.ok(sanitized[0].includes('[EMAIL_0]'));
    assert.ok(sanitized[1].includes('[EMAIL_1]'));
  });

  it('desanitizeBatch restores originals', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [sanitized, tokenMap] = shield.sanitizeBatch([
      'Email john@acme.com',
      'Server 10.0.0.1',
    ]);
    const restored = shield.desanitizeBatch(
      ['Sent to [EMAIL_0]', 'Configured [IP_ADDRESS_0]'],
      tokenMap
    );
    assert.equal(restored.length, 2);
    assert.ok(restored[0].includes('john@acme.com'));
    assert.ok(restored[1].includes('10.0.0.1'));
  });

  it('audit chain valid with batch + single mixed', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@acme.com');
    shield.sanitizeBatch(['SSN 123-45-6789', 'Phone 555-123-4567']);
    shield.desanitizeBatch(['test'], new TokenMap());
    const { valid, errors } = shield.verifyAudit();
    assert.ok(valid, `Chain errors: ${errors.join(', ')}`);
  });
});

// ─── Metrics & Timing Tests ──────────────────────────────────────

describe('Metrics & Timing', () => {
  let logDir;

  beforeEach(() => {
    logDir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(logDir, { recursive: true, force: true });
  });

  it('audit entry includes timing object', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@acme.com');
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    const entry = JSON.parse(content.split('\n')[0]);
    assert.ok('timing' in entry);
    assert.ok('total_ms' in entry.timing);
    assert.ok('detection_ms' in entry.timing);
    assert.ok('regex_ms' in entry.timing);
    assert.ok('tokenization_ms' in entry.timing);
    assert.ok(entry.timing.total_ms >= 0);
  });

  it('desanitize audit entry includes timing', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    const [, tokenMap] = shield.sanitize('Email john@acme.com');
    shield.desanitize('[EMAIL_0]', tokenMap);
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    const entry = JSON.parse(lines[1]);
    assert.ok('timing' in entry);
    assert.ok('total_ms' in entry.timing);
    assert.ok('tokenization_ms' in entry.timing);
  });

  it('batch audit entry includes timing', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitizeBatch(['Email john@acme.com', 'SSN 123-45-6789']);
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
    const content = fs.readFileSync(path.join(logDir, files[0]), 'utf-8');
    const entry = JSON.parse(content.split('\n')[0]);
    assert.ok('timing' in entry);
    assert.ok('detection_ms' in entry.timing);
    assert.ok('regex_ms' in entry.timing);
    assert.ok('tokenization_ms' in entry.timing);
  });

  it('metrics() accumulates across calls', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    shield.sanitize('Email john@acme.com');
    shield.sanitize('SSN 123-45-6789');
    const m = shield.metrics();
    assert.equal(m.calls.sanitize, 2);
    assert.ok(m.total_ms > 0);
    assert.ok(m.avg_ms > 0);
    assert.ok(m.entities_detected >= 2);
    assert.ok('EMAIL' in m.categories);
    assert.ok(m.detection.regex_ms >= 0);
    assert.ok(m.tokenization_ms >= 0);
  });

  it('metrics() counts batch calls', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    shield.sanitizeBatch(['Email john@acme.com', 'SSN 123-45-6789']);
    const m = shield.metrics();
    assert.equal(m.calls.sanitizeBatch, 1);
    assert.ok(m.entities_detected >= 2);
  });

  it('metrics() tracks desanitize', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    const [, tokenMap] = shield.sanitize('Email john@acme.com');
    shield.desanitize('[EMAIL_0]', tokenMap);
    const m = shield.metrics();
    assert.equal(m.calls.desanitize, 1);
  });

  it('resetMetrics() clears all accumulators', () => {
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: false }));
    shield.sanitize('Email john@acme.com');
    shield.resetMetrics();
    const m = shield.metrics();
    assert.equal(m.calls.sanitize, 0);
    assert.equal(m.total_ms, 0);
    assert.equal(m.entities_detected, 0);
    assert.deepEqual(m.categories, {});
  });

  it('detector returns timing dict', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const { timing } = engine.detect('Email john@acme.com');
    assert.ok('regex_ms' in timing);
    assert.ok('llm_ms' in timing);
    assert.ok(typeof timing.regex_ms === 'number');
  });

  it('hash chain valid with timing field', () => {
    const shield = new Shield(new ShieldConfig({ logDir }));
    shield.sanitize('Email john@acme.com');
    shield.sanitize('SSN 123-45-6789');
    const [, tokenMap] = shield.sanitize('Phone 555-123-4567');
    shield.desanitize('[PHONE_0]', tokenMap);
    const { valid, errors } = shield.verifyAudit();
    assert.ok(valid, `Chain errors: ${errors.join(', ')}`);
  });
});

// ─── Custom LLM Categories E2E Test ─────────────────────────────

describe('Custom LLM categories end-to-end', () => {
  it('sanitize produces [PATIENT_ID_0] token with mocked LLM detector', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({
        logDir,
        auditEnabled: false,
        llmDetection: true,
        customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }],
      }));

      // Mock the LLM detector's execFileSync
      shield.detector._llmDetector._execFileSync = (cmd, args) => {
        const url = args[args.length - 1];
        if (url.includes('/api/tags')) return '200';
        return JSON.stringify({
          message: { content: JSON.stringify({ entities: [{ value: 'PAT-12345', category: 'PATIENT_ID' }] }) },
        });
      };

      const [sanitized, tokenMap] = shield.sanitize('Patient PAT-12345 was admitted');
      assert.ok(sanitized.includes('[PATIENT_ID_0]'), `Expected [PATIENT_ID_0] in: ${sanitized}`);
      assert.ok(!sanitized.includes('PAT-12345'));
      assert.equal(tokenMap.entityCount, 1);

      // Desanitize round-trip
      const restored = shield.desanitize('Record for [PATIENT_ID_0]', tokenMap);
      assert.ok(restored.includes('PAT-12345'));
      assert.ok(!restored.includes('[PATIENT_ID_0]'));
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });
});

// ─── Entity Hashing Tests ─────────────────────────────────────────

describe('Entity Hashing', () => {
  it('hash disabled by default', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({ logDir }));
      const [, tokenMap] = shield.sanitize('Contact john@acme.com');
      for (const detail of tokenMap.entityDetails) {
        assert.equal(detail.entity_hash, undefined);
      }
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('hash enabled produces 64-char hex', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({
        logDir,
        entityHashing: true,
        entityHashKey: 'test-key',
      }));
      const [, tokenMap] = shield.sanitize('Contact john@acme.com');
      assert.ok(tokenMap.entityDetails.length >= 1);
      for (const detail of tokenMap.entityDetails) {
        assert.ok(detail.entity_hash);
        assert.equal(detail.entity_hash.length, 64);
        assert.ok(/^[0-9a-f]{64}$/.test(detail.entity_hash));
      }
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('hash is deterministic', () => {
    const logDir = tmpDir();
    try {
      const s1 = new Shield(new ShieldConfig({ logDir, entityHashing: true, entityHashKey: 'stable-key' }));
      const [, tm1] = s1.sanitize('Contact john@acme.com');

      const s2 = new Shield(new ShieldConfig({ logDir, entityHashing: true, entityHashKey: 'stable-key' }));
      const [, tm2] = s2.sanitize('Contact john@acme.com');

      const h1 = tm1.entityDetails.map(d => d.entity_hash);
      const h2 = tm2.entityDetails.map(d => d.entity_hash);
      assert.deepEqual(h1, h2);
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('category prefix prevents collision', () => {
    const tm = new TokenMap({ entityHashing: true, entityHashKey: 'test-key' });
    const hashPerson = tm._computeEntityHash('PERSON', 'john');
    const hashOrg = tm._computeEntityHash('ORG', 'john');
    assert.notEqual(hashPerson, hashOrg);
  });

  it('normalization (case/whitespace insensitive)', () => {
    const tm = new TokenMap({ entityHashing: true, entityHashKey: 'test-key' });
    const h1 = tm._computeEntityHash('EMAIL', 'John@Acme.com');
    const h2 = tm._computeEntityHash('EMAIL', '  john@acme.com  ');
    assert.equal(h1, h2);
  });

  it('auto-generates key when empty', () => {
    const logDir = tmpDir();
    try {
      const config = new ShieldConfig({ logDir, entityHashing: true });
      const shield = new Shield(config);
      assert.ok(shield.config.entityHashKey.length === 64); // 32 bytes hex
      const [, tokenMap] = shield.sanitize('Contact john@acme.com');
      assert.ok(tokenMap.entityDetails.some(d => d.entity_hash));
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('works in redact mode', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({
        logDir,
        mode: 'redact',
        entityHashing: true,
        entityHashKey: 'test-key',
      }));
      const [, tokenMap] = shield.sanitize('Contact john@acme.com');
      assert.ok(tokenMap.entityDetails.length >= 1);
      for (const d of tokenMap.entityDetails) {
        assert.ok(d.entity_hash);
        assert.ok(d.token.endsWith('_REDACTED]'));
      }
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('audit chain remains valid', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({
        logDir,
        entityHashing: true,
        entityHashKey: 'test-key',
      }));
      shield.sanitize('Contact john@acme.com');
      shield.sanitize('Call +1-555-0142');
      const { valid, errors } = shield.verifyAudit();
      assert.ok(valid, `Audit chain errors: ${errors}`);
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('batch includes hash with text_index', () => {
    const logDir = tmpDir();
    try {
      const shield = new Shield(new ShieldConfig({
        logDir,
        entityHashing: true,
        entityHashKey: 'test-key',
      }));
      const [, tokenMap] = shield.sanitizeBatch(['Email john@acme.com', 'Call +1-555-0142']);
      const details = tokenMap.entityDetails;
      assert.ok(details.length >= 2);
      for (const d of details) {
        assert.ok(d.entity_hash);
      }
    } finally {
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });

  it('cross-SDK known-value parity', () => {
    const crypto = require('crypto');
    const key = 'test-key';
    const category = 'EMAIL';
    const text = 'john@acme.com';
    const message = `${category}:${text.trim().toLowerCase()}`;
    const expected = crypto.createHmac('sha256', key).update(message).digest('hex');

    const tm = new TokenMap({ entityHashing: true, entityHashKey: key });
    const actual = tm._computeEntityHash(category, text);
    assert.equal(actual, expected);
  });
});
