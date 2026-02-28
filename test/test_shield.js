const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig, TokenMap, DetectionEngine, AuditLogger } = require('../src');

// Helper: create temp dir for audit logs
function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-test-'));
}

// ─── Detection Tests ─────────────────────────────────────────────

describe('DetectionEngine', () => {
  it('detects emails', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('Contact john@example.com for info');
    assert.equal(detections.length, 1);
    assert.equal(detections[0].category, 'EMAIL');
    assert.equal(detections[0].text, 'john@example.com');
  });

  it('detects SSNs', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('SSN: 123-45-6789');
    assert.ok(detections.some(d => d.category === 'SSN'));
  });

  it('detects credit cards', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('Card: 4111111111111111');
    assert.ok(detections.some(d => d.category === 'CREDIT_CARD'));
  });

  it('detects phone numbers', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('Call +1-555-0142');
    assert.ok(detections.some(d => d.category === 'PHONE'));
  });

  it('detects IP addresses', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('Server at 192.168.1.1');
    assert.ok(detections.some(d => d.category === 'IP_ADDRESS'));
  });

  it('detects API keys', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('Key: sk_live_abc123def456ghi789jkl012');
    assert.ok(detections.some(d => d.category === 'API_KEY'));
  });

  it('detects multiple entities', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect(
      'Email john@test.com, SSN 123-45-6789, IP 10.0.0.1'
    );
    assert.ok(detections.length >= 3);
  });

  it('respects config flags', () => {
    const engine = new DetectionEngine(new ShieldConfig({ detectEmails: false }));
    const detections = engine.detect('Email john@test.com');
    assert.equal(detections.filter(d => d.category === 'EMAIL').length, 0);
  });

  it('handles custom patterns', () => {
    const engine = new DetectionEngine(new ShieldConfig({
      customPatterns: [{ name: 'CUSTOM_ID', pattern: 'CUST-\\d{6}' }],
    }));
    const detections = engine.detect('Customer CUST-123456');
    assert.ok(detections.some(d => d.category === 'CUSTOM_ID'));
  });

  it('handles overlapping detections', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('john@acme.com');
    // Should only detect once (email), not also as phone or other
    const emails = detections.filter(d => d.category === 'EMAIL');
    assert.equal(emails.length, 1);
  });

  it('returns detections sorted by start position', () => {
    const engine = new DetectionEngine(new ShieldConfig());
    const detections = engine.detect('IP 10.0.0.1 and email a@b.com');
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
