/**
 * v0.6.3 NEW-3 / P0-2 / P0-4 / P1-1 / P1-2 / P1-5 / P2-1 / P2-3
 * — JS streaming audit invariant tests.
 *
 * Mirrors cloakllm-py/tests/test_streaming_audit.py.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig, TokenMap, StreamDesanitizer } = require('../src');
const middleware = require('../src/middleware');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-stream-audit-'));
}

function readAuditEntries(auditDir) {
  const entries = [];
  const files = fs.readdirSync(auditDir).filter(f => f.startsWith('audit_'));
  for (const f of files.sort()) {
    const text = fs.readFileSync(path.join(auditDir, f), 'utf-8');
    for (const line of text.split('\n').filter(l => l.trim())) {
      entries.push(JSON.parse(line));
    }
  }
  return entries;
}

// ─── StreamDesanitizer cap (NEW-3.e + P2-1) ───────────────────────────────

describe('StreamDesanitizer cap + chars_processed (NEW-3.e + P2-1)', () => {
  it('default no cap — back-compat', () => {
    const tm = new TokenMap();
    const desan = new StreamDesanitizer(tm);
    desan.feed('x'.repeat(1000000));
    assert.equal(desan.charsProcessed, 1000000);
  });

  it('cap enforced when > 0', () => {
    const tm = new TokenMap();
    const desan = new StreamDesanitizer(tm, { maxInputLength: 100 });
    desan.feed('x'.repeat(90));
    assert.throws(
      () => desan.feed('x'.repeat(20)),
      /maxInputLength=100/,
    );
  });

  it('charsProcessed accumulates', () => {
    const tm = new TokenMap();
    const desan = new StreamDesanitizer(tm);
    desan.feed('hello ');
    desan.feed('world');
    assert.equal(desan.charsProcessed, 11);
  });

  it('bytesProcessed alias still works (deprecated)', () => {
    const tm = new TokenMap();
    const desan = new StreamDesanitizer(tm);
    desan.feed('hello');
    // bytesProcessed should return same value as charsProcessed
    assert.equal(desan.bytesProcessed, 5);
  });
});

// ─── Streaming audit (NEW-3) ──────────────────────────────────────────────

function mockChunk(content, finish_reason = null) {
  return { choices: [{ delta: { content }, finish_reason }] };
}

async function* mockStream(chunks) {
  for (const c of chunks) yield c;
}

async function* errorStream() {
  yield mockChunk('partial ');
  throw new Error('upstream LLM exploded');
}

describe('OpenAI middleware streaming audit (NEW-3 + Phase 0 fixes)', () => {
  it('writes exactly one desanitize_stream entry on normal completion (P2-1: chars_processed)', async () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    });

    const mockClient = {
      chat: {
        completions: {
          create: async () => mockStream([
            mockChunk('Hello '),
            mockChunk('[EMAIL_0]'),
            mockChunk('!', 'stop'),
          ]),
        },
      },
    };

    middleware.disable(mockClient);
    middleware.enable(mockClient, cfg);

    const stream = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'Email me at john@acme.com' }],
    });

    for await (const _ of stream) { /* drain */ }

    const entries = readAuditEntries(dir);
    const streamEntries = entries.filter(e => e.event_type === 'desanitize_stream');
    assert.equal(streamEntries.length, 1);
    const e = streamEntries[0];
    assert.ok('EMAIL' in e.categories);
    assert.ok(e.tokens_used.includes('[EMAIL_0]'));
    // P2-1: field renamed bytes_processed -> chars_processed
    assert.ok('chars_processed' in e.metadata);
    assert.ok(e.metadata.chars_processed > 0);
    assert.ok(!('stream_error' in e.metadata));

    middleware.disable(mockClient);
  });

  it('writes desanitize_stream entry with stream_error=true on mid-stream raise (P1-2)', async () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    });

    const mockClient = {
      chat: { completions: { create: async () => errorStream() } },
    };

    middleware.disable(mockClient);
    middleware.enable(mockClient, cfg);

    const stream = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'Email me at john@acme.com' }],
    });

    let raised = false;
    try {
      for await (const _ of stream) { /* drain */ }
    } catch (e) {
      raised = true;
      assert.match(e.message, /exploded/);
    }
    assert.ok(raised);

    const entries = readAuditEntries(dir);
    const streamEntries = entries.filter(e => e.event_type === 'desanitize_stream');
    assert.equal(streamEntries.length, 1);
    assert.equal(streamEntries[0].metadata.stream_error, true);
    assert.equal(streamEntries[0].metadata.error_type, 'Error');

    middleware.disable(mockClient);
  });

  it('P2-3: writes desanitize_stream entry even when no PII detected', async () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    });

    const mockClient = {
      chat: { completions: { create: async () => mockStream([mockChunk('ok', 'stop')]) } },
    };

    middleware.disable(mockClient);
    middleware.enable(mockClient, cfg);

    const stream = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'plain text no pii' }],
    });
    for await (const _ of stream) { /* drain */ }

    const entries = readAuditEntries(dir);
    const streamEntries = entries.filter(e => e.event_type === 'desanitize_stream');
    // P2-3: even no-PII streams MUST log (Article 12)
    assert.equal(streamEntries.length, 1, 'P2-3 audit invariant');
    assert.equal(streamEntries[0].entity_count, 0);

    middleware.disable(mockClient);
  });

  it('P1-2: defensive error_type extraction handles non-Error throws', async () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    });

    async function* throwString() {
      yield mockChunk('part');
      throw 'string-not-Error';  // eslint-disable-line no-throw-literal
    }

    const mockClient = {
      chat: { completions: { create: async () => throwString() } },
    };

    middleware.disable(mockClient);
    middleware.enable(mockClient, cfg);

    const stream = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'john@acme.com' }],
    });

    let caught = false;
    try {
      for await (const _ of stream) { /* drain */ }
    } catch (e) {
      caught = true;
    }
    assert.ok(caught);

    const entries = readAuditEntries(dir);
    const streamEntries = entries.filter(e => e.event_type === 'desanitize_stream');
    // CRITICAL: P1-2 defends against the case where naive .constructor.name
    // would throw on a primitive throw, swallowing the audit entry.
    assert.equal(streamEntries.length, 1, 'P1-2: audit must fire even for primitive throws');
    assert.equal(streamEntries[0].metadata.stream_error, true);
    assert.equal(streamEntries[0].metadata.error_type, 'String');

    middleware.disable(mockClient);
  });

  it('P1-5: generator break (consumer abandons stream) still writes audit entry', async () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    });

    const mockClient = {
      chat: { completions: { create: async () => mockStream([
        mockChunk('hi '),
        mockChunk('[EMAIL_0]'),
        mockChunk(' more'),
        mockChunk(' stuff', 'stop'),
      ]) } },
    };

    middleware.disable(mockClient);
    middleware.enable(mockClient, cfg);

    const stream = await mockClient.chat.completions.create({
      model: 'gpt-4',
      stream: true,
      messages: [{ role: 'user', content: 'Email me at john@acme.com' }],
    });

    // Consume ONE chunk, then break
    for await (const _ of stream) {
      break;
    }
    // Async iterator's implicit return() should run the finally block

    const entries = readAuditEntries(dir);
    const streamEntries = entries.filter(e => e.event_type === 'desanitize_stream');
    assert.equal(streamEntries.length, 1, 'P1-5: gen abort must still trigger audit');

    middleware.disable(mockClient);
  });
});
