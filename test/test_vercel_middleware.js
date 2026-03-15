const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { createCloakLLMMiddleware, ShieldConfig } = require('../src');

// ─── Helper: create a ReadableStream from an array of chunks ─────
function chunksToStream(chunks) {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(chunk);
      }
      controller.close();
    },
  });
}

// ─── Helper: collect all chunks from a ReadableStream ────────────
async function collectStream(stream) {
  const chunks = [];
  const reader = stream.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return chunks;
}

// ─── Factory Tests ───────────────────────────────────────────────

describe('createCloakLLMMiddleware', () => {
  it('returns correct middleware shape', () => {
    const mw = createCloakLLMMiddleware();
    assert.equal(typeof mw.transformParams, 'function');
    assert.equal(typeof mw.wrapGenerate, 'function');
    assert.equal(typeof mw.wrapStream, 'function');
  });

  it('accepts ShieldConfig instance', () => {
    const config = new ShieldConfig({ detectEmails: true, auditEnabled: false });
    const mw = createCloakLLMMiddleware(config);
    assert.equal(typeof mw.transformParams, 'function');
  });

  it('accepts plain options object', () => {
    const mw = createCloakLLMMiddleware({ detectEmails: true, auditEnabled: false });
    assert.equal(typeof mw.transformParams, 'function');
  });
});

// ─── transformParams Tests ───────────────────────────────────────

describe('transformParams', () => {
  it('sanitizes system content (string)', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });
    const params = {
      prompt: [
        { role: 'system', content: 'You help john@acme.com with tasks' },
        { role: 'user', content: [{ type: 'text', text: 'Hello' }] },
      ],
    };

    const result = await mw.transformParams({ params, type: 'generate' });

    assert.ok(!result.prompt[0].content.includes('john@acme.com'));
    assert.ok(result.prompt[0].content.includes('[EMAIL_0]'));
  });

  it('sanitizes user content (array of parts)', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });
    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com about the deal' }],
        },
      ],
    };

    const result = await mw.transformParams({ params, type: 'generate' });

    const textPart = result.prompt.find(m => m.role === 'user')
      .content.find(p => p.type === 'text');
    assert.ok(!textPart.text.includes('john@acme.com'));
    assert.ok(textPart.text.includes('[EMAIL_0]'));
  });

  it('injects system hint (prepend new) when PII found', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });
    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com' }],
        },
      ],
    };

    const result = await mw.transformParams({ params, type: 'generate' });

    // System message should be prepended
    assert.equal(result.prompt[0].role, 'system');
    assert.ok(result.prompt[0].content.includes('placeholders'));
  });

  it('injects system hint (append to existing) when PII found', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });
    const params = {
      prompt: [
        { role: 'system', content: 'You are a helpful assistant.' },
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com' }],
        },
      ],
    };

    const result = await mw.transformParams({ params, type: 'generate' });

    assert.equal(result.prompt[0].role, 'system');
    assert.ok(result.prompt[0].content.includes('You are a helpful assistant.'));
    assert.ok(result.prompt[0].content.includes('placeholders'));
  });

  it('skips sanitization for skipModels', async () => {
    const mw = createCloakLLMMiddleware({
      auditEnabled: false,
      skipModels: ['ollama/'],
    });
    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com' }],
        },
      ],
    };

    const result = await mw.transformParams({
      params,
      type: 'generate',
      model: { modelId: 'ollama/llama3' },
    });

    // Should be unchanged — same reference
    assert.equal(result, params);
  });

  it('passes through when no PII found', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });
    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'What is the weather today?' }],
        },
      ],
    };

    const result = await mw.transformParams({ params, type: 'generate' });

    const textPart = result.prompt.find(m => m.role === 'user')
      .content.find(p => p.type === 'text');
    assert.equal(textPart.text, 'What is the weather today?');
    // No system hint should be injected
    assert.ok(!result.prompt.some(m => m.role === 'system'));
  });

  it('preserves non-text parts (images, files)', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });
    const imagePart = { type: 'image', image: 'base64data', mimeType: 'image/png' };
    const params = {
      prompt: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Describe john@acme.com profile picture' },
            imagePart,
          ],
        },
      ],
    };

    const result = await mw.transformParams({ params, type: 'generate' });

    const userMsg = result.prompt.find(m => m.role === 'user');
    const img = userMsg.content.find(p => p.type === 'image');
    assert.deepEqual(img, imagePart);
  });
});

// ─── wrapGenerate Tests ──────────────────────────────────────────

describe('wrapGenerate', () => {
  it('full sanitize -> generate -> desanitize round-trip', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    // Step 1: transformParams (sanitize)
    const params = {
      prompt: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Write a reminder for sarah.j@techcorp.io about Q3' },
          ],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'generate' });

    // Verify sanitization happened
    const userMsg = newParams.prompt.find(m => m.role === 'user');
    const textPart = userMsg.content.find(p => p.type === 'text');
    assert.ok(textPart.text.includes('[EMAIL_0]'));
    assert.ok(!textPart.text.includes('sarah.j@techcorp.io'));

    // Step 2: wrapGenerate (mock LLM returns tokens)
    const mockModel = { modelId: 'gpt-4o' };
    const doGenerate = async () => ({
      content: [
        { type: 'text', text: 'Sure, I will email [EMAIL_0] about Q3.' },
      ],
      finishReason: 'stop',
      usage: { promptTokens: 10, completionTokens: 20 },
    });

    const result = await mw.wrapGenerate({
      doGenerate,
      params: newParams,
      model: mockModel,
    });

    // Verify desanitization happened
    const resultText = result.content.find(p => p.type === 'text');
    assert.ok(resultText.text.includes('sarah.j@techcorp.io'));
    assert.ok(!resultText.text.includes('[EMAIL_0]'));
    assert.equal(result.finishReason, 'stop');
  });

  it('passes through result when no PII was found', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Hello world' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'generate' });

    const doGenerate = async () => ({
      content: [{ type: 'text', text: 'Hi there!' }],
      finishReason: 'stop',
    });

    const result = await mw.wrapGenerate({
      doGenerate,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    assert.equal(result.content[0].text, 'Hi there!');
  });

  it('preserves non-text parts in result', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'generate' });

    const toolCallPart = {
      type: 'tool-call',
      toolCallId: 'tc1',
      toolName: 'send_email',
      args: { to: '[EMAIL_0]' },
    };

    const doGenerate = async () => ({
      content: [
        { type: 'text', text: 'Sending to [EMAIL_0]' },
        toolCallPart,
      ],
    });

    const result = await mw.wrapGenerate({
      doGenerate,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    const tc = result.content.find(p => p.type === 'tool-call');
    assert.equal(tc.toolName, 'send_email');
  });
});

// ─── wrapStream Tests ────────────────────────────────────────────

describe('wrapStream', () => {
  it('buffers text-deltas and desanitizes on text-end', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    // Sanitize first
    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Remind sarah.j@techcorp.io about the meeting' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'stream' });

    // Mock stream with text-delta chunks that reference the token
    const inputChunks = [
      { type: 'text-delta', textDelta: 'Sure, I will email ' },
      { type: 'text-delta', textDelta: '[EMAIL_0]' },
      { type: 'text-delta', textDelta: ' about the meeting.' },
      { type: 'text-end' },
      { type: 'finish', finishReason: 'stop' },
    ];

    const doStream = async () => ({
      stream: chunksToStream(inputChunks),
    });

    const result = await mw.wrapStream({
      doStream,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    const outputChunks = await collectStream(result.stream);

    // Incremental streaming: text-deltas emitted as text arrives
    const textDeltas = outputChunks.filter(c => c.type === 'text-delta');
    assert.ok(textDeltas.length >= 1, `Expected at least 1 text-delta, got ${textDeltas.length}`);
    const fullText = textDeltas.map(c => c.textDelta).join('');
    assert.ok(fullText.includes('sarah.j@techcorp.io'));
    assert.ok(!fullText.includes('[EMAIL_0]'));

    // text-end and finish should pass through
    assert.ok(outputChunks.some(c => c.type === 'text-end'));
    assert.ok(outputChunks.some(c => c.type === 'finish'));
  });

  it('passes through non-text chunks unchanged', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'stream' });

    const toolCallChunk = {
      type: 'tool-call',
      toolCallId: 'tc1',
      toolName: 'lookup',
      args: {},
    };

    const inputChunks = [
      { type: 'text-delta', textDelta: 'Looking up [EMAIL_0]' },
      { type: 'text-end' },
      toolCallChunk,
      { type: 'finish', finishReason: 'stop' },
    ];

    const doStream = async () => ({
      stream: chunksToStream(inputChunks),
    });

    const result = await mw.wrapStream({
      doStream,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    const outputChunks = await collectStream(result.stream);

    const tc = outputChunks.find(c => c.type === 'tool-call');
    assert.deepEqual(tc, toolCallChunk);
  });

  it('passes through stream unchanged when no PII was found', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Hello' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'stream' });

    const inputChunks = [
      { type: 'text-delta', textDelta: 'Hi there!' },
      { type: 'text-end' },
      { type: 'finish', finishReason: 'stop' },
    ];

    const doStream = async () => ({
      stream: chunksToStream(inputChunks),
    });

    const result = await mw.wrapStream({
      doStream,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    const outputChunks = await collectStream(result.stream);

    // No tokenMap, so stream should pass through unchanged
    assert.equal(outputChunks.length, 3);
    assert.equal(outputChunks[0].textDelta, 'Hi there!');
  });

  it('handles token split across text-delta chunks', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Contact sarah.j@techcorp.io please' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'stream' });

    // Token [EMAIL_0] split across chunks
    const inputChunks = [
      { type: 'text-delta', textDelta: 'Contact [EM' },
      { type: 'text-delta', textDelta: 'AIL_0] please' },
      { type: 'text-end' },
    ];

    const doStream = async () => ({
      stream: chunksToStream(inputChunks),
    });

    const result = await mw.wrapStream({
      doStream,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    const outputChunks = await collectStream(result.stream);

    const textDeltas = outputChunks.filter(c => c.type === 'text-delta');
    const fullText = textDeltas.map(c => c.textDelta).join('');
    assert.ok(fullText.includes('sarah.j@techcorp.io'));
    assert.ok(!fullText.includes('[EMAIL_0]'));
  });

  it('buffers per block ID', async () => {
    const mw = createCloakLLMMiddleware({ auditEnabled: false });

    const params = {
      prompt: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'Email john@acme.com and call +1-555-0142' }],
        },
      ],
    };

    const newParams = await mw.transformParams({ params, type: 'stream' });

    const inputChunks = [
      { type: 'text-delta', textDelta: 'Emailing [EMAIL_0]', id: 'block-0' },
      { type: 'text-delta', textDelta: ', calling [PHONE_0]', id: 'block-0' },
      { type: 'text-end', id: 'block-0' },
    ];

    const doStream = async () => ({
      stream: chunksToStream(inputChunks),
    });

    const result = await mw.wrapStream({
      doStream,
      params: newParams,
      model: { modelId: 'gpt-4o' },
    });

    const outputChunks = await collectStream(result.stream);

    const textDeltas = outputChunks.filter(c => c.type === 'text-delta');
    assert.ok(textDeltas.length >= 1, `Expected at least 1 text-delta, got ${textDeltas.length}`);
    const fullText = textDeltas.map(c => c.textDelta).join('');
    assert.ok(fullText.includes('john@acme.com'));
    assert.ok(fullText.includes('+1-555-0142'));
  });
});
