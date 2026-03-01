/**
 * CloakLLM + Vercel AI SDK Example
 *
 * Prerequisites:
 *   npm install ai @ai-sdk/openai
 *   export OPENAI_API_KEY=sk-...
 *
 * Run: node examples/vercel_ai_example.js
 */

const { createCloakLLMMiddleware } = require('../src');

async function main() {
  // These are loaded dynamically so this file doesn't fail
  // if the ai package isn't installed.
  const { generateText, streamText, wrapLanguageModel } = require('ai');
  const { openai } = require('@ai-sdk/openai');

  // 1. Create the middleware
  const middleware = createCloakLLMMiddleware({
    logDir: './example_audit',
    auditEnabled: true,
  });

  // 2. Wrap a model
  const model = wrapLanguageModel({
    model: openai('gpt-4o-mini'),
    middleware,
  });

  // ─── Non-streaming example ───────────────────────────────────
  console.log('=== Non-Streaming (generateText) ===\n');

  const { text } = await generateText({
    model,
    prompt:
      'Write a short meeting reminder for sarah.j@techcorp.io about the Q3 audit. ' +
      'CC john@acme.com and call +1-555-0142 if needed.',
  });

  console.log('Response (PII restored automatically):');
  console.log(text);
  console.log();

  // ─── Streaming example ──────────────────────────────────────
  console.log('=== Streaming (streamText) ===\n');

  const result = streamText({
    model,
    prompt:
      'Draft a one-paragraph email to sarah.j@techcorp.io about Project Falcon. ' +
      'Mention that john@acme.com approved the budget.',
  });

  process.stdout.write('Response: ');
  for await (const chunk of result.textStream) {
    process.stdout.write(chunk);
  }
  console.log('\n');

  console.log('Done! Check ./example_audit/ for audit logs.');
}

main().catch(console.error);
