/**
 * CloakLLM + OpenAI SDK Example
 *
 * Prerequisites:
 *   npm install openai
 *   export OPENAI_API_KEY=sk-...
 *
 * Run: node examples/openai_example.js
 */

const { enable } = require('../src');

async function main() {
  // Import OpenAI
  const OpenAI = require('openai');
  const client = new OpenAI();

  // Enable CloakLLM — one line
  enable(client);

  // Make a normal API call — PII is automatically cloaked
  // Note: JS version uses regex detection only (no NER), so names like
  // "Sarah Johnson" pass through uncloaked. Emails, phones, SSNs, etc.
  // are all detected and cloaked.
  const response = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      {
        role: 'user',
        content:
          'Write a meeting reminder for sarah.j@techcorp.io ' +
          'about the Q3 security audit. Call +1-555-0142 if needed.',
      },
    ],
  });

  console.log('\n=== Response (PII automatically restored) ===\n');
  console.log(response.choices[0].message.content);
}

main().catch(console.error);
