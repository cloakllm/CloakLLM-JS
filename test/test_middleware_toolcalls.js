/**
 * v0.11.4: OpenAI-style middleware sanitizes PII in tool-call arguments
 * (outbound) and restores it (inbound, all choices); enable()/disable() banners
 * are ASCII-only. Mirror of the Python regression guard.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const cloakllm = require('../src');
const { ShieldConfig } = require('../src');

function makeClient(capture, nChoices = 3) {
  return {
    chat: {
      completions: {
        create(kw) {
          capture.messages = kw.messages;
          let sentArgs = null;
          for (const m of kw.messages) for (const tc of (m.tool_calls || [])) sentArgs = tc.function.arguments;
          const choices = [];
          for (let i = 0; i < nChoices; i++) {
            choices.push({ message: { content: 'ok', tool_calls: [{ id: '1', type: 'function', function: { name: 'send', arguments: sentArgs } }] } });
          }
          return { choices };
        },
      },
    },
  };
}

function withCapturedConsole(fn) {
  const out = [];
  const log = console.log, warn = console.warn;
  console.log = (...a) => out.push(a.join(' '));
  console.warn = (...a) => out.push(a.join(' '));
  try { fn(); } finally { console.log = log; console.warn = warn; }
  return out.join('\n');
}

describe('v0.11.4 middleware tool-call sanitization', () => {
  it('sanitizes tool_call args outbound + restores in all choices', async () => {
    const cap = {};
    const client = makeClient(cap, 3);
    withCapturedConsole(() => cloakllm.enable(client, new ShieldConfig({ auditEnabled: false })));
    const resp = await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'assistant', content: null, tool_calls: [
        { id: '1', type: 'function', function: { name: 'send', arguments: '{"to":"victim@example.com","ssn":"123-45-6789"}' } }] }],
    });
    const sent = JSON.stringify(cap.messages);
    assert.ok(!sent.includes('victim@example.com') && !sent.includes('123-45-6789'),
      'PII in tool_call args reached the provider: ' + sent);
    for (const ch of resp.choices) {
      const args = ch.message.tool_calls[0].function.arguments;
      assert.ok(args.includes('victim@example.com') && args.includes('123-45-6789'),
        'tool_call args not restored for a choice: ' + args);
    }
    if (cloakllm.disable) cloakllm.disable(client);
  });

  it('enable()/disable() banners are ASCII-only', () => {
    const client = makeClient({});
    const out = withCapturedConsole(() => {
      cloakllm.enable(client, new ShieldConfig({ auditEnabled: false }));
      if (cloakllm.disable) cloakllm.disable(client);
    });
    // eslint-disable-next-line no-control-regex
    assert.ok(/^[\x00-\x7F]*$/.test(out), 'banner has non-ASCII (crashes cp1255/cp932): ' + JSON.stringify(out));
  });
});
