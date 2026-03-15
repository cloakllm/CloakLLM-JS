const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { enable, disable, isEnabled } = require('../src/middleware');
const { ShieldConfig } = require('../src/config');

describe('OpenAI Middleware Integration', () => {
    let mockClient;

    beforeEach(() => {
        mockClient = {
            chat: {
                completions: {
                    create: async (params) => {
                        const n = params.n || 1;
                        const choices = [];
                        for (let i = 0; i < n; i++) {
                            choices.push({
                                index: i,
                                message: {
                                    role: 'assistant',
                                    content: `Reply to [EMAIL_0] about the project.`,
                                },
                                finish_reason: 'stop',
                            });
                        }
                        return { choices };
                    },
                },
            },
        };
    });

    afterEach(() => {
        if (isEnabled()) disable();
    });

    it('desanitizes all n>1 choices', async () => {
        enable(mockClient, new ShieldConfig({ auditEnabled: false }));

        const result = await mockClient.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: 'Email john@acme.com about the project' }],
            n: 3,
        });

        for (const choice of result.choices) {
            assert.ok(!choice.message.content.includes('[EMAIL_0]'),
                `Choice ${choice.index} still has token`);
            assert.ok(choice.message.content.includes('john@acme.com'),
                `Choice ${choice.index} missing original`);
        }
    });

    it('handles streaming with incremental desanitization', async () => {
        mockClient.chat.completions.create = async (params) => {
            if (!params.stream) throw new Error('Expected stream');
            async function* chunks() {
                yield { choices: [{ delta: { content: 'Contact ' } }] };
                yield { choices: [{ delta: { content: '[EMA' } }] };
                yield { choices: [{ delta: { content: 'IL_0]' } }] };
                yield { choices: [{ delta: { content: ' now.' }, finish_reason: 'stop' }] };
            }
            return chunks();
        };

        enable(mockClient, new ShieldConfig({ auditEnabled: false }));

        const stream = await mockClient.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: 'Email john@acme.com about the deal' }],
            stream: true,
        });

        let full = '';
        for await (const chunk of stream) {
            if (chunk.choices?.[0]?.delta?.content) {
                full += chunk.choices[0].delta.content;
            }
        }

        assert.ok(!full.includes('[EMAIL_0]'), `Stream has token: ${full}`);
        assert.ok(full.includes('john@acme.com'), `Stream missing original: ${full}`);
    });

    it('streaming passthrough when no PII', async () => {
        mockClient.chat.completions.create = async (params) => {
            async function* chunks() {
                yield { choices: [{ delta: { content: 'Hello ' } }] };
                yield { choices: [{ delta: { content: 'world!' }, finish_reason: 'stop' }] };
            }
            return chunks();
        };

        enable(mockClient, new ShieldConfig({ auditEnabled: false }));

        const stream = await mockClient.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: 'Say hello' }],
            stream: true,
        });

        let full = '';
        let chunkCount = 0;
        for await (const chunk of stream) {
            chunkCount++;
            if (chunk.choices?.[0]?.delta?.content) {
                full += chunk.choices[0].delta.content;
            }
        }

        assert.equal(full, 'Hello world!');
        assert.ok(chunkCount >= 2, 'Should pass through multiple chunks');
    });

    it('streaming handles finish without finish_reason', async () => {
        mockClient.chat.completions.create = async (params) => {
            async function* chunks() {
                yield { choices: [{ delta: { content: 'Reply to [EMAIL_0]' } }] };
                // Stream ends abruptly — no finish_reason
            }
            return chunks();
        };

        enable(mockClient, new ShieldConfig({ auditEnabled: false }));

        const stream = await mockClient.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: 'Email john@acme.com' }],
            stream: true,
        });

        let full = '';
        for await (const chunk of stream) {
            if (chunk.choices?.[0]?.delta?.content) {
                full += chunk.choices[0].delta.content;
            }
        }

        assert.ok(full.includes('john@acme.com'), `Should desanitize: ${full}`);
    });
});
