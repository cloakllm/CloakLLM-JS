/**
 * Vercel AI SDK Middleware.
 *
 * Usage:
 *   const { createCloakLLMMiddleware } = require('cloakllm');
 *   const { wrapLanguageModel } = require('ai');
 *   const { openai } = require('@ai-sdk/openai');
 *
 *   const middleware = createCloakLLMMiddleware();
 *   const model = wrapLanguageModel({ model: openai('gpt-4o'), middleware });
 *
 * Returns a LanguageModelV3Middleware-compatible object with three hooks:
 *   - transformParams: sanitizes prompt messages before the LLM call
 *   - wrapGenerate: desanitizes the complete response (non-streaming)
 *   - wrapStream: buffers streamed text, desanitizes on text-end
 */

const { ShieldConfig } = require('./config');
const { Shield } = require('./shield');
const { StreamDesanitizer } = require('./stream');

/** Symbol key for attaching token maps to params objects (survives spread/copy) */
const _TOKEN_MAP_KEY = Symbol.for('cloakllm.tokenMap');

const TOKEN_HINT =
  'This conversation contains placeholders like [PERSON_0], [EMAIL_0], [ORG_0], etc. ' +
  'Treat each placeholder as if it were the real value. Use them exactly as-is in your ' +
  'response — do not ask the user to replace them or provide actual details.';

/**
 * Sanitize a V3-format prompt.
 * System messages have content: string; user/assistant messages have content: Array<Part>.
 *
 * @param {Shield} shield
 * @param {Array<Object>} prompt
 * @param {string} modelId
 * @returns {[Array<Object>, import('./tokenizer').TokenMap|null]}
 */
function _sanitizeV3Prompt(shield, prompt, modelId) {
  if (!prompt?.length) return [prompt, null];

  /** @type {import('./tokenizer').TokenMap|null} */
  let tokenMap = null;

  const sanitized = prompt.map(msg => {
    // System messages: content is a plain string
    if (msg.role === 'system' && typeof msg.content === 'string' && msg.content.trim()) {
      const [sanitizedContent, map] = shield.sanitize(msg.content, {
        tokenMap,
        model: modelId,
        metadata: { role: 'system' },
      });
      tokenMap = map;
      return { ...msg, content: sanitizedContent };
    }

    // User/assistant messages: content is Array<Part>
    if (Array.isArray(msg.content)) {
      // v0.11.4: tool-call `args` and tool-result `result` are JSON-serializable
      // objects that bypass text parts; sanitize their string values via a JSON
      // round-trip so PII in tool calls/results doesn't reach the provider raw.
      const sanJSON = (value) => {
        try {
          const [out, map] = shield.sanitize(JSON.stringify(value), {
            tokenMap, model: modelId, metadata: { role: 'tool_call' },
          });
          tokenMap = map;
          return JSON.parse(out);
        } catch (_) {
          return value;
        }
      };
      const sanitizedParts = msg.content.map(part => {
        if (part?.type === 'text' && part.text) {
          const [sanitizedText, map] = shield.sanitize(part.text, {
            tokenMap,
            model: modelId,
            metadata: { role: msg.role || 'unknown' },
          });
          tokenMap = map;
          return { ...part, text: sanitizedText };
        }
        if (part?.type === 'tool-call' && part.args !== undefined) {
          return { ...part, args: sanJSON(part.args) };
        }
        if (part?.type === 'tool-result' && part.result !== undefined) {
          return { ...part, result: sanJSON(part.result) };
        }
        return part; // Preserve images, files, etc.
      });
      return { ...msg, content: sanitizedParts };
    }

    return msg;
  });

  // Inject system hint so LLM treats tokens as real values
  if (tokenMap && tokenMap.entityCount > 0) {
    const systemIdx = sanitized.findIndex(m => m.role === 'system');
    if (systemIdx >= 0) {
      const existing = sanitized[systemIdx].content || '';
      sanitized[systemIdx] = {
        ...sanitized[systemIdx],
        content: existing ? `${existing}\n\n${TOKEN_HINT}` : TOKEN_HINT,
      };
    } else {
      sanitized.unshift({ role: 'system', content: TOKEN_HINT });
    }
  }

  return [sanitized, tokenMap];
}

/**
 * Create a CloakLLM middleware for the Vercel AI SDK.
 *
 * @param {ShieldConfig|import('./config').ShieldConfigOptions} [config]
 * @returns {Object} LanguageModelV3Middleware-compatible object
 */
function createCloakLLMMiddleware(config) {
  const shieldConfig =
    config instanceof ShieldConfig ? config : new ShieldConfig(config || {});
  const shield = new Shield(shieldConfig);

  return {
    /**
     * Sanitize prompt messages before the LLM call.
     */
    transformParams: async ({ params, type, model }) => {
      const modelId = model?.modelId || '';

      // Check skipModels
      if (shieldConfig.skipModels.some(prefix => modelId.startsWith(prefix))) {
        return params;
      }

      const [sanitizedPrompt, tokenMap] = _sanitizeV3Prompt(
        shield,
        params.prompt,
        modelId
      );

      const newParams = { ...params, prompt: sanitizedPrompt };

      if (tokenMap && tokenMap.entityCount > 0) {
        // Attach token map directly via Symbol — survives spread/copy
        // unlike WeakMap which requires exact object identity
        newParams[_TOKEN_MAP_KEY] = tokenMap;
      }

      return newParams;
    },

    /**
     * Desanitize the complete response (non-streaming).
     */
    wrapGenerate: async ({ doGenerate, params, model }) => {
      const result = await doGenerate();
      const tokenMap = params[_TOKEN_MAP_KEY];

      if (!tokenMap) return result;

      const modelId = model?.modelId || '';

      // V3: result.content is Array<Part>
      if (Array.isArray(result.content)) {
        // v0.11.4: inbound mirror — restore tool-call args the model echoed back.
        const desanJSON = (value) => {
          try { return JSON.parse(shield.desanitize(JSON.stringify(value), tokenMap, { model: modelId })); }
          catch (_) { return value; }
        };
        const desanitizedContent = result.content.map(part => {
          if (part?.type === 'text' && part.text) {
            return {
              ...part,
              text: shield.desanitize(part.text, tokenMap, { model: modelId }),
            };
          }
          if (part?.type === 'tool-call' && part.args !== undefined) {
            return { ...part, args: desanJSON(part.args) };
          }
          return part;
        });
        return { ...result, content: desanitizedContent };
      }

      // V1 fallback: result.text is a string
      if (typeof result.text === 'string') {
        return {
          ...result,
          text: shield.desanitize(result.text, tokenMap, { model: modelId }),
        };
      }

      return result;
    },

    /**
     * Incrementally desanitize streamed text-deltas.
     *
     * Uses StreamDesanitizer state machine to emit text as soon as it's safe,
     * buffering only when a potential token boundary is encountered.
     */
    wrapStream: async ({ doStream, params, model }) => {
      const result = await doStream();
      const tokenMap = params[_TOKEN_MAP_KEY];

      if (!tokenMap) return result;

      const desan = new StreamDesanitizer(tokenMap);

      const transformStream = new TransformStream({
        transform(chunk, controller) {
          if (chunk.type === 'text-delta') {
            const output = desan.feed(chunk.textDelta);
            if (output) {
              controller.enqueue({
                ...chunk,
                textDelta: output,
              });
            }
            return;
          }

          if (chunk.type === 'text-end') {
            const flushed = desan.flush();
            if (flushed) {
              controller.enqueue({
                type: 'text-delta',
                textDelta: flushed,
                ...(chunk.id ? { id: chunk.id } : {}),
              });
            }
            controller.enqueue(chunk);
            return;
          }

          // Pass through all other chunk types unchanged
          controller.enqueue(chunk);
        },

        flush(controller) {
          // Flush any remaining buffered text (edge case: stream ends without text-end)
          const flushed = desan.flush();
          if (flushed) {
            controller.enqueue({
              type: 'text-delta',
              textDelta: flushed,
            });
          }
        },
      });

      return {
        ...result,
        stream: result.stream.pipeThrough(transformStream),
      };
    },
  };
}

module.exports = { createCloakLLMMiddleware, _sanitizeV3Prompt };
