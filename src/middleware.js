/**
 * OpenAI SDK Middleware.
 *
 * Usage:
 *   const { enable, disable } = require('cloakllm');
 *   const OpenAI = require('openai');
 *
 *   const client = new OpenAI();
 *   enable(client);  // All chat.completions.create calls are now cloaked
 *
 * Works with any OpenAI-compatible SDK (OpenAI, Azure OpenAI, etc.)
 */

const path = require('path');
const { version: PKG_VERSION } = require(path.join(__dirname, '..', 'package.json'));
const { ShieldConfig } = require('./config');
const { Shield } = require('./shield');
const { TokenMap } = require('./tokenizer');
const crypto = require('crypto');

/** @type {Shield|null} */
let _shield = null;
let _enabled = false;

/** @type {Map<string, TokenMap>} */
const _activeMaps = new Map();

/** @type {WeakMap<Object, Function>} client -> original create function */
const _originalFunctions = new WeakMap();

/** @type {Set<Object>} */
const _patchedClients = new Set();

/**
 * Sanitize messages array, inject system prompt hint.
 * @param {Array<Object>} messages
 * @param {string} model
 * @returns {[Array<Object>, string]} [sanitizedMessages, callKey]
 */
function _sanitizeMessages(messages, model) {
  if (!_shield || !messages?.length) return [messages, ''];

  const callKey = crypto.randomUUID();
  /** @type {TokenMap|null} */
  let tokenMap = null;

  const sanitized = messages.map(msg => {
    const content = msg.content;

    if (typeof content === 'string' && content.trim()) {
      const [sanitizedContent, map] = _shield.sanitize(content, {
        tokenMap,
        model,
        metadata: { role: msg.role || 'unknown' },
      });
      tokenMap = map;
      return { ...msg, content: sanitizedContent };
    }

    if (Array.isArray(content)) {
      const sanitizedParts = content.map(part => {
        if (part?.type === 'text' && part.text) {
          const [sanitizedText, map] = _shield.sanitize(part.text, { tokenMap, model });
          tokenMap = map;
          return { ...part, text: sanitizedText };
        }
        return part;
      });
      return { ...msg, content: sanitizedParts };
    }

    return msg;
  });

  _activeMaps.set(callKey, tokenMap);

  // Inject system instruction so LLM treats tokens as real values
  if (tokenMap && tokenMap.entityCount > 0) {
    const tokenHint =
      'This conversation contains placeholders like [PERSON_0], [EMAIL_0], [ORG_0], etc. ' +
      'Treat each placeholder as if it were the real value. Use them exactly as-is in your ' +
      'response — do not ask the user to replace them or provide actual details.';

    if (sanitized[0]?.role === 'system') {
      const existing = sanitized[0].content || '';
      sanitized[0] = {
        ...sanitized[0],
        content: existing ? `${existing}\n\n${tokenHint}` : tokenHint,
      };
    } else {
      sanitized.unshift({ role: 'system', content: tokenHint });
    }
  }

  return [sanitized, callKey];
}

/**
 * Desanitize a response using stored token map.
 * @param {string} responseText
 * @param {string} model
 * @param {string} callKey
 * @returns {string}
 */
function _desanitizeResponse(responseText, model, callKey) {
  if (!_shield || !callKey) return responseText;

  const tokenMap = _activeMaps.get(callKey);
  _activeMaps.delete(callKey);

  if (!tokenMap || tokenMap.entityCount === 0) return responseText;

  return _shield.desanitize(responseText, tokenMap, { model });
}

/**
 * Check if model should skip sanitization.
 * @param {string} model
 * @returns {boolean}
 */
function _shouldSkip(model) {
  if (!_shield) return true;
  return _shield.config.skipModels.some(prefix => model?.startsWith(prefix));
}

/**
 * Enable CloakLLM for an OpenAI client instance.
 *
 * @param {Object} client - OpenAI client instance
 * @param {ShieldConfig} [config] - Optional config
 */
function enable(client, config = null) {
  if (!client?.chat?.completions?.create) {
    throw new Error(
      'CloakLLM: Expected an OpenAI client with chat.completions.create. ' +
      'Usage: enable(new OpenAI())'
    );
  }

  if (!_shield) {
    _shield = new Shield(config || new ShieldConfig());
  }

  if (_patchedClients.has(client)) return;

  const originalCreate = client.chat.completions.create.bind(client.chat.completions);
  _originalFunctions.set(client, originalCreate);

  client.chat.completions.create = async function shieldedCreate(params, ...rest) {
    const model = params.model || 'unknown';
    let callKey = '';

    if (!_shouldSkip(model) && params.messages) {
      const [sanitizedMessages, key] = _sanitizeMessages(params.messages, model);
      params = { ...params, messages: sanitizedMessages };
      callKey = key;
    }

    try {
      const response = await originalCreate(params, ...rest);

      // Handle streaming responses: buffer all chunks, then desanitize the
      // full assembled text before yielding a single final chunk.
      // Trade-off: no incremental streaming UX, but guarantees correct
      // desanitization. A partial-flush approach can be added later.
      if (params.stream) {
        if (!callKey || _shouldSkip(model)) return response;

        const streamCallKey = callKey;
        callKey = ''; // let the generator own cleanup

        async function* bufferAndDesanitize(stream) {
          try {
            let buffer = '';
            let lastChunk = null;

            for await (const chunk of stream) {
              lastChunk = chunk;
              const delta = chunk.choices?.[0]?.delta;
              if (delta?.content) {
                buffer += delta.content;
              }

              const finishReason = chunk.choices?.[0]?.finish_reason;
              if (finishReason) {
                // Desanitize the full buffered response
                const desanitized = _desanitizeResponse(buffer, model, streamCallKey);
                yield {
                  ...chunk,
                  choices: [{
                    ...chunk.choices[0],
                    delta: { ...chunk.choices[0].delta, content: desanitized },
                  }],
                };
                return;
              }
            }

            // Stream ended without finish_reason — emit whatever we have
            if (buffer && lastChunk) {
              const desanitized = _desanitizeResponse(buffer, model, streamCallKey);
              yield {
                ...lastChunk,
                choices: [{
                  ...lastChunk.choices[0],
                  delta: { content: desanitized },
                }],
              };
            }
          } finally {
            _activeMaps.delete(streamCallKey);
          }
        }

        return bufferAndDesanitize(response);
      }

      // Desanitize non-streaming response
      if (callKey && !_shouldSkip(model) && response?.choices) {
        for (const choice of response.choices) {
          if (choice?.message?.content) {
            choice.message.content = _desanitizeResponse(
              choice.message.content, model, callKey
            );
          }
        }
      }

      return response;
    } finally {
      // Always clean up (streaming path handles its own cleanup)
      if (callKey) _activeMaps.delete(callKey);
    }
  };

  _patchedClients.add(client);
  _enabled = true;

  _shield.audit.log({
    eventType: 'shield_enabled',
    metadata: { runtime: 'node', version: PKG_VERSION },
  });

  console.log(`🛡️  CloakLLM enabled — detecting PII across all OpenAI calls`);
  console.log(`   Audit logs: ${path.resolve(_shield.config.logDir)}`);
}

/**
 * Disable CloakLLM and restore original functions.
 * @param {Object} [client] - Specific client, or all clients
 */
function disable(client = null) {
  const clients = client ? [client] : [..._patchedClients];

  for (const c of clients) {
    const original = _originalFunctions.get(c);
    if (original && c?.chat?.completions) {
      c.chat.completions.create = original;
    }
    _originalFunctions.delete(c);
    _patchedClients.delete(c);
  }

  if (_patchedClients.size === 0) {
    if (_shield) {
      _shield.audit.log({ eventType: 'shield_disabled' });
    }
    _shield = null;
    _enabled = false;
    _activeMaps.clear();
    console.log('🛡️  CloakLLM disabled');
  }
}

/** Get the active Shield instance. */
function getShield() {
  return _shield;
}

/** Check if CloakLLM is currently enabled. */
function isEnabled() {
  return _enabled;
}

module.exports = { enable, disable, getShield, isEnabled };
