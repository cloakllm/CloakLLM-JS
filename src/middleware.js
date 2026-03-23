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
const { StreamDesanitizer } = require('./stream');
const { TokenMap } = require('./tokenizer');
const crypto = require('crypto');

const MAP_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** @type {Shield|null} */
let _shield = null;
let _enabled = false;

/** @type {Map<string, {tokenMap: TokenMap, created: number}>} */
const _activeMaps = new Map();

function _cleanupExpiredMaps() {
  const now = Date.now();
  for (const [key, entry] of _activeMaps) {
    if (now - entry.created > MAP_TTL_MS) {
      _activeMaps.delete(key);
    }
  }
}

/** @type {WeakMap<Object, Function>} client -> original create function */
const _originalFunctions = new WeakMap();

/** @type {WeakSet<Object>} */
const _patchedClients = new WeakSet();

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

  _cleanupExpiredMaps();
  _activeMaps.set(callKey, { tokenMap, created: Date.now() });

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

  const entry = _activeMaps.get(callKey);
  _activeMaps.delete(callKey);
  const tokenMap = entry?.tokenMap;

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

  if (_shield) {
    if (config) {
      console.warn('CloakLLM: enable() called again — existing config unchanged. Call disable() first to reconfigure.');
    }
  } else {
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

      // Handle streaming responses: incrementally desanitize tokens as they arrive.
      // Uses StreamDesanitizer state machine to emit text as soon as it's safe,
      // buffering only when a potential token boundary is encountered.
      if (params.stream) {
        if (!callKey || _shouldSkip(model)) return response;

        const streamCallKey = callKey;
        callKey = ''; // let the generator own cleanup

        async function* incrementalDesanitize(stream) {
          const streamEntry = _activeMaps.get(streamCallKey);
          _activeMaps.delete(streamCallKey);
          const tokenMap = streamEntry?.tokenMap;

          if (!tokenMap || tokenMap.entityCount === 0) {
            yield* stream;
            return;
          }

          const desan = new StreamDesanitizer(tokenMap);

          try {
            for await (const chunk of stream) {
              const delta = chunk.choices?.[0]?.delta;
              if (delta?.content) {
                const output = desan.feed(delta.content);
                if (output) {
                  yield {
                    ...chunk,
                    choices: [{
                      ...chunk.choices[0],
                      delta: { ...chunk.choices[0].delta, content: output },
                    }],
                  };
                }
              } else {
                yield chunk;
              }

              if (chunk.choices?.[0]?.finish_reason) {
                const flushed = desan.flush();
                if (flushed) {
                  yield {
                    ...chunk,
                    choices: [{
                      ...chunk.choices[0],
                      delta: { content: flushed },
                      finish_reason: null,
                    }],
                  };
                }
              }
            }

            // Stream ended without finish_reason — flush remainder
            const flushed = desan.flush();
            if (flushed) {
              yield { choices: [{ delta: { content: flushed } }] };
            }
          } catch (err) {
            desan.flush();
            throw err;
          }
        }

        return incrementalDesanitize(response);
      }

      // Desanitize non-streaming response (all choices share the same token map)
      if (callKey && !_shouldSkip(model) && response?.choices) {
        const respEntry = _activeMaps.get(callKey);
        _activeMaps.delete(callKey);
        const tokenMap = respEntry?.tokenMap;
        callKey = ''; // consumed — cleanup handled above
        if (tokenMap && tokenMap.entityCount > 0) {
          for (const choice of response.choices) {
            if (choice?.message?.content) {
              choice.message.content = _shield.desanitize(choice.message.content, tokenMap, { model });
            }
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
  _clientRefs.add(client);
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
/** @type {Set<Object>} Track clients for disable() iteration */
const _clientRefs = new Set();

function disable(client = null) {
  const clients = client ? [client] : [..._clientRefs];

  for (const c of clients) {
    const original = _originalFunctions.get(c);
    if (original && c?.chat?.completions) {
      c.chat.completions.create = original;
    }
    _originalFunctions.delete(c);
    _patchedClients.delete(c);
    _clientRefs.delete(c);
  }

  if (_clientRefs.size === 0) {
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
