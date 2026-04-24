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

/**
 * v0.6.4 G12: store `lastAccessed` (refreshed on every retrieval) instead of
 * just `created`. The previous wall-clock TTL evicted any token map exactly
 * 5 minutes after the FIRST request that created it — even if the same
 * conversation was actively reusing the map every few seconds. Long-running
 * multi-turn conversations would silently lose their token map mid-stream
 * and tokens like [EMAIL_0] would no longer round-trip.
 *
 * The MCP server already uses an idle-refresh pattern (server.py refreshes
 * `created` on map reuse). Aligning the JS middleware to the same semantics.
 *
 * @type {Map<string, {tokenMap: TokenMap, lastAccessed: number}>}
 */
const _activeMaps = new Map();

function _cleanupExpiredMaps() {
  const now = Date.now();
  for (const [key, entry] of _activeMaps) {
    // v0.6.4 G12: idle-based eviction — only drops maps that have been
    // untouched for MAP_TTL_MS, not maps that were merely created that long ago.
    if (now - entry.lastAccessed > MAP_TTL_MS) {
      _activeMaps.delete(key);
    }
  }
}

/**
 * v0.6.4 G12: retrieve a stored map AND refresh its lastAccessed timestamp.
 * Single helper so every reuse site (sync stream, async stream, future
 * callers) goes through one path.
 */
function _getActiveMap(key) {
  const entry = _activeMaps.get(key);
  if (!entry) return undefined;
  entry.lastAccessed = Date.now();
  return entry.tokenMap;
}

/** @type {WeakMap<Object, Function>} client -> original create function */
const _originalFunctions = new WeakMap();

/** @type {WeakSet<Object>} */
const _patchedClients = new WeakSet();

// v0.6.3 P0-4: warn once per process about audit failures (don't spam logs).
let _auditFailureWarnedOnce = false;

function _safeErrorTypeName(err) {
  // v0.6.3 P1-2: defensive extraction. Handles `throw "string"`, `throw 42`,
  // `throw null`, `throw undefined`. Without this guard, `err.constructor.name`
  // throws TypeError on null/undefined, which the outer audit catch swallows
  // — silently dropping the audit entry (NEW-3 regression).
  if (err === null) return 'null';
  if (err === undefined) return 'undefined';
  try {
    if (err && err.constructor && typeof err.constructor.name === 'string') {
      return err.constructor.name;
    }
  } catch (_) { /* ignore */ }
  return typeof err;
}

function _streamAuditLog(tokenMap, model, desan, startMs, streamError, shieldLocal) {
  // v0.6.3 NEW-3 / P0-2 / P0-4: write one desanitize_stream entry per stream
  // lifecycle. shieldLocal captured at wrapper start so disable()-mid-stream
  // can't cause silent gaps. Audit failure logged once via console.warn
  // (operator visibility) but never re-raised (must not break the user stream).
  if (!shieldLocal || !shieldLocal.audit) return;
  const elapsedMs = Date.now() - startMs;
  // P2-1: rename bytes_processed -> chars_processed (the field counts JS
  // string .length / UTF-16 code units, not bytes — name was misleading).
  const metadata = { chars_processed: Math.trunc(desan && desan.charsProcessed) || 0 };
  if (streamError) {
    metadata.stream_error = true;
    metadata.error_type = _safeErrorTypeName(streamError);
  }
  try {
    shieldLocal.audit.log({
      eventType: 'desanitize_stream',
      entityCount: tokenMap ? tokenMap.entityCount : 0,
      categories: tokenMap ? { ...tokenMap.categories } : {},
      tokensUsed: tokenMap ? Array.from(tokenMap.reverse.keys()) : [],
      latencyMs: elapsedMs,
      mode: tokenMap ? tokenMap.mode : null,
      entityDetails: tokenMap ? tokenMap.entityDetails : [],
      model: model,
      metadata: metadata,
    });
  } catch (e) {
    if (!_auditFailureWarnedOnce) {
      _auditFailureWarnedOnce = true;
      // eslint-disable-next-line no-console
      console.warn(
        '[CloakLLM] audit log write failed in stream wrapper: ' +
        _safeErrorTypeName(e) +
        '. All subsequent failures of this kind will be silenced. ' +
        'Investigate disk space, permissions, or audit chain integrity.'
      );
    }
  }
}

// v0.6.3 P0-2: extracted from inside enable() so it can be a clean module-level
// function. Takes pre-popped tokenMap + pre-captured shieldLocal — no module
// globals consulted during stream lifecycle.
async function* _incrementalDesanitize(stream, model, tokenMap, shieldLocal) {
  // v0.6.3 P2-3: even when no PII, write a desanitize_stream entry — strict
  // Article 12 "every interaction logged".
  if (!tokenMap || tokenMap.entityCount === 0) {
    const startMs = Date.now();
    let streamError = null;
    try {
      yield* stream;
    } catch (err) {
      streamError = err;
      throw err;
    } finally {
      _streamAuditLog(tokenMap, model, { charsProcessed: 0 }, startMs, streamError, shieldLocal);
    }
    return;
  }

  // v0.6.3 NEW-3.e: per-stream input cap
  const maxIn = (shieldLocal && shieldLocal.config && shieldLocal.config.maxInputLength) || 0;
  const desan = new StreamDesanitizer(tokenMap, { maxInputLength: maxIn });
  const startMs = Date.now();
  let streamError = null;

  try {
    try {
      for await (const chunk of stream) {
        const delta = chunk.choices?.[0]?.delta;
        const finishReason = chunk.choices?.[0]?.finish_reason;
        let yielded = false;

        if (delta?.content) {
          const output = desan.feed(delta.content);
          if (output) {
            // v0.6.3 P1-1: preserve finish_reason on the desanitized chunk.
            yield {
              ...chunk,
              choices: [{
                ...chunk.choices[0],
                delta: { ...chunk.choices[0].delta, content: output },
              }],
            };
            yielded = true;
          } else if (finishReason) {
            // v0.6.3 P1-1: content was buffered (mid-token boundary) AND
            // chunk has finish_reason. Without this branch, finish_reason
            // never reaches the consumer — they may hang waiting for stop.
            // Emit a finish-only chunk preserving finish_reason; flush below.
            yield {
              ...chunk,
              choices: [{ ...chunk.choices[0], delta: {} }],
            };
            yielded = true;
          }
        } else {
          yield chunk;
          yielded = true;
        }

        if (finishReason) {
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
          if (yielded) return;  // P1-1: terminate after finish; mirrors Python
        }
      }

      // Stream ended without finish_reason — flush remainder
      const flushed = desan.flush();
      if (flushed) {
        yield { choices: [{ delta: { content: flushed } }] };
      }
    } catch (err) {
      streamError = err;
      desan.flush();
      throw err;
    }
  } finally {
    _streamAuditLog(tokenMap, model, desan, startMs, streamError, shieldLocal);
  }
}

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
  // v0.6.4 G12: store lastAccessed (refreshed via _getActiveMap on retrieval).
  _activeMaps.set(callKey, { tokenMap, lastAccessed: Date.now() });

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

        // v0.6.3 P0-2: pop token_map AND capture _shield reference SYNCHRONOUSLY
        // before returning the lazy stream wrapper. Otherwise a concurrent
        // disable() between this point and the consumer's first iteration
        // would clear _activeMaps AND null _shield — re-opening the Article 12
        // gap NEW-3 was supposed to close.
        const streamEntry = _activeMaps.get(callKey);
        _activeMaps.delete(callKey);
        const streamTokenMap = streamEntry?.tokenMap;
        const streamShield = _shield;  // capture before potential disable()
        callKey = ''; // consumed
        return _incrementalDesanitize(response, model, streamTokenMap, streamShield);
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
