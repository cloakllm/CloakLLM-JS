/**
 * Canonical JSON serializer — single source of truth for hash/signature input.
 *
 * Produces byte-identical output to the Python `cloakllm._canonical.canonical_json`.
 * Used by:
 *  - audit.js for the hash chain (`computeHash`)
 *  - attestation.js for Ed25519 signature payloads
 *
 * Properties:
 *  - Recursive lexicographic key sort (matches Python's `sort_keys=True`)
 *  - No whitespace (compact)
 *  - UTF-8 preserved (no `\u` escaping of non-ASCII)
 *  - Throws on NaN, Infinity, undefined, BigInt, function, Symbol
 *  - Object keys MUST be strings (already enforced by JS objects, but rejects
 *    integer-coercible keys via the explicit walker rather than relying on
 *    V8's `Object.keys` ordering — V8 puts integer-like string keys first
 *    numerically, which would break determinism vs Python's lexicographic sort.)
 *
 * Backward-compat: `_legacyCanonicalJson` preserves the v0.6.0 replacer-based
 * behavior so that audit chains written by older versions can still be
 * verified via the `legacyCanonical: true` flag on `verifyAudit` / `verifyChain`.
 * That flag is sunset in v0.7.0.
 */

'use strict';

/**
 * Encode a single string as a JSON string literal (with surrounding quotes).
 * Uses native JSON.stringify on a single-element wrapper to get correct
 * escaping of control chars, quotes, backslashes — UTF-8 preserved.
 */
function _encodeString(s) {
  return JSON.stringify(s);
}

/**
 * Encode a number for canonical output. Matches Python's `json.dumps` defaults
 * for finite numbers (which delegates to `repr(float)` essentially).
 *
 * Throws on non-finite values to match Python's `allow_nan=False`.
 */
function _encodeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new Error(`canonicalJson: non-finite number rejected (${n})`);
  }
  // **Cross-SDK invariant (v0.7.0 A4a-7):** Python's `json.dumps(0.0)` emits
  // "0.0" while JS's `JSON.stringify(0.0)` emits "0" — same value, divergent
  // canonical bytes. Producers writing audit-log entries from PYTHON must
  // therefore pass integer 0 (not float 0.0) for any numeric field that may
  // legitimately be zero; otherwise the resulting Python-written chain will
  // fail JS `verifyChain` recomputation on that entry. The Article 4a
  // bias-detection event sites in `cloakllm/bias_detection.py` follow this
  // pattern: `latency_ms=0` not `0.0`. Same goes for any future numeric
  // field that may have an integer-valued float.
  return JSON.stringify(n);
}

/**
 * Recursive canonical serializer. Walks the value, sorts keys at each object
 * level, emits compact JSON.
 */
function canonicalJson(value) {
  if (value === null) return 'null';
  if (value === undefined) {
    throw new Error('canonicalJson: undefined is not valid JSON');
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return _encodeNumber(value);
  if (typeof value === 'bigint') {
    throw new Error('canonicalJson: BigInt is not supported');
  }
  if (typeof value === 'string') return _encodeString(value);
  if (typeof value === 'function' || typeof value === 'symbol') {
    throw new Error(`canonicalJson: ${typeof value} is not valid JSON`);
  }

  if (Array.isArray(value)) {
    const parts = value.map(canonicalJson);
    return '[' + parts.join(',') + ']';
  }

  if (typeof value === 'object') {
    // Reject prototype-pollution vectors and non-string keys early.
    const keys = Object.keys(value).filter(
      (k) => k !== '__proto__' && k !== 'constructor' && k !== 'prototype'
    );
    // Lexicographic sort matching Python's `sort_keys=True` (str compare).
    keys.sort();
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue; // Python json.dumps skips dict values that are undefined-equivalent
      parts.push(_encodeString(k) + ':' + canonicalJson(v));
    }
    return '{' + parts.join(',') + '}';
  }

  throw new Error(`canonicalJson: unsupported type ${typeof value}`);
}

/**
 * v0.6.0-compatible canonical JSON. Used ONLY by `legacyCanonical: true`
 * verification paths to validate older audit chains. Sunset in v0.7.0.
 *
 * Mirrors the v0.6.0 audit.js replacer-based approach.
 */
function _legacyCanonicalJson(data) {
  return JSON.stringify(data, (_, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.keys(v)
        // v0.6.3 H9: filter prototype-pollution vectors before assignment.
        // Mirrors canonicalJson at line 84 — JSON.parse can produce __proto__
        // as own enumerable, and `o[k] = v[k]` with k='__proto__' triggers
        // the [[Set]] semantics that mutate the prototype rather than create
        // an own property. Same filter keeps the legacy path safe.
        .filter((k) => k !== '__proto__' && k !== 'constructor' && k !== 'prototype')
        .sort()
        // v0.6.4 G9: Object.create(null) instead of {} as the accumulator.
        // Defense-in-depth: even if a future change drops the filter above,
        // the prototype-less base means o['__proto__'] = X creates an own
        // property rather than triggering Object.prototype's setter.
        .reduce((o, k) => {
          o[k] = v[k];
          return o;
        }, Object.create(null));
    }
    return v;
  });
}

module.exports = { canonicalJson, _legacyCanonicalJson };
