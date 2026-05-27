/**
 * v0.7.1 C7.1-1: minimal ULID generator (no runtime dep).
 *
 * Mirror of cloakllm-py/cloakllm/_ulid.py. ULID = Universally Unique
 * Lexicographically Sortable Identifier. 26-char Crockford-base32 string,
 * timestamp-prefixed so lexicographic sort yields chronological order.
 *
 * See the Python module docstring for the rationale (ULID vs UUID4 vs UUID7).
 */

'use strict';

const crypto = require('crypto');

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ULID_LENGTH = 26;

/**
 * Generate a fresh ULID -- 26-char Crockford-base32 string.
 *
 * First 10 chars: 48-bit millisecond timestamp.
 * Last 16 chars:  80-bit CSPRNG randomness.
 *
 * Not monotonic within a single millisecond -- two ULIDs in the same ms
 * sort by their random suffix, not by call order. Acceptable for the
 * decision_id use case.
 *
 * @returns {string} 26-character ULID
 */
function generateUlid() {
  const ts = BigInt(Date.now()) & ((1n << 48n) - 1n);

  // 80 bits of randomness (10 bytes)
  const randBytes = crypto.randomBytes(10);
  let randPart = 0n;
  for (let i = 0; i < 10; i++) {
    randPart = (randPart << 8n) | BigInt(randBytes[i]);
  }

  const full = (ts << 80n) | randPart;

  const chars = [];
  for (let i = ULID_LENGTH - 1; i >= 0; i--) {
    chars.push(CROCKFORD[Number((full >> BigInt(i * 5)) & 0x1Fn)]);
  }
  return chars.join('');
}

/**
 * Validate a decision_id candidate.
 *
 * Loose by design -- callers may supply existing IDs from upstream systems
 * (UUID, integer keys, opaque tokens). Acceptance:
 *   - non-empty string
 *   - length 1..64
 *   - no NUL bytes, no control characters
 *   - ASCII-printable (rejects bidi-formatting + display-spoofing)
 *
 * @param {string} value
 * @returns {boolean}
 */
function isValidDecisionId(value) {
  if (typeof value !== 'string') return false;
  if (value.length < 1 || value.length > 64) return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c > 0x7E) return false;
  }
  return true;
}

module.exports = { generateUlid, isValidDecisionId, ULID_LENGTH };
