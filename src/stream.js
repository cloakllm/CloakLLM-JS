/**
 * Incremental Streaming Desanitizer.
 *
 * State machine that replaces tokens in streamed text without buffering
 * the entire response. Emits text as soon as it's safe to do so.
 */

const {
  ESCAPED_OPEN,
  ESCAPED_CLOSE,
  MAX_TOKEN_LENGTH: MAX_TOKEN_LEN,
} = require('./token-spec');
// v0.6.3 I5/G3: shared one-shot warning gate. Streaming is the dominant
// production path; without wiring this in, streaming users get no signal
// when their LLM lowercases tokens.
const { _warnCaseMismatchOnce } = require('./tokenizer');

const UNESCAPE_RE = new RegExp(`${ESCAPED_OPEN}([A-Z][A-Z0-9_]*_(?:\\d+|REDACTED))${ESCAPED_CLOSE}`, 'g');

class StreamDesanitizer {
    /**
     * Create a new StreamDesanitizer.
     * @param {import('./tokenizer').TokenMap} tokenMap
     * @param {Object} [options]
     * @param {number} [options.maxInputLength=0] - v0.6.3 (NEW-3.e): hard cap
     *   on cumulative bytes fed via `feed()`. Default 0 = no cap (back-compat).
     *   When > 0, throws Error if cumulative bytes exceed the cap. Mirrors
     *   `Shield.maxInputLength` for streams.
     */
    constructor(tokenMap, { maxInputLength = 0 } = {}) {
        this._buffer = '';
        /** @type {Map<string, string>} lowercase token -> original value */
        this._reverseCI = new Map();
        /** v0.6.3 I5/G3: lowercase token -> CANONICAL form (the case the
         *  token was issued in during sanitize). Used by feed() to detect
         *  case-variant substitutions and fire the shared one-shot warning.
         *  @type {Map<string, string>} */
        this._canonicalByLower = new Map();
        for (const [token, original] of tokenMap.reverse) {
            const lower = token.toLowerCase();
            this._reverseCI.set(lower, original);
            this._canonicalByLower.set(lower, token);
        }
        // v0.6.3 NEW-3.e + P2-1: track cumulative chunk CHARS (not bytes —
        // String.length is UTF-16 code units, not byte count). Middleware
        // reads this for the audit entry's `chars_processed` field.
        this.charsProcessed = 0;
        this._maxInputLength = Math.max(0, Number(maxInputLength) || 0);
    }

    /**
     * @deprecated v0.6.3: use `charsProcessed`. Same value, accurate name.
     * Removed in v0.7.0.
     */
    get bytesProcessed() {
        // eslint-disable-next-line no-console
        console.warn(
            '[CloakLLM] StreamDesanitizer.bytesProcessed is deprecated since v0.6.3 — ' +
            'the field counts characters not bytes. Use `charsProcessed` instead. ' +
            'This alias will be removed in v0.7.0.'
        );
        return this.charsProcessed;
    }

    _unescape(text) {
        return text.replace(UNESCAPE_RE, (_, m) => `[${m}]`);
    }

    /**
     * Feed a chunk of text through the desanitizer.
     *
     * Returns text that is safe to emit. May return empty string
     * if the chunk is being buffered (potential token boundary).
     *
     * @param {string} chunk
     * @returns {string}
     */
    feed(chunk) {
        // v0.6.3 NEW-3.e: enforce per-stream length cap to prevent
        // unbounded-stream memory exhaustion attacks.
        const chunkLen = chunk ? chunk.length : 0;
        const newTotal = this.charsProcessed + chunkLen;
        if (this._maxInputLength > 0 && newTotal > this._maxInputLength) {
            throw new Error(
                `StreamDesanitizer: cumulative chars ${newTotal} exceeds ` +
                `maxInputLength=${this._maxInputLength}. Set ` +
                `ShieldConfig({ maxInputLength: 0 }) to disable, or raise the cap.`
            );
        }
        this.charsProcessed = newTotal;

        const parts = [];
        this._buffer += chunk;

        while (this._buffer.length > 0) {
            const bracketPos = this._buffer.indexOf('[');

            if (bracketPos === -1) {
                parts.push(this._buffer);
                this._buffer = '';
                break;
            }

            if (bracketPos > 0) {
                parts.push(this._buffer.slice(0, bracketPos));
                this._buffer = this._buffer.slice(bracketPos);
            }

            const closePos = this._buffer.indexOf(']');

            if (closePos === -1) {
                if (this._buffer.length > MAX_TOKEN_LEN) {
                    parts.push(this._buffer[0]);
                    this._buffer = this._buffer.slice(1);
                } else {
                    break;
                }
            } else {
                const candidate = this._buffer.slice(0, closePos + 1);
                const candidateLower = candidate.toLowerCase();
                const original = this._reverseCI.get(candidateLower);

                if (original !== undefined) {
                    // v0.6.3 I5/G3: detect case-variant before substituting.
                    // `candidate` is what the LLM emitted; canonical is what
                    // we issued during sanitize. If they differ, fire the
                    // one-shot warning so operators know to fix the prompt.
                    const canonical = this._canonicalByLower.get(candidateLower);
                    if (candidate !== canonical) {
                        _warnCaseMismatchOnce(candidate);
                    }
                    parts.push(original);
                } else {
                    parts.push(candidate);
                }
                this._buffer = this._buffer.slice(closePos + 1);
            }
        }

        return this._unescape(parts.join(''));
    }

    /**
     * Flush any remaining buffered text.
     *
     * Call this when the stream ends to emit any partial buffer.
     *
     * @returns {string}
     */
    flush() {
        const remaining = this._buffer;
        this._buffer = '';
        return this._unescape(remaining);
    }
}

module.exports = { StreamDesanitizer };
