/**
 * Incremental Streaming Desanitizer.
 *
 * State machine that replaces tokens in streamed text without buffering
 * the entire response. Emits text as soon as it's safe to do so.
 */

const MAX_TOKEN_LEN = 40;

class StreamDesanitizer {
    /**
     * Create a new StreamDesanitizer.
     * @param {import('./tokenizer').TokenMap} tokenMap
     */
    constructor(tokenMap) {
        this._buffer = '';
        /** @type {Map<string, string>} lowercase token -> original value */
        this._reverseCI = new Map();
        for (const [token, original] of tokenMap.reverse) {
            this._reverseCI.set(token.toLowerCase(), original);
        }
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
                const original = this._reverseCI.get(candidate.toLowerCase());

                if (original !== undefined) {
                    parts.push(original);
                } else {
                    parts.push(candidate);
                }
                this._buffer = this._buffer.slice(closePos + 1);
            }
        }

        return parts.join('');
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
        return remaining;
    }
}

module.exports = { StreamDesanitizer };
