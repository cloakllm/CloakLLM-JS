# Contributing to CloakLLM (JavaScript)

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/cloakllm/CloakLLM-JS.git
cd CloakLLM-JS
```

No `npm install` is needed — CloakLLM has zero runtime dependencies.

## Running Tests

```bash
node --test test/*.js
```

All 80 tests should pass. Node.js 18+ is required.

## Project Structure

```
src/
  index.js           # Public API and exports
  index.d.ts         # TypeScript type declarations
  detector.js        # PII detection engine (regex patterns)
  tokenizer.js       # Deterministic tokenizer with reversible tokens
  shield.js          # Shield engine (detection + tokenization + audit)
  audit.js           # Hash-chained tamper-evident audit logger
  config.js          # Configuration and defaults
  middleware.js       # OpenAI SDK middleware
  vercel-middleware.js # Vercel AI SDK middleware
  cli.js             # CLI entry point (scan/verify/stats)
test/
  *.js               # Test files (node:test)
examples/
  *.js               # Usage examples
```

## Making Changes

1. Fork the repo and create a feature branch from `main`.
2. Make your changes in `src/`.
3. Add or update tests in `test/` for any new behavior.
4. Run `node --test test/*.js` and ensure all tests pass.
5. Update `README.md` if you changed public API or behavior.
6. Open a pull request with a clear description of the change.

## Code Style

- Use `const`/`let`, never `var`.
- Use CommonJS (`require`/`module.exports`) for compatibility.
- Keep zero runtime dependencies — use only Node.js builtins.
- Add JSDoc comments for public functions.
- Follow existing naming conventions (camelCase for functions, UPPER_SNAKE for constants).

## Reporting Issues

Open an issue at [github.com/cloakllm/CloakLLM-JS/issues](https://github.com/cloakllm/CloakLLM-JS/issues) with:

- A clear description of the problem or suggestion.
- Steps to reproduce (if reporting a bug).
- Your Node.js version (`node --version`).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
