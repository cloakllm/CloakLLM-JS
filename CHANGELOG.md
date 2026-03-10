# Changelog

All notable changes to CloakLLM (JavaScript) will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-03-10

### Added

- Per-entity HMAC hashing: `new ShieldConfig({ entityHashing: true, entityHashKey: "..." })` generates deterministic HMAC-SHA256 hashes per detected entity
- Hash included in `entityDetails` as `entity_hash` field
- Auto-generates random 32-byte hex key if enabled but no key provided
- TypeScript types updated: `entityHashing`, `entityHashKey` in config, `entity_hash` in `EntityDetail`
- Works with both `tokenize` and `redact` modes, and with `sanitizeBatch`
- 10 new tests for entity hashing (total: 130 tests)

## [0.2.0] - 2026-03-09

### Added

- Custom LLM detection categories: `new ShieldConfig({ customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }] })` — define domain-specific semantic PII types for Ollama-based detection
- Excluded category conflict detection with console warnings
- Category description hints injected into Ollama system prompt
- TypeScript type: `customLlmCategories` in `ShieldConfigOptions`
- New tests for custom LLM categories (total: 120 tests)

## [0.1.9] - 2026-03-08

### Added

- Per-pass timing breakdown in audit log entries: `timing` object with `total_ms`, `detection_ms`, `regex_ms`, `llm_ms`, `tokenization_ms`
- `shield.metrics()` — accumulated performance metrics (call counts, total/avg latency, per-pass detection timing, entity counts by category)
- `shield.resetMetrics()` — clear accumulated metrics
- `DetectionEngine.detect()` now returns `{ detections, timing }` with per-pass millisecond breakdowns
- TypeScript types: `Timing`, `DetectorTiming`, `Metrics`
- 9 new tests for metrics and timing (total: 81 tests)

## [0.1.8] - 2026-03-07

### Added

- Batch processing API: `shield.sanitizeBatch(texts)` / `shield.desanitizeBatch(texts, tokenMap)` — shared token map, single audit entry
- `BatchEntityDetail` TypeScript interface (extends `EntityDetail` with `text_index`)
- `sanitizeBatch` / `desanitizeBatch` type declarations
- 9 new tests for batch operations (total: 72 tests)

## [0.1.7] - 2026-03-06

### Added

- `TokenMap.entityDetails` getter — per-entity metadata (PII-safe)
- `TokenMap.toReport()` — extended summary with entity details and mode
- `entity_details` field in audit log entries (included in hash chain)
- `EntityDetail` TypeScript interface
- 7 new tests for entity details

## [0.1.6] - 2026-03-04

### Added

- Redaction mode: `new ShieldConfig({ mode: 'redact' })` for irreversible PII removal — replaces entities with `[CATEGORY_REDACTED]`
- No token map stored in redact mode — desanitize() is a no-op
- `mode` field in audit log entries
- TypeScript type support for mode option
- 8 new tests for redaction mode (total: 88 tests)

## [0.1.5] - 2026-03-04

### Changed

- Version bump to stay in sync with cloakllm 0.1.5 (Python OpenAI SDK middleware)

## [0.1.4] - 2026-03-04

### Fixed

- OpenAI SDK streaming responses are now desanitized: chunks are buffered until completion, then the full text is desanitized and yielded as a single final chunk

## [0.1.3] - 2026-03-02

### Fixed

- Custom regex patterns now take priority over built-in patterns during detection, so user-defined patterns correctly match before built-ins claim overlapping spans

## [0.1.2] - 2026-03-01

### Changed

- Chore: added `package-lock.json` to `.gitignore`

## [0.1.1] - 2026-03-01

### Added

- Local LLM detection (opt-in, via Ollama) for semantic PII: names, orgs, locations, addresses, medical info, financial data, national IDs, biometrics, usernames, passwords, vehicle info
- LLM detection config: `llmDetection`, `llmModel`, `llmOllamaUrl`, `llmTimeout`, `llmConfidence`
- TypeScript definitions for LLM detection config fields
- Vercel AI SDK middleware integration

### Fixed

- Strengthened ReDoS safety check for custom regex patterns (longer test input, stricter threshold)
- API_KEY regex now uses optional separator `[-_]?` to match Python SDK behavior

## [0.1.0] - 2026-02-27

### Added

- PII detection engine with regex patterns (emails, SSNs, credit cards, phones, IPs, API keys, AWS keys, JWTs, IBANs)
- Deterministic tokenizer with reversible `[CATEGORY_N]` tokens
- Tamper-evident hash-chained audit logger (EU AI Act Article 12 compliance)
- Shield engine tying detection, tokenization, and audit into a single interface
- OpenAI SDK middleware integration (`cloakllm.enable(client)` / `cloakllm.disable(client)`)
- Multi-turn conversation support via reusable token maps
- Custom regex pattern support via `ShieldConfig.customPatterns`
- CLI commands: `scan`, `verify`, `stats`
- Full TypeScript type declarations (`index.d.ts`)
- Zero runtime dependencies — uses only Node.js builtins
- Test suite with 50 tests covering detection, tokenization, audit chain, and end-to-end flows

[0.2.1]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.2.1
[0.2.0]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.2.0
[0.1.9]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.9
[0.1.8]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.8
[0.1.7]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.7
[0.1.6]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.6
[0.1.5]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.5
[0.1.4]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.4
[0.1.3]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.3
[0.1.2]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.2
[0.1.1]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.1
[0.1.0]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.0
