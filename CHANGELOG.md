# Changelog

All notable changes to CloakLLM (JavaScript) will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-05-19

**Headline: EU AI Act Article 4a Bias Detection Workflow.**

Mirror of cloakllm-py 0.7.0. Article 4a (May 7 2026 Digital Omnibus) permits processing GDPR Article 9 special-category data for bias detection / correction in AI systems under six safeguards; `BiasDetectionSession` operationalises all six.

### Added

- **`BiasDetectionSession`** (require: `purpose`, `necessityJustification` ≤ 2000 chars, `categoriesAllowed` subset of `SPECIAL_CATEGORY_CATEGORIES`, `maxLifetimeSeconds` 1..604800). No language-level `with` block in JS — use the static `BiasDetectionSession.run({...}, async (session) => {...})` helper which guarantees `.end()` runs on success or throw, or `.start()` / `.end()` explicitly inside try/finally.
- **8 new special-category PII categories** in `SPECIAL_CATEGORY_CATEGORIES` and `BUILTIN_CATEGORIES`: `RACE`, `ETHNICITY`, `RELIGION`, `POLITICAL_OPINION`, `HEALTH_BIOMETRIC`, `SEXUAL_ORIENTATION`, `TRADE_UNION`, `GENETIC`. Not auto-detected — introduced only via `session.pseudonymise(text, { forceCategories: [[start, end, category], ...] })`.
- **4 new audit event types** in the hash chain: `bias_session_start`, `bias_pseudonymise`, `bias_finding`, `bias_session_end`. Strict-validated `bias_context` field on each (per-key allow-list, per-key length caps, PII-forbidden-key list). When `complianceMode: 'eu_ai_act_article12'` is set, `EU_AI_Act_Art_4a` is appended to `article_ref`.
- **Typed exceptions**: `BiasDetectionError`, `BiasDetectionScopeError`, `BiasDetectionTimeoutError`, `BiasDetectionStateError`. All extend `Error`.
- **Full TypeScript declarations** for the new API in `src/index.d.ts`.
- **Cross-SDK fixture `audit_chain_bias_js.jsonl`** + I7 test that the chain Python writes verifies under JS `verifyChain` and vice versa.

### Notes

- `canonicalJson` documents the cross-SDK numeric invariant: Python's `json.dumps(0.0)` → `"0.0"`, JS's `JSON.stringify(0.0)` → `"0"`. New Python audit-log call sites must pass int 0 for zero-valued numeric fields. JS handles this automatically.

### Test suite growth

488 → 536 tests (added bias-detection suite + cross-SDK bias-chain verification).

## [0.6.5] - 2026-04-24

Drop-in safe from v0.6.4. Mirror of cloakllm-py 0.6.5 + cloakllm-mcp 0.6.5
— adds a CI install-smoke step learned from the v0.6.4.post1 FastMCP
hotfix postmortem.

### CI / supply-chain hardening

- **New pack-smoke step in `ci.yml`.** Runs `npm pack` to produce the
  publishable tarball, then installs it into a fresh directory (no
  `npm install` shortcut over the local checkout) and runs a round-trip
  sanitize/desanitize via `require('cloakllm')`. Catches broken `files`
  field, missing dist files, or package.json metadata that would only
  surface on `npm install` from the registry. Runs on Node 22 only
  (the matrix above already covers test-suite breadth across 18/20/22).

## [0.6.4] - 2026-04-20

Polish release — v0.6.4 round-up of items the v0.6.3 review pass parked.
Safe drop-in upgrade.

### Hardening

- **G8 — Timing-safe hash comparison in `verifyChain`.** `storedHash !== recomputed`
  short-circuits character-by-character; replaced with
  `crypto.timingSafeEqual` (with length pre-check, since the API throws
  on length mismatch). Defense-in-depth on `verifyChain` timing channel.

### Correctness

- **G9 — `Object.create(null)` accumulator in `_legacyCanonicalJson`.** The
  filter at line 115 already strips `__proto__`/`constructor`/`prototype`
  before any assignment, so functional behaviour is unchanged. `Object.create(null)`
  is the maximally strict accumulator — even if a future change drops
  the filter, the prototype-less base means `o['__proto__'] = X` creates
  an own property rather than triggering `Object.prototype`'s setter.

### Ergonomics

- **G10 — JSDoc for `verifyChain.legacyCanonical`.** Documents the v0.6.0
  Python-vs-JS canonicalizer asymmetry (Python escaped non-ASCII as
  `\uXXXX`; JS preserved UTF-8) and points to
  `CloakLLM/COMPLIANCE.md` § Cross-Language Compatibility for the
  per-SDK flag table. Same content was already in `Shield.verifyAudit`'s
  JSDoc; the lower-level `AuditLogger.verifyChain` was missed.
- **G12 — JS middleware idle TTL.** `_activeMaps` now stores `lastAccessed`
  (refreshed on retrieval via `_getActiveMap`) instead of `created`.
  Aligns with the MCP server's idle-refresh pattern. The current
  middleware's single-use-per-call semantics make this defense-in-depth
  rather than bug-fix, but it removes a future footgun and clarifies
  the eviction semantic ("untouched for 5 min" vs "5 min since first
  request").

### TypeScript types

- `auditStrictChain` and `auditStrictPaths` (added in v0.6.3 but missing
  from `index.d.ts`) declared on both `ShieldConfigOptions` (input) and
  `ShieldConfig` (runtime) shapes.
- `AuditLogger.verifyChain.options.legacyCanonical?: boolean` now
  documented in the type signature.

## [0.6.3] - 2026-04-19

JS mirror of the cloakllm-py v0.6.3 security release. See
`CloakLLM/COMPLIANCE.md` § "v0.6.3 Hardening Summary" for the full
audit-reviewer overview.

### Phase 0 — streaming audit

- **NEW-3** — OpenAI streaming wrapper writes a `desanitize_stream`
  audit entry per stream lifecycle (normal completion, errors,
  consumer-break). Mirrors Python wrappers.
- **P1-1** — `finish_reason` preserved at token boundaries (was
  swallowed when `delta.content` produced empty output).
- **P1-2** — `_safeErrorTypeName` handles `throw null`, `throw "string"`,
  primitives, etc. without crashing the streaming error handler.
- **P2-1** — `bytesProcessed` → `charsProcessed` rename (deprecated
  alias preserved with `console.warn`).

### Security — high severity

- **H2** — Ollama SSRF blocklist with numeric range arithmetic
  (avoiding the JS signed-32-bit bitwise trap that broke the obvious
  `(n & 0xffff0000) === 0xa9fe0000` pattern). RFC 6761 canonical
  loopback names trusted (`localhost`, `*.localhost`,
  `localhost.localdomain`, `ip6-localhost`). IPv4-mapped IPv6 unwrap
  for both dotted and hex forms. `192.0.0.0/24` covers Oracle Cloud
  IMDS. Known gap: `fd00:ec2::254` (AWS IPv6 IMDS in ULA range)
  deferred to v0.7.0 — Node lacks a synchronous IPv6 normalizer.
- **SEC-1** — `--max-redirs 0` on both curl call sites refuses HTTP
  3xx redirects. A malicious Ollama at a permitted IP could 301-redirect
  to cloud metadata, bypassing the H2 blocklist.
- **H3** — Desanitize `tokens_used` / `entity_details` filtered to
  present-only subset; `latency_ms` / `timing.*` bucketed to 10ms.
- **G2** — Desanitize `sanitized_hash` PII oracle closed
  (mirror of Python G2). `sanitized_hash == prompt_hash` on desanitize
  entries; restored PII never hashed.
- **H4** — Backward-scan audit chain recovery; `auditStrictChain` opt-in
  refuses silent GENESIS restart on full corruption; partial-write
  tail detection prepends `\n` on next write.
- **H5** — `logDir` and `attestationKeyPath` reject NUL bytes and
  symlinks at construction time. `auditStrictPaths` opt-in promotes
  outside-CWD warning to error.
- **SEC-3** — `Shield.exportComplianceConfig(outPath)` validates the
  runtime path through `_validatePath` (now exported from `config.js`).
  Opens with `O_NOFOLLOW` + `0o600` on POSIX; ELOOP raised as a clear
  TOCTOU error.
- **G7** — Audit dir mode `0o700`, audit log files mode `0o600` on
  POSIX. Windows path runs unchanged.
- **H9** — Prototype pollution defenses: `audit.js` metadata validators
  REJECT `__proto__`/`constructor`/`prototype` keys (was: silent
  `continue`). `customPatterns` name validation parity with
  `customLlmCategories`. `_legacyCanonicalJson` filters prototype
  keys before reduce. `Shield._accumulate` skips prototype-vector
  metric keys + uses `hasOwnProperty.call` for existence checks.

### Security — informational / observability

- **I3** — JS `verifyAudit()` JSDoc documents the v0.6.0 cross-SDK
  canonical-JSON asymmetry. Missing `legacyCanonical` JSDoc param
  added.
- **I5 / G3** — `Tokenizer.detokenize` AND `StreamDesanitizer.feed`
  fire a one-time `console.warn` per process when the LLM produces
  a case-variant of a canonical token. Shared module-level gate
  (`_caseVariantWarned`) so streaming + batched paths share the warn
  quota.
- **I6.1** — npm OIDC trusted publishing (auto-provenance) replaces
  long-lived NPM_TOKEN. Node 24 in publish workflow for npm CLI ≥ 11.5.
- **I7** — Cross-SDK round-trip fixtures (`audit_chain_js.jsonl`,
  `certificate_js.json`, mirrored `*_py.json`). Each SDK's tests
  verify the OTHER SDK's output.

### Audit-log shape changes (mostly informational)

- Desanitize entries: `entityCount` now means "tokens present in this
  call" (was: total in map). `tokensUsed` and `entityDetails` filtered
  to present-only subset. `sanitized_hash` equals `prompt_hash` (both
  hash the tokenized input). Reconstruct full map from the matching
  `sanitize` entry.

### Breaking changes

- External tools matching `sanitized_hash` against restored PII text on
  desanitize entries will no longer find matches — that capability
  WAS the G2 oracle. Switch to matching `prompt_hash` against
  tokenized text.

## [0.6.2] - 2026-04-17

### Added (hotfix release for v0.6.1 audit findings)

- **I2 — `test/test_audit_schema.js`.** The v0.6.1 plan committed to a JS mirror of the Python audit schema test (B3.5) but the JS file was never written. The `_validateAuditEntrySchema` function in `audit.js` is correct but had zero dedicated test coverage; this release adds the missing tests covering the 9-key allow-list, the legacy denylist, metadata length/depth bounds, and the always-on enforcement.

### Notes

- This is a **patch release**, not the second-tier security cleanup (deferred to v0.6.3).
- Version bumped to `0.6.2` (not `0.6.1.1`) because npm semver does not support 4-digit versions and we maintain version parity across all SDKs.

## [0.6.1] - 2026-04-16

### Security (blocker fixes from internal audit)

- **B1 — Cross-language canonical JSON.** Replaces the v0.6.0 replacer-based `JSON.stringify` with a hand-rolled canonical serializer (`src/_canonical.js::canonicalJson`) that produces byte-identical output to the Python SDK, including for non-ASCII keys/values, numeric-string keys, nested arrays, and prototype-pollution vectors (`__proto__` / `constructor` / `prototype` keys are skipped). Cross-SDK certificate / audit-chain verification now works for non-ASCII data.
- **B3 — Always-on allow-list audit schema validator.** Replaces v0.6.0's compliance-mode-gated denylist. Every audit write enforces:
  - top-level keys must be in the allow-list;
  - `entity_details` elements may only contain the 9 verified-allowed keys (`category, start, end, length, confidence, source, token, entity_hash, text_index`);
  - `metadata` values must be strict-typed and bounded (256-char value cap, depth 3, scalar/list/dict only).
- **B4 — MCP defaults to compliance mode** (Python `cloakllm-mcp` change; documented for cross-SDK awareness).

### Security (high-severity fixes)

- **H1 — ReDoS hardening.** Built-in regex patterns now go through the `_testRegexSafety` harness. `PHONE` and `IBAN` rewritten to eliminate ambiguity. New `_canonical.js` is prototype-pollution-safe (H9).
- **H1.4 — Input length cap.** New `ShieldConfig({ maxInputLength: ... })` (default 1MB). Raises on oversize input.
- **F1 — API_KEY pattern bound to `{20,512}`** with body allowing `-` and `_` so multi-segment keys (Anthropic, GitHub fine-grained PAT) are detected.
- **H6 — Dependency hygiene.** `npm audit` added to CI (non-fatal until v0.7). Dependabot config added.
- **H7 — CI/CD hardening.** All workflows now have explicit `permissions:` and `concurrency:` groups.
- **F5 — `legacyCanonical` shim.** Verify v0.5.x/v0.6.0 chains with `shield.verifyAudit({ legacyCanonical: true })` or `auditLogger.verifyChain({ legacyCanonical: true })`. Sunset in v0.7.0.

### Deprecations

- **F4 — `shield.analyze()` default `redactValues: false`.** v0.7.0 flips to `true`. Calling without explicit value emits a console warning.

### Known issues

- **`llmAllowRemote: true` SSRF bypass paths (H2).** Same gaps as the Python SDK. Runtime warning fires at `LlmDetector` init. Do not use in production until v0.6.2.
- **Cross-SDK verification of v0.6.0 legacy chains containing non-ASCII data.** JS v0.6.0 preserved UTF-8 in canonical JSON while Python v0.6.0 escaped non-ASCII as `\uXXXX`. Audit chains written by JS v0.6.0 containing non-ASCII data cannot be verified by the Python SDK with `legacy_canonical=True`, and vice versa. Re-write the chain by replaying through v0.6.1+ to get fully cross-SDK verifiable entries. ASCII-only legacy chains verify correctly across both SDKs. See `CloakLLM/COMPLIANCE.md` § Cross-Language Compatibility.

## [0.6.0] - 2026-04-16

### Added

- **Article 12 Compliance Mode** — formal EU AI Act compliance profile
  - `new ShieldConfig({ complianceMode: 'eu_ai_act_article12' })` enforces compliant audit log structure
  - Audit entries gain four new fields: `compliance_version`, `article_ref`, `retention_hint_days`, `pii_in_log`
  - Compliance fields are part of the SHA-256 hash chain (tamper-detectable)
  - Configurable retention hint via `ShieldConfig({ retentionHintDays: N })` — defaults to 180
- **`shield.complianceSummary()`** — structured coverage map of EU AI Act and GDPR articles
- **`shield.exportComplianceConfig(path)`** — exports a JSON snapshot for auditors
- **`shield.verifyAudit({ outputFormat: 'compliance_report' })`** — structured report with `verdict: 'COMPLIANT' | 'NON_COMPLIANT'`
- **`AuditLogger.verifyChain({ outputFormat })`** — same compliance report shape at the lower level
- **`_assertNoPiiInEntry` runtime guard** in `audit.js` — refuses entries with forbidden PII fields in `entity_details`

### Notes

- All changes backward-compatible. Default behavior unchanged when `complianceMode` is `null`.
- `shield.verifyAudit()` without arguments returns the existing `{valid, errors, finalSeq}` shape.
- KMS-backed signing keys are Python-only in v0.6 — JS continues to use local Ed25519 keys.

## [0.5.2] - 2026-04-06

### Added

- **Pluggable Detection Backends** — `DetectorBackend` base class for custom detection pipelines
  - New `backends/` module: `DetectorBackend`, `RegexBackend`, `NerBackend`, `LlmBackend`
  - `DetectionEngine` accepts optional `backends` parameter to replace the default pipeline
  - `Shield` accepts optional `{ backends }` option, forwarded to `DetectionEngine`
  - Custom backends implement `get name()` + `detect(text, coveredSpans)` method
  - TypeScript declarations for all backend classes
  - All backend classes exported from top-level `cloakllm` package

### Changed

- `DetectionEngine` refactored from inline 3-pass detection to backend pipeline orchestrator
- Metrics timing keys are now dynamic (`{backend.name}_ms`) instead of hardcoded `regex_ms`/`ner_ms`/`llm_ms`
- Attestation `detection_passes` derived from active backends instead of config introspection
- `_emptyMetrics()` changed from static to instance method (reads backend names)
- `_accumulate()` handles dynamic timing keys from custom backends
- PATTERNS single source of truth in `detector.js` (backends/regex.js imports from there)

### Removed

- Redundant final regex safety-check sweep in pattern compilation
- Duplicated `_testRegexSafety` in `DetectionEngine` (now delegates to `RegexBackend`)
- Unused `LOCALE_PATTERNS` and `NerDetector` imports from `detector.js`

## [0.5.1] - 2026-03-31

### Added

- **Normalized Token Standard** — formal specification for CloakLLM token format
  - New `token-spec.js` module: canonical regex, category registry, validation utilities
  - `validateToken()`, `parseToken()`, `isRedactedToken()`, `validateCategoryName()`
  - `BUILTIN_CATEGORIES`, `CLOAKLLM_TOKEN_PATTERN`, `MAX_TOKEN_LENGTH` constants
  - TypeScript declarations for all new exports

### Changed

- Tokenizer and stream modules now import from `token-spec` (single source of truth)
- Config validation now rejects custom LLM categories that collide with built-in names
- Token regex updated from `[A-Z_]+` to `[A-Z][A-Z0-9_]*` (stricter, spec-conformant)
- `API_KEY` regex aligned with Python (removed underscore from character class)
- `LLM_CATEGORIES` aligned with Python: `PERSON`, `ORG`, `GPE` removed (NER-only)

## [0.5.0] - 2026-03-30

### Added

- **Context-based PII leakage analysis** — new `ContextAnalyzer` class (`context-analyzer.js`)
  - Three heuristic signals: token density, identifying descriptors, relationship edges
  - `shield.analyzeContextRisk(sanitizedText)` — standalone analysis method
  - `contextAnalysis` config flag for automatic analysis after `sanitize()`
  - `contextRiskThreshold` config option (default: 0.7)
  - Risk assessment attached to `tokenMap.riskAssessment` when auto-analysis enabled
  - Risk assessment included in audit log entries
  - CLI `--context-risk` flag for `scan` command
  - TypeScript declarations for `ContextAnalyzer`, `RiskAssessment`

## [0.4.0] - 2026-03-23

### Added

- **Multi-language PII detection** — 13 locales with locale-specific regex patterns
  - Supported locales: `de`, `fr`, `es`, `it`, `pt`, `nl`, `pl`, `se`, `no`, `dk`, `fi`, `gb`, `au`
  - Locale-specific patterns for SSN, phone, IBAN, tax IDs, national ID numbers
  - New `locale` config option in `ShieldConfig`
- **NER via compromise** — optional `compromise` npm package for PERSON, ORG, GPE detection
  - `NerDetector` class with character offset extraction
  - Input truncation at 100K chars for safety
- `analyze({ redactValues: true })` option to mask PII values in analysis output
- Replay-resistant attestation certificates with UUID4 `nonce` field
- `verifyChain()` / `verifyAudit()` now return `finalSeq` for truncation detection
- Middleware TTL eviction (5-min) for `_activeMaps` to prevent memory leaks

### Security

- **Ollama SSRF prevention** — URL validation restricts to localhost/private IPs by default (`llmAllowRemote` opt-in)
- **LLM cache PII protection** — cache keys hashed with SHA-256 instead of raw text
- **CLI PII protection** — `--show-pii` flag required to display raw PII values (redacted by default)
- **StreamDesanitizer** now unescapes fullwidth brackets on output
- **ReDoS hardening** — 5 adversarial test inputs, 20ms threshold, built-in patterns tested at construction
- **Token pattern** extended to match `[CATEGORY_REDACTED]` tokens for consistent handling
- Removed unused `logOriginalValues` config option
- Path validation warnings for `logDir` and `attestationKeyPath` outside CWD
- Windows permission warning in `DeploymentKeyPair.save()`
- Full TypeScript declarations updated for all new APIs

## [0.3.2] - 2026-03-15

### Added

- **Cryptographic attestation** — Ed25519 digital signatures for sanitization certificates
  - `DeploymentKeyPair` — generate, save, load Ed25519 signing keys (Node.js built-in crypto, zero deps)
  - `SanitizationCertificate` — signed proof that a sanitization operation occurred
  - `MerkleTree` — binary Merkle tree for batch attestation with proof generation and verification
  - `deriveEntityHashKey()` — HKDF-SHA256 key derivation
  - `shield.verifyCertificate()` — verify a certificate's signature
  - `Shield.generateAttestationKey()` — convenience static method
- Attestation config: `attestationKey`, `attestationKeyPath`, `CLOAKLLM_SIGNING_KEY_PATH` env var
- Certificate attached to `tokenMap.certificate` after `sanitize()` and `sanitizeBatch()`
- Batch certificates include Merkle roots (`tokenMap.merkleTree`)
- Audit log entries include `certificate_hash` and `key_id` fields
- Full TypeScript declarations for all attestation types
- Cross-language compatible: certificates signed in Python verify in JS and vice versa

## [0.3.1] - 2026-03-15

### Added

- Detection benchmark suite: 108-sample labeled PII corpus (`benchmarks/corpus.json`)
- Benchmark harness measuring recall/precision/F1 per detection category (`benchmarks/evaluate.js`)
- CI-integrated threshold tests: overall recall >= 95%, precision >= 80%, per-category recall >= 80%
- CLI: `node benchmarks/evaluate.js [--json]` for standalone benchmark runs

## [0.3.0] - 2026-03-15

### Added

- `StreamDesanitizer` — incremental streaming desanitization state machine (`cloakllm/stream.js`)
- TypeScript types for `StreamDesanitizer` class
- Integration tests for OpenAI middleware (n>1 choices, streaming, edge cases)

### Changed

- OpenAI middleware streaming: replaced full-buffer approach with incremental `StreamDesanitizer`
- Vercel AI SDK middleware streaming: replaced buffered TransformStream with `StreamDesanitizer`
- All middleware paths now emit desanitized text as chunks arrive instead of buffering entire response

## [0.2.5] - 2026-03-15

### Changed

- Version bump to keep all packages in sync (no code changes)

## [0.2.4] - 2026-03-15

### Fixed

- LLM detector unbounded cache — replaced plain `Map` with `BoundedCache` (LRU, maxSize=1024) to prevent memory leaks in long-running services

## [0.2.3] - 2026-03-13

### Fixed

- Vercel AI SDK middleware token map fragility — replaced `WeakMap` (breaks when params object is spread/copied) with `Symbol.for('cloakllm.tokenMap')` property that survives object spread

## [0.2.2] - 2026-03-10

### Fixed

- **[SECURITY]** Multi-choice desanitization in OpenAI middleware — `_activeMaps.delete()` on first choice caused remaining choices to skip desanitization
- `enable()` silently ignoring new config on second call — now warns to call `disable()` first
- LLM detector `_checkAvailable()` not validating HTTP status code — curl exit 0 on 404/500 caused false availability
- LLM detector hardcoded `/dev/null` — now uses `NUL` on Windows for cross-platform support
- LLM detector `.sort()` mutating cached entities array — now copies before sorting
- PHONE filter not stripping `+` from digit count — `+` now excluded from minimum length check
- `_patchedClients` Set preventing garbage collection of discarded clients — changed to WeakSet

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

[0.2.2]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.2.2
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
