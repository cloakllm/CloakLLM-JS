/**
 * CloakLLM Detection Backends.
 *
 * Pluggable detection backends for the CloakLLM detection pipeline.
 *
 * Usage:
 *   const { DetectorBackend, RegexBackend, NerBackend, LlmBackend } = require('cloakllm');
 */

const { DetectorBackend } = require('./base');
const { RegexBackend } = require('./regex');
const { NerBackend } = require('./ner');
const { LlmBackend } = require('./llm');

module.exports = {
  DetectorBackend,
  RegexBackend,
  NerBackend,
  LlmBackend,
};
