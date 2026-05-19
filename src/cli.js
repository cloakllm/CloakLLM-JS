#!/usr/bin/env node

/**
 * CloakLLM CLI.
 *
 * Usage:
 *   cloakllm scan "Send email to john@acme.com, SSN 123-45-6789"
 *   cloakllm verify ./cloakllm_audit/
 *   cloakllm stats ./cloakllm_audit/
 */

const { Shield } = require('./shield');
const { ShieldConfig } = require('./config');
const { AuditLogger } = require('./audit');

const args = process.argv.slice(2);
const showPii = args.includes('--show-pii');
const contextRisk = args.includes('--context-risk');
const filteredArgs = args.filter(a => a !== '--show-pii' && a !== '--context-risk');
const command = filteredArgs[0];

function cmdScan() {
  const text = filteredArgs.slice(1).join(' ');
  if (!text) {
    console.error('Usage: cloakllm scan "text to scan" [--show-pii]');
    process.exit(1);
  }

  const config = new ShieldConfig({ auditEnabled: false });
  const shield = new Shield(config);

  const analysis = shield.analyze(text, { redactValues: !showPii });

  if (analysis.entity_count === 0) {
    console.log('[OK] No sensitive entities detected.');
    return;
  }

  console.log(`[WARN]  Found ${analysis.entity_count} sensitive entities:\n`);

  for (const ent of analysis.entities) {
    console.log(`  [${ent.category}] "${ent.text}"`);
    console.log(`    Position: ${ent.start}-${ent.end} | Confidence: ${Math.round(ent.confidence * 100)}% | Source: ${ent.source}`);
  }

  const [sanitized, tokenMap] = shield.sanitize(text);
  console.log(`\n${'-'.repeat(60)}`);
  console.log(`ORIGINAL:  ${showPii ? text : '***'}`);
  console.log(`SANITIZED: ${sanitized}`);
  console.log(`${'-'.repeat(60)}`);
  console.log(`\nToken map (${tokenMap.entityCount} entities):`);
  for (const [token, original] of tokenMap.reverse) {
    console.log(`  ${token} -> "${showPii ? original : '***'}"`);
  }

  // Context risk analysis (opt-in)
  if (contextRisk) {
    const risk = shield.analyzeContextRisk(sanitized);
    console.log(`\n${'-'.repeat(60)}`);
    console.log(`CONTEXT RISK: ${risk.risk_level.toUpperCase()} (score: ${risk.risk_score.toFixed(3)})`);
    console.log(`  Token density: ${risk.token_density.toFixed(3)}`);
    console.log(`  Identifying descriptors: ${risk.identifying_descriptors}`);
    console.log(`  Relationship edges: ${risk.relationship_edges}`);
    if (risk.warnings.length > 0) {
      console.log('  Warnings:');
      for (const w of risk.warnings) {
        console.log(`    * ${w}`);
      }
    }
  }
}

function warnIfOutsideCwd(dirPath) {
  const path = require('path');
  const resolved = path.resolve(dirPath);
  const cwd = process.cwd();
  if (!resolved.startsWith(cwd + path.sep) && resolved !== cwd) {
    console.warn(`Warning: Log directory '${resolved}' is outside the current working directory.`);
  }
}

function cmdVerify() {
  const logDir = filteredArgs[1];
  if (!logDir) {
    console.error('Usage: cloakllm verify <log_dir>');
    process.exit(1);
  }

  warnIfOutsideCwd(logDir);

  const fs = require('fs');
  if (!fs.existsSync(logDir)) {
    console.error(`[FAIL] Log directory not found: ${logDir}`);
    process.exit(1);
  }

  const config = new ShieldConfig({ logDir });
  const logger = new AuditLogger(config);

  console.log(`Verifying audit chain in ${logDir}...`);
  const { valid, errors } = logger.verifyChain();

  if (valid) {
    console.log('[OK] Audit chain integrity verified -- no tampering detected.');
  } else {
    console.error(`[FAIL] CHAIN INTEGRITY FAILURE -- ${errors.length} error(s):\n`);
    for (const err of errors) {
      console.error(`  * ${err}`);
    }
    process.exit(1);
  }
}

function cmdStats() {
  const logDir = filteredArgs[1];
  if (!logDir) {
    console.error('Usage: cloakllm stats <log_dir>');
    process.exit(1);
  }

  warnIfOutsideCwd(logDir);

  const config = new ShieldConfig({ logDir });
  const logger = new AuditLogger(config);
  console.log(JSON.stringify(logger.getStats(), null, 2));
}

switch (command) {
  case 'scan':
    cmdScan();
    break;
  case 'verify':
    cmdVerify();
    break;
  case 'stats':
    cmdStats();
    break;
  default:
    console.log('CloakLLM -- AI Compliance Middleware CLI\n');
    console.log('Commands:');
    console.log('  scan <text>      Scan text for sensitive data');
    console.log('  verify <dir>     Verify audit log integrity');
    console.log('  stats <dir>      Show audit statistics');
    console.log('');
    console.log('Flags:');
    console.log('  --show-pii       Show raw PII values (default: masked)');
    console.log('  --context-risk   Analyze sanitized output for context leakage risk');
    break;
}
