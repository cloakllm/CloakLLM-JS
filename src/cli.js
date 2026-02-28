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
const command = args[0];

function cmdScan() {
  const text = args.slice(1).join(' ');
  if (!text) {
    console.error('Usage: cloakllm scan "text to scan"');
    process.exit(1);
  }

  const config = new ShieldConfig({ auditEnabled: false });
  const shield = new Shield(config);

  const analysis = shield.analyze(text);

  if (analysis.entity_count === 0) {
    console.log('✅ No sensitive entities detected.');
    return;
  }

  console.log(`⚠️  Found ${analysis.entity_count} sensitive entities:\n`);

  for (const ent of analysis.entities) {
    console.log(`  [${ent.category}] "${ent.text}"`);
    console.log(`    Position: ${ent.start}-${ent.end} | Confidence: ${Math.round(ent.confidence * 100)}% | Source: ${ent.source}`);
  }

  const [sanitized, tokenMap] = shield.sanitize(text);
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`ORIGINAL:  ${text}`);
  console.log(`SANITIZED: ${sanitized}`);
  console.log(`${'─'.repeat(60)}`);
  console.log(`\nToken map (${tokenMap.entityCount} entities):`);
  for (const [token, original] of tokenMap.reverse) {
    console.log(`  ${token} → "${original}"`);
  }
}

function cmdVerify() {
  const logDir = args[1];
  if (!logDir) {
    console.error('Usage: cloakllm verify <log_dir>');
    process.exit(1);
  }

  const fs = require('fs');
  if (!fs.existsSync(logDir)) {
    console.error(`❌ Log directory not found: ${logDir}`);
    process.exit(1);
  }

  const config = new ShieldConfig({ logDir });
  const logger = new AuditLogger(config);

  console.log(`Verifying audit chain in ${logDir}...`);
  const { valid, errors } = logger.verifyChain();

  if (valid) {
    console.log('✅ Audit chain integrity verified — no tampering detected.');
  } else {
    console.error(`❌ CHAIN INTEGRITY FAILURE — ${errors.length} error(s):\n`);
    for (const err of errors) {
      console.error(`  • ${err}`);
    }
    process.exit(1);
  }
}

function cmdStats() {
  const logDir = args[1];
  if (!logDir) {
    console.error('Usage: cloakllm stats <log_dir>');
    process.exit(1);
  }

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
    console.log('CloakLLM — AI Compliance Middleware CLI\n');
    console.log('Commands:');
    console.log('  scan <text>      Scan text for sensitive data');
    console.log('  verify <dir>     Verify audit log integrity');
    console.log('  stats <dir>      Show audit statistics');
    break;
}
