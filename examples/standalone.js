/**
 * CloakLLM Standalone Example
 *
 * Run: node examples/standalone.js
 */

const { Shield, ShieldConfig } = require('../src');

const config = new ShieldConfig({
  logDir: './example_audit',
  auditEnabled: true,
});

const shield = new Shield(config);

// --- Scan text ---
const text = `
Please process the following customer record:
  Name: Sarah Johnson
  Email: sarah.j@techcorp.io
  SSN: 123-45-6789
  Phone: +1-555-0142
  Credit Card: 4111111111111111
  Server: 192.168.1.100
`;

console.log('=== CloakLLM Standalone Example ===\n');
console.log('ORIGINAL:');
console.log(text);

// --- Sanitize ---
const [sanitized, tokenMap] = shield.sanitize(text);
console.log('SANITIZED:');
console.log(sanitized);

console.log(`\nToken map (${tokenMap.entityCount} entities):`);
for (const [token, original] of tokenMap.reverse) {
  console.log(`  ${token} → "${original}"`);
}

// --- Simulate LLM response ---
const llmResponse = `I've processed the customer record for [EMAIL_0].
Their SSN ([SSN_0]) has been verified. I'll send a confirmation to [PHONE_0].`;

console.log('\nSIMULATED LLM RESPONSE:');
console.log(llmResponse);

// --- Desanitize ---
const restored = shield.desanitize(llmResponse, tokenMap);
console.log('\nRESTORED:');
console.log(restored);

// --- Verify audit ---
const { valid, errors } = shield.verifyAudit();
console.log(`\nAudit chain: ${valid ? '✅ Valid' : '❌ Broken'}`);
if (errors.length) console.log('Errors:', errors);

// --- Stats ---
console.log('\nAudit stats:', JSON.stringify(shield.auditStats(), null, 2));
