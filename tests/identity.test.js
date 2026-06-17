#!/usr/bin/env node
/**
 * Unit tests for AgentIdentityBroker.
 * Run with: npm test
 */

import { AgentIdentityBroker } from '../src/AgentIdentity.js';

let passed = 0;
let failed = 0;
function assert(condition, message) {
  if (condition) { passed++; console.log(`  ✓ ${message}`); }
  else { failed++; console.error(`  ✗ ${message}`); }
}

console.log('Agent-Identity Test Suite\n');

// A controllable clock so expiry is deterministic.
let now = 1_000_000;
const broker = new AgentIdentityBroker('test-secret', { defaultTtlMs: 1000, clock: () => now });

console.log('Test 1: Issue + verify');
const token = broker.issue({ agentId: 'a1', role: 'researcher', scopes: ['web.fetch', 'fs.read'] });
const v = broker.verify(token);
assert(v.valid === true, 'freshly issued token verifies');
assert(v.payload.agentId === 'a1', 'identity claim is carried');
assert(typeof v.payload.jti === 'string', 'token has a unique jti');

console.log('\nTest 2: Scope enforcement');
assert(broker.authorize(token, 'web.fetch').allowed === true, 'in-scope action allowed');
assert(broker.authorize(token, 'fs.write').allowed === false, 'out-of-scope action denied');
assert(broker.authorize(token, 'fs.write').reason === 'OUT_OF_SCOPE', 'denial reason is OUT_OF_SCOPE');

console.log('\nTest 3: Wildcard scopes');
const wild = broker.issue({ agentId: 'a2', role: 'coder', scopes: ['fs.*'] });
assert(broker.authorize(wild, 'fs.write').allowed === true, 'fs.* allows fs.write');
assert(broker.authorize(wild, 'fs.read').allowed === true, 'fs.* allows fs.read');
assert(broker.authorize(wild, 'shell.run').allowed === false, 'fs.* does not allow shell.run');

console.log('\nTest 4: Tamper detection');
const tampered = token.slice(0, -2) + 'zz';
assert(broker.verify(tampered).valid === false, 'tampered token fails verification');
assert(broker.verify(tampered).reason === 'BAD_SIGNATURE', 'reason is BAD_SIGNATURE');
assert(broker.verify('garbage').valid === false, 'malformed token rejected');

console.log('\nTest 5: Expiry');
now += 2000; // advance past the 1000ms TTL
assert(broker.verify(token).valid === false, 'expired token fails verification');
assert(broker.authorize(token, 'web.fetch').reason === 'EXPIRED', 'expired authorize reason is EXPIRED');

console.log('\nTest 6: Revocation');
const live = broker.issue({ agentId: 'a3', role: 'auditor', scopes: ['fs.read'] });
assert(broker.authorize(live, 'fs.read').allowed === true, 'works before revoke');
broker.revoke(broker.verify(live).payload.jti);
assert(broker.authorize(live, 'fs.read').allowed === false, 'denied after revoke');
assert(broker.authorize(live, 'fs.read').reason === 'REVOKED', 'reason is REVOKED');

console.log('\nTest 7: Audit trail');
const audit = broker.getAudit();
assert(audit.length > 0, 'audit log records decisions');
assert(audit.some((e) => e.decision === 'allow'), 'audit captures allows');
assert(audit.some((e) => e.decision === 'deny'), 'audit captures denies');
assert(audit.some((e) => e.decision === 'revoke'), 'audit captures revocations');

console.log(`\n${'─'.repeat(40)}`);
console.log(`Tests passed: ${passed}`);
console.log(`Tests failed: ${failed}`);
console.log(`${'─'.repeat(40)}\n`);
process.exit(failed > 0 ? 1 : 0);
