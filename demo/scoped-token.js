#!/usr/bin/env node
/**
 * Demo: issue a scoped, short-lived credential for an agent, then watch authorization,
 * expiry, and revocation in action — with a full audit trail at the end.
 *
 * Run: node demo/scoped-token.js
 */

import { AgentIdentityBroker } from '../src/AgentIdentity.js';

const broker = new AgentIdentityBroker('demo-secret-rotate-me', { defaultTtlMs: 1000 });

console.log('Agent Identity demo\n' + '─'.repeat(48));

// A Researcher agent gets a minimal credential: read + fetch, nothing else.
const token = broker.issue({
  agentId: 'agent://researcher-7f3a',
  role: 'researcher',
  scopes: ['web.fetch', 'fs.read'],
});
console.log('\nIssued a 1s credential for a Researcher (scopes: web.fetch, fs.read)');

// In scope — allowed.
console.log('\nResearcher tries web.fetch :', broker.authorize(token, 'web.fetch').reason);   // IN_SCOPE
console.log('Researcher tries fs.read   :', broker.authorize(token, 'fs.read').reason);       // IN_SCOPE

// Out of scope — denied. This is the line a prompt-injection would try to cross.
console.log('Researcher tries fs.write  :', broker.authorize(token, 'fs.write').reason);      // OUT_OF_SCOPE
console.log('Researcher tries shell.run :', broker.authorize(token, 'shell.run').reason);     // OUT_OF_SCOPE

// Tampering with the token breaks the signature.
const tampered = token.slice(0, -3) + 'xxx';
console.log('\nTampered token authorizes? :', broker.authorize(tampered, 'web.fetch').reason); // BAD_SIGNATURE

// Short TTL means a stolen credential is worthless in seconds.
await new Promise((r) => setTimeout(r, 1100));
console.log('After 1.1s, web.fetch      :', broker.authorize(token, 'web.fetch').reason);      // EXPIRED

// A fresh credential can be revoked the instant something looks wrong.
const t2 = broker.issue({ agentId: 'agent://coder-22b1', role: 'coder', scopes: ['fs.*'] });
const { payload } = broker.verify(t2);
console.log('\nCoder (scope fs.*) fs.write:', broker.authorize(t2, 'fs.write').reason);         // IN_SCOPE
broker.revoke(payload.jti);
console.log('After revoke, fs.write     :', broker.authorize(t2, 'fs.write').reason);           // REVOKED

console.log('\nAudit log (every decision is recorded):');
for (const e of broker.getAudit()) {
  console.log(`  ${e.decision.padEnd(7)} ${e.action ?? ''} ${e.reason ?? ''} ${e.agentId ?? e.jti ?? ''}`.trimEnd());
}
console.log('─'.repeat(48));
