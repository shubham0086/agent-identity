# agent-identity

> An autonomous agent that holds a credential is a privileged actor that can be *talked into*
> misusing it. Capability scoping says which tools a *role* may call. Identity says **who this agent
> is, what short-lived credential it carries right now, and how to audit and revoke it.**

> For project walkthroughs, architecture diagrams, and system context, visit the live portfolio: [my-portfolio-github-io-beta-five.vercel.app](https://my-portfolio-github-io-beta-five.vercel.app)

A zero-dependency broker that issues scoped, short-lived, signed credentials to agents and authorizes
their actions against those scopes — with an append-only audit log and instant revocation. The
defense against the confused-deputy / token-theft attack class: a hijacked token is bound to one
agent and a minimal scope, expires in minutes, and can be revoked, so the blast radius is small and
observable instead of "acting as you".

## The problem

Give an agent an OAuth token (GitHub, Slack, a database) and one prompt-injection later the agent —
or the attacker driving it — is acting *as you*, with every scope that token carries, and you have no
record of it and no kill switch. Capability scoping ("the Coder role may write files") helps, but it
doesn't answer *which* agent instance acted, *when its authority expires*, or *how to cut it off mid-run*.

## What it does

```
issue(agentId, role, scopes, ttl)  →  signed token   (HMAC-SHA256, expires in minutes)
authorize(token, action)           →  allow / deny    (scope-checked, every call audited)
revoke(jti)                        →  instant kill    (subsequent authorize fails)
getAudit()                         →  full decision log
```

| Property | How |
|----------|-----|
| **Identity** | Each credential carries a verifiable `agentId` + `role` + unique `jti`. |
| **Least privilege** | Scopes are explicit (`web.fetch`, `fs.read`) or prefix-wildcard (`fs.*`); anything else is denied. |
| **Short-lived** | Credentials expire (default 5 min), so a stolen one is worthless fast. |
| **Tamper-evident** | HMAC-signed; any edit flips the signature. Constant-time comparison. |
| **Revocable** | Revoke by `jti` for an instant kill switch. |
| **Auditable** | Every issue / allow / deny / revoke lands in an append-only log. |

## Quick start

```bash
npm install      # no dependencies — just sets up the package
npm run demo     # watch issue → authorize → expiry → revoke + the audit trail
npm test         # unit tests
```

```js
import { AgentIdentityBroker } from './src/AgentIdentity.js';

const broker = new AgentIdentityBroker(process.env.AGENT_SIGNING_SECRET);

const token = broker.issue({
  agentId: 'agent://researcher-7f3a',
  role: 'researcher',
  scopes: ['web.fetch', 'fs.read'],   // least privilege
});

broker.authorize(token, 'web.fetch'); // { allowed: true,  reason: 'IN_SCOPE' }
broker.authorize(token, 'fs.write');  // { allowed: false, reason: 'OUT_OF_SCOPE' }
```

## Lessons learned

- **Identity is the half of authz that capability scoping leaves out.** Scopes say what a role may do;
  identity says who did it, until when, and how to stop them. You need both.
- **Short TTL is a security control, not a UX detail.** The cheapest mitigation for a stolen credential
  is one that expires before the attacker can use it twice.
- **The audit log is the point.** For an unattended agent, "what did it decide and why" is the forensic
  trail you'll wish you had after the incident, so it's built in from line one — not bolted on.

## Where this sits

In 2026 agent identity became its own product category (governed agent identities, scoped credentials,
audit). This is the minimal, readable, self-hostable core of that idea — the layer that sits between an
agent and the [MCP gateway](https://github.com/shubham0086/mcp-agent-toolkit) that fronts its tools.

## Related

- [agent-routing](https://github.com/shubham0086/agent-routing) — the provider layer this protects
- [mcp-agent-toolkit](https://github.com/shubham0086/mcp-agent-toolkit) — tools this scopes access to
- Handbook: [The Machine OS / SECURITY](https://github.com/shubham0086/the-machine-os/tree/master/SECURITY)
