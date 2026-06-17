# Setup

## Requirements
- Node.js >= 18 (uses built-in `node:crypto`, `crypto.randomUUID`, `base64url`)

## Install & run
```bash
npm install        # no runtime dependencies
npm test           # run the unit suite
npm run demo       # issue → authorize → expiry → revoke, with audit trail
```

## Configuration
The broker takes a signing secret. In the demo it's hard-coded; in real use, pass one from the
environment (and rotate it):

```bash
cp .env.example .env
# set AGENT_SIGNING_SECRET to a long random string
```

```js
const broker = new AgentIdentityBroker(process.env.AGENT_SIGNING_SECRET);
```

In production the secret should live in a KMS / secrets manager, not an env file, and be rotated on a
schedule. Treat credential TTL as a security control: shorter is safer.
