/**
 * Agent Identity & Authorization.
 *
 * Capability scoping answers "which tools may this role call?". Identity answers the
 * questions that come *after* an agent can act autonomously and hold credentials:
 *   - WHO is this agent (a verifiable identity, not just a role string)?
 *   - WHAT short-lived, scoped credential is it carrying right now?
 *   - Can I AUDIT every authorization decision it made?
 *   - Can I REVOKE it the moment something looks wrong?
 *
 * This is the defense against the confused-deputy / token-theft attack class: a stolen or
 * injection-hijacked token is bound to one agent and a minimal scope, expires in minutes,
 * and can be revoked — so the blast radius is small and observable instead of "acting as you".
 *
 * Zero-dependency: signing is HMAC-SHA256 via node:crypto. The token format is a small,
 * self-contained, tamper-evident envelope (base64url payload + signature), the same shape a
 * JWT uses, kept deliberately tiny and readable.
 *
 * Pattern extracted from the per-agent capability scoping in the Sovereign SDLC engine and
 * the MCP gateway threat model.
 */

import crypto from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (str) => Buffer.from(str, 'base64url').toString('utf8');

export class AgentIdentityBroker {
  /**
   * @param {string} secret - signing secret (in production: a KMS-held key, rotated)
   * @param {object} [opts]
   * @param {number} [opts.defaultTtlMs=300000] - default credential lifetime (5 min)
   * @param {() => number} [opts.clock] - injectable clock for testing
   */
  constructor(secret, { defaultTtlMs = 5 * 60 * 1000, clock = () => Date.now() } = {}) {
    if (!secret || typeof secret !== 'string') {
      throw new Error('AgentIdentityBroker requires a signing secret');
    }
    this.secret = secret;
    this.defaultTtlMs = defaultTtlMs;
    this.clock = clock;
    this.revoked = new Set(); // revoked jti values
    this.audit = [];          // append-only authorization log
  }

  _sign(payloadB64) {
    return crypto.createHmac('sha256', this.secret).update(payloadB64).digest('base64url');
  }

  _log(decision, detail) {
    this.audit.push({ at: new Date(this.clock()).toISOString(), decision, ...detail });
  }

  /**
   * Issue a scoped, short-lived, signed credential for one agent.
   * @param {object} claims
   * @param {string} claims.agentId - the agent's stable identity
   * @param {string} claims.role - its role (researcher, coder, ...)
   * @param {string[]} claims.scopes - capability scopes, e.g. ['web.fetch','fs.read'] or ['fs.*']
   * @param {number} [claims.ttlMs] - lifetime override
   * @returns {string} the credential token
   */
  issue({ agentId, role, scopes, ttlMs }) {
    if (!agentId || !role || !Array.isArray(scopes)) {
      throw new Error('issue() requires agentId, role, and scopes[]');
    }
    const iat = this.clock();
    const payload = {
      agentId,
      role,
      scopes,
      jti: crypto.randomUUID(),
      iat,
      exp: iat + (ttlMs ?? this.defaultTtlMs),
    };
    const payloadB64 = b64url(JSON.stringify(payload));
    const token = `${payloadB64}.${this._sign(payloadB64)}`;
    this._log('issue', { agentId, role, scopes, jti: payload.jti, exp: payload.exp });
    return token;
  }

  /**
   * Verify a credential's signature, expiry, and revocation status.
   * @param {string} token
   * @returns {{ valid: boolean, payload?: object, reason?: string }}
   */
  verify(token) {
    if (typeof token !== 'string' || !token.includes('.')) {
      return { valid: false, reason: 'MALFORMED' };
    }
    const [payloadB64, sig] = token.split('.');
    const expected = this._sign(payloadB64);
    // constant-time comparison to avoid signature-timing leaks
    const sigBuf = Buffer.from(sig || '', 'utf8');
    const expBuf = Buffer.from(expected, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return { valid: false, reason: 'BAD_SIGNATURE' };
    }
    let payload;
    try {
      payload = JSON.parse(fromB64url(payloadB64));
    } catch {
      return { valid: false, reason: 'MALFORMED' };
    }
    if (this.clock() >= payload.exp) return { valid: false, reason: 'EXPIRED', payload };
    if (this.revoked.has(payload.jti)) return { valid: false, reason: 'REVOKED', payload };
    return { valid: true, payload };
  }

  /**
   * Authorize a specific action against a credential's scopes. Every call is audited.
   * Scope match is exact ('fs.read') or prefix-wildcard ('fs.*' allows 'fs.read', 'fs.write').
   * @param {string} token
   * @param {string} action - e.g. 'fs.write', 'web.fetch'
   * @returns {{ allowed: boolean, reason: string, agentId?: string }}
   */
  authorize(token, action) {
    const v = this.verify(token);
    if (!v.valid) {
      this._log('deny', { action, reason: v.reason, agentId: v.payload?.agentId });
      return { allowed: false, reason: v.reason };
    }
    const { scopes, agentId } = v.payload;
    const matched = scopes.some((s) =>
      s === action || (s.endsWith('.*') && action.startsWith(s.slice(0, -1)))
    );
    const reason = matched ? 'IN_SCOPE' : 'OUT_OF_SCOPE';
    this._log(matched ? 'allow' : 'deny', { action, reason, agentId, jti: v.payload.jti });
    return { allowed: matched, reason, agentId };
  }

  /**
   * Revoke a credential by its jti. Subsequent verify/authorize fail immediately.
   * @param {string} jti
   */
  revoke(jti) {
    this.revoked.add(jti);
    this._log('revoke', { jti });
  }

  /** @returns {Array<object>} a copy of the append-only authorization audit log */
  getAudit() {
    return [...this.audit];
  }
}
