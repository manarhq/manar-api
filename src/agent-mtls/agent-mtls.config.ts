import { z } from 'zod';

/**
 * Environment schema for the agent-facing mTLS HTTPS listener (Phase 4:
 * Agent Identity & Enrollment — see docs/agent-identity.md). Kept separate
 * from `OpenBaoConfigSchema`: these are *this listener's own* TLS server
 * identity (cert/key files written by `deploy/openbao-init.mjs`) and trust
 * anchor, not OpenBao API connection details.
 *
 * Read directly via `validate()` in `src/main.ts` *before* `NestFactory`
 * bootstraps the second (mTLS) application — Fastify/Node's `https` server
 * options (cert/key/ca/requestCert) must be resolved synchronously at
 * `FastifyAdapter` construction time, before Nest's DI container (and
 * therefore `ConfigService`) exists yet. This is the same class of
 * bootstrap-time constraint `EnvSecretProvider`'s doc comment describes for
 * reading `process.env` outside the config module — unavoidable here for
 * the same reason.
 */
export const AgentMtlsConfigSchema = z.object({
  /** Port the agent-facing `/agent/v1/*` mTLS HTTPS listener binds. Distinct from PORT (the human-facing HTTP listener). */
  AGENT_MTLS_PORT: z.coerce.number().int().min(1).max(65535).default(3443),

  /** PEM file: this listener's own TLS server certificate (+ issuing chain), issued by OpenBao's `manar-server` role. */
  AGENT_MTLS_SERVER_CERT_PATH: z
    .string()
    .min(1)
    .default('deploy/openbao/server-cert.pem'),

  /** PEM file: the private key for AGENT_MTLS_SERVER_CERT_PATH. */
  AGENT_MTLS_SERVER_KEY_PATH: z
    .string()
    .min(1)
    .default('deploy/openbao/server-key.pem'),

  /**
   * PEM file: the CA(s) this listener trusts to have signed an agent's
   * client certificate. Node's TLS layer rejects the handshake outright
   * for a client cert that doesn't chain to this trust anchor, before
   * `AgentMtlsGuard` (defense in depth beyond that) ever runs.
   *
   * Deliberately the FULL chain (intermediate + root — `ca-chain.pem`,
   * see `deploy/openbao-init.mjs`), not the intermediate alone: Node's
   * `tls`/`https` `ca` option does not treat a listed certificate as an
   * implicit trust anchor the way OpenSSL's CLI `-partial_chain` flag
   * does — verifying a leaf issued by the intermediate requires the
   * intermediate's *own* issuer (the root) to also be present, or every
   * client certificate fails closed with `UNABLE_TO_GET_ISSUER_CERT`
   * (confirmed against a bare `https.createServer`, independent of
   * Fastify/Nest, while diagnosing this exact failure mode).
   */
  AGENT_MTLS_CLIENT_CA_PATH: z
    .string()
    .min(1)
    .default('deploy/openbao/ca-chain.pem'),
});

export type AgentMtlsConfig = z.infer<typeof AgentMtlsConfigSchema>;
