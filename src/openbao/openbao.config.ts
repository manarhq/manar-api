import { z } from 'zod';

/**
 * OpenBao-related environment schema (Phase 4: Agent Identity &
 * Enrollment), kept alongside the `openbao` module rather than growing
 * `AppConfigSchema` into a god-schema — see `src/config/env.validation.ts`
 * and `src/database/database.config.ts` for the established pattern.
 *
 * OpenBao is the PKI *signing* backend only — Manar owns enrollment policy
 * (CSR subject/SAN validation, leaf-cert TTL) via
 * `CertificateAuthorityService`. `OPENBAO_TOKEN` here is a deployment-wide
 * bootstrap token (the dev root token in local/CI), analogous to
 * `KEYCLOAK_ADMIN_USERNAME`/`PASSWORD` — a production deployment would
 * scope this to a narrow OpenBao policy via AppRole/Kubernetes auth instead
 * of a static root token, which is out of scope for this phase.
 */
export const OpenBaoConfigSchema = z.object({
  /** Base URL of the OpenBao server, no trailing slash (e.g. http://localhost:8200). */
  OPENBAO_ADDR: z.string().min(1, 'OPENBAO_ADDR is required'),

  /** Bootstrap token used to call the PKI secrets engine's authenticated endpoints. Never logged. */
  OPENBAO_TOKEN: z.string().min(1, 'OPENBAO_TOKEN is required'),

  /** Mount path of the (offline, unused-for-issuance) root CA — see deploy/openbao-init.mjs. */
  OPENBAO_PKI_ROOT_PATH: z.string().min(1).default('pki'),

  /** Mount path of the online issuing intermediate CA. */
  OPENBAO_PKI_INTERMEDIATE_PATH: z.string().min(1).default('pki_int'),

  /**
   * The signing role `CertificateAuthorityService` calls via `sign-verbatim`
   * for agent leaf certificates. `sign-verbatim` always uses exactly the
   * CSR's own subject/SANs regardless of this role's name-constraint
   * settings (`allowed_domains` and friends) — Manar's own subject/SAN
   * check (run before OpenBao is ever called) is the actual security
   * boundary, not this role.
   */
  OPENBAO_PKI_AGENT_ROLE: z.string().min(1).default('manar-agent'),
});

export type OpenBaoConfig = z.infer<typeof OpenBaoConfigSchema>;
