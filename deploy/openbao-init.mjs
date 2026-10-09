#!/usr/bin/env node
/**
 * One-time (safe to re-run) OpenBao PKI bootstrap for local dev/CI.
 *
 * Unlike Postgres/Keycloak, `deploy/docker-compose.yml`'s `openbao` service
 * boots with no PKI configured (a fresh volume locally, a `-dev` server in
 * CI). Every step below skips what already exists, so re-running is safe. This
 * script drives OpenBao's HTTP API directly (no `vault`/`bao` CLI
 * dependency, so it runs identically in a bare `node` GitLab CI job as it
 * does locally) to:
 *
 *   1. Enable the PKI secrets engine at `pki` (root) and `pki_int`
 *      (intermediate).
 *   2. Generate a root CA (ECDSA P-256 — see docs/agent-identity.md for why
 *      this beats RSA-2048 for new workload-identity PKI).
 *   3. Generate an intermediate CA CSR, sign it with the root, and mount
 *      the signed intermediate as the online issuer. The root CA is never
 *      used for issuance after this — standard PKI practice, avoids an
 *      always-online root.
 *   4. Create `manar-agent`, the signing role `CertificateAuthorityService`
 *      calls via `sign-verbatim` for agent leaf certificates (short TTL —
 *      see LEAF_CERT_TTL below, must match
 *      `src/agents/certificate-authority.service.ts`'s constant).
 *   5. Create `manar-server` and issue a TLS server certificate/key for the
 *      API's own `/agent/v1/*` mTLS listener (see src/main.ts) — this one
 *      *is* server-generated (OpenBao holds the private key only
 *      momentarily to return it once), unlike agent identity keys, which
 *      never leave the agent process. Regenerated on every re-run.
 *
 * Writes the intermediate CA (the mTLS listener's trust anchor for
 * verifying client certs) and the server cert/key to deploy/openbao/
 * (gitignored — regenerable, and the intermediate's *private* key never
 * leaves OpenBao, only its public certificate is written here).
 *
 * Run after `pnpm infra:up`: `node deploy/openbao-init.mjs`.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BAO_ADDR = process.env.OPENBAO_ADDR ?? 'http://localhost:8200';
const BAO_TOKEN = process.env.OPENBAO_TOKEN ?? 'manar-dev-root-token';

const ROOT_PATH = 'pki';
const INTERMEDIATE_PATH = 'pki_int';
const AGENT_ROLE = 'manar-agent';
const SERVER_ROLE = 'manar-server';
// Must match OPENBAO_KV_MOUNT_PATH's default in src/openbao/openbao.config.ts.
const KV_MOUNT_PATH = process.env.OPENBAO_KV_MOUNT_PATH ?? 'secret';

const ROOT_TTL = '87600h'; // 10y — root stays offline for issuance after this script.
const INTERMEDIATE_TTL = '43800h'; // 5y — the online issuer.
// Must match AGENT_LEAF_CERTIFICATE_TTL in
// src/agents/certificate-authority.service.ts.
const LEAF_TTL = '24h';
const SERVER_CERT_TTL = '8760h'; // 1y — this dev-only TLS server cert, not an agent identity.

const outDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'openbao',
);

async function baoRequest(method, apiPath, body) {
  const response = await fetch(`${BAO_ADDR}/v1/${apiPath}`, {
    method,
    headers: {
      'X-Vault-Token': BAO_TOKEN,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(
      `OpenBao API ${method} ${apiPath} failed: HTTP ${response.status}${text ? `: ${text}` : ''}`,
    );
  }
  if (response.status === 204) return null;
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

async function ensureMount(mountPath, maxLeaseTtl) {
  const mounts = await baoRequest('GET', 'sys/mounts');
  if (mounts?.data?.[`${mountPath}/`]) {
    console.log(`==> Mount "${mountPath}/" already exists, skipping enable`);
  } else {
    console.log(`==> Enabling PKI secrets engine at "${mountPath}/"`);
    await baoRequest('POST', `sys/mounts/${mountPath}`, { type: 'pki' });
  }
  await baoRequest('POST', `sys/mounts/${mountPath}/tune`, {
    max_lease_ttl: maxLeaseTtl,
  });
}

/**
 * Phase 7b (Tool Registry, Credential Broker & Proxy Execution): the KV v2
 * mount `OpenBaoSecretProvider` reads `Tool.credentialReference` values
 * from. OpenBao's `-dev` mode already auto-mounts a `kv-v2` engine at
 * `secret/` (see deploy/docker-compose.yml's `openbao` service) — this is
 * still enabled explicitly and idempotently, exactly like `ensureMount`
 * above does for the PKI engines, rather than relying on that dev-only
 * default, since a non-dev OpenBao deployment has no such default and this
 * script is meant to describe the *whole* required bootstrap.
 */
async function ensureKvV2Mount(mountPath) {
  const mounts = await baoRequest('GET', 'sys/mounts');
  if (mounts?.data?.[`${mountPath}/`]) {
    console.log(`==> Mount "${mountPath}/" already exists, skipping enable`);
    return;
  }
  console.log(`==> Enabling KV v2 secrets engine at "${mountPath}/"`);
  await baoRequest('POST', `sys/mounts/${mountPath}`, {
    type: 'kv',
    options: { version: '2' },
  });
}

/**
 * `root/generate/internal` and `intermediate/generate/internal` are NOT
 * idempotent by themselves — calling either again silently replaces the
 * existing CA/key with a brand new one, invalidating every certificate
 * signed under the old one. Checked explicitly so re-running this script
 * against an already-initialized OpenBao is actually safe, as documented
 * at the top of this file.
 */
async function caAlreadyIssued(mountPath) {
  const response = await fetch(`${BAO_ADDR}/v1/${mountPath}/ca/pem`);
  if (!response.ok) return false;
  const text = await response.text();
  return text.includes('BEGIN CERTIFICATE');
}

async function main() {
  await mkdir(outDir, { recursive: true });

  await ensureMount(ROOT_PATH, ROOT_TTL);
  await ensureMount(INTERMEDIATE_PATH, INTERMEDIATE_TTL);
  await ensureKvV2Mount(KV_MOUNT_PATH);

  if (await caAlreadyIssued(ROOT_PATH)) {
    console.log('==> Root CA already generated, skipping');
  } else {
    console.log(
      '==> Generating root CA (ECDSA P-256, internal/non-exportable key)',
    );
    await baoRequest('POST', `${ROOT_PATH}/root/generate/internal`, {
      common_name: 'Manar Dev Root CA',
      ttl: ROOT_TTL,
      key_type: 'ec',
      key_bits: 256,
    });
  }

  await baoRequest('POST', `${ROOT_PATH}/config/urls`, {
    issuing_certificates: `${BAO_ADDR}/v1/${ROOT_PATH}/ca`,
    crl_distribution_points: `${BAO_ADDR}/v1/${ROOT_PATH}/crl`,
  });

  if (await caAlreadyIssued(INTERMEDIATE_PATH)) {
    console.log('==> Intermediate CA already generated, skipping sign/set-signed');
  } else {
    console.log('==> Generating intermediate CA CSR (ECDSA P-256)');
    const intermediateGenerate = await baoRequest(
      'POST',
      `${INTERMEDIATE_PATH}/intermediate/generate/internal`,
      {
        common_name: 'Manar Dev Intermediate CA',
        key_type: 'ec',
        key_bits: 256,
      },
    );

    console.log('==> Signing intermediate CSR with root CA');
    const signed = await baoRequest('POST', `${ROOT_PATH}/root/sign-intermediate`, {
      csr: intermediateGenerate.data.csr,
      format: 'pem_bundle',
      ttl: INTERMEDIATE_TTL,
    });

    console.log('==> Setting signed certificate on intermediate mount');
    await baoRequest('POST', `${INTERMEDIATE_PATH}/intermediate/set-signed`, {
      certificate: signed.data.certificate,
    });
  }

  await baoRequest('POST', `${INTERMEDIATE_PATH}/config/urls`, {
    issuing_certificates: `${BAO_ADDR}/v1/${INTERMEDIATE_PATH}/ca`,
    crl_distribution_points: `${BAO_ADDR}/v1/${INTERMEDIATE_PATH}/crl`,
  });

  console.log(`==> Creating agent signing role "${AGENT_ROLE}"`);
  await baoRequest('POST', `${INTERMEDIATE_PATH}/roles/${AGENT_ROLE}`, {
    // sign-verbatim (what CertificateAuthorityService calls) always uses
    // exactly the CSR's own subject/SANs regardless of these name-constraint
    // settings (allowed_domains and friends) — Manar's own subject/SAN
    // check (CertificateAuthorityService, run *before* this role is ever
    // reached) is the actual security boundary, not this role. These
    // settings only govern TTL and key-usage constraints.
    allow_any_name: true,
    enforce_hostnames: false,
    client_flag: true,
    server_flag: false,
    key_type: 'any',
    max_ttl: LEAF_TTL,
    ttl: LEAF_TTL,
    key_usage: ['DigitalSignature'],
    ext_key_usage: ['ClientAuth'],
  });

  console.log(`==> Creating + issuing dev TLS server role/cert "${SERVER_ROLE}"`);
  await baoRequest('POST', `${INTERMEDIATE_PATH}/roles/${SERVER_ROLE}`, {
    allowed_domains: 'localhost',
    allow_bare_domains: true,
    allow_ip_sans: true,
    server_flag: true,
    client_flag: false,
    key_type: 'ec',
    key_bits: 256,
    max_ttl: SERVER_CERT_TTL,
    ttl: SERVER_CERT_TTL,
  });
  const serverCert = await baoRequest(
    'POST',
    `${INTERMEDIATE_PATH}/issue/${SERVER_ROLE}`,
    {
      common_name: 'localhost',
      ip_sans: '127.0.0.1',
      alt_names: 'localhost',
    },
  );

  const intermediateCaPem = await (
    await fetch(`${BAO_ADDR}/v1/${INTERMEDIATE_PATH}/ca/pem`)
  ).text();
  const rootCaPem = await (
    await fetch(`${BAO_ADDR}/v1/${ROOT_PATH}/ca/pem`)
  ).text();

  await writeFile(path.join(outDir, 'root-ca.pem'), rootCaPem);
  await writeFile(path.join(outDir, 'intermediate-ca.pem'), intermediateCaPem);
  await writeFile(
    path.join(outDir, 'ca-chain.pem'),
    `${intermediateCaPem}\n${rootCaPem}`,
  );
  await writeFile(
    path.join(outDir, 'server-cert.pem'),
    `${serverCert.data.certificate}\n${serverCert.data.issuing_ca}`,
  );
  await writeFile(path.join(outDir, 'server-key.pem'), serverCert.data.private_key);

  console.log(`\nDone. Wrote CA/server material to ${outDir}/`);
  console.log(
    `Agent signing role: ${INTERMEDIATE_PATH}/roles/${AGENT_ROLE} (leaf TTL ${LEAF_TTL})`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
