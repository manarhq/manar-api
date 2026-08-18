import 'dotenv/config';
import { randomUUID, webcrypto } from 'node:crypto';
import * as https from 'node:https';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import * as x509 from '@peculiar/x509';
import {
  FileIdentityStore,
  ManarAgent,
  generateAgentCsr,
} from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

/**
 * Mandatory Phase 4 agent-identity scenarios (design spec's "Testing"
 * section), run against a real HTTP server, real local Postgres, real
 * local Keycloak (for the human operator's JWT), and real local OpenBao
 * (`pnpm infra:up` + `pnpm infra:openbao-init`) — nothing here mocks the
 * CA or the database. Two real, separately-listening Nest applications are
 * bootstrapped, mirroring src/main.ts exactly: the human-facing HTTP app
 * (AppModule) and the agent-facing mTLS HTTPS app (AgentMtlsAppModule).
 */
describe('Agent identity & enrollment (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsPort: number;

  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  // The FULL chain (intermediate + root) -- what the test's own TLS
  // *client* needs to verify the *server's* cert up to a trust anchor it
  // holds, and (same file, AGENT_MTLS_CLIENT_CA_PATH below) what the
  // *server* needs to verify an inbound *client* cert. Node's `tls`/`https`
  // `ca` option does not treat a listed certificate as an implicit trust
  // anchor the way OpenSSL's `-partial_chain` flag does -- giving it only
  // the intermediate (the client cert's direct issuer) is not enough; the
  // intermediate's own issuer (the root) must be present too, or
  // verification fails closed with UNABLE_TO_GET_ISSUER_CERT. See
  // agent-mtls.config.ts's doc comment for how this was diagnosed.
  const fullCaChainPem = readFileSync(
    process.env.AGENT_MTLS_CA_CHAIN_PATH ?? 'deploy/openbao/ca-chain.pem',
    'utf8',
  );

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let adminToken: string;

  const ADMIN_USERNAME = `agent-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  // Captures every line Winston's Console transport writes for the whole
  // suite, and every outbound fetch body the SDK sends — so the "private
  // key never appears in a log line or request body" assertion is a real
  // grep over real captured output, not an inspection-by-reading-the-code
  // claim.
  const capturedStdout: string[] = [];
  const capturedFetchBodies: string[] = [];
  let originalStdoutWrite: typeof process.stdout.write;
  let originalFetch: typeof fetch;

  function uniqueSlug(label: string): string {
    return `agent-${label}-${randomUUID().slice(0, 8)}`;
  }

  async function dropRealDatabase(databaseName: string): Promise<void> {
    const admin = new PgClient({
      connectionString: process.env.CONTROL_DATABASE_URL,
    });
    await admin.connect();
    try {
      await admin.query(
        `DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`,
      );
    } finally {
      await admin.end();
    }
  }

  async function cleanupTenant(t: ProvisionedTenant): Promise<void> {
    if (t.keycloakRealm) await deleteRealm(t.keycloakRealm);
    if (t.databaseBinding?.databaseName) {
      await dropRealDatabase(t.databaseBinding.databaseName);
    }
    await control.tenantDatabaseBinding.deleteMany({
      where: { tenantId: t.id },
    });
    await control.secretReference.deleteMany({ where: { tenantId: t.id } });
    await control.tenant.deleteMany({ where: { id: t.id } });
  }

  /** Creates a PENDING_ENROLLMENT agent + a fresh enrollment token as the admin user, via the real HTTP API. */
  async function createAgentWithToken(slugLabel: string) {
    const slug = uniqueSlug(slugLabel);
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ slug, displayName: `Test agent ${slug}` })
      .expect(201);
    const agentId = (createResponse.body as { id: string }).id;

    const tokenResponse = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/enrollment-tokens`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);
    const rawToken = (tokenResponse.body as { token: string }).token;

    return { agentId, slug, rawToken };
  }

  /** Performs a raw mTLS GET /agent/v1/whoami using the given identity's cert/key against the real listener — never through the SDK (no task/execute API exists yet), just a direct TLS client. */
  function whoamiOverMtls(identity: {
    certificatePem: string;
    caChainPem: string;
    privateKeyPem: string;
  }): Promise<{ status: number; body: unknown }> {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: agentMtlsPort,
          path: '/agent/v1/whoami',
          method: 'GET',
          cert: identity.certificatePem,
          key: identity.privateKeyPem,
          ca: fullCaChainPem,
          rejectUnauthorized: true,
          timeout: 5000,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
          res.on('end', () => {
            resolve({
              status: res.statusCode ?? 0,
              body: data ? (JSON.parse(data) as unknown) : undefined,
            });
          });
        },
      );
      req.on('error', reject);
      req.end();
    });
  }

  /** Builds a client certificate signed by a throwaway, wholly unrelated CA (not chained to Manar's real intermediate) claiming a given agent identifier. */
  async function generateForeignCaClientCertificate(identifier: string) {
    const alg = {
      name: 'ECDSA',
      namedCurve: 'P-256',
      hash: 'SHA-256',
    } as const;
    const caKeys = (await webcrypto.subtle.generateKey(alg, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;

    const rogueCa = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=Foreign Test CA',
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
      keys: caKeys,
      signingAlgorithm: alg,
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true,
        ),
      ],
    });

    const leafKeys = (await webcrypto.subtle.generateKey(alg, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const leafCert = await x509.X509CertificateGenerator.create({
      serialNumber: '02',
      subject: `CN=${identifier}`,
      issuer: 'CN=Foreign Test CA',
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
      publicKey: leafKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          new x509.GeneralName('url', identifier),
        ]),
      ],
    });

    const privateKeyPem = x509.PemConverter.encode(
      await webcrypto.subtle.exportKey('pkcs8', leafKeys.privateKey),
      x509.PemConverter.PrivateKeyTag,
    );

    return {
      certificatePem: leafCert.toString('pem'),
      caChainPem: rogueCa.toString('pem'),
      privateKeyPem,
    };
  }

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();
    humanApp = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await humanApp.init();
    await humanApp.getHttpAdapter().getInstance().ready();
    await humanApp.listen(0, '127.0.0.1');
    const humanAddress = humanApp.getHttpServer().address() as AddressInfo;
    humanEndpoint = `http://127.0.0.1:${humanAddress.port}`;

    const agentMtlsFixture: TestingModule = await Test.createTestingModule({
      imports: [AgentMtlsAppModule],
    }).compile();
    agentMtlsApp =
      agentMtlsFixture.createNestApplication<NestFastifyApplication>(
        new FastifyAdapter({
          https: {
            cert: readFileSync(
              process.env.AGENT_MTLS_SERVER_CERT_PATH ??
                'deploy/openbao/server-cert.pem',
            ),
            key: readFileSync(
              process.env.AGENT_MTLS_SERVER_KEY_PATH ??
                'deploy/openbao/server-key.pem',
            ),
            ca: readFileSync(
              process.env.AGENT_MTLS_CLIENT_CA_PATH ??
                'deploy/openbao/ca-chain.pem',
            ),
            requestCert: true,
            rejectUnauthorized: true,
          },
        }),
      );
    await agentMtlsApp.init();
    await agentMtlsApp.getHttpAdapter().getInstance().ready();
    await agentMtlsApp.listen(0, '127.0.0.1');
    const mtlsAddress = agentMtlsApp.getHttpServer().address() as AddressInfo;
    agentMtlsPort = mtlsAddress.port;

    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);
    provisioning = moduleFixture.get(TenantProvisioningService);

    tenant = await provisioning.provisionTenant({
      slug: uniqueSlug('tenant'),
      name: 'Agent Identity Test Tenant',
    });
    if (!tenant.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }

    const clientSecretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });

    const adminUserId = await createRealmUser(tenant.keycloakRealm, {
      username: ADMIN_USERNAME,
      email: `${ADMIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, adminUserId, 'SECURITY_ADMIN');

    adminToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: ADMIN_USERNAME,
      password: USER_PASSWORD,
    });
  }, 120_000);

  afterAll(async () => {
    await humanApp.close();
    await agentMtlsApp.close();
    if (tenant) await cleanupTenant(tenant);
    await control.$disconnect();
  }, 60_000);

  beforeEach(() => {
    capturedStdout.length = 0;
    capturedFetchBodies.length = 0;

    originalStdoutWrite = process.stdout.write.bind(process.stdout);

    process.stdout.write = (
      chunk: string | Uint8Array,
      ...rest: unknown[]
    ): boolean => {
      capturedStdout.push(typeof chunk === 'string' ? chunk : String(chunk));
      return (
        originalStdoutWrite as (
          chunk: string | Uint8Array,
          ...rest: unknown[]
        ) => boolean
      )(chunk, ...rest);
    };

    originalFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      if (init?.body && typeof init.body === 'string') {
        capturedFetchBodies.push(init.body);
      }
      return originalFetch(input, init);
    };
  });

  afterEach(() => {
    process.stdout.write = originalStdoutWrite;
    globalThis.fetch = originalFetch;
  });

  it('1. full enrollment flow end-to-end via the real SDK against the real API and real OpenBao', async () => {
    const { rawToken } = await createAgentWithToken('full-flow');

    const identityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const manar = new ManarAgent({ endpoint: humanEndpoint, identityStore });

    const identity = await manar.enroll(rawToken);

    expect(identity.certificatePem).toContain('BEGIN CERTIFICATE');
    expect(identity.caChainPem).toContain('BEGIN CERTIFICATE');
    expect(identity.privateKeyPem).toContain('BEGIN PRIVATE KEY');

    const storedIdentity = await identityStore.load();
    expect(storedIdentity).not.toBeNull();
    expect(storedIdentity?.certificatePem).toBe(identity.certificatePem);

    // The certificate is usable end-to-end: a real mTLS request succeeds.
    const whoami = await whoamiOverMtls(identity);
    expect(whoami.status).toBe(200);

    await identityStore.clear();
  }, 60_000);

  it('2. reusing an already-used enrollment token fails', async () => {
    const { rawToken, slug } = await createAgentWithToken('reuse');
    const identifier = `agent://${tenant.slug}/${slug}`;
    const { csrPem } = await generateAgentCsr(identifier);

    await request(humanApp.getHttpServer() as App)
      .post('/agents/enroll')
      .send({ token: rawToken, csr: csrPem })
      .expect(201);

    const { csrPem: secondCsrPem } = await generateAgentCsr(identifier);
    await request(humanApp.getHttpServer() as App)
      .post('/agents/enroll')
      .send({ token: rawToken, csr: secondCsrPem })
      .expect(401);
  }, 20_000);

  it('3. an expired enrollment token fails', async () => {
    const { agentId, rawToken, slug } = await createAgentWithToken('expired');
    const identifier = `agent://${tenant.slug}/${slug}`;

    // The token TTL (AgentsService.ENROLLMENT_TOKEN_TTL_MS, 15 minutes) is
    // a fixed constant, not configurable per-environment the way Phase 3's
    // Keycloak realm accessTokenLifespan is — waiting 15 real minutes isn't
    // feasible in a test. Instead, directly backdate the real, persisted
    // AgentEnrollmentToken row's expiresAt via the real tenant database
    // (never mocked) to simulate elapsed time, then exercise the actual
    // expiry check in AgentsService.enroll against that real row.
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    await tenantClient.agentEnrollmentToken.updateMany({
      where: { agentId },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const { csrPem } = await generateAgentCsr(identifier);
    await request(humanApp.getHttpServer() as App)
      .post('/agents/enroll')
      .send({ token: rawToken, csr: csrPem })
      .expect(401);
  }, 20_000);

  it('4. a CSR whose SAN does not match the enrolling agent is rejected', async () => {
    const { rawToken } = await createAgentWithToken('csr-mismatch');

    // A syntactically valid, self-signed-proof-of-possession CSR -- but
    // claiming a completely different agent identity than the one this
    // token was minted for. CertificateAuthorityService must reject this
    // before ever calling OpenBao.
    const wrongIdentifier = `agent://${tenant.slug}/someone-elses-agent-${randomUUID().slice(0, 8)}`;
    const { csrPem } = await generateAgentCsr(wrongIdentifier);

    await request(humanApp.getHttpServer() as App)
      .post('/agents/enroll')
      .send({ token: rawToken, csr: csrPem })
      .expect(400);
  }, 20_000);

  it('5. immediate revocation: provision, use successfully once, revoke, retry must fail', async () => {
    const { agentId, rawToken } = await createAgentWithToken('revoke');

    const identityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const manar = new ManarAgent({ endpoint: humanEndpoint, identityStore });
    const identity = await manar.enroll(rawToken);

    // Use successfully once.
    const beforeRevoke = await whoamiOverMtls(identity);
    expect(beforeRevoke.status).toBe(200);

    // Revoke.
    await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ reason: 'e2e test revocation' })
      .expect(201);

    // Retry with the exact same, still cryptographically-valid,
    // not-yet-expired certificate -- must fail on the very next request,
    // not merely at next renewal (Section 71).
    const afterRevoke = await whoamiOverMtls(identity);
    expect(afterRevoke.status).toBe(401);

    await identityStore.clear();
  }, 30_000);

  it('6. an mTLS request with a certificate from a foreign (non-Manar) CA is rejected', async () => {
    const identifier = `agent://${tenant.slug}/foreign-ca-agent`;
    const foreignIdentity =
      await generateForeignCaClientCertificate(identifier);

    // The TLS handshake itself must fail -- the server's trust anchor is
    // only the real Manar intermediate CA, so a client certificate from an
    // entirely unrelated CA can never complete a connection, regardless of
    // what agent identity its SAN claims.
    await expect(whoamiOverMtls(foreignIdentity)).rejects.toBeTruthy();
  }, 20_000);

  it('7. the private key never appears in any captured log line or request body', async () => {
    const { rawToken } = await createAgentWithToken('key-secrecy');

    const identityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const manar = new ManarAgent({ endpoint: humanEndpoint, identityStore });
    const identity = await manar.enroll(rawToken);

    // Also exercise the mTLS path so the guard's request handling is
    // covered by this capture window too.
    await whoamiOverMtls(identity);

    const privateKeyBody = identity.privateKeyPem
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .trim();
    // A meaningful, non-trivial slice of the actual key material -- not
    // just the PEM header/footer, which would be uninteresting to grep for.
    const keyFingerprint = privateKeyBody.slice(0, 120);

    const allStdout = capturedStdout.join('');
    expect(allStdout).not.toContain(keyFingerprint);
    expect(allStdout).not.toContain('BEGIN PRIVATE KEY');

    const allFetchBodies = capturedFetchBodies.join('\n');
    expect(allFetchBodies).not.toContain(keyFingerprint);
    expect(allFetchBodies).not.toContain('BEGIN PRIVATE KEY');

    await identityStore.clear();
  }, 30_000);
});
