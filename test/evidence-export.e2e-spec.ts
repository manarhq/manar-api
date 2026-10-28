import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import {
  signEvidenceBundle,
  verifyEvidenceBundle,
} from '../src/evidence/evidence-signing.util';
import { AuditCheckpointService } from '../src/audit/checkpoint/audit-checkpoint.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { verifyInclusion } from '../src/audit/merkle';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import {
  EvidenceExportService,
  type EvidenceExportResult,
} from '../src/evidence/evidence-export.service';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Phase 9b (Evidence export, Section 49) — "bundle for a known scenario
 * contains the expected audit events + context, and its signature/hash
 * verifies; tampering the exported JSON after the fact makes verification
 * fail."
 */
describe('Evidence export (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let provisioning: TenantProvisioningService;

  const ADMIN_USERNAME = `evidence-admin-${randomUUID().slice(0, 8)}`;
  const READ_ONLY_USERNAME = `evidence-ro-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';
  const SIGNING_SECRET =
    process.env.APPROVAL_GRANT_SIGNING_SECRET ??
    'dev-only-approval-grant-signing-secret-change-me';

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let adminToken: string;
  let readOnlyToken: string;
  let agentId: string;
  let taskId: string;

  function uniqueSlug(label: string): string {
    return `evd-${label}-${randomUUID().slice(0, 8)}`;
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

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();
    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    await app.listen(0, '127.0.0.1');

    control = app.get(ControlPrismaService);
    provisioning = moduleFixture.get(TenantProvisioningService);

    tenant = await provisioning.provisionTenant({
      slug: uniqueSlug('t'),
      name: 'Evidence Export Test Tenant',
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

    const readOnlyUserId = await createRealmUser(tenant.keycloakRealm, {
      username: READ_ONLY_USERNAME,
      email: `${READ_ONLY_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, readOnlyUserId, 'READ_ONLY');
    readOnlyToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: READ_ONLY_USERNAME,
      password: USER_PASSWORD,
    });

    const agentResponse = await request(app.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        slug: `evd-agt-${randomUUID().slice(0, 8)}`,
        displayName: 'Evidence Export Test Agent',
      })
      .expect(201);
    agentId = (agentResponse.body as { id: string }).id;

    const taskResponse = await request(app.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Evidence export scenario task',
        assignedAgentId: agentId,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      })
      .expect(201);
    taskId = (taskResponse.body as { id: string }).id;

    await request(app.getHttpServer() as App)
      .post(`/tasks/${taskId}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ reason: 'evidence export scenario cleanup' })
      .expect(201);
  }, 120_000);

  afterAll(async () => {
    if (tenant?.keycloakRealm) await deleteRealm(tenant.keycloakRealm);
    if (tenant?.databaseBinding) {
      await dropRealDatabase(tenant.databaseBinding.databaseName);
      await control.tenantDatabaseBinding.deleteMany({
        where: { tenantId: tenant.id },
      });
      await control.secretReference.deleteMany({
        where: { tenantId: tenant.id },
      });
      await control.tenant.deleteMany({ where: { id: tenant.id } });
    }
    await app.close();
  }, 60_000);

  it('rejects a request with no filter dimension at all', async () => {
    await request(app.getHttpServer() as App)
      .post('/evidence/export')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({})
      .expect(400);
  });

  it('rejects a caller without AUDITOR/SECURITY_ADMIN/TENANT_OWNER', async () => {
    await request(app.getHttpServer() as App)
      .post('/evidence/export')
      .set('Authorization', `Bearer ${readOnlyToken}`)
      .send({ taskId })
      .expect(403);
  });

  it('returns a bundle containing the expected events + context, and its signature verifies; tampering breaks verification', async () => {
    const response = await request(app.getHttpServer() as App)
      .post('/evidence/export')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ taskId })
      .expect(201);

    const result = response.body as EvidenceExportResult;

    expect(result.bundle.tenantId).toBe(tenant.id);
    expect(result.bundle.filter.taskId).toBe(taskId);

    const eventTypes = result.bundle.events.map((e) => e.eventType);
    expect(eventTypes).toContain('task.created');
    expect(eventTypes).toContain('task.revoked');
    for (const event of result.bundle.events) {
      expect(event.eventHash).toBeTruthy();
    }

    const taskContext = result.bundle.context.tasks.find(
      (t) => t.id === taskId,
    );
    expect(taskContext).toBeDefined();
    expect(taskContext?.assignedAgentId).toBe(agentId);
    expect(taskContext?.status).toBe('REVOKED');

    // Chain-segment self-consistency within each audit partition: an
    // exported event directly after another in the same partition links to
    // it (Section 49's "let a recipient verify those specific events").
    const events = result.bundle.events;
    for (const later of events) {
      const earlier = events.find(
        (e) =>
          e.partition === later.partition &&
          e.partitionSeq + 1 === later.partitionSeq,
      );
      if (earlier) expect(later.previousHash).toBe(earlier.eventHash);
    }

    const verifyGood = await verifyEvidenceBundle(
      result.bundle,
      result.signature.signature,
      SIGNING_SECRET,
    );
    expect(verifyGood).toEqual({ valid: true });

    const tamperedBundle = {
      ...result.bundle,
      events: result.bundle.events.map((e, i) =>
        i === 0 ? { ...e, data: { tampered: true } } : e,
      ),
    };
    const verifyTampered = await verifyEvidenceBundle(
      tamperedBundle,
      result.signature.signature,
      SIGNING_SECRET,
    );
    expect(verifyTampered.valid).toBe(false);
  });

  it('POST /evidence/verify confirms an untouched bundle and rejects a tampered one (R9)', async () => {
    const exported = (
      await request(app.getHttpServer() as App)
        .post('/evidence/export')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ taskId })
        .expect(201)
    ).body as EvidenceExportResult;

    const verify = (bundle: unknown) =>
      request(app.getHttpServer() as App)
        .post('/evidence/verify')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ bundle, signature: exported.signature.signature })
        .expect(200);

    expect((await verify(exported.bundle)).body).toMatchObject({
      valid: true,
    });
    expect(
      (await verify({ ...exported.bundle, tenantId: 'someone-else' })).body,
    ).toMatchObject({ valid: false });

    await request(app.getHttpServer() as App)
      .post('/evidence/verify')
      .set('Authorization', `Bearer ${readOnlyToken}`)
      .send({
        bundle: exported.bundle,
        signature: exported.signature.signature,
      })
      .expect(403);
  });

  it('carries an inclusion proof for every sealed event, and verify checks each against the tenant key', async () => {
    const client = await app.get(TenantDatabaseManager).getClient(tenant.id);
    await app.get(AuditCheckpointService).createCheckpoint(client, tenant.id);

    const exported = (
      await request(app.getHttpServer() as App)
        .post('/evidence/export')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ taskId })
        .expect(201)
    ).body as EvidenceExportResult;

    const key = await app.get(CheckpointSigner).publicKey(tenant.id);
    expect(exported.bundle.checkpointPublicKey).toEqual(key);
    const sealed = exported.bundle.events.filter((e) => e.proof !== null);
    expect(sealed.length).toBe(exported.bundle.events.length);
    for (const e of sealed) {
      expect(verifyInclusion(e.eventHash, e.proof!.proof, e.proof!.root)).toBe(
        true,
      );
    }
    // Each SEAL is in the bundle once; proofs point at it by seq.
    const seqs = exported.bundle.checkpoints.map((c) => c.seq);
    expect(new Set(seqs).size).toBe(seqs.length);
    for (const e of sealed) {
      expect(seqs).toContain(e.proof!.checkpointSeq);
    }

    const verified = (
      await request(app.getHttpServer() as App)
        .post('/evidence/verify')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          bundle: exported.bundle,
          signature: exported.signature.signature,
        })
        .expect(200)
    ).body as { valid: boolean; proofsVerified: number; proofsMissing: number };
    expect(verified).toEqual({
      valid: true,
      proofsVerified: sealed.length,
      proofsMissing: 0,
    });

    // A bundle whose HMAC signature is genuine but whose proof does not lead
    // to a SEAL signed by the tenant key (a leaked signing secret, say) fails.
    const forged = {
      ...exported.bundle,
      checkpoints: exported.bundle.checkpoints.map((c, i) =>
        i === 0 ? { ...c, signature: 'AAAA' } : c,
      ),
    };
    const resigned = await signEvidenceBundle(
      forged,
      exported.exportId,
      SIGNING_SECRET,
    );
    const service = app.get(EvidenceExportService);
    expect(
      await service.verify(forged, resigned.signature, client),
    ).toMatchObject({ valid: false, reason: 'proof_invalid' });

    // Changed data under an unchanged eventHash/leaf: the hash recomputed
    // from the event's own fields no longer matches.
    const edited = {
      ...exported.bundle,
      events: exported.bundle.events.map((e, i) =>
        i === 0 ? { ...e, data: { edited: true } } : e,
      ),
    };
    const editedSig = await signEvidenceBundle(
      edited,
      exported.exportId,
      SIGNING_SECRET,
    );
    expect(
      await service.verify(edited, editedSig.signature, client),
    ).toMatchObject({ valid: false, reason: 'proof_invalid' });

    // A proof stripped from an event a checkpoint does cover is not
    // "missing", it was removed.
    const stripped = {
      ...exported.bundle,
      events: exported.bundle.events.map((e, i) =>
        i === 0 ? { ...e, proof: null } : e,
      ),
    };
    const strippedSig = await signEvidenceBundle(
      stripped,
      exported.exportId,
      SIGNING_SECRET,
    );
    expect(
      await service.verify(stripped, strippedSig.signature, client),
    ).toMatchObject({ valid: false, reason: 'proof_missing' });

    // Without the bundle's own tenant database, a missing proof can't be
    // judged: unverifiable, never valid.
    expect(await service.verify(stripped, strippedSig.signature)).toMatchObject(
      { valid: false, reason: 'proof_unverifiable' },
    );

    // An event the tenant's log doesn't hold, with no proof: unverifiable.
    const invented = {
      ...exported.bundle,
      events: [
        ...exported.bundle.events,
        { ...exported.bundle.events[0]!, id: randomUUID(), proof: null },
      ],
    };
    const inventedSig = await signEvidenceBundle(
      invented,
      exported.exportId,
      SIGNING_SECRET,
    );
    expect(
      await service.verify(invented, inventedSig.signature, client),
    ).toMatchObject({ valid: false, reason: 'proof_unverifiable' });
  });
});
