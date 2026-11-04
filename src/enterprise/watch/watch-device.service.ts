import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import type { z } from 'zod';
import { AuditService } from '../../audit/audit.service';
import { failClosed } from '../../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { EnterpriseGateService } from '../common/enterprise-gate.service';
import { ENT_AUDIT_EVENT_TYPES as EV } from '../common/ent-audit-events';
import { entConfig } from '../common/ent-config';
import { isP256PublicJwk, thumbprint } from './device-signature';
import type { WatchDevice } from './device-signature.guard';
import { WatchIdTokenVerifier } from './id-token.verifier';
import type {
  EnrolSchema,
  EventsSchema,
  HeartbeatSchema,
} from './watch.validation';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const NONCE_TTL_MS = 10 * 60_000;
const SYSTEM = { type: 'system' as const, id: 'watch' };

/** Enrolment, heartbeat, events and identity proof for WATCH devices. Metadata only. */
@Injectable()
export class WatchDeviceService {
  constructor(
    private readonly gate: EnterpriseGateService,
    private readonly tenants: TenantDatabaseManager,
    private readonly control: ControlPrismaService,
    private readonly audit: AuditService,
    private readonly idTokens: WatchIdTokenVerifier,
  ) {}

  /**
   * A browser enrols with the tenant's enrolment key. The same public key always maps to the same
   * device. The profile email is only a claim: the device is linked to that person UNVERIFIED until
   * an id_token proves it (verifyIdentity).
   */
  async enrol(body: z.infer<typeof EnrolSchema>) {
    await this.gate.requireEnabled(body.tenantId);
    if (!isP256PublicJwk(body.publicKeyJwk))
      throw new BadRequestException({ code: 'bad_key' });
    const jwk = body.publicKeyJwk;
    return failClosed('watch-enrol', async () => {
      const db = await this.tenants.getClient(body.tenantId);
      const key = await db.entEnrolKey.findUnique({
        where: { keyHash: sha256(body.enrolKey) },
      });
      if (!key || key.revokedAt || key.expiresAt <= new Date())
        throw new UnauthorizedException({ code: 'enrol_key_invalid' });
      const tp = thumbprint(jwk);
      const existing = await db.entDevice.findUnique({
        where: { keyThumbprint: tp },
      });
      if (existing) return { deviceId: existing.id };
      const email = body.profileEmail?.toLowerCase() ?? null;
      const person = email
        ? await db.entPerson.findUnique({ where: { email } })
        : null;
      const device = await db.entDevice.create({
        data: {
          publicKeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
          keyThumbprint: tp,
          profileEmail: email,
          personId: person?.id ?? null,
          browser: body.browser,
          extensionVersion: body.extensionVersion,
          enrolKeyId: key.id,
        },
      });
      await db.entEnrolKey.update({
        where: { id: key.id },
        data: { uses: { increment: 1 } },
      });
      await this.audit.record(db, body.tenantId, {
        eventType: EV.ENT_DEVICE_ENROLLED,
        actor: SYSTEM,
        data: {
          deviceId: device.id,
          enrolKeyId: key.id,
          personId: person?.id ?? null,
          verified: false,
        },
      });
      return { deviceId: device.id };
    });
  }

  /** Issues a single-use nonce bound to this device and returns the silent sign-in URL. */
  async identityNonce(d: WatchDevice, redirectUri: string) {
    const { watchIssuer, watchClientId } = entConfig();
    if (!watchIssuer || !this.idTokens.enabled())
      throw new NotFoundException({ code: 'identity_not_configured' });
    if (!/^https:\/\/[a-p]{32}\.chromiumapp\.org\/$/.test(redirectUri))
      throw new BadRequestException({ code: 'bad_redirect' });
    const nonce = randomBytes(32).toString('base64url');
    await failClosed('watch-identity', async () => {
      const db = await this.tenants.getClient(d.tenantId);
      await db.entIdentityNonce.create({
        data: {
          deviceId: d.deviceId,
          nonceHash: sha256(nonce),
          expiresAt: new Date(Date.now() + NONCE_TTL_MS),
        },
      });
    });
    const url = new URL(`${watchIssuer}/protocol/openid-connect/auth`);
    url.search = new URLSearchParams({
      client_id: watchClientId,
      response_type: 'id_token',
      scope: 'openid email',
      redirect_uri: redirectUri,
      nonce,
      prompt: 'none',
      kc_idp_hint: 'microsoft',
    }).toString();
    return { authorizeUrl: url.toString() };
  }

  /**
   * Binds the device to the person the token proves. The token must carry a nonce this device was
   * issued, unused and unexpired (burned here, once), and come from the tenant's own Entra tenant.
   */
  async verifyIdentity(d: WatchDevice, idToken: string) {
    let claims: Awaited<ReturnType<WatchIdTokenVerifier['verify']>>;
    try {
      claims = await this.idTokens.verify(idToken);
    } catch {
      throw new UnauthorizedException({ code: 'id_token_invalid' });
    }
    const nonce = typeof claims.nonce === 'string' ? claims.nonce : '';
    const email =
      typeof claims.email === 'string' ? claims.email.toLowerCase() : '';
    if (!nonce || !email || claims.email_verified === false)
      throw new UnauthorizedException({ code: 'id_token_invalid' });
    return failClosed('watch-identity', async () => {
      const tenant = await this.control.tenant.findUnique({
        where: { id: d.tenantId },
        select: { entraTenantId: true },
      });
      if (!tenant?.entraTenantId || claims.tid !== tenant.entraTenantId)
        throw new UnauthorizedException({ code: 'wrong_directory' });
      const db = await this.tenants.getClient(d.tenantId);
      const burned = await db.entIdentityNonce.updateMany({
        where: {
          nonceHash: sha256(nonce),
          deviceId: d.deviceId,
          usedAt: null,
          expiresAt: { gt: new Date() },
        },
        data: { usedAt: new Date() },
      });
      if (burned.count !== 1)
        throw new UnauthorizedException({ code: 'nonce_invalid' });
      const person = await db.entPerson.upsert({
        where: { email },
        create: {
          email,
          displayName: typeof claims.name === 'string' ? claims.name : email,
        },
        update: {},
      });
      await db.entDevice.update({
        where: { id: d.deviceId },
        data: { personId: person.id, identityVerified: true },
      });
      await this.audit.record(db, d.tenantId, {
        eventType: EV.ENT_DEVICE_IDENTITY_VERIFIED,
        actor: SYSTEM,
        data: { deviceId: d.deviceId, personId: person.id },
      });
      return { personId: person.id };
    });
  }

  async heartbeat(d: WatchDevice, hb: z.infer<typeof HeartbeatSchema>) {
    return failClosed('watch-heartbeat', async () => {
      const db = await this.tenants.getClient(d.tenantId);
      const device = await db.entDevice.findUniqueOrThrow({
        where: { id: d.deviceId },
      });
      const signals: string[] = [];
      if (hb.hints.unpacked) signals.push('unpacked');
      if (device.configHash && device.configHash !== hb.configHash)
        signals.push('config_changed');
      for (const kind of signals) {
        const open = await db.entTamperSignal.findFirst({
          where: { deviceId: d.deviceId, kind, closedAt: null },
        });
        if (open) continue;
        await db.entTamperSignal.create({
          data: { deviceId: d.deviceId, kind },
        });
        await this.audit.record(db, d.tenantId, {
          eventType: EV.ENT_DEVICE_TAMPER,
          actor: SYSTEM,
          data: { deviceId: d.deviceId, kind },
        });
      }
      await db.entDevice.update({
        where: { id: d.deviceId },
        data: {
          lastHeartbeatAt: new Date(),
          extensionVersion: hb.extensionVersion,
          policyVersion: hb.policyVersion,
          configHash: hb.configHash,
        },
      });
      for (const [day, hosts] of Object.entries(hb.visits)) {
        for (const [host, count] of Object.entries(hosts)) {
          await db.entSiteVisit.upsert({
            where: { deviceId_day_host: { deviceId: d.deviceId, day, host } },
            create: { deviceId: d.deviceId, day, host, count },
            update: { count: { increment: count } },
          });
        }
      }
    });
  }

  async events(d: WatchDevice, body: z.infer<typeof EventsSchema>) {
    return failClosed('watch-events', async () => {
      const db = await this.tenants.getClient(d.tenantId);
      const r = await db.entEvent.createMany({
        skipDuplicates: true,
        data: body.events.map((e) => ({
          deviceId: d.deviceId,
          personId: d.personId,
          clientEventId: e.clientEventId,
          host: e.host,
          kind: e.kind,
          outcome: e.outcome,
          ruleId: e.ruleId ?? null,
          trace: e.trace,
          counts: e.counts,
          packVersion: e.packVersion ?? null,
          at: new Date(e.at),
        })),
      });
      return { stored: r.count };
    });
  }
}
