import 'reflect-metadata';
import 'dotenv/config';
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  webcrypto,
} from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { Client as PgClient } from 'pg';
import type { PrismaClient } from '../src/generated/tenant-client/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CertificateAuthorityService } from '../src/agents/certificate-authority.service';
import { AuditService } from '../src/audit/audit.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { LdapsAdDirectory } from '../src/hosts/adcs/ad-directory.client';
import { AdcsAdminService } from '../src/hosts/adcs/adcs-admin.service';
import { AdcsDirectoryService } from '../src/hosts/adcs/adcs-directory.service';
import {
  AdcsCertificateRejectedError,
  AdcsEnrolmentService,
} from '../src/hosts/adcs/adcs-enrolment.service';
import {
  signProof,
  spkiFingerprint,
} from '../src/hosts/adcs/computer-proof.util';
import {
  HostsAdminService,
  UnverifiedRuleError,
} from '../src/hosts/hosts-admin.service';
import {
  HostRefusedError,
  HostRekeyPendingError,
  HostsService,
} from '../src/hosts/hosts.service';
import { InstallKeysService } from '../src/hosts/install-keys.service';
import {
  activateCredential,
  rsaTpmtPublic,
} from '../src/hosts/tpm/software-tpm';
import {
  TpmAttestationError,
  TpmAttestationService,
} from '../src/hosts/tpm/tpm-attestation.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { OpenBaoPkiClient } from '../src/openbao/openbao-pki.client';
import { tpmName } from '../src/hosts/tpm/tpm-structures';
import { fakeConfigService } from './support/audit-test-config';
import { startLdapsServer, type FakeComputer } from './support/ldaps-server';
import {
  makeCa,
  makeCrl,
  makeCsrPem,
  makeLeaf,
  newKeys,
  type TestCa,
  type TestLeaf,
} from './support/test-pki';

const admin = { type: 'human' as const, id: 'user-admin' };
const BIND_PASSWORD = 'bind-pw-must-not-leak-9f3a';
const FIN = 'OU=Finance,DC=corp,DC=example';
const LAP = 'OU=Laptops,OU=Finance,DC=corp,DC=example';
const SALES = 'OU=Sales,DC=corp,DC=example';
const day = 86_400_000;
const TEMPLATE = '1.3.6.1.4.1.311.21.8.1.2.3';
const USER_TEMPLATE = '1.3.6.1.4.1.311.21.8.9.9.9';

async function nodePrivate(keys: CryptoKeyPair) {
  return createPrivateKey({
    key: Buffer.from(
      await webcrypto.subtle.exportKey('pkcs8', keys.privateKey),
    ),
    format: 'der',
    type: 'pkcs8',
  });
}
async function nodePublic(keys: CryptoKeyPair) {
  return createPublicKey({
    key: Buffer.from(await webcrypto.subtle.exportKey('spki', keys.publicKey)),
    format: 'der',
    type: 'spki',
  });
}

/** F2b against a real tenant database, real OpenBao, and an in-process LDAPS server. */
describe('AD CS enrolment, OU mapping, TPM attestation, rule guard (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafka: KafkaPublisherService;
  let audit: AuditService;
  let kv: OpenBaoKvClient;
  let hosts: HostsService;
  let tpm: TpmAttestationService;
  let adcsAdmin: AdcsAdminService;
  let hostsAdmin: HostsAdminService;
  let enrolment: AdcsEnrolmentService;
  let customerCa: TestCa;
  let otherCa: TestCa;
  let ldaps: Awaited<ReturnType<typeof startLdapsServer>>;
  let ldapsCa: TestCa;
  const computers: FakeComputer[] = [];
  const crls = new Map<string, Uint8Array | Error>();
  const provisioned: { tenantId: string; databaseName: string }[] = [];
  // The shared Postgres has a connection ceiling, so the suite uses a few tenants, not one per test.
  let ad: T;
  let down: T;
  let noAd: T;
  let other: T;
  let mut: T;

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    kafka = new KafkaPublisherService(fakeConfigService());
    await kafka.onModuleInit();
    kv = new OpenBaoKvClient(fakeConfigService());
    audit = new AuditService(kafka, new CheckpointSigner(kv));
    const ca = new CertificateAuthorityService(
      new OpenBaoPkiClient(fakeConfigService()),
    );
    tpm = new TpmAttestationService(control, manager, audit);
    hosts = new HostsService(
      control,
      manager,
      new InstallKeysService(audit),
      audit,
      ca,
      tpm,
    );
    const directory = new AdcsDirectoryService(new LdapsAdDirectory(), kv);
    adcsAdmin = new AdcsAdminService(audit, kv, directory);
    hostsAdmin = new HostsAdminService(audit, ca);
    enrolment = new AdcsEnrolmentService(
      control,
      manager,
      ca,
      directory,
      tpm,
      hosts,
      fakeConfigService(),
      (url) => {
        const got = crls.get(url);
        if (got instanceof Uint8Array) return Promise.resolve(got);
        return Promise.reject(got ?? new Error('unreachable'));
      },
    );
    customerCa = await makeCa('Corp Issuing CA');
    otherCa = await makeCa('Attacker CA');
    ldapsCa = await makeCa('LDAPS CA');
    ldaps = await startLdapsServer({
      serverCert: await makeLeaf(ldapsCa, {
        dns: 'localhost',
        eku: [x509.ExtendedKeyUsage.serverAuth],
      }),
      bindDn: 'CN=svc-manar,DC=corp,DC=example',
      password: BIND_PASSWORD,
      computers,
    });
    ad = await tenant('ad');
    down = await tenant('down', { ldapsUrl: 'ldaps://localhost:1' });
    noAd = await tenant('noad', { noAd: true });
    other = await tenant('other', { trust: [otherCa] });
    mut = await tenant('mut');
  }, 240_000);

  /** Rules are per test; drop the previous test's rules. */
  const fresh = async (t: T) => {
    await t.client.hostApprovalRule.deleteMany();
    return t;
  };

  afterAll(async () => {
    await ldaps.close();
    await audit.onModuleDestroy();
    await kafka.onModuleDestroy();
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await pg.end();
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
      await kv
        .deleteV1(`secret/metadata/adcs/${tenantId}/ad-bind`)
        .catch(() => undefined);
    }
    await control.$disconnect();
  }, 60_000);

  async function tenant(
    label: string,
    opts: { ldapsUrl?: string; noAd?: boolean; trust?: TestCa[] } = {},
  ) {
    const t = await manager.provisionTenant({
      slug: `adcs-${label}-${randomUUID().slice(0, 6)}`,
      name: `AD CS ${label}`,
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const def = await client.hostGroup.create({ data: { name: 'Unmapped' } });
    const fin = await client.hostGroup.create({ data: { name: 'Finance' } });
    const lap = await client.hostGroup.create({ data: { name: 'Laptops' } });
    const sales = await client.hostGroup.create({ data: { name: 'Sales' } });
    for (const ca of opts.trust ?? [customerCa]) {
      await adcsAdmin.addCa(client, t.id, admin, {
        label: 'corp',
        certPem: ca.pem,
      });
    }
    await adcsAdmin.putSettings(
      client,
      t.id,
      admin,
      opts.noAd
        ? { defaultHostGroupId: def.id, allowedTemplateOids: [TEMPLATE] }
        : {
            defaultHostGroupId: def.id,
            allowedTemplateOids: [TEMPLATE],
            ldapsUrl: opts.ldapsUrl ?? ldaps.url,
            baseDn: 'DC=corp,DC=example',
            bindDn: 'CN=svc-manar,DC=corp,DC=example',
            serverCaPem: ldapsCa.pem,
            bindPassword: BIND_PASSWORD,
          },
    );
    await adcsAdmin.createOuRule(client, t.id, admin, {
      ouDn: FIN,
      hostGroupId: fin.id,
    });
    await adcsAdmin.createOuRule(client, t.id, admin, {
      ouDn: LAP,
      hostGroupId: lap.id,
    });
    await adcsAdmin.createOuRule(client, t.id, admin, {
      ouDn: SALES,
      hostGroupId: sales.id,
    });
    return { id: t.id, slug: t.slug, client, def, fin, lap, sales };
  }

  function addComputer(dnsName: string, ouDn: string) {
    const cn = dnsName.split('.')[0]!.toUpperCase();
    const entry = { dn: `CN=${cn},${ouDn}`, dNSHostName: dnsName };
    computers.push(entry);
    return entry;
  }

  const CRL_URL = 'http://pki.corp.example/ca.crl';

  async function computerCert(
    dns: string,
    o: Parameters<typeof makeLeaf>[1] = {},
    issuer: TestCa = customerCa,
  ) {
    return makeLeaf(issuer, {
      dns,
      crlUrl: CRL_URL,
      template: TEMPLATE,
      serial: randomUUID().replace(/-/g, '').slice(0, 12),
      ...o,
    });
  }

  async function enrol(
    t: T,
    leaf: TestLeaf,
    o: Partial<{
      machineId: string;
      slug: string;
      timestamp: string;
      forgeProof: boolean;
      hostKeys: CryptoKeyPair;
      tpmChallengeId: string;
      certificates: string[];
    }> = {},
  ) {
    const machineId = o.machineId ?? `m-${randomUUID().slice(0, 8)}`;
    const slug = o.slug ?? t.slug;
    const hostKeys = o.hostKeys ?? (await newKeys());
    const csr = await makeCsrPem(hostKeys, `host://${t.slug}/${machineId}`);
    const fp = spkiFingerprint(
      new Uint8Array(new x509.Pkcs10CertificateRequest(csr).publicKey.rawData),
    );
    const timestamp = o.timestamp ?? new Date().toISOString();
    const signer = o.forgeProof
      ? await nodePrivate(await newKeys())
      : await nodePrivate(leaf.keys);
    const result = await enrolment.register({
      tenantSlug: slug,
      certificates: o.certificates ?? [leaf.pem],
      csr,
      machineId,
      os: 'Windows 11',
      keyType: 'SOFTWARE',
      timestamp,
      signature: signProof(signer, {
        tenantSlug: slug,
        machineId,
        csrKeyFingerprint: fp,
        os: 'Windows 11',
        keyType: 'SOFTWARE',
        timestamp,
      }),
      tpmChallengeId: o.tpmChallengeId,
      ip: '10.0.0.7',
    });
    return { ...result, machineId, csr, hostKeys };
  }

  const rejected = (p: Promise<unknown>) =>
    p.then(
      () => 'accepted',
      (e: unknown) =>
        e instanceof AdcsCertificateRejectedError
          ? e.reason
          : `other:${String(e)}`,
    );

  describe('computer certificate', () => {
    it('registers key-less: group from the AD OU (longest match), PENDING without a rule', async () => {
      const t = await fresh(ad);
      addComputer('pc-happy.corp.example', LAP);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      const r = await enrol(t, await computerCert('pc-happy.corp.example'));
      expect(r.status).toBe('PENDING');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: r.hostId },
      });
      expect(host.hostGroupId).toBe(t.lap.id);
      expect(host).toMatchObject({
        enrolmentMethod: 'ADCS',
        hostname: 'pc-happy.corp.example',
        adDn: expect.stringContaining('OU=Laptops') as string,
        tpmVerified: false,
      });
      const ev = await t.client.auditEvent.findFirst({
        where: { eventType: 'host.registered' },
      });
      expect(ev?.data).toMatchObject({
        enrolmentMethod: 'ADCS',
        installKeyId: null,
      });
    }, 60_000);

    it('auto-approves when a rule on the verified certificate and OU matches', async () => {
      const t = await fresh(ad);
      addComputer('pc-appr.corp.example', FIN);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireAdcs: true,
        adOuDn: FIN,
      });
      const r = await enrol(t, await computerCert('pc-appr.corp.example'));
      expect(r.status).toBe('APPROVED');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: r.hostId },
      });
      expect(host.hostGroupId).toBe(t.fin.id);
      expect(host.approvedBy).toMatch(/^rule:/);
    }, 60_000);

    it('refuses a certificate from the wrong CA, and one trusted only by another tenant', async () => {
      const t = await fresh(ad);
      const before = await t.client.host.count();
      addComputer('pc-wca.corp.example', FIN);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      const bad = await makeLeaf(otherCa, { dns: 'pc-wca.corp.example' });
      expect(await rejected(enrol(t, bad))).toBe('untrusted');
      // trusted by `other`, presented to `t`
      expect(await rejected(enrol(t, bad, { slug: t.slug }))).toBe('untrusted');
      // and the reverse: a customer-CA cert is not enough for `other`
      const good = await computerCert('pc-wca.corp.example');
      expect(await rejected(enrol(other, good))).toBe('untrusted');
      expect(await t.client.host.count()).toBe(before);
      expect(await other.client.host.count()).toBe(0);
    }, 90_000);

    it('refuses expired, not-yet-valid and wrong-EKU certificates and a forged proof', async () => {
      const t = await fresh(ad);
      const before = await t.client.host.count();
      addComputer('pc-inv.corp.example', FIN);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      expect(
        await rejected(
          enrol(
            t,
            await computerCert('pc-inv.corp.example', {
              notBefore: new Date(Date.now() - 10 * day),
              notAfter: new Date(Date.now() - day),
            }),
          ),
        ),
      ).toBe('expired');
      expect(
        await rejected(
          enrol(
            t,
            await computerCert('pc-inv.corp.example', {
              eku: [x509.ExtendedKeyUsage.serverAuth],
            }),
          ),
        ),
      ).toBe('wrong_eku');
      const ok = await computerCert('pc-inv.corp.example');
      expect(await rejected(enrol(t, ok, { forgeProof: true }))).toBe(
        'proof of possession failed',
      );
      expect(
        await rejected(
          enrol(t, ok, {
            timestamp: new Date(Date.now() - 3_600_000).toISOString(),
          }),
        ),
      ).toBe('proof of possession failed');
      expect(
        await rejected(
          enrol(
            t,
            await computerCert(null as unknown as string, { dns: null }),
          ),
        ),
      ).toBe('no DNS name');
      expect(await t.client.host.count()).toBe(before);
    }, 90_000);

    it('accepts only certificates from a listed template; an empty list accepts none', async () => {
      const t = await fresh(noAd);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      const before = await t.client.host.count();
      // a Client Authentication certificate from a user/service template
      expect(
        await rejected(
          enrol(
            t,
            await computerCert('pc-tpl.corp.example', {
              template: USER_TEMPLATE,
            }),
          ),
        ),
      ).toBe('template not allowed');
      // no template extension at all
      expect(
        await rejected(
          enrol(
            t,
            await computerCert('pc-tpl.corp.example', { template: undefined }),
          ),
        ),
      ).toBe('template not allowed');
      const settings = {
        defaultHostGroupId: t.def.id,
        allowedTemplateOids: [] as string[],
      };
      await adcsAdmin.putSettings(t.client, t.id, admin, settings);
      try {
        expect(
          await rejected(enrol(t, await computerCert('pc-tpl.corp.example'))),
        ).toBe('template not allowed');
      } finally {
        await adcsAdmin.putSettings(t.client, t.id, admin, {
          ...settings,
          allowedTemplateOids: [TEMPLATE],
        });
      }
      expect(await t.client.host.count()).toBe(before);
      const ok = await enrol(t, await computerCert('pc-tpl.corp.example'));
      expect(ok.status).toBe('PENDING');
    }, 60_000);

    it('refuses a revoked certificate', async () => {
      const t = await fresh(ad);
      const before = await t.client.host.count();
      addComputer('pc-rev.corp.example', FIN);
      const leaf = await computerCert('pc-rev.corp.example', {
        serial: '0badc0de01',
      });
      crls.set(CRL_URL, await makeCrl(customerCa, ['0badc0de01']));
      expect(await rejected(enrol(t, leaf))).toBe('revoked');
      expect(await t.client.host.count()).toBe(before);
    }, 60_000);

    it('CRL unreachable or too stale: registers PENDING and never auto-approves', async () => {
      const t = await fresh(ad);
      addComputer('pc-crl.corp.example', FIN);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireAdcs: true,
        adOuDn: FIN,
      });
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        cidrs: ['10.0.0.0/8'],
      });
      crls.set(CRL_URL, new Error('ECONNREFUSED'));
      const down = await enrol(t, await computerCert('pc-crl.corp.example'));
      expect(down.status).toBe('PENDING');
      crls.set(
        CRL_URL,
        await makeCrl(customerCa, [], {
          nextUpdate: new Date(Date.now() - 1000),
        }),
      );
      addComputer('pc-crl2.corp.example', FIN);
      const stale = await enrol(t, await computerCert('pc-crl2.corp.example'));
      expect(stale.status).toBe('PENDING');
    }, 60_000);

    it('AD unreachable: default group, PENDING, no auto-approval', async () => {
      const t = await fresh(down);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireAdcs: true,
      });
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        cidrs: ['10.0.0.0/8'],
      });
      const r = await enrol(t, await computerCert('pc-down.corp.example'));
      expect(r.status).toBe('PENDING');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: r.hostId },
      });
      expect(host.hostGroupId).toBe(t.def.id);
      expect(host.adDn).toBeNull();
    }, 60_000);

    it('AD not configured, computer not in AD, or OU not mapped: default group, PENDING', async () => {
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      await fresh(noAd);
      await hostsAdmin.createApprovalRule(noAd.client, noAd.id, admin, {
        cidrs: ['10.0.0.0/8'],
      });
      expect(
        (await enrol(noAd, await computerCert('pc-noad.corp.example'))).status,
      ).toBe('PENDING');

      const t = await fresh(ad);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        cidrs: ['10.0.0.0/8'],
      });
      addComputer('pc-hr.corp.example', 'OU=HR,DC=corp,DC=example');
      const hr = await enrol(t, await computerCert('pc-hr.corp.example'));
      expect(hr.status).toBe('PENDING');
      expect(
        (await t.client.host.findUniqueOrThrow({ where: { id: hr.hostId } }))
          .hostGroupId,
      ).toBe(t.def.id);
      const ghost = await enrol(t, await computerCert('pc-ghost.corp.example'));
      expect(ghost.status).toBe('PENDING');
    }, 90_000);

    it('moving the computer between OUs moves its group on re-sync; AD down changes nothing', async () => {
      const t = await fresh(mut);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      const entry = addComputer('pc-move.corp.example', FIN);
      const r = await enrol(t, await computerCert('pc-move.corp.example'));
      await t.client.host.update({
        where: { id: r.hostId },
        data: { status: 'APPROVED' },
      });
      expect(
        (await t.client.host.findUniqueOrThrow({ where: { id: r.hostId } }))
          .hostGroupId,
      ).toBe(t.fin.id);

      entry.dn = `CN=PC-MOVE,${SALES}`;
      const run = await adcsAdmin.resync(t.client, t.id, admin);
      expect(run).toMatchObject({ status: 'ok', moved: 1 });
      const moved = await t.client.host.findUniqueOrThrow({
        where: { id: r.hostId },
      });
      expect(moved.hostGroupId).toBe(t.sales.id);
      expect(moved.status).toBe('APPROVED');
      expect(
        await t.client.auditEvent.count({
          where: { eventType: 'host.group_moved' },
        }),
      ).toBe(1);

      // AD becomes unreachable: nothing moves, and the run says why.
      entry.dn = `CN=PC-MOVE,${FIN}`;
      await adcsAdmin.putSettings(t.client, t.id, admin, {
        defaultHostGroupId: t.def.id,
        allowedTemplateOids: [TEMPLATE],
        ldapsUrl: 'ldaps://localhost:1',
        baseDn: 'DC=corp,DC=example',
        bindDn: 'CN=svc-manar,DC=corp,DC=example',
        serverCaPem: ldapsCa.pem,
        bindPassword: BIND_PASSWORD,
      });
      const downRun = await adcsAdmin.resync(t.client, t.id, admin);
      expect(downRun).toMatchObject({ status: 'ad_unreachable', moved: 0 });
      expect(
        (await t.client.host.findUniqueOrThrow({ where: { id: r.hostId } }))
          .hostGroupId,
      ).toBe(t.sales.id);
    }, 90_000);

    it('a known computer-certificate host follows its OU when it registers again', async () => {
      const t = await fresh(ad);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      const entry = addComputer('pc-rereg.corp.example', FIN);
      const first = await enrol(t, await computerCert('pc-rereg.corp.example'));
      entry.dn = `CN=PC-REREG,${SALES}`;
      const again = await enrol(
        t,
        await computerCert('pc-rereg.corp.example'),
        {
          machineId: first.machineId,
          hostKeys: first.hostKeys,
        },
      );
      expect(again.hostId).toBe(first.hostId);
      expect(
        (await t.client.host.findUniqueOrThrow({ where: { id: first.hostId } }))
          .hostGroupId,
      ).toBe(t.sales.id);
    }, 60_000);

    it('the AD password is only in OpenBao: not in settings, not in audit', async () => {
      const t = await fresh(ad);
      const settings = await t.client.adcsSettings.findFirstOrThrow();
      expect(JSON.stringify(settings)).not.toContain(BIND_PASSWORD);
      const events = await t.client.auditEvent.findMany();
      expect(JSON.stringify(events)).not.toContain(BIND_PASSWORD);
      expect(
        (await adcsAdmin.getSettings(t.client, t.id)) as {
          bindPasswordSet: boolean;
        },
      ).toMatchObject({ bindPasswordSet: true });
      expect(
        JSON.stringify(await adcsAdmin.getSettings(t.client, t.id)),
      ).not.toContain(BIND_PASSWORD);
      const stored = await kv.readSecret(`adcs/${t.id}/ad-bind`);
      expect(stored.password).toBe(BIND_PASSWORD);
    }, 60_000);

    it('changing the AD target needs the password again, and the old secret is not used', async () => {
      const t = await fresh(ad);
      const base = {
        defaultHostGroupId: t.def.id,
        allowedTemplateOids: [TEMPLATE],
        baseDn: 'DC=corp,DC=example',
        bindDn: 'CN=svc-manar,DC=corp,DC=example',
        serverCaPem: ldapsCa.pem,
      };
      const before = await kv.readSecret(`adcs/${t.id}/ad-bind`);
      for (const change of [
        { ldapsUrl: 'ldaps://attacker.example:636' },
        { bindDn: 'CN=other,DC=corp,DC=example' },
        { serverCaPem: otherCa.pem },
      ]) {
        await expect(
          adcsAdmin.putSettings(t.client, t.id, admin, {
            ...base,
            ldapsUrl: ldaps.url,
            ...change,
          }),
        ).rejects.toThrow('bindPassword is required');
      }
      expect((await t.client.adcsSettings.findFirstOrThrow()).ldapsUrl).toBe(
        ldaps.url,
      );
      expect(await kv.readSecret(`adcs/${t.id}/ad-bind`)).toEqual(before);
      // an unchanged target may be saved without the password
      await adcsAdmin.putSettings(t.client, t.id, admin, {
        ...base,
        ldapsUrl: ldaps.url,
      });
    }, 60_000);

    it('one certificate identity is one host: no second machineId, no taking over another machineId', async () => {
      const t = await fresh(ad);
      crls.set(CRL_URL, await makeCrl(customerCa, []));
      addComputer('pc-bind-a.corp.example', FIN);
      addComputer('pc-bind-b.corp.example', FIN);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireAdcs: true,
        adOuDn: FIN,
      });
      const certA = await computerCert('pc-bind-a.corp.example');
      const certB = await computerCert('pc-bind-b.corp.example');
      const first = await enrol(t, certA, { machineId: 'bind-a' });
      expect(first.status).toBe('APPROVED');
      const hosts0 = await t.client.host.count();
      // the same certificate, another machineId: refused, nothing created
      await expect(
        enrol(t, certA, { machineId: 'bind-a2' }),
      ).rejects.toBeInstanceOf(HostRefusedError);
      // another computer's certificate claiming bind-a's machineId
      await expect(
        enrol(t, certB, { machineId: 'bind-a' }),
      ).rejects.toBeInstanceOf(HostRefusedError);
      expect(await t.client.host.count()).toBe(hosts0);
      // the real owner still re-registers
      const again = await enrol(t, certA, {
        machineId: 'bind-a',
        hostKeys: first.hostKeys,
      });
      expect(again.hostId).toBe(first.hostId);
      // a host enrolled with an install key is not taken over by a certificate
      const key = await new InstallKeysService(audit).create(
        t.client,
        t,
        admin,
        { hostGroupId: t.def.id, label: 'legacy' },
      );
      const keys = await newKeys();
      await hosts.register({
        installKey: key.raw,
        csr: await makeCsrPem(keys, `host://${t.slug}/bind-key`),
        machineId: 'bind-key',
        hostname: 'KEYED',
        os: 'Windows 11',
        keyType: 'SOFTWARE',
        ip: '10.0.0.7',
      });
      await expect(
        enrol(t, certB, { machineId: 'bind-key', hostKeys: keys }),
      ).rejects.toBeInstanceOf(HostRekeyPendingError);
    }, 90_000);

    it('refuses plain ldap:// settings', async () => {
      const t = await fresh(noAd);
      await expect(
        adcsAdmin.putSettings(t.client, t.id, admin, {
          defaultHostGroupId: t.def.id,
          allowedTemplateOids: [TEMPLATE],
          ldapsUrl: 'ldap://dc.corp.example',
          baseDn: 'DC=corp',
          bindDn: 'CN=x',
          serverCaPem: ldapsCa.pem,
          bindPassword: 'x',
        }),
      ).rejects.toThrow('ldaps://');
    }, 60_000);
  });

  describe('TPM attestation', () => {
    async function setupTpm(t: T, withRoot = true) {
      const tpmRoot = await makeCa('TPM Vendor Root');
      if (withRoot) {
        await tpm.addRoot(t.client, t.id, admin, {
          label: 'vendor',
          certPem: tpmRoot.pem,
        });
      }
      const ekKeys = await newKeys();
      const ekCert = await makeLeaf(tpmRoot, {
        keys: ekKeys,
        dns: null,
        eku: null,
      });
      const hostKeys = await newKeys();
      const hostPublic = rsaTpmtPublic(await nodePublic(hostKeys)).toString(
        'base64',
      );
      return { tpmRoot, ekKeys, ekCert, hostKeys, hostPublic };
    }
    const challengeFor = (
      t: T,
      machineId: string,
      s: Awaited<ReturnType<typeof setupTpm>>,
    ) =>
      tpm.challenge({
        tenantSlug: t.slug,
        machineId,
        ekCertificates: [s.ekCert.pem],
        hostKeyPublic: s.hostPublic,
      });
    async function answer(
      t: T,
      c: Awaited<ReturnType<typeof challengeFor>>,
      s: Awaited<ReturnType<typeof setupTpm>>,
      ekPrivate?: Awaited<ReturnType<typeof nodePrivate>>,
    ) {
      const secret = activateCredential({
        ekPrivateKey: ekPrivate ?? (await nodePrivate(s.ekKeys)),
        akName: tpmName(Buffer.from(s.hostPublic, 'base64')),
        credentialBlob: Buffer.from(c.credentialBlob, 'base64'),
        encryptedSecret: Buffer.from(c.encryptedSecret, 'base64'),
      });
      return tpm.activate({
        tenantSlug: t.slug,
        challengeId: c.challengeId,
        secret: secret.toString('base64'),
      });
    }
    async function registerWithKey(
      t: T,
      machineId: string,
      keys: CryptoKeyPair,
      challengeId?: string,
    ) {
      const key = await new InstallKeysService(audit).create(
        t.client,
        t,
        admin,
        {
          hostGroupId: t.def.id,
          label: 'tpm',
        },
      );
      return hosts.register({
        installKey: key.raw,
        csr: await makeCsrPem(keys, `host://${t.slug}/${machineId}`),
        machineId,
        hostname: 'LAPTOP-TPM',
        os: 'Windows 11',
        keyType: 'TPM',
        tpmChallengeId: challengeId,
        ip: '10.0.0.7',
      });
    }

    it('a host that passes activation is tpmVerified and satisfies requireTpm', async () => {
      const t = await fresh(noAd);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireTpm: true,
      });
      const s = await setupTpm(t);
      const c = await challengeFor(t, 'tpm-1', s);
      expect(await answer(t, c, s)).toBe(true);
      const r = await registerWithKey(t, 'tpm-1', s.hostKeys, c.challengeId);
      expect(r.status).toBe('APPROVED');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: r.hostId },
      });
      expect(host).toMatchObject({ tpmVerified: true, keyType: 'TPM' });
      expect(host.tpmEkFingerprint).toHaveLength(64);
      // the challenge is single use
      const replay = await registerWithKey(
        t,
        'tpm-2',
        s.hostKeys,
        c.challengeId,
      );
      expect(replay.status).toBe('PENDING');
    }, 90_000);

    it('a self-reported TPM does not satisfy requireTpm', async () => {
      const t = await fresh(noAd);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireTpm: true,
      });
      const r = await registerWithKey(t, 'claim-1', await newKeys());
      expect(r.status).toBe('PENDING');
      const host = await t.client.host.findUniqueOrThrow({
        where: { id: r.hostId },
      });
      expect(host.tpmVerified).toBe(false);
      // the installer's TPM claim is not kept
      expect(host.keyType).toBe('SOFTWARE');
    }, 60_000);

    it('refuses an EK certificate that does not chain to a configured root', async () => {
      const t = await fresh(noAd);
      await setupTpm(t, true); // a root exists, but not the one that issued this EK certificate
      const forged = await setupTpm(t, false);
      await expect(challengeFor(t, 'f-1', forged)).rejects.toBeInstanceOf(
        TpmAttestationError,
      );
      // a certificate from a CA that is not a TPM root at all
      const fake = await makeLeaf(otherCa, {
        keys: forged.ekKeys,
        dns: null,
        eku: null,
      });
      await expect(
        challengeFor(t, 'f-2', { ...forged, ekCert: fake }),
      ).rejects.toBeInstanceOf(TpmAttestationError);
    }, 90_000);

    it('a TPM without the EK private key cannot activate; three failures end the challenge', async () => {
      const t = await fresh(noAd);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireTpm: true,
      });
      const s = await setupTpm(t);
      const c = await challengeFor(t, 'x-1', s);
      // an attacker holding the EK certificate but not its key
      const thief = await nodePrivate(await newKeys());
      await expect(answer(t, c, s, thief)).rejects.toThrow();
      for (let i = 0; i < 3; i += 1) {
        expect(
          await tpm.activate({
            tenantSlug: t.slug,
            challengeId: c.challengeId,
            secret: Buffer.from(`wrong-${i}`).toString('base64'),
          }),
        ).toBe(false);
      }
      expect(await answer(t, c, s)).toBe(false); // right answer after exhaustion
      const r = await registerWithKey(t, 'x-1', s.hostKeys, c.challengeId);
      expect(r.status).toBe('PENDING');
    }, 90_000);

    it('a verified challenge cannot vouch for a different key or machine', async () => {
      const t = await fresh(noAd);
      await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        requireTpm: true,
      });
      const s = await setupTpm(t);
      const c = await challengeFor(t, 'b-1', s);
      expect(await answer(t, c, s)).toBe(true);
      const otherKey = await registerWithKey(
        t,
        'b-1',
        await newKeys(),
        c.challengeId,
      );
      expect(otherKey.status).toBe('PENDING');
      const c2 = await challengeFor(t, 'b-2', s);
      expect(await answer(t, c2, s)).toBe(true);
      const otherMachine = await registerWithKey(
        t,
        'b-other',
        s.hostKeys,
        c2.challengeId,
      );
      expect(otherMachine.status).toBe('PENDING');
    }, 90_000);

    it('refuses a host key that is not TPM-resident', async () => {
      const t = await fresh(noAd);
      const s = await setupTpm(t);
      const exportable = rsaTpmtPublic(
        await nodePublic(s.hostKeys),
        0x40000,
      ).toString('base64');
      await expect(
        tpm.challenge({
          tenantSlug: t.slug,
          machineId: 's-1',
          ekCertificates: [s.ekCert.pem],
          hostKeyPublic: exportable,
        }),
      ).rejects.toThrow('not TPM-resident');
    }, 60_000);
  });

  describe('rule guard', () => {
    it('refuses rules with only self-reported conditions, on create and on update', async () => {
      const t = await fresh(noAd);
      await expect(
        hostsAdmin.createApprovalRule(t.client, t.id, admin, {
          hostnamePattern: 'dev-*',
        }),
      ).rejects.toBeInstanceOf(UnverifiedRuleError);
      await expect(
        hostsAdmin.createApprovalRule(t.client, t.id, admin, {}),
      ).rejects.toBeInstanceOf(UnverifiedRuleError);
      await expect(
        hostsAdmin.createApprovalRule(t.client, t.id, admin, {
          cidrs: [],
          requireTpm: false,
        }),
      ).rejects.toBeInstanceOf(UnverifiedRuleError);
      const ok = await hostsAdmin.createApprovalRule(t.client, t.id, admin, {
        hostnamePattern: 'dev-*',
        requireAdcs: true,
      });
      await expect(
        hostsAdmin.updateApprovalRule(t.client, t.id, admin, ok.id, {
          requireAdcs: false,
        }),
      ).rejects.toBeInstanceOf(UnverifiedRuleError);
      // a patch that keeps a verified condition is fine
      await hostsAdmin.updateApprovalRule(t.client, t.id, admin, ok.id, {
        requireAdcs: false,
        cidrs: ['10.0.0.0/8'],
      });
      expect(await t.client.hostApprovalRule.count()).toBe(1);
    }, 60_000);

    it('a legacy rule that breaks the guard is skipped at match time', async () => {
      const t = await fresh(noAd);
      await t.client.hostApprovalRule.create({
        data: { hostnamePattern: 'LAPTOP-*' },
      });
      await t.client.hostApprovalRule.create({ data: {} });
      const key = await new InstallKeysService(audit).create(
        t.client,
        t,
        admin,
        {
          hostGroupId: t.def.id,
          label: 'legacy',
        },
      );
      const keys = await newKeys();
      const r = await hosts.register({
        installKey: key.raw,
        csr: await makeCsrPem(keys, `host://${t.slug}/legacy-1`),
        machineId: 'legacy-1',
        hostname: 'LAPTOP-1',
        os: 'Windows 11',
        keyType: 'SOFTWARE',
        ip: '10.0.0.7',
      });
      expect(r.status).toBe('PENDING');
    }, 60_000);
  });
});

interface T {
  id: string;
  slug: string;
  client: PrismaClient;
  def: { id: string };
  fin: { id: string };
  lap: { id: string };
  sales: { id: string };
}
