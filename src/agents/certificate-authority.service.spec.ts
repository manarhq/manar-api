import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { OpenBaoPkiClient } from '../openbao/openbao-pki.client';
import { CertificateAuthorityService } from './certificate-authority.service';

interface CertRow {
  id: string;
  agentId: string;
  serialNumber: string;
  revokedAt: Date | null;
  revocationReason: string | null;
  caRevokedAt: Date | null;
}

/** Just enough of the tenant client for `revoke`, backed by arrays. */
function fakeTenantClient(certs: CertRow[]) {
  const agent = { id: 'agent-1', status: 'ACTIVE' };
  const client = {
    agent: {
      update: vi.fn(({ data }: { data: { status: string } }) => {
        agent.status = data.status;
        return Promise.resolve();
      }),
    },
    agentCertificate: {
      updateMany: vi.fn(({ data }: { data: Partial<CertRow> }) => {
        for (const c of certs) if (c.revokedAt === null) Object.assign(c, data);
        return Promise.resolve();
      }),
      findMany: vi.fn(() =>
        Promise.resolve(
          certs.filter((c) => c.revokedAt !== null && c.caRevokedAt === null),
        ),
      ),
      update: vi.fn(
        ({
          where,
          data,
        }: {
          where: { id: string };
          data: Partial<CertRow>;
        }) => {
          Object.assign(
            certs.find((c) => c.id === where.id)!,
            data,
          );
          return Promise.resolve();
        },
      ),
    },
    $transaction: vi.fn((ops: Promise<unknown>[]) => Promise.all(ops)),
  };
  return { client: client as unknown as TenantPrismaClient, agent };
}

function cert(id: string, serialNumber: string): CertRow {
  return {
    id,
    agentId: 'agent-1',
    serialNumber,
    revokedAt: null,
    revocationReason: null,
    caRevokedAt: null,
  };
}

describe('CertificateAuthorityService.revoke (S10: local first)', () => {
  it('blocks the agent locally even when OpenBao is down, and reports the CA revocation as pending', async () => {
    const c1 = cert('c1', '0A0B');
    const certs = [c1];
    const { client, agent } = fakeTenantClient(certs);
    const openBao = {
      revoke: vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED')),
    };
    const service = new CertificateAuthorityService(
      openBao as unknown as OpenBaoPkiClient,
    );

    const result = await service.revoke(client, 'agent-1', 'compromised');

    expect(agent.status).toBe('REVOKED');
    expect(c1.revokedAt).toBeInstanceOf(Date);
    expect(c1.caRevokedAt).toBeNull();
    expect(result).toEqual({ caRevocationPending: 1 });
  });

  it('retries the owed CA revocation on the next call and records the confirmation', async () => {
    const c1 = cert('c1', '0A0B');
    const certs = [c1];
    const { client } = fakeTenantClient(certs);
    const openBao = {
      revoke: vi
        .fn()
        .mockRejectedValueOnce(new Error('connect ECONNREFUSED'))
        .mockResolvedValue(undefined),
    };
    const service = new CertificateAuthorityService(
      openBao as unknown as OpenBaoPkiClient,
    );

    await service.revoke(client, 'agent-1', 'compromised');
    const firstRevokedAt = c1.revokedAt;
    const result = await service.revoke(client, 'agent-1', 'compromised');

    expect(openBao.revoke).toHaveBeenCalledTimes(2);
    expect(openBao.revoke).toHaveBeenLastCalledWith('0A:0B');
    expect(c1.caRevokedAt).toBeInstanceOf(Date);
    expect(c1.revokedAt).toBe(firstRevokedAt);
    expect(result).toEqual({ caRevocationPending: 0 });
  });

  it('commits local revocation before calling OpenBao', async () => {
    const c1 = cert('c1', '0A0B');
    const certs = [c1];
    const { client, agent } = fakeTenantClient(certs);
    let statusSeenByOpenBao: string | undefined;
    const openBao = {
      revoke: vi.fn(() => {
        statusSeenByOpenBao = agent.status;
        return Promise.resolve();
      }),
    };
    const service = new CertificateAuthorityService(
      openBao as unknown as OpenBaoPkiClient,
    );

    await service.revoke(client, 'agent-1', 'compromised');

    expect(statusSeenByOpenBao).toBe('REVOKED');
  });
});

describe('CertificateAuthorityService CSR names', () => {
  x509.cryptoProvider.set(webcrypto as unknown as Crypto);
  async function csrWith(names: x509.JsonGeneralName[]): Promise<string> {
    const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
    const keys = (await webcrypto.subtle.generateKey(alg, true, [
      'sign',
      'verify',
    ])) as unknown as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: 'CN=test',
      keys,
      signingAlgorithm: alg,
      extensions: [new x509.SubjectAlternativeNameExtension(names)],
    });
    return csr.toString('pem');
  }
  const ca = new CertificateAuthorityService({} as OpenBaoPkiClient);

  it('accepts exactly the one expected URI name', async () => {
    await expect(
      ca.assertCsrNames(
        await csrWith([{ type: 'url', value: 'host://t/m1' }]),
        'host://t/m1',
      ),
    ).resolves.toBeUndefined();
  });

  it('refuses any extra name (DNS, IP, email) that would be signed verbatim', async () => {
    for (const extra of [
      { type: 'dns', value: 'manar-api.internal' },
      { type: 'ip', value: '10.0.0.1' },
      { type: 'email', value: 'x@example.test' },
    ] as x509.JsonGeneralName[]) {
      await expect(
        ca.assertCsrNames(
          await csrWith([{ type: 'url', value: 'host://t/m1' }, extra]),
          'host://t/m1',
        ),
      ).rejects.toThrow(/Subject Alternative Name/);
    }
  });
});

describe('CertificateAuthorityService.revokeHostCertificates', () => {
  it("asks OpenBao in its colon-hex serial format and records the CA's confirmation", async () => {
    const revoke = vi.fn(() => Promise.resolve());
    const rows = [
      {
        id: 'c1',
        serialNumber: '0a1b2c',
        revokedAt: null as Date | null,
        caRevokedAt: null as Date | null,
      },
    ];
    const client = {
      hostCertificate: {
        updateMany: vi.fn(({ data }: { data: { revokedAt: Date } }) => {
          for (const r of rows) if (!r.revokedAt) r.revokedAt = data.revokedAt;
          return Promise.resolve();
        }),
        findMany: vi.fn(() =>
          Promise.resolve(rows.filter((r) => r.revokedAt && !r.caRevokedAt)),
        ),
        update: vi.fn(
          ({
            where,
            data,
          }: {
            where: { id: string };
            data: { caRevokedAt: Date };
          }) => {
            rows.find((r) => r.id === where.id)!.caRevokedAt = data.caRevokedAt;
            return Promise.resolve();
          },
        ),
      },
    } as unknown as TenantPrismaClient;
    const ca = new CertificateAuthorityService({
      revoke,
    } as unknown as OpenBaoPkiClient);

    await ca.revokeHostCertificates(client, 'h1');

    expect(revoke).toHaveBeenCalledWith('0A:1B:2C');
    expect(rows[0]!.caRevokedAt).not.toBeNull();
  });
});
