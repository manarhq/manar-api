import { randomBytes } from 'node:crypto';
import type { ExecutionContext } from '@nestjs/common';
import {
  GoneException,
  HttpException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { HostAuthGuard } from './host-auth.guard';
import type { RequestWithHost } from './host-context';
import { parseHostIdentifier } from './host-context';

const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

async function hostCert(identifier: string, serialHex: string) {
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serialHex,
    name: 'CN=host',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3_600_000),
    signingAlgorithm: alg,
    keys,
    extensions: [
      new x509.SubjectAlternativeNameExtension([
        { type: 'url', value: identifier },
      ]),
    ],
  });
  return Buffer.from(cert.rawData);
}

function ctx(der: Buffer | null, authorized = true) {
  const request = {
    raw: {
      socket: {
        authorized,
        getPeerCertificate: () => (der ? { raw: der } : {}),
      },
    },
  } as unknown as RequestWithHost;
  return {
    request,
    context: {
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext,
  };
}

/** Two tenants, each with its own database; a host machineId lives in one of them only. */
function world(
  opts: {
    tenantA?: Record<string, unknown>;
    restricted?: boolean | 'error';
  } = {},
) {
  const hostA = {
    id: 'host-a',
    machineId: 'm-1',
    status: 'APPROVED',
    ownerSubject: 'sub-a',
  };
  const tenantsBySlug: Record<string, Record<string, unknown>> = {
    a: { id: 'tid-a', slug: 'a', status: 'ACTIVE', ...opts.tenantA },
    b: { id: 'tid-b', slug: 'b', status: 'ACTIVE' },
  };
  const dbs: Record<string, unknown> = {
    'tid-a': {
      host: {
        findUnique: vi.fn(({ where }: { where: Record<string, string> }) =>
          Promise.resolve(where.machineId === 'm-1' ? hostA : null),
        ),
      },
      hostCertificate: {
        findUnique: vi.fn(({ where }: { where: Record<string, string> }) =>
          Promise.resolve(
            where.serialNumber === '0A0A'
              ? { hostId: 'host-a', revokedAt: null, host: hostA }
              : where.serialNumber === '0B0B'
                ? { hostId: 'host-a', revokedAt: new Date(), host: hostA }
                : null,
          ),
        ),
      },
    },
    'tid-b': {
      host: { findUnique: vi.fn(() => Promise.resolve(null)) },
      hostCertificate: { findUnique: vi.fn(() => Promise.resolve(null)) },
    },
  };
  const deleted: Record<string, { slug: string; reason: string }> = {
    gone: { slug: 'gone', reason: 'account_deleted' },
  };
  const control = {
    tenant: {
      findUnique: vi.fn(({ where }: { where: Record<string, string> }) =>
        Promise.resolve(tenantsBySlug[where.slug ?? ''] ?? null),
      ),
    },
    deletedWorkspace: {
      findUnique: vi.fn(({ where }: { where: Record<string, string> }) =>
        Promise.resolve(deleted[where.slug ?? ''] ?? null),
      ),
    },
  };
  const manager = {
    getClient: vi.fn((id: string) => Promise.resolve(dbs[id])),
  };
  return {
    guard: new HostAuthGuard(
      control as never,
      manager as never,
      {
        activeFor: vi.fn(() =>
          opts.restricted === 'error'
            ? Promise.reject(new ServiceUnavailableException())
            : Promise.resolve(
                opts.restricted ? { id: 'r', kind: 'BAN' } : null,
              ),
        ),
      } as never,
    ),
    hostA,
    dbs,
    tenantsBySlug,
  };
}

/** The refusal a valid device certificate gets: never a 401, which manar-edge 0.1.6 counts (three
 * in a row) as "take Manar's hooks out". 423 is read by every edge as "cannot ask: deny, keep". */
async function refusal(guard: HostAuthGuard, context: ExecutionContext) {
  const error: unknown = await guard
    .canActivate(context)
    .catch((e: unknown) => e);
  expect(error).toBeInstanceOf(HttpException);
  expect(error).not.toBeInstanceOf(UnauthorizedException);
  const e = error as HttpException;
  return { status: e.getStatus(), body: e.getResponse() as { code: string } };
}

describe('HostAuthGuard', () => {
  beforeAll(() => x509.cryptoProvider.set(crypto));

  it('parses only host:// identifiers', () => {
    expect(parseHostIdentifier('host://acme/m-1')).toEqual({
      tenantSlug: 'acme',
      machineId: 'm-1',
    });
    for (const bad of [
      'agent://acme/x',
      'host://acme',
      'host://acme/a/b',
      'host://acme/a b',
      '',
    ]) {
      expect(parseHostIdentifier(bad)).toBeNull();
    }
  });

  it('accepts a host certificate and attaches the host, tenant and owner', async () => {
    const { guard } = world();
    const { request, context } = ctx(await hostCert('host://a/m-1', '0A0A'));
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.hostContext).toEqual({
      hostId: 'host-a',
      tenantId: 'tid-a',
      machineId: 'm-1',
      ownerSubject: 'sub-a',
      status: 'APPROVED',
    });
  });

  it("a host cert of tenant A cannot be used as tenant B's: the tenant comes only from the SAN", async () => {
    const { guard, dbs } = world();
    // A certificate that claims tenant B for a machine that exists only in tenant A.
    const { request, context } = ctx(await hostCert('host://b/m-1', '0A0A'));
    expect(await refusal(guard, context)).toMatchObject({
      status: 423,
      body: { code: 'certificate_revoked' },
    });
    expect(request.hostContext).toBeUndefined();
    // Tenant A's database was never consulted for it.
    expect(
      (dbs['tid-a'] as { host: { findUnique: ReturnType<typeof vi.fn> } }).host
        .findUnique,
    ).not.toHaveBeenCalled();
  });

  it('refuses a serial that was not issued to this host, and a revoked one, with 423 (keep protecting)', async () => {
    const { guard } = world();
    for (const serial of ['0C0C', '0B0B']) {
      const { context } = ctx(await hostCert('host://a/m-1', serial));
      expect(await refusal(guard, context)).toMatchObject({
        status: 423,
        body: { code: 'certificate_revoked' },
      });
    }
  });

  it('a certificate whose SAN names another machine than the one it was issued to is refused', async () => {
    const { guard } = world();
    const { context } = ctx(await hostCert('host://a/other', '0A0A'));
    expect(await refusal(guard, context)).toMatchObject({
      status: 423,
      body: { code: 'certificate_revoked' },
    });
  });

  it('a suspended workspace, or one being deleted, is 423 with its own code, never 401', async () => {
    const { guard, tenantsBySlug } = world();
    for (const [status, code] of [
      ['SUSPENDED', 'account_suspended'],
      ['DEPROVISIONING', 'workspace_deleted'],
      ['DELETED', 'workspace_deleted'],
    ] as const) {
      tenantsBySlug.a!.status = status;
      const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
      expect(await refusal(guard, context)).toMatchObject({
        status: 423,
        body: { code },
      });
    }
  });

  it('a workspace whose owner deleted their account tells its devices 410 device_removed; any other missing workspace is 423', async () => {
    const { guard } = world();
    const gone: unknown = await guard
      .canActivate(ctx(await hostCert('host://gone/m-1', '0A0A')).context)
      .catch((e: unknown) => e);
    expect(gone).toBeInstanceOf(GoneException);
    expect((gone as GoneException).getResponse()).toMatchObject({
      code: 'device_removed',
    });
    const { context } = ctx(await hostCert('host://zzz/m-1', '0A0A'));
    expect(await refusal(guard, context)).toMatchObject({
      status: 423,
      body: { code: 'workspace_deleted' },
    });
  });

  it('a database that cannot be read is 503, never a refusal the device acts on', async () => {
    const { guard, dbs } = world();
    (
      dbs['tid-a'] as { hostCertificate: { findUnique: unknown } }
    ).hostCertificate.findUnique = vi.fn(() =>
      Promise.reject(new Error('connection lost')),
    );
    const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
    const error: unknown = await guard
      .canActivate(context)
      .catch((e: unknown) => e);
    expect((error as HttpException).getStatus()).toBe(503);
  });

  it('refuses an agent certificate and no certificate with 401 (not a device of ours)', async () => {
    const { guard } = world();
    for (const id of ['agent://a/x']) {
      const { context } = ctx(await hostCert(id, '0A0A'));
      await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    }
    await expect(guard.canActivate(ctx(null).context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    await expect(
      guard.canActivate(
        ctx(await hostCert('host://a/m-1', '0A0A'), false).context,
      ),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('refuses rejected and revoked hosts with 423 device_revoked: the device locks, it does not unprotect', async () => {
    const { guard, hostA } = world();
    for (const status of ['REJECTED', 'REVOKED']) {
      hostA.status = status;
      const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
      expect(await refusal(guard, context)).toMatchObject({
        status: 423,
        body: { code: 'device_revoked' },
      });
    }
  });

  it('tells a removed device so with 410 device_removed, its revoked certificate included', async () => {
    const { guard, hostA } = world();
    hostA.status = 'REMOVED';
    for (const serial of ['0A0A', '0B0B']) {
      const { context } = ctx(await hostCert('host://a/m-1', serial));
      const error: unknown = await guard
        .canActivate(context)
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(GoneException);
      expect((error as GoneException).getResponse()).toMatchObject({
        statusCode: 410,
        code: 'device_removed',
      });
    }
    // A certificate the removed host never had is not told it was removed.
    const { context } = ctx(await hostCert('host://a/m-1', 'FFFF'));
    expect(await refusal(guard, context)).toMatchObject({ status: 423 });
  });

  describe('DESK restrictions (spec §9.2, AC-21)', () => {
    it('a workspace Manar suspended answers 423 account_suspended', async () => {
      const { guard } = world({ tenantA: { status: 'SUSPENDED' } });
      const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
      await expect(guard.canActivate(context)).rejects.toMatchObject({
        response: { code: 'account_suspended' },
      });
      // 423 like every refusal of a genuine device: it keeps protecting (live-risk fix).
      await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
        HttpException,
      );
      await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 423 });
    });

    it('a personal workspace whose owner is restricted answers 423 account_suspended', async () => {
      const personal = {
        kind: 'PERSONAL',
        ownerIssuer: 'iss',
        ownerSubject: 'sub-a',
      };
      const { guard } = world({ tenantA: personal, restricted: true });
      const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
      await expect(guard.canActivate(context)).rejects.toMatchObject({
        response: { code: 'account_suspended' },
      });
      const free = world({ tenantA: personal, restricted: false });
      await expect(
        free.guard.canActivate(
          ctx(await hostCert('host://a/m-1', '0A0A')).context,
        ),
      ).resolves.toBe(true);
    });

    it('an unreadable restriction store fails closed', async () => {
      const personal = {
        kind: 'PERSONAL',
        ownerIssuer: 'iss',
        ownerSubject: 'sub-a',
      };
      const { guard } = world({ tenantA: personal, restricted: 'error' });
      const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
      await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
    });
  });

  it('a random serial is unknown', async () => {
    const { guard } = world();
    const { context } = ctx(
      await hostCert(
        'host://a/m-1',
        randomBytes(8).toString('hex').toUpperCase(),
      ),
    );
    expect(await refusal(guard, context)).toMatchObject({
      status: 423,
      body: { code: 'certificate_revoked' },
    });
  });
});
