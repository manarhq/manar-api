import { randomBytes } from 'node:crypto';
import type { ExecutionContext } from '@nestjs/common';
import { GoneException, UnauthorizedException } from '@nestjs/common';
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
function world() {
  const hostA = {
    id: 'host-a',
    machineId: 'm-1',
    status: 'APPROVED',
    ownerSubject: 'sub-a',
  };
  const tenantsBySlug: Record<
    string,
    { id: string; slug: string; status: string }
  > = {
    a: { id: 'tid-a', slug: 'a', status: 'ACTIVE' },
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
  const control = {
    tenant: {
      findUnique: vi.fn(({ where }: { where: Record<string, string> }) =>
        Promise.resolve(tenantsBySlug[where.slug ?? ''] ?? null),
      ),
    },
  };
  const manager = {
    getClient: vi.fn((id: string) => Promise.resolve(dbs[id])),
  };
  return {
    guard: new HostAuthGuard(control as never, manager as never),
    hostA,
    dbs,
  };
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
    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(request.hostContext).toBeUndefined();
    // Tenant A's database was never consulted for it.
    expect(
      (dbs['tid-a'] as { host: { findUnique: ReturnType<typeof vi.fn> } }).host
        .findUnique,
    ).not.toHaveBeenCalled();
  });

  it('refuses a serial that was not issued to this host, and a revoked one', async () => {
    const { guard } = world();
    for (const serial of ['0C0C', '0B0B']) {
      const { context } = ctx(await hostCert('host://a/m-1', serial));
      await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    }
  });

  it('refuses an agent certificate, an unknown tenant, an unknown machine, and no certificate', async () => {
    const { guard } = world();
    for (const id of ['agent://a/x', 'host://zzz/m-1', 'host://a/other']) {
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

  it('refuses rejected and revoked hosts', async () => {
    const { guard, hostA } = world();
    for (const status of ['REJECTED', 'REVOKED']) {
      hostA.status = status;
      const { context } = ctx(await hostCert('host://a/m-1', '0A0A'));
      await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
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
    // A certificate the removed host never had learns nothing.
    const { context } = ctx(await hostCert('host://a/m-1', 'FFFF'));
    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('a random serial is unknown', async () => {
    const { guard } = world();
    const { context } = ctx(
      await hostCert(
        'host://a/m-1',
        randomBytes(8).toString('hex').toUpperCase(),
      ),
    );
    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
