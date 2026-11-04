import { randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { ControlPrismaService } from '../../src/database/control-prisma.service';
import type { BuiltInStaffRole } from '../../src/staff/rbac/permissions';
import { StaffRbacService } from '../../src/staff/rbac/staff-rbac.service';
import { StaffAppModule } from '../../src/staff/staff-app.module';
import { createStaffUser, staffToken } from './staff-realm';
import { STAFF_E2E_SUFFIX, STAFF_E2E_TID } from './staff-env';

export interface SeededStaff {
  id: string;
  email: string;
  oid: string;
  token: () => Promise<string>;
}

/** Boots the staff listener's own app (as main.ts does) against the real stack. */
export async function bootStaffApp() {
  const moduleRef = await Test.createTestingModule({
    imports: [StaffAppModule],
  }).compile();
  const app = moduleRef.createNestApplication<NestFastifyApplication>(
    new FastifyAdapter(),
  );
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  const control = app.get(ControlPrismaService);
  const rbac = app.get(StaffRbacService);
  await rbac.ensureBuiltInRoles();
  const roleId = async (key: string) =>
    (await control.staffRole.findUniqueOrThrow({ where: { key } })).id;

  /** An ACTIVE, bound staff member with a role, and a Keycloak user that signs in as them. */
  async function seed(
    name: string,
    role: BuiltInStaffRole | null,
    opts: {
      eligible?: BuiltInStaffRole;
      team?: 'DEV' | 'SALES' | 'PARTNERSHIPS' | 'SUPPORT' | 'TRUST_SAFETY';
      acr?: string;
    } = {},
  ): Promise<SeededStaff> {
    const email = `${name}-${STAFF_E2E_SUFFIX}@fixio.test`;
    const oid = randomUUID();
    const row = await control.staffMember.create({
      data: {
        email,
        displayName: `${name[0]!.toUpperCase()}${name.slice(1)} Staff`,
        team: opts.team ?? 'DEV',
        status: 'ACTIVE',
        entraOid: oid,
        boundAt: new Date(),
      },
    });
    if (role)
      await rbac.grant({
        roleId: await roleId(role),
        principalType: 'STAFF',
        principalId: row.id,
        kind: 'ACTIVE',
        grantedBy: 'system',
      });
    if (opts.eligible)
      await rbac.grant({
        roleId: await roleId(opts.eligible),
        principalType: 'STAFF',
        principalId: row.id,
        kind: 'ELIGIBLE',
        grantedBy: 'system',
      });
    await createStaffUser({ email, oid, tid: STAFF_E2E_TID, acr: opts.acr });
    return { id: row.id, email, oid, token: () => staffToken(email) };
  }

  const http = () => request(app.getHttpServer());
  return { app, control, rbac, seed, roleId, http };
}
