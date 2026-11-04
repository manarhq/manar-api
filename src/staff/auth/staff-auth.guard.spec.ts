import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { StaffAuthGuard, verifyStaffClaims } from './staff-auth.guard';
import { checkStepUp } from './step-up';

const ISS = 'https://auth.test/realms/vax-staff';
const TID = '11111111-2222-3333-4444-555555555555';
const cfg = {
  issuer: ISS,
  clientId: 'manar-admin',
  audience: 'manar-api-staff',
  entraTenantId: TID,
};

let key: CryptoKey;
let jwks: JWTVerifyGetKey;
beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  key = pair.privateKey;
  jwks = () => Promise.resolve(pair.publicKey);
});

const good = () => ({
  typ: 'Bearer',
  azp: 'manar-admin',
  aud: ['manar-api-staff', 'account'],
  sub: 'kc-sub-1',
  email: 'ali@fixio.ae',
  email_verified: true,
  name: 'Ali Awwad',
  idp: 'entra',
  entra_tid: TID,
  entra_oid: 'oid-ali',
  acr: 'staff',
  auth_time: Math.floor(Date.now() / 1000) - 60,
});
const sign = (c: Record<string, unknown>, iss = ISS) =>
  new SignJWT(c)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(iss)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);

describe('verifyStaffClaims', () => {
  it('accepts a staff token from Entra through vax-staff', async () => {
    await expect(
      verifyStaffClaims(await sign(good()), cfg, jwks),
    ).resolves.toMatchObject({
      sub: 'kc-sub-1',
      entra_oid: 'oid-ali',
    });
  });

  it.each([
    ['another issuer', {}, 'https://auth.test/realms/manar'],
    ['an id token', { typ: 'ID' }, ISS],
    ['another client', { azp: 'manar-web' }, ISS],
    ['no CORE audience', { aud: ['account'] }, ISS],
    ['a local password user', { idp: undefined }, ISS],
    ['another IdP', { idp: 'github' }, ISS],
    ['another Entra tenant', { entra_tid: 'other' }, ISS],
    ['no Entra object id', { entra_oid: undefined }, ISS],
    ['an unverified email', { email_verified: false }, ISS],
  ])('refuses %s', async (_name, change, iss) => {
    await expect(
      verifyStaffClaims(await sign({ ...good(), ...change }, iss), cfg, jwks),
    ).rejects.toMatchObject({ status: 401 });
  });
});

describe('StaffAuthGuard staff resolution', () => {
  const claims = { ...good(), iss: ISS };
  const row = (over: Record<string, unknown> = {}) => ({
    id: 'staff-ali',
    email: 'ali@fixio.ae',
    displayName: 'Ali Awwad',
    title: '',
    team: 'SALES',
    status: 'ACTIVE',
    entraOid: 'oid-ali',
    subject: 'kc-sub-1',
    ...over,
  });
  const make = (byOid: unknown, fail = false) => {
    const updates: unknown[] = [];
    const audit: unknown[] = [];
    const control = {
      staffMember: {
        findUnique: () =>
          fail ? Promise.reject(new Error('db down')) : Promise.resolve(byOid),
        updateMany: (u: unknown) => {
          updates.push(u);
          return Promise.resolve({ count: 1 });
        },
      },
    };
    const guard = new StaffAuthGuard(
      { get: () => undefined } as never,
      control as never,
      { append: (a: unknown) => (audit.push(a), Promise.resolve()) } as never,
      {} as never,
    );
    return { guard, updates, audit };
  };

  it('finds an ACTIVE staff member by their Entra object id', async () => {
    const { guard } = make(row());
    await expect(guard.resolveStaff(claims)).resolves.toMatchObject({
      staffId: 'staff-ali',
      firstName: 'Ali',
    });
  });

  it('refuses a DISABLED staff member', async () => {
    const { guard } = make(row({ status: 'DISABLED' }));
    await expect(guard.resolveStaff(claims)).rejects.toMatchObject({
      status: 403,
    });
  });

  it('records the Keycloak subject of a row pre-bound by object id, once', async () => {
    const { guard, updates, audit } = make(row({ subject: null }));
    await guard.resolveStaff(claims);
    expect(updates[0]).toMatchObject({
      where: { id: 'staff-ali', subject: null },
    });
    expect(audit[0]).toMatchObject({ action: 'staff.bound' });
  });

  it('refuses and records a bound row signing in with another Keycloak subject', async () => {
    const { guard, audit } = make(row({ subject: 'kc-someone-else' }));
    await expect(guard.resolveStaff(claims)).rejects.toMatchObject({
      status: 403,
      response: { code: 'staff_identity_mismatch' },
    });
    expect(audit[0]).toMatchObject({ action: 'staff.identity_mismatch' });
  });

  it('never binds by email: an unknown object id is not staff', async () => {
    const { guard, updates } = make(null);
    await expect(guard.resolveStaff(claims)).rejects.toMatchObject({
      status: 403,
    });
    expect(updates).toHaveLength(0);
  });

  it('lets an unbound caller through only where the route allows it (invite claim)', async () => {
    const { guard } = make(null);
    await expect(
      guard.resolveStaff(claims, { allowUnbound: true }),
    ).resolves.toBeNull();
  });

  it('answers 503 when the control database is down (fail closed)', async () => {
    const { guard } = make(null, true);
    await expect(guard.resolveStaff(claims)).rejects.toMatchObject({
      status: 503,
    });
  });
});

describe('checkStepUp', () => {
  const now = 1_800_000_000;
  it('needs acr=passkey', () => {
    expect(() =>
      checkStepUp({ acr: 'staff', authTime: now - 10 }, now),
    ).toThrow();
  });
  it('needs a sign-in no older than 300 seconds', () => {
    expect(() =>
      checkStepUp({ acr: 'passkey', authTime: now - 301 }, now),
    ).toThrow();
    expect(() =>
      checkStepUp({ acr: 'passkey', authTime: now - 299 }, now),
    ).not.toThrow();
    expect(() => checkStepUp({ acr: 'passkey' }, now)).toThrow();
  });
  it('answers 401 step_up_required', () => {
    try {
      checkStepUp({ acr: 'staff', authTime: now }, now);
    } catch (e) {
      expect(e).toMatchObject({
        status: 401,
        response: { code: 'step_up_required' },
      });
    }
  });
});
