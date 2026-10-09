/**
 * DEMO FIXTURE seed state for the local Microsoft Graph / Defender for
 * Endpoint mimic (`./fixture.ts`). Every identifier is synthetic and every
 * domain is under `fixture.example`; nothing here was read from a real
 * tenant. The shapes follow the public Graph v1.0 and Defender API
 * references closely enough to exercise manar-api's Microsoft connector,
 * not to stand in for either service.
 */

export const FIXTURE_USER_ID = '7f3c2a1e-4b5d-4e6f-8a9b-0c1d2e3f4a5b';
export const FIXTURE_USER_UPN = 'adele.vance@fixture.example';
export const FIXTURE_SECOND_USER_ID = '2b1e9c7d-5a3f-4c8e-9d0b-1a2b3c4d5e6f';
export const FIXTURE_MACHINE_ID = '4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70';
export const FIXTURE_INCIDENT_ID = '4201';
export const FIXTURE_GROUP_ID = '5c0de9a1-7b2f-4e3d-8c1a-9f8e7d6c5b4a';
export const FIXTURE_DYNAMIC_GROUP_ID = '6d1ef0b2-8c3a-4f4e-9d2b-0a9f8e7d6c5b';

export interface FixtureUser {
  id: string;
  userPrincipalName: string;
  displayName: string;
  accountEnabled: boolean;
  /** Fixture-only bookkeeping, never serialized: when sessions were last revoked / the password last reset. */
  sessionsRevokedAt: string | null;
  passwordResetAt: string | null;
  forceChangePasswordNextSignIn: boolean;
  /** Registered authentication methods (`id`, `@odata.type`), as Graph lists them. */
  authMethods: { id: string; '@odata.type': string }[];
}

export interface FixtureGroup {
  id: string;
  displayName: string;
  groupTypes: string[];
  mailEnabled: boolean;
  /** Member user ids. */
  members: string[];
}

export interface FixtureRiskyUser {
  id: string;
  userPrincipalName: string;
  riskLevel: 'none' | 'low' | 'medium' | 'high';
  riskState:
    'none' | 'atRisk' | 'confirmedCompromised' | 'dismissed' | 'remediated';
  riskDetail: string;
  riskLastUpdatedDateTime: string;
}

export interface FixtureMachine {
  id: string;
  computerDnsName: string;
  osPlatform: string;
  healthStatus: string;
  riskScore: string;
  exposureLevel: string;
  lastSeen: string;
}

export interface FixtureMachineAction {
  id: string;
  type: string;
  requestor: string;
  requestorComment: string;
  status: 'Pending' | 'Succeeded';
  machineId: string;
  computerDnsName: string;
  creationDateTimeUtc: string;
  lastUpdateDateTimeUtc: string;
}

export interface FixtureSeed {
  users: FixtureUser[];
  groups: FixtureGroup[];
  riskyUsers: FixtureRiskyUser[];
  machines: FixtureMachine[];
  incidents: Record<string, unknown>[];
  alerts: Record<string, unknown>[];
  signIns: Record<string, unknown>[];
}

const T0 = '2026-09-25T06:12:00Z';

export function seedData(): FixtureSeed {
  return {
    users: [
      {
        id: FIXTURE_USER_ID,
        userPrincipalName: FIXTURE_USER_UPN,
        displayName: 'Adele Vance (fixture)',
        accountEnabled: true,
        sessionsRevokedAt: null,
        passwordResetAt: null,
        forceChangePasswordNextSignIn: false,
        authMethods: [
          {
            id: '28c10230-6103-485e-b985-444c60001490',
            '@odata.type': '#microsoft.graph.passwordAuthenticationMethod',
          },
          {
            id: '3179e48a-750b-4051-897c-87b9720928f7',
            '@odata.type': '#microsoft.graph.phoneAuthenticationMethod',
          },
          {
            id: 'b1c2d3e4-0001-4a5b-8c6d-7e8f9a0b1c2d',
            '@odata.type':
              '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
          },
        ],
      },
      {
        id: FIXTURE_SECOND_USER_ID,
        userPrincipalName: 'lee.gu@fixture.example',
        displayName: 'Lee Gu (fixture)',
        accountEnabled: true,
        sessionsRevokedAt: null,
        passwordResetAt: null,
        forceChangePasswordNextSignIn: false,
        authMethods: [],
      },
    ],
    groups: [
      {
        id: FIXTURE_GROUP_ID,
        displayName: 'Helpdesk (fixture)',
        groupTypes: [],
        mailEnabled: false,
        members: [FIXTURE_USER_ID],
      },
      {
        id: FIXTURE_DYNAMIC_GROUP_ID,
        displayName: 'All staff (fixture, dynamic)',
        groupTypes: ['DynamicMembership'],
        mailEnabled: false,
        members: [FIXTURE_USER_ID, FIXTURE_SECOND_USER_ID],
      },
    ],
    riskyUsers: [
      {
        id: FIXTURE_USER_ID,
        userPrincipalName: FIXTURE_USER_UPN,
        riskLevel: 'high',
        riskState: 'atRisk',
        riskDetail: 'none',
        riskLastUpdatedDateTime: T0,
      },
    ],
    machines: [
      {
        id: FIXTURE_MACHINE_ID,
        computerDnsName: 'fx-ws-042.fixture.example',
        osPlatform: 'Windows11',
        healthStatus: 'Active',
        riskScore: 'High',
        exposureLevel: 'Medium',
        lastSeen: T0,
      },
    ],
    incidents: [
      {
        id: FIXTURE_INCIDENT_ID,
        displayName:
          'Credential theft and malware on one endpoint (DEMO FIXTURE)',
        status: 'active',
        severity: 'high',
        classification: 'unknown',
        createdDateTime: T0,
        lastUpdateDateTime: T0,
        assignedTo: null,
        incidentWebUrl: 'https://security.fixture.example/incidents/4201',
      },
    ],
    alerts: [
      {
        id: 'da-fixture-0001',
        incidentId: FIXTURE_INCIDENT_ID,
        title: 'Credential dumping tool detected on fx-ws-042',
        severity: 'high',
        status: 'new',
        serviceSource: 'microsoftDefenderForEndpoint',
        createdDateTime: T0,
        evidence: [
          {
            '@odata.type': '#microsoft.graph.security.deviceEvidence',
            mdeDeviceId: FIXTURE_MACHINE_ID,
            deviceDnsName: 'fx-ws-042.fixture.example',
          },
          {
            '@odata.type': '#microsoft.graph.security.fileEvidence',
            fileDetails: {
              fileName: 'lsass-dump.exe',
              sha1: '3395856ce81f2b7382dee72602f798b642f14140',
            },
          },
        ],
      },
      {
        id: 'da-fixture-0002',
        incidentId: FIXTURE_INCIDENT_ID,
        title: 'Sign-in from an unfamiliar location for adele.vance',
        severity: 'medium',
        status: 'new',
        serviceSource: 'azureAdIdentityProtection',
        createdDateTime: T0,
        evidence: [
          {
            '@odata.type': '#microsoft.graph.security.userEvidence',
            userAccount: {
              azureAdUserId: FIXTURE_USER_ID,
              userPrincipalName: FIXTURE_USER_UPN,
            },
          },
        ],
      },
    ],
    signIns: [
      {
        id: 'si-fixture-0001',
        createdDateTime: '2026-09-25T05:58:00Z',
        userId: FIXTURE_USER_ID,
        userPrincipalName: FIXTURE_USER_UPN,
        appDisplayName: 'Office 365 Exchange Online',
        ipAddress: '203.0.113.77',
        location: { city: 'Unknown', countryOrRegion: 'ZZ' },
        riskLevelDuringSignIn: 'high',
        status: { errorCode: 0 },
      },
      {
        id: 'si-fixture-0002',
        createdDateTime: '2026-09-24T07:40:00Z',
        userId: FIXTURE_USER_ID,
        userPrincipalName: FIXTURE_USER_UPN,
        appDisplayName: 'Microsoft Teams',
        ipAddress: '198.51.100.20',
        location: { city: 'Abu Dhabi', countryOrRegion: 'AE' },
        riskLevelDuringSignIn: 'none',
        status: { errorCode: 0 },
      },
    ],
  };
}
