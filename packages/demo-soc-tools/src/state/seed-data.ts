import type {
  EdrHost,
  IamUser,
  Incident,
  IpReputation,
  SiemEvent,
} from '../types';

/**
 * Deterministic seed state (Phase 7a design doc, "Seed data" section).
 *
 * IDs here are deliberately recognizable and stable — `WS-042`,
 * `INC-2026-0042`, the `jdoe` user, and the `203.0.113.77` suspicious IP
 * (RFC 5737 TEST-NET-3, safe to use in a demo) are all reused by Phase
 * 13's full demo scenario, so nothing here should be renamed casually.
 *
 * Each function below returns a *fresh* object graph on every call —
 * `DemoStore.reset()` calls these rather than deep-cloning a shared
 * static object, so seeded state can never accidentally alias mutable
 * state a previous test/demo run mutated.
 */

export function seedHosts(): EdrHost[] {
  return [
    {
      id: 'WS-042',
      hostname: 'WS-042',
      ipAddress: '10.20.30.42',
      os: 'Windows 11 Enterprise',
      isolated: false,
      lastSeen: '2026-08-15T09:20:11Z',
      processes: [
        {
          pid: 4521,
          name: 'powershell.exe',
          commandLine:
            'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdw...',
          status: 'running',
          suspicious: true,
        },
        {
          pid: 1188,
          name: 'explorer.exe',
          commandLine: 'C:\\Windows\\explorer.exe',
          status: 'running',
          suspicious: false,
        },
      ],
    },
    {
      id: 'WS-017',
      hostname: 'WS-017',
      ipAddress: '10.20.30.17',
      os: 'Windows 11 Enterprise',
      isolated: false,
      lastSeen: '2026-08-15T09:20:11Z',
      processes: [
        {
          pid: 2044,
          name: 'explorer.exe',
          commandLine: 'C:\\Windows\\explorer.exe',
          status: 'running',
          suspicious: false,
        },
      ],
    },
  ];
}

export function seedIncidents(): Incident[] {
  return [
    {
      id: 'INC-2026-0042',
      title: 'Suspicious encoded PowerShell execution on WS-042',
      description:
        'EDR detected an encoded PowerShell command (pid 4521) spawned on ' +
        'WS-042 shortly after user jdoe authenticated. An outbound ' +
        'connection was then observed from WS-042 to 203.0.113.77, an IP ' +
        'with a known-malicious reputation.',
      status: 'open',
      severity: 'high',
      hostId: 'WS-042',
      suspiciousIp: '203.0.113.77',
      relatedUser: 'jdoe',
      createdAt: '2026-08-15T09:14:22Z',
    },
  ];
}

export function seedUsers(): IamUser[] {
  return [
    {
      id: 'jdoe',
      username: 'jdoe',
      displayName: 'Jane Doe',
      email: 'jdoe@manar-demo.local',
      department: 'Finance',
      enabled: true,
    },
    {
      id: 'bsmith',
      username: 'bsmith',
      displayName: 'Bob Smith',
      email: 'bsmith@manar-demo.local',
      department: 'Engineering',
      enabled: true,
    },
  ];
}

export function seedEvents(): SiemEvent[] {
  return [
    {
      id: 'EVT-1001',
      timestamp: '2026-08-15T09:10:03Z',
      host: 'WS-042',
      eventType: 'authentication',
      description: 'User jdoe authenticated to WS-042 from IP 10.20.30.42.',
      severity: 'low',
      sourceIp: '10.20.30.42',
      user: 'jdoe',
    },
    {
      id: 'EVT-1002',
      timestamp: '2026-08-15T09:13:47Z',
      host: 'WS-042',
      eventType: 'process-creation',
      description: 'Encoded PowerShell command spawned (pid 4521) on WS-042.',
      severity: 'high',
      user: 'jdoe',
    },
    {
      id: 'EVT-1003',
      timestamp: '2026-08-15T09:14:05Z',
      host: 'WS-042',
      eventType: 'network-connection',
      description: 'Outbound connection from WS-042 to 203.0.113.77:443.',
      severity: 'critical',
      sourceIp: '203.0.113.77',
    },
    {
      id: 'EVT-1004',
      timestamp: '2026-08-15T09:14:22Z',
      host: 'WS-042',
      eventType: 'incident-created',
      description: 'Incident INC-2026-0042 opened for host WS-042.',
      severity: 'high',
    },
    {
      id: 'EVT-1005',
      timestamp: '2026-08-15T09:20:11Z',
      host: 'WS-017',
      eventType: 'authentication',
      description: 'User bsmith authenticated to WS-017 from IP 10.20.30.17.',
      severity: 'low',
      sourceIp: '10.20.30.17',
      user: 'bsmith',
    },
  ];
}

export function seedIpReputations(): IpReputation[] {
  return [
    {
      ip: '203.0.113.77',
      reputation: 'malicious',
      country: 'RU',
      asn: 'AS64512',
      notes:
        'Known C2 infrastructure — associated with incident INC-2026-0042.',
    },
    {
      ip: '10.20.30.42',
      reputation: 'clean',
      country: 'US',
      asn: 'AS64500',
      notes: 'Internal corporate workstation subnet.',
    },
    {
      ip: '10.20.30.17',
      reputation: 'clean',
      country: 'US',
      asn: 'AS64500',
      notes: 'Internal corporate workstation subnet.',
    },
  ];
}
