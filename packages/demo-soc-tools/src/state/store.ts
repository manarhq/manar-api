import {
  seedEvents,
  seedHosts,
  seedIncidents,
  seedIpReputations,
  seedUsers,
} from './seed-data';
import type {
  EdrHost,
  FirewallBlockResult,
  IamUser,
  Incident,
  IpLookupResult,
  IpReputation,
  SiemEvent,
} from '../types';

export type TerminateProcessResult =
  | { ok: true; host: EdrHost }
  | { ok: false; reason: 'host-not-found' | 'process-not-found' };

/**
 * The service's entire state, in memory, for the lifetime of the process
 * (Phase 7a design doc: "Persistence beyond the process lifetime" is
 * explicitly out of scope — this is a demo fixture, not a database).
 *
 * `reset()` restores deterministic seed state — used both at boot and by
 * the unauthenticated `POST /_demo/reset` convenience endpoint so tests
 * and repeated demo runs always start clean.
 */
export class DemoStore {
  private hosts = new Map<string, EdrHost>();
  private incidents = new Map<string, Incident>();
  private users = new Map<string, IamUser>();
  private events: SiemEvent[] = [];
  private ipReputations = new Map<string, IpReputation>();
  private blockedIps = new Set<string>();

  constructor() {
    this.reset();
  }

  reset(): void {
    this.hosts = new Map(seedHosts().map((host) => [host.id, host]));
    this.incidents = new Map(
      seedIncidents().map((incident) => [incident.id, incident]),
    );
    this.users = new Map(seedUsers().map((user) => [user.id, user]));
    this.events = seedEvents();
    this.ipReputations = new Map(
      seedIpReputations().map((rep) => [rep.ip, rep]),
    );
    this.blockedIps = new Set();
  }

  // ---- SIEM ----

  searchEvents(query?: string): SiemEvent[] {
    const events = [...this.events].sort((a, b) =>
      a.timestamp.localeCompare(b.timestamp),
    );

    if (!query) {
      return events;
    }

    const needle = query.toLowerCase();
    return events.filter((event) =>
      [event.host, event.eventType, event.description, event.user ?? '']
        .join(' ')
        .toLowerCase()
        .includes(needle),
    );
  }

  getIncident(id: string): Incident | undefined {
    return this.incidents.get(id);
  }

  // ---- EDR ----

  getHost(id: string): EdrHost | undefined {
    return this.hosts.get(id);
  }

  isolateHost(id: string): EdrHost | undefined {
    const host = this.hosts.get(id);
    if (!host) return undefined;
    host.isolated = true;
    return host;
  }

  releaseHost(id: string): EdrHost | undefined {
    const host = this.hosts.get(id);
    if (!host) return undefined;
    host.isolated = false;
    return host;
  }

  terminateProcess(hostId: string, pid: number): TerminateProcessResult {
    const host = this.hosts.get(hostId);
    if (!host) return { ok: false, reason: 'host-not-found' };

    const process = host.processes.find((p) => p.pid === pid);
    if (!process) return { ok: false, reason: 'process-not-found' };

    process.status = 'terminated';
    return { ok: true, host };
  }

  // ---- IAM ----

  getUser(id: string): IamUser | undefined {
    return this.users.get(id);
  }

  disableUser(id: string): IamUser | undefined {
    const user = this.users.get(id);
    if (!user) return undefined;
    user.enabled = false;
    return user;
  }

  // ---- Firewall ----

  lookupIp(ip: string): IpLookupResult {
    const reputation = this.ipReputations.get(ip) ?? {
      ip,
      reputation: 'unknown' as const,
      country: 'unknown',
      asn: 'unknown',
      notes: 'No reputation data on file for this IP.',
    };

    return { ...reputation, blocked: this.blockedIps.has(ip) };
  }

  blockIp(ip: string): FirewallBlockResult {
    this.blockedIps.add(ip);
    return {
      ip,
      blocked: true,
      blocklist: [...this.blockedIps].sort(),
    };
  }

  unblockIp(ip: string): FirewallBlockResult {
    this.blockedIps.delete(ip);
    return {
      ip,
      blocked: false,
      blocklist: [...this.blockedIps].sort(),
    };
  }
}
