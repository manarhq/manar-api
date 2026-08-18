/**
 * Domain types for the demo SOC tool backend's in-memory state.
 *
 * This service is a standalone demo fixture (see the Phase 7a design doc
 * at docs/superpowers/specs/2026-08-19-phase7a-demo-soc-tools-design.md)
 * — these shapes exist to make `search-events`/`get-host`/etc. respond
 * with something a demo scenario can narrate, not to model a real SIEM/EDR
 * data model.
 */

export type EdrProcessStatus = 'running' | 'terminated';

export interface EdrProcess {
  pid: number;
  name: string;
  commandLine: string;
  status: EdrProcessStatus;
  suspicious: boolean;
}

export interface EdrHost {
  id: string;
  hostname: string;
  ipAddress: string;
  os: string;
  isolated: boolean;
  lastSeen: string;
  processes: EdrProcess[];
}

export type EventSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SiemEvent {
  id: string;
  timestamp: string;
  host: string;
  eventType: string;
  description: string;
  severity: EventSeverity;
  sourceIp?: string;
  user?: string;
}

export type IncidentStatus = 'open' | 'investigating' | 'closed';

export interface Incident {
  id: string;
  title: string;
  description: string;
  status: IncidentStatus;
  severity: EventSeverity;
  hostId: string;
  suspiciousIp: string;
  relatedUser: string;
  createdAt: string;
}

export interface IamUser {
  id: string;
  username: string;
  displayName: string;
  email: string;
  department: string;
  enabled: boolean;
}

export type IpReputationLevel =
  'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface IpReputation {
  ip: string;
  reputation: IpReputationLevel;
  country: string;
  asn: string;
  notes: string;
}

export interface IpLookupResult extends IpReputation {
  blocked: boolean;
}

export interface FirewallBlockResult {
  ip: string;
  blocked: boolean;
  blocklist: string[];
}
