/**
 * Phase 9b (OCSF mapping, Section 50). This codebase targets **OCSF schema
 * v1.9.0** (`https://schema.ocsf.io/1.9.0/`, the current stable release as
 * of this phase — v1.10.0 exists only as a `-dev` prerelease) — pinned
 * explicitly here rather than "whatever the latest schema happens to be"
 * so a future schema bump is a deliberate, reviewed change to this file,
 * not a silent drift. See `docs/ocsf-mapping.md` for which
 * `AuditEvent.eventType`s map to which class below, and why the rest
 * deliberately don't.
 *
 * Only the fields this mapper actually populates are typed here — not a
 * full reproduction of any class's schema (every class has dozens of
 * optional fields this phase's mapping never sets).
 */
export const OCSF_SCHEMA_VERSION = '1.9.0';

/** Every OCSF event class carries this — https://schema.ocsf.io/1.9.0/base_event. */
export interface OcsfMetadata {
  version: string;
  product: { name: string; vendor_name: string };
}

/** https://schema.ocsf.io/1.9.0/objects/actor */
export interface OcsfActor {
  user: {
    uid: string;
    /**
     * OCSF's `user.type` is a free-text "the type of the user" field —
     * genuinely the right place for Manar's `human`/`agent`/`system`
     * actor kind, not a repurposed unrelated field.
     */
    type: string;
  };
}

/** https://schema.ocsf.io/1.9.0/objects/user */
export interface OcsfUser {
  uid: string;
  type: string;
}

/** https://schema.ocsf.io/1.9.0/classes/authentication (class_uid 3002). */
export interface OcsfAuthenticationEvent {
  class_uid: 3002;
  class_name: 'Authentication';
  category_uid: 3;
  category_name: 'Identity & Access Management';
  activity_id: 1 | 2; // 1 = Logon, 2 = Logoff
  activity_name: 'Logon' | 'Logoff';
  type_uid: number;
  severity_id: number;
  status_id: 0 | 1 | 2; // Unknown | Success | Failure
  status: 'Unknown' | 'Success' | 'Failure';
  time: number;
  metadata: OcsfMetadata;
  user: OcsfUser;
  actor: OcsfActor;
  message: string;
  /** OCSF's own documented catch-all for fields with no schema equivalent — see docs/ocsf-mapping.md. */
  unmapped: Record<string, unknown>;
}

/** https://schema.ocsf.io/1.9.0/classes/authorize_session (class_uid 3003). */
export interface OcsfAuthorizeSessionEvent {
  class_uid: 3003;
  class_name: 'Authorize Session';
  category_uid: 3;
  category_name: 'Identity & Access Management';
  activity_id: 1; // Assign Privileges
  activity_name: 'Assign Privileges';
  type_uid: number;
  severity_id: number;
  status_id: 0 | 1 | 2; // Unknown (pending) | Success (allowed) | Failure (denied)
  status: 'Unknown' | 'Success' | 'Failure';
  time: number;
  metadata: OcsfMetadata;
  user: OcsfUser;
  actor: OcsfActor;
  privileges: string[];
  session: { uid: string };
  message: string;
  unmapped: Record<string, unknown>;
}

/** https://schema.ocsf.io/1.9.0/classes/api_activity (class_uid 6003). */
export interface OcsfApiActivityEvent {
  class_uid: 6003;
  class_name: 'API Activity';
  category_uid: 6;
  category_name: 'Application Activity';
  activity_id: 0; // Unknown — see docs/ocsf-mapping.md for why this phase never infers Create/Read/Update/Delete
  activity_name: 'Unknown';
  type_uid: number;
  severity_id: number;
  status_id: 0 | 1 | 2; // Unknown (started) | Success (completed) | Failure (failed)
  status: 'Unknown' | 'Success' | 'Failure';
  time: number;
  metadata: OcsfMetadata;
  actor: OcsfActor;
  api: { operation: string; service: { name: string } };
  resources: { uid: string }[];
  message: string;
  unmapped: Record<string, unknown>;
}

export type OcsfEvent =
  OcsfAuthenticationEvent | OcsfAuthorizeSessionEvent | OcsfApiActivityEvent;

export type OcsfMappingResult =
  | { mapped: true; ocsf: OcsfEvent }
  | { mapped: false; eventType: string; reason: string };
