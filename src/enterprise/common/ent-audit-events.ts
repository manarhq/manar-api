/** Audit event types for enterprise mode, spread into AUDIT_EVENT_TYPES (src/audit/audit-event-types.ts). */
export const ENT_AUDIT_EVENT_TYPES = {
  /** A WATCH browser enrolled with an enrolment key. */
  ENT_DEVICE_ENROLLED: 'ent.device.enrolled',
  /** A device proved its person through a nonce-bound id_token. */
  ENT_DEVICE_IDENTITY_VERIFIED: 'ent.device.identity_verified',
  /** A tamper signal opened (unpacked copy, managed configuration changed). */
  ENT_DEVICE_TAMPER: 'ent.device.tamper',
} as const;
