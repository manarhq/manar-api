/**
 * Phase 9b (Retention, Section 48). "Default 30 days" — the retention
 * window `AuditRetentionWorkflow` prunes events older than, when no
 * explicit override is given at workflow-start time (tests, in
 * particular, always pass a short explicit window rather than waiting out
 * 30 real days).
 */
export const DEFAULT_AUDIT_RETENTION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
