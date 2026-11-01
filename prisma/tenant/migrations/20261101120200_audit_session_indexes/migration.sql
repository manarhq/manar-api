-- Indexes for the sessions timeline (insight track). Additive; they speed up reads and slow audit
-- inserts slightly. The expression indexes are partial: only the few event types the timeline reads.
--
-- Rollback: DROP INDEX "audit_events_eventType_timestamp_idx", "audit_events_session_host_idx",
--           "audit_events_approval_request_idx";

CREATE INDEX "audit_events_eventType_timestamp_idx" ON "audit_events"("eventType", "timestamp");

CREATE INDEX "audit_events_session_host_idx" ON "audit_events" ((data->>'hostId'), "timestamp")
  WHERE "eventType" IN ('host.action_decided', 'secret.touched', 'secret.vault.denied');

CREATE INDEX "audit_events_approval_request_idx" ON "audit_events" ((data->>'approvalRequestId'))
  WHERE "eventType" IN ('approval.approved', 'approval.denied');
