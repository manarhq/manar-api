-- Phase 1 (Gate 0 finding R1): a mutating or destructive tool call that ends
-- without a definite answer (timeout, connection lost after sending, 5xx) is
-- no longer retried and no longer recorded as FAILURE. It is UNKNOWN: the side
-- effect may have happened and needs reconciliation.
--
-- Additive. Rollback: PostgreSQL cannot drop an enum value; rows would first
-- need `UPDATE "tool_invocations" SET "status" = 'FAILURE' WHERE "status" = 'UNKNOWN'`
-- and the type recreated without the value.

-- AlterEnum
ALTER TYPE "ToolInvocationStatus" ADD VALUE 'UNKNOWN';
