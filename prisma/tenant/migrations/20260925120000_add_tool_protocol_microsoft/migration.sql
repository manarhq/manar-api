-- Phase 2 (ADR-0004): a Tool whose actions run through MicrosoftToolAdapter
-- (Graph / Defender for Endpoint, OAuth2 client-credentials).
--
-- Additive. Rollback: PostgreSQL cannot drop an enum value; delete or
-- re-point the MICROSOFT tools first (`DELETE FROM "tools" WHERE "protocol" =
-- 'MICROSOFT'` after removing their actions and invocations), then recreate
-- the type without the value.

-- AlterEnum
ALTER TYPE "ToolProtocol" ADD VALUE 'MICROSOFT';
