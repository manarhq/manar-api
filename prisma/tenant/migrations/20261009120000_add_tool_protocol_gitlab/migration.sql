-- ADR-0011: a Tool whose actions run through GitLabToolAdapter (REST v4,
-- project access token from OpenBao, catalog in src/tools/gitlab-actions.ts).
--
-- Additive. Rollback: PostgreSQL cannot drop an enum value; delete or
-- re-point the GITLAB tools first (`DELETE FROM "tools" WHERE "protocol" =
-- 'GITLAB'` after removing their actions and invocations), then recreate
-- the type without the value.

-- AlterEnum
ALTER TYPE "ToolProtocol" ADD VALUE 'GITLAB';
