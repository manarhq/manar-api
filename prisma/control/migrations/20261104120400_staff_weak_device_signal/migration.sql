-- Weak device signal (security review 4 Nov): the self-reported machine id queues a review, never blocks.
-- Rollback: Postgres cannot drop an enum value; leave it (unused) or recreate the type.
ALTER TYPE "StaffFingerprintKind" ADD VALUE IF NOT EXISTS 'MACHINE_ID';
