-- Once-per-interval periodic jobs across replicas (6 Nov 2026). Additive. Rollback: drop the table.
CREATE TABLE "job_runs" (
    "name" TEXT NOT NULL,
    "ranAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "job_runs_pkey" PRIMARY KEY ("name")
);
