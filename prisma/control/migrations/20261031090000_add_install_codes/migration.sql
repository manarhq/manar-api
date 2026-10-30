-- docs/hosts.md "Add device": the short code of the install one-liner -> tenant + install key.
--
-- Additive: one table, nothing reads it until POST /devices/install-code is used.
--
-- Rollback (after rolling back the code; open one-liners then answer "code not found"):
--   DROP TABLE "install_codes";

-- CreateTable
CREATE TABLE "install_codes" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "installKey" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "install_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "install_codes_code_key" ON "install_codes"("code");

-- CreateIndex
CREATE INDEX "install_codes_expiresAt_idx" ON "install_codes"("expiresAt");

-- AddForeignKey
ALTER TABLE "install_codes" ADD CONSTRAINT "install_codes_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;
