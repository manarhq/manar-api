-- AlterEnum
ALTER TYPE "SecretKind" ADD VALUE 'KEYCLOAK_CLIENT_SECRET';

-- AlterEnum
ALTER TYPE "SecretProvider" ADD VALUE 'CONTROL_DB';

-- AlterTable
ALTER TABLE "tenants" ADD COLUMN     "keycloakClientId" TEXT,
ADD COLUMN     "keycloakIssuerUrl" TEXT,
ADD COLUMN     "keycloakRealm" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "tenants_keycloakRealm_key" ON "tenants"("keycloakRealm");

-- CreateIndex
CREATE UNIQUE INDEX "tenants_keycloakIssuerUrl_key" ON "tenants"("keycloakIssuerUrl");

