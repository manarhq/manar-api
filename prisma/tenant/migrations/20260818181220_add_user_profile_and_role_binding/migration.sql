-- CreateEnum
CREATE TYPE "Role" AS ENUM ('TENANT_OWNER', 'SECURITY_ADMIN', 'AI_GOVERNANCE_MANAGER', 'SOC_OPERATOR', 'APPROVER', 'AUDITOR', 'DEVELOPER', 'READ_ONLY');

-- CreateTable
CREATE TABLE "user_profiles" (
    "id" TEXT NOT NULL,
    "keycloakSubject" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_bindings" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "grantedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "grantedBy" TEXT NOT NULL,

    CONSTRAINT "role_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_profiles_keycloakSubject_key" ON "user_profiles"("keycloakSubject");

-- CreateIndex
CREATE UNIQUE INDEX "role_bindings_userId_role_key" ON "role_bindings"("userId", "role");

-- AddForeignKey
ALTER TABLE "role_bindings" ADD CONSTRAINT "role_bindings_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

