-- CreateEnum
CREATE TYPE "DataClassification" AS ENUM ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED');

-- AlterTable
ALTER TABLE "tool_actions" ADD COLUMN     "classification" "DataClassification" NOT NULL DEFAULT 'INTERNAL';
