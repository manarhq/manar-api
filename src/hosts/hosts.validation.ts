import { z } from 'zod';

/** `POST /hosts/register` (docs/hosts.md). `machineId` goes into a certificate URI, so it is narrow. */
export const RegisterHostRequestSchema = z
  .object({
    installKey: z.string().min(1).max(200),
    csr: z.string().min(1).max(16_384),
    machineId: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/),
    hostname: z.string().trim().min(1).max(255),
    os: z.string().trim().min(1).max(200),
    keyType: z.enum(['TPM', 'SOFTWARE']),
  })
  .strict();
export type RegisterHostRequest = z.infer<typeof RegisterHostRequestSchema>;

const uuid = z.string().uuid();

export const CreateInstallKeySchema = z
  .object({
    hostGroupId: uuid,
    label: z.string().trim().min(1).max(200),
    allowedCidrs: z.array(z.string().max(64)).max(100).optional(),
    maxUses: z.number().int().min(1).max(1_000_000).optional(),
    expiresAt: z.coerce.date().optional(),
  })
  .strict();

export const HostGroupSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    orgUnitId: uuid.nullable().optional(),
  })
  .strict();
export const UpdateHostGroupSchema = HostGroupSchema.partial();

export const OrgUnitSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    parentId: uuid.nullable().optional(),
  })
  .strict();
export const UpdateOrgUnitSchema = OrgUnitSchema.partial();

export const ApprovalRuleSchema = z
  .object({
    hostGroupId: uuid.nullable().optional(),
    hostnamePattern: z.string().trim().min(1).max(255).nullable().optional(),
    cidrs: z.array(z.string().max(64)).max(100).optional(),
    requireTpm: z.boolean().optional(),
    enabled: z.boolean().optional(),
  })
  .strict();
export const UpdateApprovalRuleSchema = ApprovalRuleSchema.omit({
  hostGroupId: true,
}).partial();
