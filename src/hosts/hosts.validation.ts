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
    tpmChallengeId: z.string().uuid().optional(),
  })
  .strict();
export type RegisterHostRequest = z.infer<typeof RegisterHostRequestSchema>;

const uuid = z.string().uuid();
const pem = z.string().min(1).max(16_384);
const b64 = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .regex(/^[A-Za-z0-9+/=]+$/);

/** `POST /hosts/register/adcs`: key-less enrolment with the AD CS computer certificate. */
export const RegisterAdcsRequestSchema = z
  .object({
    tenantSlug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
    /** Computer certificate first, then intermediates (PEM). */
    certificates: z.array(pem).min(1).max(5),
    csr: z.string().min(1).max(16_384),
    machineId: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/),
    os: z.string().trim().min(1).max(200),
    keyType: z.enum(['TPM', 'SOFTWARE']),
    timestamp: z.string().min(1).max(40),
    signature: b64(2048),
    tpmChallengeId: z.string().uuid().optional(),
  })
  .strict();

export const TpmChallengeSchema = z
  .object({
    tenantSlug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
    machineId: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/),
    /** EK certificate first, then its intermediates (PEM). */
    ekCertificates: z.array(pem).min(1).max(5),
    /** Base64 marshalled TPMT_PUBLIC of the host key. */
    hostKeyPublic: b64(2048),
  })
  .strict();

export const TpmAkChallengeSchema = z
  .object({
    tenantSlug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
    machineId: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/),
    /** Base64 marshalled TPMT_PUBLIC of the host key. */
    hostKeyPublic: b64(2048),
  })
  .strict();

export const TpmAkCertifySchema = z
  .object({
    tenantSlug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
    challengeId: uuid,
    /** AK certificate first, then its intermediates (PEM). */
    akCertificates: z.array(pem).min(1).max(5),
    hostKeyPublic: b64(2048),
    /** Base64 TPMS_ATTEST from TPM2_Certify (the TPM2B_ATTEST body, without its size prefix). */
    certifyInfo: b64(2048),
    /** Base64 marshalled TPMT_SIGNATURE. */
    signature: b64(1024),
  })
  .strict();

export const TpmActivateSchema = z
  .object({
    tenantSlug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
    challengeId: uuid,
    secret: b64(512),
  })
  .strict();

export const AdcsTrustedCaSchema = z
  .object({ label: z.string().trim().min(1).max(200), certPem: pem })
  .strict();

export const AdcsSettingsSchema = z
  .object({
    defaultHostGroupId: uuid,
    ldapsUrl: z.string().max(500).nullable().optional(),
    baseDn: z.string().max(500).nullable().optional(),
    bindDn: z.string().max(500).nullable().optional(),
    serverCaPem: pem.nullable().optional(),
    /** Required for key-less enrolment: empty accepts no certificate. */
    allowedTemplateOids: z
      .array(
        z
          .string()
          .regex(/^[0-9]+(\.[0-9]+)+$/)
          .max(200),
      )
      .max(50)
      .default([]),
    bindPassword: z.string().min(1).max(500).optional(),
  })
  .strict();

export const AdOuRuleSchema = z
  .object({ ouDn: z.string().trim().min(3).max(500), hostGroupId: uuid })
  .strict();
export const UpdateAdOuRuleSchema = z.object({ hostGroupId: uuid }).strict();

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
    /** Hostname characters plus `*`/`?`, at most 3 `*` (docs/hosts.md). */
    hostnamePattern: z
      .string()
      .regex(/^[A-Za-z0-9.*?_-]{1,255}$/)
      .refine((p) => (p.match(/\*/g) ?? []).length <= 3, {
        message: 'at most 3 * wildcards',
      })
      .nullable()
      .optional(),
    cidrs: z.array(z.string().max(64)).max(100).optional(),
    /** Verified TPM only (credential activation). */
    requireTpm: z.boolean().optional(),
    requireAdcs: z.boolean().optional(),
    adOuDn: z.string().trim().min(3).max(500).nullable().optional(),
    enabled: z.boolean().optional(),
  })
  .strict();
export const UpdateApprovalRuleSchema = ApprovalRuleSchema.omit({
  hostGroupId: true,
}).partial();

/** Approving a pending rekey names the exact key it binds. */
export const DecideHostSchema = z
  .object({
    keyFingerprint: z
      .string()
      .regex(/^[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();
