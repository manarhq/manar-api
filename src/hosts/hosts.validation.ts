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
