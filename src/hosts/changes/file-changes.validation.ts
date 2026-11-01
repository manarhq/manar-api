import { z } from 'zod';

/** One snapshot the device took before an AI tool edited a file outside its project folder. */
export const FileChangeReportSchema = z
  .object({
    snapshotId: z.string().regex(/^[a-f0-9]{16,64}$/),
    tool: z.string().regex(/^[a-z0-9._-]{1,64}$/),
    path: z.string().min(1).max(1024),
    existed: z.boolean(),
    sizeBytes: z.number().int().min(0).max(2_000_000_000),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    takenAt: z.string().datetime(),
  })
  .strict();

export const FileChangeBatchSchema = z
  .object({ changes: z.array(FileChangeReportSchema).min(1).max(50) })
  .strict();

export const RestoreResultSchema = z
  .object({
    status: z.enum(['RESTORED', 'FAILED']),
    // A short reason code or sentence from the device; never file contents.
    error: z.string().max(300).optional(),
    // Set when the file changed after the AI tool edited it (the device saved the later version).
    note: z.string().max(300).optional(),
  })
  .strict();
