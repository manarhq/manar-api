/** Cursor for `GET /approvals/allow-grants`: newest first by creation time, then id. */
export function encodeGrantCursor(g: { createdAt: Date; id: string }): string {
  return Buffer.from(`${g.createdAt.toISOString()}|${g.id}`).toString(
    'base64url',
  );
}

export function decodeGrantCursor(
  c: string | undefined,
): { createdAt: Date; id: string } | null {
  if (!c) return null;
  const [iso, id] = Buffer.from(c, 'base64url').toString().split('|');
  const createdAt = new Date(iso ?? '');
  return id && !Number.isNaN(createdAt.getTime()) ? { createdAt, id } : null;
}
