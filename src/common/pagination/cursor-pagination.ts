import { BadRequestException } from '@nestjs/common';

/**
 * Phase 11b Part 1 (Section 8's pagination requirement) — the single
 * pagination convention every new list endpoint in this codebase uses
 * (`Agent`, `Task`, `Tool`, `Policy`, `ApprovalRequest`, `KillSwitch`,
 * `WebhookEndpoint`, plus the OpenSearch-backed `GET /audit`).
 *
 * **Cursor-based, not offset-based** — chosen deliberately over
 * `skip`/`page` for the same reason most write-heavy operational UIs
 * (this one included: agents/tasks/approvals/audit events are all
 * actively being created while an operator is paging through them) avoid
 * offset pagination: a `LIMIT/OFFSET` page is defined relative to the
 * *current* row order, so a row inserted or deleted while an operator is
 * mid-scroll shifts every subsequent page by one, causing either a
 * skipped or a duplicated row — silently, with no error. A cursor page is
 * instead defined relative to the *last row already seen*
 * (`(createdAt, id) < (cursor.createdAt, cursor.id)`), which stays correct
 * regardless of concurrent inserts anywhere in the set, and is O(1) rather
 * than O(offset) per page for Postgres to compute (no cost blowup for an
 * operator paging deep into a large audit/task list). The one capability
 * this trades away — jumping directly to "page 14" — is not a real
 * requirement for any surface Section 65/66 describes (an infinite-scroll/
 * "load more" operator UI, not a numbered pager).
 *
 * The cursor itself is opaque to callers (a base64url-encoded `{createdAt,
 * id}` pair) — callers must treat it as a token, not construct one, so the
 * encoding can change later without being an API break.
 */
export interface CursorPage<T> {
  items: T[];
  /** `null` once there are no more rows after this page. */
  nextCursor: string | null;
}

export interface DecodedCursor {
  /** ISO-8601 instant of the last row already seen. */
  ts: Date;
  /** `id` of the last row already seen — the tie-breaker for rows sharing the same timestamp. */
  id: string;
}

/** A row shape every cursor-paginated resource satisfies: a stable `id` plus *some* timestamp field this page is ordered by (the field's actual name varies per resource — `createdAt` for most, `requestedAt` for `ApprovalRequest` — see each call site). */
export interface CursoredRow {
  id: string;
}

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

/** Parses and clamps the `limit` query param — never throws (an out-of-range or non-numeric value silently clamps/falls back rather than 400ing, since a limit is an optimization hint, not semantically load-bearing the way a cursor is). */
export function parseLimit(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_LIMIT;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_LIMIT;
  return Math.min(parsed, MAX_LIMIT);
}

/** Encodes the last row of a page into the opaque cursor string returned as `nextCursor`. */
export function encodeCursor(row: { id: string }, ts: Date): string {
  return Buffer.from(
    JSON.stringify({ ts: ts.toISOString(), id: row.id }),
  ).toString('base64url');
}

/**
 * Decodes a caller-supplied `cursor` query param. Throws `BadRequestException`
 * (never leaks a stack trace — matches `parseBodyOrThrow`'s convention) for
 * anything malformed, since — unlike `limit` — a broken cursor can't be
 * silently defaulted without silently returning the wrong page.
 */
export function parseCursor(
  raw: string | undefined,
): DecodedCursor | undefined {
  if (raw === undefined) return undefined;
  try {
    const decoded = JSON.parse(
      Buffer.from(raw, 'base64url').toString('utf8'),
    ) as { ts?: unknown; id?: unknown };
    if (typeof decoded.ts !== 'string' || typeof decoded.id !== 'string') {
      throw new Error('malformed cursor payload');
    }
    const ts = new Date(decoded.ts);
    if (Number.isNaN(ts.getTime()))
      throw new Error('malformed cursor timestamp');
    return { ts, id: decoded.id };
  } catch {
    throw new BadRequestException('Invalid cursor');
  }
}

/**
 * The Prisma `where` fragment implementing "strictly before the cursor
 * row" for a compound `(tsField, id)` ordering — `tsField` is the actual
 * column name this resource orders by (e.g. `'createdAt'`,
 * `'requestedAt'`). Ties on `tsField` are broken by `id` descending, which
 * is what makes the pair a total, stable order (two rows can share the
 * same millisecond; no two rows share the same `id`).
 *
 * Returned as a plain object (computed key) rather than a typed Prisma
 * `WhereInput` because the field name varies per resource and this helper
 * is shared across several different Prisma models — callers spread this
 * into their own typed `where` object, which Prisma still validates at
 * the call site.
 */
export function cursorWhereClause(
  tsField: string,
  cursor: DecodedCursor | undefined,
): Record<string, unknown> | undefined {
  if (!cursor) return undefined;
  return {
    OR: [
      { [tsField]: { lt: cursor.ts } },
      { [tsField]: cursor.ts, id: { lt: cursor.id } },
    ],
  };
}

/**
 * Turns a page of rows (fetched with `take: limit + 1`, see call sites)
 * into a `CursorPage`: trims the lookahead row if present and uses it to
 * compute `nextCursor`.
 */
export function toCursorPage<T extends CursoredRow>(
  rows: T[],
  limit: number,
  tsOf: (row: T) => Date,
): CursorPage<T> {
  const hasMore = rows.length > limit;
  const items = hasMore ? rows.slice(0, limit) : rows;
  const last = items[items.length - 1];
  const nextCursor = hasMore && last ? encodeCursor(last, tsOf(last)) : null;
  return { items, nextCursor };
}
