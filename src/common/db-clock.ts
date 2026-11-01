/** Anything with Prisma's `$queryRaw` (a client or a transaction). */
interface RawQuery {
  $queryRaw<T = unknown>(
    query: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T>;
}

/**
 * The database's clock. Expiry is compared with this, not with the API replica's clock, so two
 * replicas with skewed clocks (or a test that moves time) agree on whether an approval is still live.
 */
export async function dbNow(client: RawQuery): Promise<Date> {
  const rows = await client.$queryRaw<{ now: Date }[]>`SELECT now() AS now`;
  const now = rows[0]?.now;
  if (!(now instanceof Date) || Number.isNaN(now.getTime()))
    throw new Error('database clock unavailable');
  return now;
}
