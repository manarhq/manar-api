import { createConnection } from 'node:net';

/**
 * A bare "can this process open a TCP connection to host:port?" check, plus
 * the parsing needed to get a host/port out of the several shapes this
 * codebase's dependency addresses come in (`http://x:8080`, `redis://x:6379`,
 * `x:7233`, `a:9092,b:9092`).
 *
 * **Why a TCP probe and not a real client-level call**, for most of the
 * dependencies `ReadinessService` checks: none of the infrastructure
 * clients in this codebase (`KafkaPublisherService`,
 * `RedisThrottlerStorageService`, `IdempotencyStoreService`,
 * `RedisPubSubService`, `TemporalClientService`, `KeycloakAdminClient`,
 * `AiAdvisoryClient`) exposes a side-effect-free ping. Every public method
 * they have does real work — publishes an event, increments a counter,
 * starts a workflow, fetches an admin token, spends a model call. Calling
 * one of those on a 10-second kubelet cadence would mean the health check
 * itself became load on the very dependency it is trying not to fall over,
 * and for the AI advisory service it would mean paying for inference to ask
 * whether inference is available.
 *
 * A TCP connect is honest about being coarse: it proves the network path
 * and the listener, not that the service behind it is answering correctly.
 * That is exactly the right resolution for the *optional* dependencies —
 * where the only decision this feeds is "flag degraded in the body" — and
 * `ReadinessService` deliberately uses a real query (`SELECT 1`) instead
 * for the one dependency where readiness genuinely gates traffic. Which
 * check each dependency gets is documented probe-by-probe there.
 */

export interface TcpEndpoint {
  host: string;
  port: number;
}

/**
 * Extracts the first `host:port` from a dependency address.
 *
 * Handles the three shapes in this codebase's config
 * (`src/config/env.validation.ts`): a full URL (`http://openfga…:8080`,
 * `redis://redis…:6379`), a bare authority (`temporal…:7233`), and a
 * comma-separated list of either (`KAFKA_BROKERS`). Returns `null` rather
 * than throwing for anything it can't parse — an address this can't read is
 * a *reporting* problem, and must never be able to fail readiness or crash
 * the handler.
 */
export function parseTcpEndpoint(
  raw: string,
  defaultPort?: number,
): TcpEndpoint | null {
  const first = raw.split(',')[0]?.trim();
  if (!first) return null;

  // `URL` needs a scheme; bare `host:port` authorities get a synthetic one.
  // The scheme is never used for anything but parsing — this only ever
  // opens a raw socket.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(first)
    ? first
    : `tcp://${first}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }

  const host = url.hostname;
  if (!host) return null;

  // A URL without a port uses its scheme's (`https://auth.example` -> 443).
  const schemePort = { 'http:': 80, 'https:': 443 }[url.protocol];
  const port = url.port ? Number(url.port) : (defaultPort ?? schemePort);
  if (
    port === undefined ||
    !Number.isInteger(port) ||
    port <= 0 ||
    port > 65535
  ) {
    return null;
  }

  return { host, port };
}

/**
 * Resolves if a TCP connection to `endpoint` can be established, rejects
 * otherwise. The socket is destroyed the instant the connection succeeds —
 * nothing is written and nothing is read, so this can never disturb the
 * dependency's own protocol state.
 *
 * No timeout is set here on purpose: `runProbe` (`readiness.ts`) owns the
 * single hard time budget for every probe, and two independent timeouts
 * layered on the same check is how you end up with a probe that reports the
 * wrong one. A connect attempt the outer race abandons is left to the OS's
 * own connect timeout and then torn down by the `error` handler below —
 * which is why that handler destroys the socket rather than just rejecting.
 */
export async function checkTcpReachable(endpoint: TcpEndpoint): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = createConnection({
      host: endpoint.host,
      port: endpoint.port,
    });

    const settle = (error?: Error): void => {
      socket.removeAllListeners();
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };

    socket.once('connect', () => settle());
    socket.once('error', (error: Error) =>
      settle(
        new Error(
          `TCP connect to ${endpoint.host}:${endpoint.port} failed: ${error.message}`,
        ),
      ),
    );
  });
}
