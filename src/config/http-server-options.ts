/** Traefik's default backend idle timeout for pooled keep-alive connections. */
export const PROXY_IDLE_TIMEOUT_MS = 90_000;

/**
 * Idle keep-alive sockets stay open longer than the proxy's idle timeout, so the proxy closes
 * them first. With Node's default (72 s) the server closed a socket Traefik still considered
 * usable, and the next request on it was a 502.
 */
export const HTTP_SERVER_OPTIONS = {
  keepAliveTimeout: PROXY_IDLE_TIMEOUT_MS + 5_000,
} as const;
