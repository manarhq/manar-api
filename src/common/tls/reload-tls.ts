import { readFileSync } from 'node:fs';
import type { Server as TlsServer } from 'node:tls';
import { Logger } from '@nestjs/common';

/** How often mounted certificate files are re-read. cert-manager renews days before expiry. */
export const TLS_RELOAD_INTERVAL_MS = 5 * 60 * 1000;

const logger = new Logger('TlsReload');

/**
 * Re-reads `paths` every `intervalMs` and calls `onChange` with the new contents when any file
 * differs from the last read. A failed read (a Kubernetes secret mid-swap, a file briefly
 * missing) skips that tick and keeps the current material. Returns a stop function.
 */
export function onFilesChanged(
  paths: readonly string[],
  onChange: (contents: Buffer[]) => void,
  intervalMs = TLS_RELOAD_INTERVAL_MS,
): () => void {
  let last: Buffer[] = paths.map((p) => readFileSync(p));
  const timer = setInterval(() => {
    let next: Buffer[];
    try {
      next = paths.map((p) => readFileSync(p));
    } catch {
      return;
    }
    if (next.every((b, i) => b.equals(last[i]!))) return;
    try {
      onChange(next);
      last = next;
    } catch (error) {
      logger.error(
        `Could not load renewed TLS material (${paths.join(', ')}); keeping the current one: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

/**
 * Keeps a TLS server's certificate, key and client CA current with the mounted files, so a
 * renewed certificate is served without a restart. `setSecureContext` applies to new
 * connections; open ones keep the context they were made with.
 */
export function reloadServerTls(
  server: Pick<TlsServer, 'setSecureContext'>,
  files: { cert: string; key: string; ca: string },
  intervalMs = TLS_RELOAD_INTERVAL_MS,
): () => void {
  return onFilesChanged(
    [files.cert, files.key, files.ca],
    ([cert, key, ca]) => {
      server.setSecureContext({ cert, key, ca });
      logger.log(`Loaded renewed TLS certificate from ${files.cert}`);
    },
    intervalMs,
  );
}
