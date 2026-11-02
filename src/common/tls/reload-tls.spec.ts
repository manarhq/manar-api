import { mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { onFilesChanged, reloadServerTls } from './reload-tls';

describe('TLS reload', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tls-reload-'));
  const file = (name: string, body: string) => {
    const p = join(dir, name);
    // Kubernetes swaps a secret volume atomically; so does rename.
    writeFileSync(`${p}.tmp`, body);
    renameSync(`${p}.tmp`, p);
    return p;
  };
  const stops: (() => void)[] = [];
  afterEach(() => {
    stops.splice(0).forEach((stop) => stop());
    vi.useRealTimers();
  });

  it('gives a running server the renewed certificate, key and CA', () => {
    vi.useFakeTimers();
    const cert = file('tls.crt', 'cert-1');
    const key = file('tls.key', 'key-1');
    const ca = file('ca.pem', 'ca-1');
    const server = { setSecureContext: vi.fn() };
    stops.push(reloadServerTls(server, { cert, key, ca }, 1000));

    vi.advanceTimersByTime(1000);
    expect(server.setSecureContext).not.toHaveBeenCalled(); // nothing changed

    file('tls.crt', 'cert-2');
    file('tls.key', 'key-2');
    vi.advanceTimersByTime(1000);
    expect(server.setSecureContext).toHaveBeenCalledTimes(1);
    const ctx = server.setSecureContext.mock.calls[0]![0] as Record<
      string,
      Buffer
    >;
    expect(ctx.cert!.toString()).toBe('cert-2');
    expect(ctx.key!.toString()).toBe('key-2');
    expect(ctx.ca!.toString()).toBe('ca-1');
  });

  it('keeps the current material while a file is missing or unusable', () => {
    vi.useFakeTimers();
    const a = file('a.pem', 'one');
    const onChange = vi.fn();
    stops.push(onFilesChanged([a], onChange, 1000));

    rmSync(a);
    vi.advanceTimersByTime(1000);
    expect(onChange).not.toHaveBeenCalled();

    file('a.pem', 'two');
    onChange.mockImplementationOnce(() => {
      throw new Error('bad key');
    });
    vi.advanceTimersByTime(1000);
    vi.advanceTimersByTime(1000); // retried on the next tick after a failed load
    expect(onChange).toHaveBeenCalledTimes(2);
  });
});
