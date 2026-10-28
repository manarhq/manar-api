import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { OpenBaoKvClient } from '../../openbao/openbao-kv.client';
import { CheckpointSigner } from './checkpoint-signer';

/** In-memory KV v2 with check-and-set: `writeSecretIfAbsent` fails when the path exists. */
function fakeKv() {
  const store = new Map<string, Record<string, unknown>>();
  const kv = {
    readSecretIfPresent: vi.fn((path: string) =>
      Promise.resolve(store.get(path) ?? null),
    ),
    writeSecretIfAbsent: vi.fn(
      (path: string, data: Record<string, unknown>) => {
        if (store.has(path)) {
          return Promise.reject(
            new Error('check-and-set parameter did not match'),
          );
        }
        store.set(path, data);
        return Promise.resolve();
      },
    ),
  };
  return { kv: kv as unknown as OpenBaoKvClient, store, raw: kv };
}

const hash = (s: string) => createHash('sha256').update(s).digest('hex');

describe('CheckpointSigner', () => {
  it('signs a checkpoint hash that verifies with the tenant public key', async () => {
    const signer = new CheckpointSigner(fakeKv().kv);
    const signature = await signer.sign('t1', hash('a'));
    const { publicKeyPem, algorithm } = await signer.publicKey('t1');

    expect(algorithm).toBe('Ed25519');
    expect(CheckpointSigner.verify(hash('a'), signature, publicKeyPem)).toBe(
      true,
    );
  });

  it('fails verification for a changed hash, a changed signature, or another key', async () => {
    const signer = new CheckpointSigner(fakeKv().kv);
    const signature = await signer.sign('t1', hash('a'));
    const own = (await signer.publicKey('t1')).publicKeyPem;
    const other = (await signer.publicKey('t2')).publicKeyPem;

    expect(CheckpointSigner.verify(hash('b'), signature, own)).toBe(false);
    const flipped = Buffer.from(signature, 'base64');
    flipped[0] = flipped[0]! ^ 1;
    expect(
      CheckpointSigner.verify(hash('a'), flipped.toString('base64'), own),
    ).toBe(false);
    expect(CheckpointSigner.verify(hash('a'), signature, other)).toBe(false);
    expect(CheckpointSigner.verify('not-a-digest', signature, own)).toBe(false);
  });

  it('gives each tenant its own key, with a stable 16-hex keyId', async () => {
    const signer = new CheckpointSigner(fakeKv().kv);
    const a1 = await signer.publicKey('t1');
    const a2 = await signer.publicKey('t1');
    const b = await signer.publicKey('t2');

    expect(a1.keyId).toMatch(/^[0-9a-f]{16}$/);
    expect(a2.keyId).toBe(a1.keyId);
    expect(b.keyId).not.toBe(a1.keyId);
  });

  it('reuses a key already in OpenBao and never overwrites it', async () => {
    const { kv, raw } = fakeKv();
    const first = await new CheckpointSigner(kv).publicKey('t1');
    raw.writeSecretIfAbsent.mockClear();

    const second = await new CheckpointSigner(kv).publicKey('t1');

    expect(second.keyId).toBe(first.keyId);
    expect(raw.writeSecretIfAbsent).not.toHaveBeenCalled();
    expect(raw.readSecretIfPresent).toHaveBeenCalledWith(
      'audit/checkpoint-signing-key/t1',
    );
  });

  it('two replicas creating the first key at once end up with the same key', async () => {
    const { kv } = fakeKv();
    const [a, b] = await Promise.all([
      new CheckpointSigner(kv).publicKey('t1'),
      new CheckpointSigner(kv).publicKey('t1'),
    ]);
    expect(a.keyId).toBe(b.keyId);
  });

  it('does not create a key when OpenBao cannot be read', async () => {
    const { kv, raw } = fakeKv();
    raw.readSecretIfPresent.mockRejectedValueOnce(
      new Error('connection refused'),
    );

    await expect(new CheckpointSigner(kv).publicKey('t1')).rejects.toThrow(
      'connection refused',
    );
    expect(raw.writeSecretIfAbsent).not.toHaveBeenCalled();
  });
});
