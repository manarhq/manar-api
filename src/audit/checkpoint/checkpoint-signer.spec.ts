import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { OpenBaoKvClient } from '../../openbao/openbao-kv.client';
import { CheckpointSigner, NoCheckpointKeyError } from './checkpoint-signer';

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
    await signer.sign('t2', hash('x'));
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
    await signer.sign('t1', hash('a'));
    await signer.sign('t2', hash('a'));
    const a1 = await signer.publicKey('t1');
    const a2 = await signer.publicKey('t1');
    const b = await signer.publicKey('t2');

    expect(a1.keyId).toMatch(/^[0-9a-f]{16}$/);
    expect(a2.keyId).toBe(a1.keyId);
    expect(b.keyId).not.toBe(a1.keyId);
  });

  it('reuses a key already in OpenBao and never overwrites it', async () => {
    const { kv, raw } = fakeKv();
    await new CheckpointSigner(kv).sign('t1', hash('a'));
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
    const a = new CheckpointSigner(kv);
    const b = new CheckpointSigner(kv);
    await Promise.all([a.sign('t1', hash('a')), b.sign('t1', hash('b'))]);
    expect((await a.publicKey('t1')).keyId).toBe(
      (await b.publicKey('t1')).keyId,
    );
  });

  it('does not create a key when OpenBao cannot be read', async () => {
    const { kv, raw } = fakeKv();
    raw.readSecretIfPresent.mockRejectedValueOnce(
      new Error('connection refused'),
    );

    await expect(
      new CheckpointSigner(kv).sign('t1', hash('a')),
    ).rejects.toThrow('connection refused');
    expect(raw.writeSecretIfAbsent).not.toHaveBeenCalled();
  });

  it('hasKey is false before the first SEAL key exists and true after', async () => {
    const { kv } = fakeKv();
    expect(await new CheckpointSigner(kv).hasKey('t1')).toBe(false);
    await new CheckpointSigner(kv).sign('t1', hash('a'));
    expect(await new CheckpointSigner(kv).hasKey('t1')).toBe(true);
    expect(await new CheckpointSigner(kv).hasKey('t2')).toBe(false);
  });

  it('looking up a key never creates it', async () => {
    const { kv, raw } = fakeKv();
    await expect(
      new CheckpointSigner(kv).publicKey('t1'),
    ).rejects.toBeInstanceOf(NoCheckpointKeyError);
    expect(raw.writeSecretIfAbsent).not.toHaveBeenCalled();
    expect(await new CheckpointSigner(kv).hasKey('t1')).toBe(false);
  });

  it('a lookup racing the first signature does not make signing fail', async () => {
    const { kv } = fakeKv();
    const signer = new CheckpointSigner(kv);
    const [lookup, signature] = await Promise.allSettled([
      signer.publicKey('t1'),
      signer.sign('t1', hash('a')),
    ]);
    expect(signature.status).toBe('fulfilled');
    expect(lookup.status).toBe('rejected');
    expect(await signer.hasKey('t1')).toBe(true);
  });
});
