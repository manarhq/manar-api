import { describe, expect, it, vi } from 'vitest';
import type { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import { OpenBaoSecretProvider } from './openbao-secret-provider';

/**
 * Returns both the fake `OpenBaoKvClient` and its `readSecret` spy as a
 * plain local variable (never accessed as `kv.readSecret` in an assertion)
 * — avoids `@typescript-eslint/unbound-method` flagging a bare method
 * reference, the same reason no other spec file in this codebase reaches
 * for `expect(obj.method)` directly.
 */
function fakeKvClient(data: Record<string, unknown> | null): {
  kv: OpenBaoKvClient;
  readSecret: ReturnType<typeof vi.fn>;
} {
  const readSecret = vi.fn().mockImplementation(() => {
    if (data === null) throw new Error('not found');
    return Promise.resolve(data);
  });
  const kv = { readSecret, writeSecret: vi.fn() } as unknown as OpenBaoKvClient;
  return { kv, readSecret };
}

describe('OpenBaoSecretProvider', () => {
  it('resolves the "value" key of the KV v2 secret at the given reference', async () => {
    const { kv, readSecret } = fakeKvClient({
      value: 'super-secret-api-key',
    });
    const provider = new OpenBaoSecretProvider(kv);

    const resolved = await provider.resolve({
      provider: 'OPENBAO',
      reference: 'tools/soc-fixture',
    });

    expect(resolved).toBe('super-secret-api-key');
    expect(readSecret).toHaveBeenCalledWith('tools/soc-fixture');
  });

  it('rejects a non-OPENBAO reference', async () => {
    const { kv } = fakeKvClient({});
    const provider = new OpenBaoSecretProvider(kv);
    await expect(
      provider.resolve({ provider: 'ENV', reference: 'FOO' }),
    ).rejects.toThrow(/cannot resolve a "ENV"/);
  });

  it('throws if the stored secret has no string "value" field', async () => {
    const { kv } = fakeKvClient({ notValue: 123 });
    const provider = new OpenBaoSecretProvider(kv);
    await expect(
      provider.resolve({ provider: 'OPENBAO', reference: 'tools/broken' }),
    ).rejects.toThrow(/no non-empty string "value" field/);
  });
});
