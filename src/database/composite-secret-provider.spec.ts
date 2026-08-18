import { describe, expect, it, vi } from 'vitest';
import { CompositeSecretProvider } from './composite-secret-provider';
import type { EnvSecretProvider } from './env-secret-provider';
import type { OpenBaoSecretProvider } from './openbao-secret-provider';

/** See openbao-secret-provider.spec.ts's fakeKvClient doc comment for why the spies are returned as plain local variables, never accessed as `obj.method` in an assertion. */
function fakeProviders(): {
  env: EnvSecretProvider;
  envResolve: ReturnType<typeof vi.fn>;
  openBao: OpenBaoSecretProvider;
  openBaoResolve: ReturnType<typeof vi.fn>;
} {
  const envResolve = vi.fn();
  const openBaoResolve = vi.fn();
  return {
    env: { resolve: envResolve },
    envResolve,
    openBao: { resolve: openBaoResolve } as unknown as OpenBaoSecretProvider,
    openBaoResolve,
  };
}

describe('CompositeSecretProvider', () => {
  it('dispatches an ENV reference to EnvSecretProvider', async () => {
    const { env, envResolve, openBao, openBaoResolve } = fakeProviders();
    envResolve.mockResolvedValue('env-value');
    const composite = new CompositeSecretProvider(env, openBao);

    const resolved = await composite.resolve({
      provider: 'ENV',
      reference: 'SOME_VAR',
    });

    expect(resolved).toBe('env-value');
    expect(envResolve).toHaveBeenCalledOnce();
    expect(openBaoResolve).not.toHaveBeenCalled();
  });

  it('dispatches an OPENBAO reference to OpenBaoSecretProvider', async () => {
    const { env, envResolve, openBao, openBaoResolve } = fakeProviders();
    openBaoResolve.mockResolvedValue('bao-value');
    const composite = new CompositeSecretProvider(env, openBao);

    const resolved = await composite.resolve({
      provider: 'OPENBAO',
      reference: 'tools/x',
    });

    expect(resolved).toBe('bao-value');
    expect(openBaoResolve).toHaveBeenCalledOnce();
    expect(envResolve).not.toHaveBeenCalled();
  });

  it('throws for a provider neither backend implements (CONTROL_DB)', async () => {
    const { env, openBao } = fakeProviders();
    const composite = new CompositeSecretProvider(env, openBao);

    await expect(
      composite.resolve({ provider: 'CONTROL_DB', reference: 'x' }),
    ).rejects.toThrow(/No SecretProvider implementation/);
  });
});
