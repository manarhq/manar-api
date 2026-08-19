import { describe, expect, it } from 'vitest';
import { resolveCorsOrigin } from './cors';

describe('resolveCorsOrigin', () => {
  it('throws in production when the origin is a wildcard (Section 99 hard rule)', () => {
    expect(() =>
      resolveCorsOrigin({ CORS_ALLOWED_ORIGINS: '*', NODE_ENV: 'production' }),
    ).toThrow(/wildcard/i);
  });

  it('throws in production when the origin is effectively empty', () => {
    expect(() =>
      resolveCorsOrigin({ CORS_ALLOWED_ORIGINS: '  ', NODE_ENV: 'production' }),
    ).toThrow(/wildcard/i);
  });

  it('allows a wildcard outside production (reflects the request origin)', () => {
    expect(
      resolveCorsOrigin({ CORS_ALLOWED_ORIGINS: '*', NODE_ENV: 'development' }),
    ).toBe(true);
    expect(
      resolveCorsOrigin({ CORS_ALLOWED_ORIGINS: '*', NODE_ENV: 'test' }),
    ).toBe(true);
  });

  it('parses a comma-separated allow-list in production', () => {
    expect(
      resolveCorsOrigin({
        CORS_ALLOWED_ORIGINS: 'https://a.example.com, https://b.example.com',
        NODE_ENV: 'production',
      }),
    ).toEqual(['https://a.example.com', 'https://b.example.com']);
  });

  it('parses a single-origin allow-list', () => {
    expect(
      resolveCorsOrigin({
        CORS_ALLOWED_ORIGINS: 'https://app.example.com',
        NODE_ENV: 'production',
      }),
    ).toEqual(['https://app.example.com']);
  });
});
