import { describe, expect, it } from 'vitest';
import { validate } from './env';

describe('validate (env)', () => {
  it('applies defaults and accepts a valid env', () => {
    const config = validate({ DEMO_TOOLS_API_KEY: 'test-key' });

    expect(config).toEqual({
      PORT: 3100,
      NODE_ENV: 'development',
      LOG_LEVEL: 'info',
      DEMO_TOOLS_API_KEY: 'test-key',
    });
  });

  it('coerces PORT from a string', () => {
    const config = validate({
      DEMO_TOOLS_API_KEY: 'test-key',
      PORT: '4000',
    });

    expect(config.PORT).toBe(4000);
  });

  it('throws an itemized error when DEMO_TOOLS_API_KEY is missing', () => {
    expect(() => validate({})).toThrow(/DEMO_TOOLS_API_KEY/);
  });

  it('throws when NODE_ENV is not one of the allowed values', () => {
    expect(() =>
      validate({ DEMO_TOOLS_API_KEY: 'test-key', NODE_ENV: 'staging' }),
    ).toThrow();
  });
});
