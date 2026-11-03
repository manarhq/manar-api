import { describe, expect, it } from 'vitest';
import {
  bindResourceToParams,
  RESOURCE_PARAM_KEYWORD,
} from './resource-binding';

const schema = { type: 'object', [RESOURCE_PARAM_KEYWORD]: 'hostId' };

describe('bindResourceToParams', () => {
  it('leaves params alone when the action declares no binding', () => {
    const params = { hostId: 'other' };
    expect(bindResourceToParams({ type: 'object' }, 'h1', params)).toEqual({
      ok: true,
      params,
    });
    expect(bindResourceToParams(null, 'h1', params).ok).toBe(true);
  });

  it('accepts a param equal to the decided resource', () => {
    expect(bindResourceToParams(schema, 'h1', { hostId: 'h1' }).ok).toBe(true);
  });

  it('refuses a param naming a different target than the decided resource', () => {
    expect(bindResourceToParams(schema, 'h1', { hostId: 'admin-1' })).toEqual({
      ok: false,
      errorMessage: 'resource_param_mismatch',
    });
  });

  it('fills the param in from the resource when it is absent', () => {
    expect(bindResourceToParams(schema, 'h1', { reason: 'x' })).toEqual({
      ok: true,
      params: { reason: 'x', hostId: 'h1' },
    });
    expect(bindResourceToParams(schema, 'h1', undefined)).toEqual({
      ok: true,
      params: { hostId: 'h1' },
    });
  });

  it('refuses non-object params for a bound action', () => {
    expect(bindResourceToParams(schema, 'h1', ['h1']).ok).toBe(false);
    expect(bindResourceToParams(schema, 'h1', 'h1').ok).toBe(false);
  });
});
