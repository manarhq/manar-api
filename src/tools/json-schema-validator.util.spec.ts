import { describe, expect, it } from 'vitest';
import {
  VALIDATOR_CACHE_MAX,
  validateAgainstSchema,
  validatorCacheSize,
} from './json-schema-validator.util';

describe('validateAgainstSchema', () => {
  it('compiles a schema once, whatever object it arrives in and whatever its key order', () => {
    const before = validatorCacheSize();
    for (let i = 0; i < 50; i++) {
      const schema =
        i % 2 === 0
          ? {
              type: 'object',
              required: ['q'],
              properties: { q: { type: 'string' } },
            }
          : {
              properties: { q: { type: 'string' } },
              required: ['q'],
              type: 'object',
            };
      expect(validateAgainstSchema(schema, { q: 'x' }).valid).toBe(true);
      expect(validateAgainstSchema(schema, {}).valid).toBe(false);
    }
    expect(validatorCacheSize()).toBe(before + 1);
  });

  it('keeps validating a schema that carries an $id on every call', () => {
    for (let i = 0; i < 3; i++) {
      const schema = {
        $id: 'https://tools.example.test/schemas/alert',
        type: 'object',
        properties: { id: { type: 'integer' } },
      };
      expect(validateAgainstSchema(schema, { id: 1 })).toEqual({ valid: true });
      expect(validateAgainstSchema(schema, { id: 'x' }).valid).toBe(false);
    }
  });

  it('stays bounded however many distinct schemas it sees', () => {
    for (let i = 0; i < VALIDATOR_CACHE_MAX + 50; i++) {
      validateAgainstSchema({ type: 'object', title: `s${i}` }, {});
    }
    expect(validatorCacheSize()).toBeLessThanOrEqual(VALIDATOR_CACHE_MAX);
  });

  it('reports an invalid schema as a validation failure, every time', () => {
    const bad = { type: 'not-a-type' };
    for (let i = 0; i < 2; i++) {
      const result = validateAgainstSchema(bad, {});
      expect(result.valid).toBe(false);
      expect(result.errors).toMatch(/not a valid JSON Schema/);
    }
  });

  it('skips validation when no schema is declared', () => {
    expect(validateAgainstSchema(null, { anything: true })).toEqual({
      valid: true,
    });
  });
});
