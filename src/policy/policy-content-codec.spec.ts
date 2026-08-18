import { describe, expect, it } from 'vitest';
import {
  computeContentHash,
  dumpPolicyContentYaml,
  parsePolicyContentYaml,
} from './policy-content-codec';
import { PolicyContentSchema } from './policy-content.schema';

describe('policy-content-codec', () => {
  it('produces an identical contentHash for equivalent YAML and JSON input, regardless of key order', () => {
    const yamlText = `
rules:
  - effect: DENY
    actionId: delete
    toolId: iam
    resourcePattern: "*"
    riskWeight: 60
  - toolId: "*"
    actionId: "*"
    effect: ALLOW
`;

    const jsonEquivalent = {
      rules: [
        {
          toolId: 'iam',
          actionId: 'delete',
          effect: 'DENY',
          riskWeight: 60,
          resourcePattern: '*',
        },
        {
          actionId: '*',
          effect: 'ALLOW',
          toolId: '*',
          resourcePattern: '*',
        },
      ],
    };

    const fromYaml = parsePolicyContentYaml(yamlText);
    const fromJson = PolicyContentSchema.parse(jsonEquivalent);

    expect(computeContentHash(fromYaml)).toBe(computeContentHash(fromJson));
  });

  it('produces a different hash for genuinely different content', () => {
    const a = PolicyContentSchema.parse({
      rules: [{ toolId: '*', actionId: '*', effect: 'ALLOW' }],
    });
    const b = PolicyContentSchema.parse({
      rules: [{ toolId: '*', actionId: '*', effect: 'DENY' }],
    });
    expect(computeContentHash(a)).not.toBe(computeContentHash(b));
  });

  it('hash is stable regardless of key order at every nesting level', () => {
    const a = {
      rules: [
        {
          toolId: 'x',
          actionId: 'y',
          effect: 'ALLOW' as const,
          resourcePattern: '*',
        },
      ],
    };
    const b = {
      rules: [
        {
          effect: 'ALLOW' as const,
          resourcePattern: '*',
          actionId: 'y',
          toolId: 'x',
        },
      ],
    };
    expect(computeContentHash(a)).toBe(computeContentHash(b));
  });

  it('YAML dump of a parsed content round-trips back through the YAML parser to the same content', () => {
    const original = PolicyContentSchema.parse({
      rules: [
        {
          toolId: 'soc',
          actionId: 'read',
          effect: 'ALLOW',
          description: 'SOC read access',
        },
      ],
    });
    const yamlText = dumpPolicyContentYaml(original);
    const reparsed = parsePolicyContentYaml(yamlText);
    expect(computeContentHash(reparsed)).toBe(computeContentHash(original));
  });

  it('rejects malformed YAML content (invalid effect) rather than silently coercing it', () => {
    const badYaml = `
rules:
  - toolId: "*"
    actionId: "*"
    effect: MAYBE
`;
    expect(() => parsePolicyContentYaml(badYaml)).toThrow();
  });
});
