import { describe, expect, it } from 'vitest';
import {
  CODE_ALPHABET,
  CODE_LENGTH,
  generateInstallCode,
  normalizeInstallCode,
} from './install-code.util';

describe('install codes', () => {
  it('uses an alphabet without look-alikes and is long enough', () => {
    expect(CODE_ALPHABET).not.toMatch(/[ILO01]/);
    expect(CODE_LENGTH).toBeGreaterThanOrEqual(8);
    for (let i = 0; i < 200; i++) {
      expect(generateInstallCode()).toMatch(
        new RegExp(`^[${CODE_ALPHABET}]{${CODE_LENGTH}}$`),
      );
    }
  });

  it('does not repeat', () => {
    const codes = new Set(Array.from({ length: 500 }, generateInstallCode));
    expect(codes.size).toBe(500);
  });

  it('normalises case and refuses anything that is not a code', () => {
    const code = generateInstallCode();
    expect(normalizeInstallCode(` ${code.toLowerCase()} `)).toBe(code);
    for (const bad of [
      '',
      'uninstall',
      'ABC',
      `${code}X`,
      'O0I1LABCDE',
      "A'; rm",
    ]) {
      expect(normalizeInstallCode(bad)).toBeNull();
    }
  });
});
