import { randomInt } from 'node:crypto';

/** No I, L, O, 0 or 1: a code read aloud or typed from a screenshot has no look-alikes. */
export const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const CODE_LENGTH = 10;
const CODE = new RegExp(`^[${CODE_ALPHABET}]{${CODE_LENGTH}}$`);

/** 10 characters of a 31-character alphabet: about 49 bits, from the CSPRNG. */
export function generateInstallCode(): string {
  let code = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  }
  return code;
}

/** Upper-cases and checks the shape; null means "cannot be a code" (no database lookup). */
export function normalizeInstallCode(raw: string): string | null {
  const code = raw.trim().toUpperCase();
  return CODE.test(code) ? code : null;
}
