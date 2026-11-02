import { randomInt } from 'node:crypto';

// Crockford base32: no I, L, O or U, so a code read aloud or retyped is unambiguous.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * A short reference for one error occurrence, e.g. `MNR-7F3K2Q`. Random, so it carries nothing
 * about the request or the user; support finds the full details by searching the logs for it.
 */
export function newErrorReference(): string {
  let code = '';
  for (let i = 0; i < 6; i++) code += ALPHABET[randomInt(ALPHABET.length)];
  return `MNR-${code}`;
}

export const ERROR_REFERENCE_PATTERN = /^MNR-[0-9A-HJKMNP-TV-Z]{6}$/;
