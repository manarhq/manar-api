import {
  randomBytes,
  scrypt as scryptCallback,
  createCipheriv,
  createDecipheriv,
  type ScryptOptions,
} from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { AgentIdentity, IdentityStore } from './identity-store';

// `util.promisify(scrypt)` resolves to the no-options overload's types;
// wrapped explicitly instead so the options (N/r/p/maxmem) overload is
// usable with a Promise-returning call site.
function scrypt(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

// scrypt cost parameters per current OWASP guidance for interactive-ish
// local use (N=2^17, r=8, p=1) — stronger than Node's historical default
// (N=2^14) since this only runs at enroll-time / process-start, not on a
// hot path. `maxmem` must be raised to accommodate N=2^17 (Node's default
// 32MB ceiling is too small for it).
const SCRYPT_N = 2 ** 17;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 32; // AES-256
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

const SALT_LENGTH = 16;
const IV_LENGTH = 12; // AES-GCM's recommended nonce length (96 bits) — NOT 16.
const AUTH_TAG_LENGTH = 16;

interface EncryptedEnvelope {
  version: 1;
  saltBase64: string;
  ivBase64: string;
  authTagBase64: string;
  ciphertextBase64: string;
}

/**
 * The one concrete `IdentityStore` implementation this phase: an
 * encrypted file on local disk. The private key (and the rest of the
 * enrolled identity) is never written in plaintext — encrypted with
 * AES-256-GCM (authenticated encryption; a corrupted/tampered file fails
 * to decrypt rather than silently returning wrong bytes) under a key
 * derived from the caller-supplied passphrase via scrypt (a memory-hard
 * KDF, appropriate here because the passphrase — unlike the token/keys
 * elsewhere in this system — may be a lower-entropy, human-manageable
 * secret; see this file's SCRYPT_* constants for the chosen cost
 * parameters).
 *
 * The passphrase itself is never read from the environment by this
 * class — the caller decides where it comes from (an env var, a
 * platform secret manager, an operator prompt, ...); this keeps the SDK
 * a plain library with no implicit env coupling.
 */
export class FileIdentityStore implements IdentityStore {
  constructor(
    private readonly filePath: string,
    private readonly passphrase: string,
  ) {
    if (!passphrase) {
      throw new Error('FileIdentityStore requires a non-empty passphrase');
    }
  }

  async save(identity: AgentIdentity): Promise<void> {
    const plaintext = Buffer.from(JSON.stringify(identity), 'utf8');

    const salt = randomBytes(SALT_LENGTH);
    const iv = randomBytes(IV_LENGTH);
    const key = await scrypt(this.passphrase, salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: SCRYPT_MAXMEM,
    });

    const cipher = createCipheriv('aes-256-gcm', key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    const envelope: EncryptedEnvelope = {
      version: 1,
      saltBase64: salt.toString('base64'),
      ivBase64: iv.toString('base64'),
      authTagBase64: authTag.toString('base64'),
      ciphertextBase64: ciphertext.toString('base64'),
    };

    await mkdir(dirname(this.filePath), { recursive: true });
    // Write to a temp file then rename: an interrupted write never leaves
    // a corrupt/partial identity file at the real path.
    const tempPath = `${this.filePath}.tmp-${process.pid}-${Date.now()}`;
    await writeFile(tempPath, JSON.stringify(envelope), { mode: 0o600 });
    await rename(tempPath, this.filePath);
  }

  async load(): Promise<AgentIdentity | null> {
    let raw: string;
    try {
      raw = await readFile(this.filePath, 'utf8');
    } catch (error) {
      if (isEnoent(error)) return null;
      throw error;
    }

    const envelope = JSON.parse(raw) as EncryptedEnvelope;
    const salt = Buffer.from(envelope.saltBase64, 'base64');
    const iv = Buffer.from(envelope.ivBase64, 'base64');
    const authTag = Buffer.from(envelope.authTagBase64, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');

    const key = await scrypt(this.passphrase, salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: SCRYPT_MAXMEM,
    });

    const decipher = createDecipheriv('aes-256-gcm', key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);
    // Throws if the passphrase is wrong or the file was tampered with —
    // GCM's authentication tag check fails closed, deliberately not
    // caught here (see class doc comment).
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return JSON.parse(plaintext.toString('utf8')) as AgentIdentity;
  }

  async clear(): Promise<void> {
    await rm(this.filePath, { force: true });
  }
}

function isEnoent(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'ENOENT'
  );
}
