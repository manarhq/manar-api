import {
  constants,
  createCipheriv,
  createHash,
  createHmac,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  verify,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/**
 * The parts of TPM 2.0 (TCG Library Part 1 section 24 and Part 2) that
 * credential activation needs, done on the server side with `node:crypto`:
 * reading a TPMT_PUBLIC, computing its name, and MakeCredential. The TPM does
 * the matching ActivateCredential; only a TPM that holds both the EK and the
 * named key can recover the secret.
 */
export class TpmStructureError extends Error {}

const ALG_RSA = 0x0001;
const ALG_ECC = 0x0023;
const ALG_NULL = 0x0010;
const HASHES: Record<number, string> = {
  0x000b: 'sha256',
  0x000c: 'sha384',
  0x000d: 'sha512',
};
const CURVES: Record<number, string> = { 0x0003: 'P-256', 0x0004: 'P-384' };

/** fixedTPM | fixedParent | sensitiveDataOrigin: made in the TPM, cannot leave it. */
export const TPMA_NON_EXPORTABLE = 0x2 | 0x10 | 0x20;

class Reader {
  private at = 0;
  constructor(private readonly buf: Buffer) {}
  take(n: number): Buffer {
    if (n < 0 || this.at + n > this.buf.length) {
      throw new TpmStructureError('truncated TPM structure');
    }
    const out = this.buf.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }
  u16(): number {
    return this.take(2).readUInt16BE(0);
  }
  u32(): number {
    return this.take(4).readUInt32BE(0);
  }
  sized(): Buffer {
    return this.take(this.u16());
  }
  get done(): boolean {
    return this.at === this.buf.length;
  }
}

export interface TpmPublic {
  kind: 'rsa' | 'ecc';
  nameAlg: string;
  attributes: number;
  /** DER SubjectPublicKeyInfo of the key the structure describes. */
  spki: Buffer;
}

/** Parses a marshalled TPMT_PUBLIC (RSA or ECC P-256/P-384). Throws `TpmStructureError`. */
export function parseTpmtPublic(raw: Buffer): TpmPublic {
  const r = new Reader(raw);
  const type = r.u16();
  const nameAlgId = r.u16();
  const nameAlg = HASHES[nameAlgId];
  if (!nameAlg) throw new TpmStructureError('unsupported name algorithm');
  const attributes = r.u32();
  r.sized(); // authPolicy
  const sym = r.u16();
  if (sym !== ALG_NULL) {
    r.u16();
    r.u16();
  }
  const scheme = r.u16();
  if (scheme !== ALG_NULL) r.u16();

  if (type === ALG_RSA) {
    r.u16(); // keyBits
    const exponent = r.u32() || 65537;
    const modulus = r.sized();
    if (!r.done) throw new TpmStructureError('trailing bytes');
    const eFull = Buffer.alloc(4);
    eFull.writeUInt32BE(exponent);
    let first = 0;
    while (first < 3 && eFull[first] === 0) first += 1;
    const key = createPublicKey({
      key: {
        kty: 'RSA',
        n: modulus.toString('base64url'),
        e: eFull.subarray(first).toString('base64url'),
      },
      format: 'jwk',
    });
    return {
      kind: 'rsa',
      nameAlg,
      attributes,
      spki: key.export({ type: 'spki', format: 'der' }),
    };
  }
  if (type === ALG_ECC) {
    const crv = CURVES[r.u16()];
    if (!crv) throw new TpmStructureError('unsupported curve');
    const kdf = r.u16();
    if (kdf !== ALG_NULL) r.u16();
    const x = r.sized();
    const y = r.sized();
    if (!r.done) throw new TpmStructureError('trailing bytes');
    const key = createPublicKey({
      key: {
        kty: 'EC',
        crv,
        x: x.toString('base64url'),
        y: y.toString('base64url'),
      },
      format: 'jwk',
    });
    return {
      kind: 'ecc',
      nameAlg,
      attributes,
      spki: key.export({ type: 'spki', format: 'der' }),
    };
  }
  throw new TpmStructureError('unsupported key type');
}

/** TPM object name: nameAlg id (2 bytes) followed by the digest of the TPMT_PUBLIC. */
export function tpmName(tpmtPublic: Buffer): Buffer {
  const alg = parseTpmtPublic(tpmtPublic).nameAlg;
  const id = Number(Object.entries(HASHES).find(([, v]) => v === alg)![0]);
  const head = Buffer.alloc(2);
  head.writeUInt16BE(id);
  return Buffer.concat([head, createHash(alg).update(tpmtPublic).digest()]);
}

/** KDFa (SP 800-108 counter mode with HMAC), as TPM 2.0 uses it. */
export function kdfa(
  hash: string,
  key: Buffer,
  label: string,
  contextU: Buffer,
  contextV: Buffer,
  bits: number,
): Buffer {
  const out: Buffer[] = [];
  const bitsBuf = Buffer.alloc(4);
  bitsBuf.writeUInt32BE(bits);
  const blocks = Math.ceil(bits / 8 / createHash(hash).digest().length);
  for (let i = 1; i <= blocks; i += 1) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(i);
    out.push(
      createHmac(hash, key)
        .update(counter)
        .update(label, 'utf8')
        .update(Buffer.from([0]))
        .update(contextU)
        .update(contextV)
        .update(bitsBuf)
        .digest(),
    );
  }
  return Buffer.concat(out).subarray(0, Math.ceil(bits / 8));
}

const be16 = (n: number) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};

/**
 * MakeCredential for an RSA endorsement key (standard EK template: name
 * algorithm SHA-256, AES-128-CFB). Returns the TPM2B_ID_OBJECT body and the
 * TPM2B_ENCRYPTED_SECRET body as the host passes them to ActivateCredential.
 */
export function makeCredential(input: {
  ekPublicKey: KeyObject;
  akName: Buffer;
  secret: Buffer;
  seed?: Buffer;
}): { credentialBlob: Buffer; encryptedSecret: Buffer } {
  const hash = 'sha256';
  const seed = input.seed ?? randomBytes(32);
  const encryptedSeed = publicEncrypt(
    {
      key: input.ekPublicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: hash,
      oaepLabel: Buffer.from('IDENTITY\0', 'utf8'),
    },
    seed,
  );
  const symKey = kdfa(
    hash,
    seed,
    'STORAGE',
    input.akName,
    Buffer.alloc(0),
    128,
  );
  const hmacKey = kdfa(
    hash,
    seed,
    'INTEGRITY',
    Buffer.alloc(0),
    Buffer.alloc(0),
    256,
  );
  const cipher = createCipheriv('aes-128-cfb', symKey, Buffer.alloc(16));
  const encIdentity = Buffer.concat([
    cipher.update(Buffer.concat([be16(input.secret.length), input.secret])),
    cipher.final(),
  ]);
  const integrity = createHmac(hash, hmacKey)
    .update(encIdentity)
    .update(input.akName)
    .digest();
  const body = Buffer.concat([be16(integrity.length), integrity, encIdentity]);
  return {
    credentialBlob: Buffer.concat([be16(body.length), body]),
    encryptedSecret: Buffer.concat([be16(encryptedSeed.length), encryptedSeed]),
  };
}

const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_CERTIFY = 0x8017;

/** Parses a TPMS_ATTEST from TPM2_Certify. Throws `TpmStructureError` unless it is a well-formed certify attestation. */
export function parseCertifyAttest(raw: Buffer): {
  extraData: Buffer;
  certifiedName: Buffer;
} {
  const r = new Reader(raw);
  if (r.u32() !== TPM_GENERATED_VALUE) {
    throw new TpmStructureError('not TPM generated');
  }
  if (r.u16() !== TPM_ST_ATTEST_CERTIFY) {
    throw new TpmStructureError('not a certify attestation');
  }
  r.sized(); // qualifiedSigner
  const extraData = Buffer.from(r.sized());
  r.take(17); // clockInfo
  r.take(8); // firmwareVersion
  const certifiedName = Buffer.from(r.sized());
  r.sized(); // qualifiedName
  if (!r.done) throw new TpmStructureError('trailing bytes');
  return { extraData, certifiedName };
}

/**
 * Checks a marshalled TPMT_SIGNATURE (RSASSA or RSAPSS, SHA-2) over `attest`
 * with an RSA key. False on anything wrong, including a malformed signature.
 */
export function verifyAttestSignature(
  akPublicKey: KeyObject,
  attest: Buffer,
  tpmtSignature: Buffer,
): boolean {
  try {
    const r = new Reader(tpmtSignature);
    const scheme = r.u16();
    const hash = HASHES[r.u16()];
    const sig = r.sized();
    if (!r.done || !hash || akPublicKey.asymmetricKeyType !== 'rsa') {
      return false;
    }
    if (scheme !== 0x0014 && scheme !== 0x0016) return false;
    return verify(
      hash,
      attest,
      {
        key: akPublicKey,
        padding:
          scheme === 0x0014
            ? constants.RSA_PKCS1_PADDING
            : constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO,
      },
      sig,
    );
  } catch {
    return false;
  }
}
