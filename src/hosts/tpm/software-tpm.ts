import {
  constants,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt,
  sign,
  timingSafeEqual,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { kdfa, tpmName } from './tpm-structures';

/**
 * Test double for the TPM side: ActivateCredential written from the TCG
 * spec (Part 1 section 24), independent of `makeCredential`. Tests only.
 */
export function activateCredential(input: {
  ekPrivateKey: KeyObject;
  akName: Buffer;
  credentialBlob: Buffer;
  encryptedSecret: Buffer;
}): Buffer {
  const hash = 'sha256';
  const blob = input.credentialBlob.subarray(2);
  const hmacLen = blob.readUInt16BE(0);
  const integrity = blob.subarray(2, 2 + hmacLen);
  const encIdentity = blob.subarray(2 + hmacLen);
  const seed = privateDecrypt(
    {
      key: input.ekPrivateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: hash,
      oaepLabel: Buffer.from('IDENTITY\0', 'utf8'),
    },
    input.encryptedSecret.subarray(2),
  );
  const hmacKey = kdfa(
    hash,
    seed,
    'INTEGRITY',
    Buffer.alloc(0),
    Buffer.alloc(0),
    256,
  );
  const expect = createHmac(hash, hmacKey)
    .update(encIdentity)
    .update(input.akName)
    .digest();
  if (
    expect.length !== integrity.length ||
    !timingSafeEqual(expect, integrity)
  ) {
    throw new Error('TPM_RC_INTEGRITY');
  }
  const symKey = kdfa(
    hash,
    seed,
    'STORAGE',
    input.akName,
    Buffer.alloc(0),
    128,
  );
  const d = createDecipheriv('aes-128-cfb', symKey, Buffer.alloc(16));
  const plain = Buffer.concat([d.update(encIdentity), d.final()]);
  return plain.subarray(2, 2 + plain.readUInt16BE(0));
}

/** A marshalled RSA TPMT_PUBLIC for `publicKey`. */
export function rsaTpmtPublic(
  publicKey: KeyObject,
  attributes = 0x2 | 0x10 | 0x20 | 0x40000,
): Buffer {
  const jwk = publicKey.export({ format: 'jwk' });
  const n = Buffer.from(jwk.n!, 'base64url');
  const u16 = (v: number) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(v);
    return b;
  };
  const u32 = (v: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v);
    return b;
  };
  return Buffer.concat([
    u16(0x0001), // RSA
    u16(0x000b), // SHA-256 name
    u32(attributes),
    u16(0), // authPolicy
    u16(0x0010), // symmetric NULL
    u16(0x0014), // RSASSA
    u16(0x000b),
    u16(2048),
    u32(0), // default exponent
    u16(n.length),
    n,
  ]);
}

export function newRsaKeys() {
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}

export interface SoftCertifyOptions {
  nonce: Buffer;
  /** Name written into the attestation; defaults to the name of `hostTpmPublic`. */
  certifiedName?: Buffer;
  magic?: number;
  type?: number;
  sigScheme?: number;
  /** Sign with this instead of `akPrivate` (bad signature test). */
  signWith?: KeyObject;
}

/**
 * Test double for TPM2_Certify: TPMS_ATTEST (TCG Part 2 section 10.12.8) and
 * TPMT_SIGNATURE written from the spec. Tests only.
 */
export function softCertify(
  akPrivate: KeyObject,
  hostTpmPublic: Buffer,
  o: SoftCertifyOptions,
): { certifyInfo: Buffer; signature: Buffer } {
  const u16 = (v: number) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(v);
    return b;
  };
  const u32 = (v: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v);
    return b;
  };
  const sized = (b: Buffer) => Buffer.concat([u16(b.length), b]);
  const name = o.certifiedName ?? tpmName(hostTpmPublic);
  const certifyInfo = Buffer.concat([
    u32(o.magic ?? 0xff544347),
    u16(o.type ?? 0x8017),
    sized(Buffer.from('qualified-signer')),
    sized(o.nonce),
    Buffer.alloc(17), // clockInfo
    Buffer.alloc(8), // firmwareVersion
    sized(name),
    sized(Buffer.from('qualified-name')),
  ]);
  const sig = sign('sha256', certifyInfo, {
    key: o.signWith ?? akPrivate,
    padding:
      (o.sigScheme ?? 0x0014) === 0x0014
        ? constants.RSA_PKCS1_PADDING
        : constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  });
  return {
    certifyInfo,
    signature: Buffer.concat([
      u16(o.sigScheme ?? 0x0014),
      u16(0x000b),
      sized(sig),
    ]),
  };
}
