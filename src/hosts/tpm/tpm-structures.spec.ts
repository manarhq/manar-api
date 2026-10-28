import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { activateCredential, newRsaKeys, rsaTpmtPublic } from './software-tpm';
import {
  makeCredential,
  parseTpmtPublic,
  TpmStructureError,
  tpmName,
} from './tpm-structures';

describe('TPM structures', () => {
  const ek = newRsaKeys();
  const ak = newRsaKeys();
  const akPublic = rsaTpmtPublic(ak.publicKey);
  const akName = tpmName(akPublic);

  it('reads the key and attributes out of a TPMT_PUBLIC', () => {
    const parsed = parseTpmtPublic(akPublic);
    expect(parsed.kind).toBe('rsa');
    expect(parsed.nameAlg).toBe('sha256');
    const expected = ak.publicKey.export({ type: 'spki', format: 'der' });
    expect(parsed.spki.equals(expected)).toBe(true);
    expect(parsed.attributes & 0x32).toBe(0x32);
  });

  it('the name is the algorithm id plus the digest', () => {
    expect(akName).toHaveLength(2 + 32);
    expect(akName.readUInt16BE(0)).toBe(0x000b);
  });

  it('rejects truncated and trailing input', () => {
    expect(() => parseTpmtPublic(akPublic.subarray(0, 20))).toThrow(
      TpmStructureError,
    );
    expect(() =>
      parseTpmtPublic(Buffer.concat([akPublic, Buffer.from([0])])),
    ).toThrow(TpmStructureError);
  });

  it('a TPM holding the EK and naming the AK recovers the secret', () => {
    const secret = randomBytes(32);
    const { credentialBlob, encryptedSecret } = makeCredential({
      ekPublicKey: ek.publicKey,
      akName,
      secret,
    });
    const got = activateCredential({
      ekPrivateKey: ek.privateKey,
      akName,
      credentialBlob,
      encryptedSecret,
    });
    expect(got.equals(secret)).toBe(true);
  });

  it('another EK cannot activate it', () => {
    const { credentialBlob, encryptedSecret } = makeCredential({
      ekPublicKey: ek.publicKey,
      akName,
      secret: randomBytes(32),
    });
    expect(() =>
      activateCredential({
        ekPrivateKey: newRsaKeys().privateKey,
        akName,
        credentialBlob,
        encryptedSecret,
      }),
    ).toThrow();
  });

  it('a different key name cannot activate it', () => {
    const { credentialBlob, encryptedSecret } = makeCredential({
      ekPublicKey: ek.publicKey,
      akName,
      secret: randomBytes(32),
    });
    const otherName = tpmName(rsaTpmtPublic(newRsaKeys().publicKey));
    expect(() =>
      activateCredential({
        ekPrivateKey: ek.privateKey,
        akName: otherName,
        credentialBlob,
        encryptedSecret,
      }),
    ).toThrow('TPM_RC_INTEGRITY');
  });

  it('a tampered blob is refused', () => {
    const { credentialBlob, encryptedSecret } = makeCredential({
      ekPublicKey: ek.publicKey,
      akName,
      secret: randomBytes(32),
    });
    credentialBlob[credentialBlob.length - 1] ^= 1;
    expect(() =>
      activateCredential({
        ekPrivateKey: ek.privateKey,
        akName,
        credentialBlob,
        encryptedSecret,
      }),
    ).toThrow('TPM_RC_INTEGRITY');
  });
});
