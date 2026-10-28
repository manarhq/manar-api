import 'reflect-metadata';
import { beforeAll, describe, expect, it } from 'vitest';
import * as x509 from '@peculiar/x509';
import {
  makeCa,
  makeLeaf,
  newEcKeys,
  newRsaKeys,
  type TestCa,
} from '../../../test/support/test-pki';
import {
  CertChainError,
  EKU_CLIENT_AUTH,
  validateChain,
} from './cert-chain.util';

const reasonOf = async (p: Promise<unknown>) =>
  p.then(
    () => 'ok',
    (e: unknown) => (e as CertChainError).reason,
  );
const day = 86_400_000;

describe('validateChain', () => {
  let root: TestCa;
  let issuing: TestCa;
  let other: TestCa;

  beforeAll(async () => {
    root = await makeCa('Corp Root CA');
    issuing = await makeCa('Corp Issuing CA', { issuer: root });
    other = await makeCa('Other Root CA');
  });

  const run = (
    leafPem: string,
    extra: Partial<Parameters<typeof validateChain>[0]> = {},
  ) =>
    validateChain({
      leafPem,
      anchorsPem: [root.pem],
      requireEku: EKU_CLIENT_AUTH,
      ...extra,
    });

  it('accepts a leaf signed directly by the anchor', async () => {
    const leaf = await makeLeaf(root);
    const { chain } = await run(leaf.pem);
    expect(chain).toHaveLength(2);
  });

  it('accepts a leaf through a presented intermediate', async () => {
    const leaf = await makeLeaf(issuing);
    expect(
      await reasonOf(run(leaf.pem, { intermediatesPem: [issuing.pem] })),
    ).toBe('ok');
  });

  it('refuses a chain whose intermediate is not presented', async () => {
    const leaf = await makeLeaf(issuing);
    expect(await reasonOf(run(leaf.pem))).toBe('untrusted');
  });

  it('refuses a certificate from another CA', async () => {
    const leaf = await makeLeaf(other);
    expect(await reasonOf(run(leaf.pem))).toBe('untrusted');
  });

  it('refuses a forged issuer name with the wrong key', async () => {
    const imposter = await makeCa('Corp Root CA'); // same name, different key
    const leaf = await makeLeaf(imposter);
    expect(await reasonOf(run(leaf.pem))).toBe('untrusted');
  });

  it('refuses expired and not-yet-valid leaves', async () => {
    const old = await makeLeaf(root, {
      notBefore: new Date(Date.now() - 10 * day),
      notAfter: new Date(Date.now() - day),
    });
    expect(await reasonOf(run(old.pem))).toBe('expired');
    const future = await makeLeaf(root, {
      notBefore: new Date(Date.now() + day),
      notAfter: new Date(Date.now() + 10 * day),
    });
    expect(await reasonOf(run(future.pem))).toBe('not_yet_valid');
  });

  it('refuses a missing or wrong EKU', async () => {
    const wrong = await makeLeaf(root, {
      eku: [x509.ExtendedKeyUsage.serverAuth],
    });
    expect(await reasonOf(run(wrong.pem))).toBe('wrong_eku');
    const none = await makeLeaf(root, { eku: null });
    expect(await reasonOf(run(none.pem))).toBe('wrong_eku');
  });

  it('refuses an expired intermediate', async () => {
    const stale = await makeCa('Stale CA', {
      issuer: root,
      notBefore: new Date(Date.now() - 10 * day),
      notAfter: new Date(Date.now() - day),
    });
    const leaf = await makeLeaf(stale);
    expect(
      await reasonOf(run(leaf.pem, { intermediatesPem: [stale.pem] })),
    ).toBe('expired');
  });

  it('refuses an intermediate that is not a CA', async () => {
    const leafCa = await makeLeaf(root, { dns: 'not-a-ca' });
    // a leaf cannot issue: build a cert "issued" by it
    const fake = {
      cert: leafCa.cert,
      keys: leafCa.keys,
      pem: leafCa.pem,
    };
    const child = await makeLeaf(fake);
    expect(
      await reasonOf(run(child.pem, { intermediatesPem: [leafCa.pem] })),
    ).toBe('not_a_ca');
  });

  it('refuses garbage and an empty trust store', async () => {
    expect(await reasonOf(run('not a certificate'))).toBe('unparseable');
    const leaf = await makeLeaf(root);
    expect(await reasonOf(run(leaf.pem, { anchorsPem: [] }))).toBe('untrusted');
  });

  it('refuses a leaf presented as its own anchor', async () => {
    const leaf = await makeLeaf(root);
    expect(await reasonOf(run(leaf.pem, { anchorsPem: [leaf.pem] }))).toBe(
      'untrusted',
    );
  });

  describe('path rules', () => {
    const critical = (oid: string) =>
      new x509.Extension(oid, true, new Uint8Array([0x30, 0x00]));

    it('enforces pathLenConstraint (root pathLen 0 cannot have two CAs below)', async () => {
      const r0 = await makeCa('PathLen Root', { pathLen: 0 });
      const mid = await makeCa('PathLen Mid', { issuer: r0 });
      const leaf = await makeLeaf(mid);
      expect(
        await reasonOf(
          validateChain({
            leafPem: leaf.pem,
            intermediatesPem: [mid.pem],
            anchorsPem: [r0.pem],
            requireEku: EKU_CLIENT_AUTH,
          }),
        ),
      ).toBe('path_length');
      const direct = await makeLeaf(r0);
      expect(
        await reasonOf(
          validateChain({ leafPem: direct.pem, anchorsPem: [r0.pem] }),
        ),
      ).toBe('ok');
    });

    it('accepts a pathLen that is large enough', async () => {
      const r1 = await makeCa('PathLen1 Root', { pathLen: 1 });
      const mid = await makeCa('PathLen1 Mid', { issuer: r1 });
      const leaf = await makeLeaf(mid);
      expect(
        await reasonOf(
          validateChain({
            leafPem: leaf.pem,
            intermediatesPem: [mid.pem],
            anchorsPem: [r1.pem],
          }),
        ),
      ).toBe('ok');
    });

    it('refuses a critical extension it does not process (name constraints)', async () => {
      const nc = await makeCa('NC Mid', {
        issuer: root,
        extra: [critical('2.5.29.30')],
      });
      const leaf = await makeLeaf(nc);
      expect(
        await reasonOf(run(leaf.pem, { intermediatesPem: [nc.pem] })),
      ).toBe('critical_extension');
      const pc = await makeCa('PC Mid', {
        issuer: root,
        extra: [critical('2.5.29.36')],
      });
      expect(
        await reasonOf(
          run((await makeLeaf(pc)).pem, { intermediatesPem: [pc.pem] }),
        ),
      ).toBe('critical_extension');
    });

    it('refuses a critical unknown extension on the leaf', async () => {
      const leaf = await makeLeaf(root, { extra: [critical('1.2.3.4.5')] });
      expect(await reasonOf(run(leaf.pem))).toBe('critical_extension');
    });

    it('ignores a non-critical unknown extension', async () => {
      const leaf = await makeLeaf(root, {
        extra: [new x509.Extension('1.2.3.4.5', false, new Uint8Array([5, 0]))],
      });
      expect(await reasonOf(run(leaf.pem))).toBe('ok');
    });

    it('refuses an issuer whose keyUsage lacks keyCertSign', async () => {
      const noSign = await makeCa('NoSign Mid', {
        issuer: root,
        keyUsages: x509.KeyUsageFlags.cRLSign,
      });
      const leaf = await makeLeaf(noSign);
      expect(
        await reasonOf(run(leaf.pem, { intermediatesPem: [noSign.pem] })),
      ).toBe('not_a_ca');
    });

    it('an intermediate with an EKU must allow clientAuth', async () => {
      const web = await makeCa('Web Mid', {
        issuer: root,
        eku: [x509.ExtendedKeyUsage.serverAuth],
      });
      const leaf = await makeLeaf(web);
      expect(
        await reasonOf(run(leaf.pem, { intermediatesPem: [web.pem] })),
      ).toBe('ca_eku');
      const ok = await makeCa('Client Mid', {
        issuer: root,
        eku: [x509.ExtendedKeyUsage.clientAuth],
      });
      expect(
        await reasonOf(
          run((await makeLeaf(ok)).pem, { intermediatesPem: [ok.pem] }),
        ),
      ).toBe('ok');
      const any = await makeCa('Any Mid', {
        issuer: root,
        eku: ['2.5.29.37.0'],
      });
      expect(
        await reasonOf(
          run((await makeLeaf(any)).pem, { intermediatesPem: [any.pem] }),
        ),
      ).toBe('ok');
    });
  });

  describe('algorithm policy', () => {
    it('accepts RSA 2048+ and EC P-256/P-384 keys with SHA-2 signatures', async () => {
      for (const keys of [
        await newRsaKeys(3072),
        await newEcKeys('P-256'),
        await newEcKeys('P-384'),
      ]) {
        const leaf = await makeLeaf(root, { keys });
        expect(await reasonOf(run(leaf.pem))).toBe('ok');
      }
      for (const sigHash of ['SHA-384', 'SHA-512']) {
        const strong = await makeCa(`${sigHash} Root`, { sigHash });
        expect(
          await reasonOf(
            run((await makeLeaf(strong)).pem, { anchorsPem: [strong.pem] }),
          ),
        ).toBe('ok');
      }
    });

    it('refuses a SHA-1 signature on the leaf and on an intermediate', async () => {
      // A CA whose signing key is a SHA-1 key signs with SHA-1.
      const sha1Root = await makeCa('SHA1 Root', { sigHash: 'SHA-1' });
      const sha1Leaf = await makeLeaf(sha1Root);
      expect(
        await reasonOf(run(sha1Leaf.pem, { anchorsPem: [sha1Root.pem] })),
      ).toBe('weak_algorithm');
      const mid = await makeCa('SHA1 Signed Mid', { issuer: sha1Root });
      const leaf = await makeLeaf(mid);
      expect(
        await reasonOf(
          run(leaf.pem, {
            intermediatesPem: [mid.pem],
            anchorsPem: [sha1Root.pem],
          }),
        ),
      ).toBe('weak_algorithm');
    });

    it('refuses weak keys: RSA 1024, EC P-521, on the leaf and on an intermediate', async () => {
      const rsa1024 = await makeLeaf(root, { keys: await newRsaKeys(1024) });
      expect(await reasonOf(run(rsa1024.pem))).toBe('weak_algorithm');
      const p521 = await makeLeaf(root, { keys: await newEcKeys('P-521') });
      expect(await reasonOf(run(p521.pem))).toBe('weak_algorithm');
      const smallCa = await makeCa('Small Mid', {
        issuer: root,
        keys: await newRsaKeys(1024),
      });
      const leaf = await makeLeaf(smallCa);
      expect(
        await reasonOf(run(leaf.pem, { intermediatesPem: [smallCa.pem] })),
      ).toBe('weak_algorithm');
    });
  });
});
