import 'reflect-metadata';
import { beforeAll, describe, expect, it } from 'vitest';
import * as x509 from '@peculiar/x509';
import { makeCa, makeLeaf, type TestCa } from '../../../test/support/test-pki';
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
});
