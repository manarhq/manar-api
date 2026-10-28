import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const RSA = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};

export interface TestCa {
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
  pem: string;
}

const day = 86_400_000;

export async function makeCa(
  name: string,
  opts: {
    issuer?: TestCa;
    notBefore?: Date;
    notAfter?: Date;
    pathLen?: number;
    sigHash?: string;
    keys?: CryptoKeyPair;
    keyUsages?: number;
    eku?: string[];
    extra?: x509.Extension[];
  } = {},
): Promise<TestCa> {
  const keys =
    opts.keys ??
    ((await webcrypto.subtle.generateKey(
      { ...RSA, hash: opts.sigHash ?? 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '01' + Buffer.from(name).toString('hex').slice(0, 8),
    subject: `CN=${name}`,
    issuer: opts.issuer ? opts.issuer.cert.subject : `CN=${name}`,
    notBefore: opts.notBefore ?? new Date(Date.now() - day),
    notAfter: opts.notAfter ?? new Date(Date.now() + 365 * day),
    signingAlgorithm: { ...RSA, hash: opts.sigHash ?? 'SHA-256' },
    publicKey: keys.publicKey,
    signingKey: opts.issuer ? opts.issuer.keys.privateKey : keys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(true, opts.pathLen, true),
      new x509.KeyUsagesExtension(
        opts.keyUsages ??
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      ...(opts.eku ? [new x509.ExtendedKeyUsageExtension(opts.eku)] : []),
      ...(opts.extra ?? []),
    ],
  });
  return { cert, keys, pem: cert.toString('pem') };
}

export interface TestLeaf {
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
  pem: string;
}

export async function makeLeaf(
  issuer: TestCa,
  opts: {
    dns?: string | null;
    eku?: string[] | null;
    notBefore?: Date;
    notAfter?: Date;
    serial?: string;
    crlUrl?: string;
    freshestCrlUrl?: string;
    keys?: CryptoKeyPair;
    extra?: x509.Extension[];
  } = {},
): Promise<TestLeaf> {
  const keys =
    opts.keys ??
    ((await webcrypto.subtle.generateKey(RSA, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair);
  const dns = opts.dns === undefined ? 'pc01.corp.example' : opts.dns;
  const eku =
    opts.eku === undefined ? [x509.ExtendedKeyUsage.clientAuth] : opts.eku;
  const extensions: x509.Extension[] = [];
  if (dns) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: dns }]),
    );
  }
  if (eku) extensions.push(new x509.ExtendedKeyUsageExtension(eku));
  if (opts.crlUrl) {
    extensions.push(new x509.CRLDistributionPointsExtension([opts.crlUrl]));
  }
  if (opts.freshestCrlUrl) {
    extensions.push(
      new x509.Extension(
        '2.5.29.46',
        false,
        new x509.CRLDistributionPointsExtension([opts.freshestCrlUrl]).value,
      ),
    );
  }
  extensions.push(...(opts.extra ?? []));
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: opts.serial ?? '0a0b0c',
    subject: `CN=${dns ?? 'nobody'}`,
    issuer: issuer.cert.subject,
    notBefore: opts.notBefore ?? new Date(Date.now() - day),
    notAfter: opts.notAfter ?? new Date(Date.now() + 30 * day),
    signingAlgorithm: RSA,
    publicKey: keys.publicKey,
    signingKey: issuer.keys.privateKey,
    extensions,
  });
  return { cert, keys, pem: cert.toString('pem') };
}

const derInt = (n: bigint) => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = '00' + hex;
  const body = Buffer.from(hex, 'hex');
  return new Uint8Array([0x02, body.length, ...body]);
};

export async function makeCrl(
  issuer: TestCa,
  revokedSerials: string[],
  opts: {
    nextUpdate?: Date;
    crlNumber?: bigint;
    /** Makes this a delta CRL on that base CRL number. */
    deltaBase?: bigint;
    /** Delta CRL locations the base points at (Freshest CRL). */
    freshest?: string[];
    wrongIssuerKey?: TestCa;
  } = {},
): Promise<Uint8Array> {
  const extensions: x509.Extension[] = [];
  if (opts.crlNumber !== undefined) {
    extensions.push(
      new x509.Extension('2.5.29.20', false, derInt(opts.crlNumber)),
    );
  }
  if (opts.deltaBase !== undefined) {
    extensions.push(
      new x509.Extension('2.5.29.27', true, derInt(opts.deltaBase)),
    );
  }
  if (opts.freshest) {
    const dp = new x509.CRLDistributionPointsExtension(opts.freshest);
    extensions.push(new x509.Extension('2.5.29.46', false, dp.value));
  }
  const crl = await x509.X509CrlGenerator.create({
    issuer: issuer.cert.subject,
    thisUpdate: new Date(Date.now() - 3_600_000),
    nextUpdate: opts.nextUpdate ?? new Date(Date.now() + day),
    entries: revokedSerials.map((serialNumber) => ({
      serialNumber,
      revocationDate: new Date(Date.now() - 1_800_000),
    })),
    extensions,
    signingAlgorithm: RSA,
    signingKey: (opts.wrongIssuerKey ?? issuer).keys.privateKey,
  });
  return new Uint8Array(crl.rawData);
}

/** A PKCS#10 request for `keys`, naming `uri` as its only SAN (the host contract). */
export async function makeCsrPem(
  keys: CryptoKeyPair,
  uri: string,
): Promise<string> {
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: 'CN=host',
    keys,
    signingAlgorithm: RSA,
    extensions: [
      new x509.SubjectAlternativeNameExtension([{ type: 'url', value: uri }]),
    ],
  });
  return csr.toString('pem');
}

export async function newRsaKeys(
  modulusLength: number,
): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey({ ...RSA, modulusLength }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}

export async function newEcKeys(namedCurve: string): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
}

export async function newKeys(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(RSA, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}
