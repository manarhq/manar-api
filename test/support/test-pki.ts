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
    keyUsages?: number;
    eku?: string[];
    extra?: x509.Extension[];
  } = {},
): Promise<TestCa> {
  const keys = (await webcrypto.subtle.generateKey(RSA, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '01' + Buffer.from(name).toString('hex').slice(0, 8),
    subject: `CN=${name}`,
    issuer: opts.issuer ? opts.issuer.cert.subject : `CN=${name}`,
    notBefore: opts.notBefore ?? new Date(Date.now() - day),
    notAfter: opts.notAfter ?? new Date(Date.now() + 365 * day),
    signingAlgorithm: RSA,
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

export async function makeCrl(
  issuer: TestCa,
  revokedSerials: string[],
  opts: { nextUpdate?: Date } = {},
): Promise<Uint8Array> {
  const crl = await x509.X509CrlGenerator.create({
    issuer: issuer.cert.subject,
    thisUpdate: new Date(Date.now() - 3_600_000),
    nextUpdate: opts.nextUpdate ?? new Date(Date.now() + day),
    entries: revokedSerials.map((serialNumber) => ({
      serialNumber,
      revocationDate: new Date(Date.now() - 1_800_000),
    })),
    signingAlgorithm: RSA,
    signingKey: issuer.keys.privateKey,
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

export async function newKeys(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(RSA, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}
