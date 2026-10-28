import { createPrivateKey, webcrypto } from 'node:crypto';
import ldapjs from 'ldapjs';
import type { TestLeaf } from './test-pki';

/** The few ldapjs calls used here (its published types do not cover them). */
interface LdapLike {
  createServer(o: { certificate: string; key: string }): LdapServer;
  InvalidCredentialsError: new () => Error;
}
interface LdapServer {
  bind(dn: string, h: Handler): void;
  search(base: string, h: Handler): void;
  listen(port: number, host: string, cb: () => void): void;
  address(): { port: number };
  close(cb: () => void): void;
}
type Handler = (
  req: {
    credentials: string;
    filter: { matches(a: Record<string, unknown>): boolean };
  },
  res: { end(): void; send(e: unknown): void },
  next: (e?: Error) => void,
) => void;
const ldap = ldapjs as unknown as LdapLike;

export interface FakeComputer {
  dn: string;
  dNSHostName: string;
}

/** An in-process LDAPS server for tests: one bind account, a list of computer objects. */
export async function startLdapsServer(input: {
  serverCert: TestLeaf;
  chainPem?: string;
  bindDn: string;
  password: string;
  computers: FakeComputer[];
}): Promise<{ url: string; port: number; close: () => Promise<void> }> {
  const pkcs8 = Buffer.from(
    await webcrypto.subtle.exportKey('pkcs8', input.serverCert.keys.privateKey),
  );
  const keyPem = createPrivateKey({
    key: pkcs8,
    format: 'der',
    type: 'pkcs8',
  })
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
  const server = ldap.createServer({
    certificate: input.serverCert.pem,
    key: keyPem,
  });
  server.bind(input.bindDn, (req, res, next) => {
    if (req.credentials !== input.password) {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });
  server.search('', (req, res, next) => {
    for (const c of input.computers) {
      const attributes = {
        objectClass: ['top', 'computer'],
        dNSHostName: c.dNSHostName,
        distinguishedName: c.dn,
      };
      if (req.filter.matches(attributes)) {
        res.send({ dn: c.dn, attributes });
      }
    }
    res.end();
    return next();
  });
  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve()),
  );
  const port = server.address().port;
  return {
    port,
    url: `ldaps://localhost:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
