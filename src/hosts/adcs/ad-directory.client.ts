import { Injectable } from '@nestjs/common';
import { Client } from 'ldapts';
import { escapeLdapFilter } from './ou.util';

/** The directory could not be used (network, TLS, bind, timeout). Callers change nothing. */
export class AdUnreachableError extends Error {}

export interface AdConnection {
  ldapsUrl: string;
  baseDn: string;
  bindDn: string;
  /** PEM of the CA that signed the LDAPS server certificate. */
  serverCaPem: string;
  password: string;
}

export type ComputerLookup = { found: true; dn: string } | { found: false };

/** Port so services can be tested without a directory; the real one is `LdapsAdDirectory`. */
export abstract class AdDirectory {
  abstract findComputer(
    connection: AdConnection,
    dnsName: string,
  ): Promise<ComputerLookup>;
}

const TIMEOUT_MS = 5_000;

/** Only `ldaps://` is accepted: plain LDAP and StartTLS are never used. */
export function isLdapsUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'ldaps:' && u.hostname !== '' && u.username === '';
  } catch {
    return false;
  }
}

/**
 * Looks a computer up in AD over LDAPS with a read-only account. The server
 * certificate is always verified (against `serverCaPem`, name included) and
 * TLS 1.2 is the floor. Nothing here logs the password or the DN contents.
 */
@Injectable()
export class LdapsAdDirectory extends AdDirectory {
  async findComputer(
    connection: AdConnection,
    dnsName: string,
  ): Promise<ComputerLookup> {
    if (!isLdapsUrl(connection.ldapsUrl)) {
      throw new AdUnreachableError('AD URL is not ldaps://');
    }
    const client = new Client({
      url: connection.ldapsUrl,
      timeout: TIMEOUT_MS,
      connectTimeout: TIMEOUT_MS,
      tlsOptions: {
        ca: [connection.serverCaPem],
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
      },
    });
    try {
      await client.bind(connection.bindDn, connection.password);
      const { searchEntries } = await client.search(connection.baseDn, {
        scope: 'sub',
        filter: `(&(objectClass=computer)(dNSHostName=${escapeLdapFilter(dnsName)}))`,
        attributes: ['dNSHostName'],
        sizeLimit: 5,
      });
      const [only, ...rest] = searchEntries;
      // None, or more than one: no OU is claimed.
      if (!only || rest.length > 0) return { found: false };
      // The entry's own DN is the computer's distinguishedName.
      return only.dn.length > 0
        ? { found: true, dn: only.dn }
        : { found: false };
    } catch (error) {
      if (error instanceof Error && error.name === 'SizeLimitExceededError') {
        return { found: false };
      }
      // The message of a bind failure can echo the DN; keep only the class.
      throw new AdUnreachableError(
        `AD request failed: ${error instanceof Error ? error.name : 'error'}`,
      );
    } finally {
      await client.unbind().catch(() => undefined);
    }
  }
}
