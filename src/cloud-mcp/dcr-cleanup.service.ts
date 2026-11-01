import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import type { KeycloakClientRepresentation } from '../keycloak/keycloak-admin.client';
import {
  DCR_FIRST_SEEN_ATTRIBUTE,
  DCR_STATE_ATTRIBUTE,
  PRE_REGISTERED_CLIENT_PREFIX,
  cloudMcpSettings,
} from './cloud-mcp.config';
import { realmOfIssuer } from './cloud-agents.service';

const SWEEP_EVERY_MS = 5 * 60_000;
/** A registration that asks for no agent scope is useless: it only takes a slot. */
export const UNSCOPED_TTL_MS = 15 * 60_000;
/** A registration for an agent that nobody confirmed. */
export const UNCONFIRMED_TTL_MS = 6 * 3_600_000;
/** Admin calls per sweep (marking + deleting); a flood is worked off over several sweeps. */
const WRITES_PER_SWEEP = 500;

/**
 * Anonymous registration on the shared realm is open to the internet (a registration request
 * cannot be made to require an agent scope in Keycloak), so unconfirmed clients are swept: one
 * that carries no agent scope lives 15 minutes, one that does 6 hours, and a waiting or
 * confirmed one (attribute `manar.dcr.state`) is never touched. The age is the time this sweep
 * first saw the client (attribute), so a public client with no registration time is handled too.
 * Only clients whose every redirect URI is on a DCR trusted host are candidates.
 */
@Injectable()
export class DcrCleanupService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DcrCleanupService.name);
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly keycloak: KeycloakAdminClient,
  ) {}

  onModuleInit(): void {
    const settings = cloudMcpSettings(this.config);
    if (
      !settings.host ||
      !settings.sharedIssuer ||
      !settings.chatGptOnSharedRealm
    ) {
      return;
    }
    // ponytail: every replica sweeps; the work is idempotent. Add a lock if the realm grows large.
    this.timer = setInterval(() => {
      this.sweep().catch((e: unknown) =>
        this.logger.error(
          `DCR sweep failed: ${e instanceof Error ? e.message : String(e)}`,
        ),
      );
    }, SWEEP_EVERY_MS);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    clearInterval(this.timer);
  }

  /** One pass; returns the client ids it deleted. */
  async sweep(now = Date.now()): Promise<string[]> {
    const settings = cloudMcpSettings(this.config);
    const realm = settings.sharedIssuer
      ? realmOfIssuer(settings.sharedIssuer)
      : null;
    if (!realm) return [];
    const consoleClient = this.config.get('KEYCLOAK_CLIENT_ID', {
      infer: true,
    });
    const onTrustedHost = (uri: string) => {
      try {
        const url = new URL(uri);
        return (
          url.protocol === 'https:' &&
          settings.dcrTrustedHosts.includes(url.hostname)
        );
      } catch {
        return false;
      }
    };
    const candidates = (await this.keycloak.listClients(realm)).filter(
      (c: KeycloakClientRepresentation) =>
        c.clientId !== consoleClient &&
        !c.clientId.startsWith(PRE_REGISTERED_CLIENT_PREFIX) &&
        !c.attributes?.[DCR_STATE_ATTRIBUTE] &&
        (c.redirectUris?.length ?? 0) > 0 &&
        c.redirectUris!.every(onTrustedHost),
    );
    const deleted: string[] = [];
    let writes = 0;
    for (const client of candidates) {
      if (writes >= WRITES_PER_SWEEP) break;
      const seen = Number(client.attributes?.[DCR_FIRST_SEEN_ATTRIBUTE]);
      if (!Number.isFinite(seen)) {
        await this.keycloak.updateClient(realm, client.clientId, {
          attributes: { [DCR_FIRST_SEEN_ATTRIBUTE]: String(now) },
        });
        writes += 1;
        continue;
      }
      const scoped = [
        ...(client.defaultClientScopes ?? []),
        ...(client.optionalClientScopes ?? []),
      ].some((s) => s.startsWith('manar-mcp-'));
      if (now - seen >= (scoped ? UNCONFIRMED_TTL_MS : UNSCOPED_TTL_MS)) {
        await this.keycloak.deleteById(realm, `clients/${client.id}`);
        deleted.push(client.clientId);
        writes += 1;
      }
    }
    if (deleted.length) {
      this.logger.log(
        `Deleted ${deleted.length} unconfirmed self-registered clients`,
      );
    }
    return deleted;
  }
}
