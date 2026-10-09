import { generateKeyPairSync } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Command, CommandRunner, Option } from 'nest-commander';
import type { AppConfig } from '../../config/env.validation';
import { OpenBaoKvClient } from '../../openbao/openbao-kv.client';

/**
 * `pnpm manar fleet:keygen [--force]`: creates this deployment's Ed25519 heartbeat key in
 * OpenBao KV (FLEET_HEARTBEAT_KEY_PATH) and prints only the public key, which an owner registers
 * in manar-fleet. Refuses to replace an existing key without --force.
 */
@Command({
  name: 'fleet:keygen',
  description: 'Create the manar-fleet heartbeat signing key in OpenBao',
})
export class FleetKeygenCommand extends CommandRunner {
  private readonly logger = new Logger(FleetKeygenCommand.name);

  constructor(
    private readonly kv: OpenBaoKvClient,
    private readonly config: ConfigService<AppConfig, true>,
  ) {
    super();
  }

  async run(_: string[], options: { force?: boolean }): Promise<void> {
    const path = this.config.get('FLEET_HEARTBEAT_KEY_PATH', { infer: true });
    const existing = await this.kv.readSecret(path).catch(() => null);
    if (
      existing &&
      typeof existing.privateKeyPem === 'string' &&
      !options.force
    ) {
      this.logger.error(
        `A heartbeat key already exists at ${path}; pass --force to replace it`,
      );
      process.exitCode = 1;
      return;
    }
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    await this.kv.writeSecret(path, {
      privateKeyPem: privateKey
        .export({ type: 'pkcs8', format: 'pem' })
        .toString(),
    });
    // The public key is not secret; register it with PUT /deployments/:id/connection in manar-fleet.
    process.stdout.write(
      publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    );
  }

  @Option({ flags: '--force', description: 'Replace an existing key' })
  parseForce(): boolean {
    return true;
  }
}
