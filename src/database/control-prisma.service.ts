import { pgPoolOptions, poolSettings } from './pool-options';
import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/control-client/client';
import { AppConfig } from '../config/env.validation';

/**
 * The control DB Prisma client, wired into Nest's DI as an injectable
 * service. Holds only provisioning/routing metadata (Tenant,
 * TenantDatabaseBinding, SecretReference) — see docs/tenant-isolation.md.
 *
 * Prisma 7 requires a driver adapter (no built-in query engine); the
 * connection string comes from `ConfigService` (`CONTROL_DATABASE_URL`),
 * never read from `process.env` directly here.
 */
@Injectable()
export class ControlPrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(ControlPrismaService.name);

  constructor(configService: ConfigService<AppConfig, true>) {
    super({
      adapter: new PrismaPg(
        pgPoolOptions(
          configService.get('CONTROL_DATABASE_URL', { infer: true }),
          poolSettings((k) => configService.get(k as never), 'control'),
        ),
      ),
    });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
    this.logger.log('Connected to control database');
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
