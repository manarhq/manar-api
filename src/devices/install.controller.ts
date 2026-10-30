import { Controller, Get, Header, Logger, Param } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { AppConfig } from '../config/env.validation';
import { DEVICES_DEFAULTS } from './devices.config';
import { InstallCodesService } from './install-codes.service';
import {
  NOT_AVAILABLE_MESSAGE,
  NOT_VALID_MESSAGE,
  ScriptUnavailableError,
  renderError,
  renderPowerShell,
  renderSh,
  renderUninstallPowerShell,
  renderUninstallSh,
} from './install-scripts';

/** 20 fetches per minute per address on the public route. */
export const INSTALL_FETCH_LIMIT = 20;

/**
 * The public bootstrap scripts (`irm .../i/<code> | iex`, `curl .../i/<code>.sh | sudo sh`).
 * Fetching never uses the install key; registering does. Unknown, malformed and expired codes
 * get a script that prints a clear message (HTTP 200: `curl -f` and `irm` would otherwise hide
 * the message behind a status code). Rate limited per address.
 */
@ApiExcludeController()
@Controller('i')
@Throttle({ human: { limit: INSTALL_FETCH_LIMIT, ttl: 60_000 } })
export class InstallController {
  private readonly logger = new Logger(InstallController.name);

  constructor(
    private readonly codes: InstallCodesService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  @Get(':code')
  @Header('Content-Type', 'text/plain; charset=utf-8')
  @Header('Cache-Control', 'no-store')
  @Header('X-Content-Type-Options', 'nosniff')
  async script(@Param('code') raw: string) {
    const sh = raw.endsWith('.sh');
    const code = sh ? raw.slice(0, -3) : raw;
    const kind = sh ? 'sh' : 'ps';
    if (code === 'uninstall') {
      return sh ? renderUninstallSh() : renderUninstallPowerShell();
    }
    const found = await this.codes.find(code);
    if (!found) return renderError(kind, NOT_VALID_MESSAGE);
    const get = <K extends keyof AppConfig>(k: K) =>
      this.config.get(k, { infer: true });
    try {
      const params = {
        version: get('MANAR_EDGE_VERSION'),
        releaseBase:
          get('MANAR_EDGE_RELEASE_BASE') ??
          DEVICES_DEFAULTS.MANAR_EDGE_RELEASE_BASE,
        consoleUrl:
          get('MANAR_CONSOLE_URL') ?? DEVICES_DEFAULTS.MANAR_CONSOLE_URL,
        hostUrl: get('MANAR_HOST_URL') ?? DEVICES_DEFAULTS.MANAR_HOST_URL,
        installKey: found.installKey,
        sha256: {
          windowsAmd64: get('MANAR_EDGE_SHA256_WINDOWS_AMD64'),
          linuxAmd64: get('MANAR_EDGE_SHA256_LINUX_AMD64'),
          linuxArm64: get('MANAR_EDGE_SHA256_LINUX_ARM64'),
        },
      };
      return sh ? renderSh(params) : renderPowerShell(params);
    } catch (error) {
      if (!(error instanceof ScriptUnavailableError)) throw error;
      this.logger.error(`install script not served: ${error.message}`);
      return renderError(kind, NOT_AVAILABLE_MESSAGE);
    }
  }
}
