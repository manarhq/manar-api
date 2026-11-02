import { describe, expect, it } from 'vitest';
import {
  NOT_VALID_MESSAGE,
  ScriptUnavailableError,
  oneLiners,
  renderError,
  renderPowerShell,
  renderSh,
  renderUninstallPowerShell,
  renderUninstallSh,
  type ScriptParams,
} from './install-scripts';

const SHA_WIN = 'a'.repeat(64);
const SHA_AMD = 'b'.repeat(64);
const SHA_ARM = 'c'.repeat(64);

const params: ScriptParams = {
  version: 'v0.1.0',
  releaseBase: 'https://github.com/manarhq/manar-edge/releases/download',
  consoleUrl: 'https://console-manar.fixio.ae',
  hostUrl: 'https://agents-manar.fixio.ae:3443',
  code: 'ABCDEFGH23',
  tenantSlug: 'me-1a2b3c',
  sha256: { windowsAmd64: SHA_WIN, linuxAmd64: SHA_AMD, linuxArm64: SHA_ARM },
};

describe('install scripts', () => {
  it('PowerShell downloads the pinned release, checks its SHA-256, then installs', () => {
    const s = renderPowerShell(params);
    expect(s).toContain(
      'https://github.com/manarhq/manar-edge/releases/download/v0.1.0/manar-edge-windows-amd64.exe',
    );
    expect(s).toContain(`'${SHA_WIN}'`);
    expect(s.indexOf('Get-FileHash')).toBeLessThan(s.indexOf('install --code'));
    expect(s).toContain("install --code 'ABCDEFGH23' --tenant 'me-1a2b3c'");
    expect(s).toContain('Administrator');
  });

  it('PowerShell downloads into a folder locked to SYSTEM and Administrators, not %TEMP%', () => {
    const s = renderPowerShell(params);
    expect(s).not.toContain('GetTempPath');
    expect(s).toContain("Join-Path $env:ProgramData ('manar-setup-'");
    expect(s).toContain('/inheritance:r');
    expect(s).toContain('*S-1-5-18:(OI)(CI)F');
    expect(s).toContain('*S-1-5-32-544:(OI)(CI)F');
    expect(s.indexOf('icacls')).toBeLessThan(s.indexOf('Invoke-WebRequest'));
    expect(s.indexOf('Get-FileHash')).toBeLessThan(s.indexOf('install --code'));
  });

  it('a tenant slug ending in a dash is refused, as the installer would', () => {
    expect(() => renderSh({ ...params, tenantSlug: 'me-' })).toThrow(
      ScriptUnavailableError,
    );
  });

  it('sh checks the checksum per architecture before it runs the binary', () => {
    const s = renderSh(params);
    expect(s).toContain(`sum='${SHA_AMD}'`);
    expect(s).toContain(`sum='${SHA_ARM}'`);
    expect(s.indexOf('sha256sum -c')).toBeLessThan(s.indexOf('install --code'));
    expect(s).toContain("install --code 'ABCDEFGH23' --tenant 'me-1a2b3c'");
    expect(s.startsWith('#!/bin/sh\n')).toBe(true);
  });

  it('refuses to render without a release, a checksum, or with a value that could break a quote', () => {
    expect(() => renderPowerShell({ ...params, version: undefined })).toThrow(
      ScriptUnavailableError,
    );
    expect(() =>
      renderSh({
        ...params,
        sha256: { ...params.sha256, linuxArm64: undefined },
      }),
    ).toThrow(ScriptUnavailableError);
    for (const bad of [
      { code: "ABCDEFGH2'; calc; '" },
      { code: 'abcdefgh23' },
      { tenantSlug: "x'; calc" },
      { version: "v1.0.0'; calc" },
      { consoleUrl: "https://x.example/'; calc" },
      { hostUrl: 'http://agents.example' },
    ]) {
      expect(() => renderPowerShell({ ...params, ...bad })).toThrow(
        ScriptUnavailableError,
      );
      expect(() => renderSh({ ...params, ...bad })).toThrow(
        ScriptUnavailableError,
      );
    }
  });

  it('an unknown code gets a script that prints a clear error', () => {
    const ps = renderError('ps', NOT_VALID_MESSAGE);
    expect(ps).toContain('not valid or has expired');
    expect(ps).not.toContain('Invoke-WebRequest');
    const sh = renderError('sh', NOT_VALID_MESSAGE);
    expect(sh).toContain('exit 1');
    expect(sh).toContain('not valid or has expired');
  });

  it('error text cannot break out of its quotes', () => {
    const quotes = (t: string) => t.split("'").length - 1;
    expect(quotes(renderError('sh', "x'; rm -rf /; echo '"))).toBe(2);
    // PowerShell doubles a quote inside a single-quoted string.
    expect(renderError('ps', "x'; calc; '")).toContain("''");
  });

  it('shows the one-liners the console copies', () => {
    const l = oneLiners('https://console-manar.fixio.ae/', 'ABCDEFGH23');
    expect(l.windows).toBe(
      'irm https://console-manar.fixio.ae/i/ABCDEFGH23 | iex',
    );
    expect(l.linux).toBe(
      'curl -fsSL https://console-manar.fixio.ae/i/ABCDEFGH23.sh | sudo sh',
    );
    expect(l.uninstallLinux).toContain('/i/uninstall.sh');
  });

  it('uninstall scripts need no code and call the installed binary', () => {
    expect(renderUninstallPowerShell()).toContain('manar-edge.exe');
    expect(renderUninstallPowerShell()).toContain('uninstall');
    expect(renderUninstallSh()).toContain('/usr/local/bin/manar-edge');
  });
});
