/**
 * The bootstrap scripts behind the "Add device" one-liners (`/i/<code>`, `/i/<code>.sh`) and
 * the uninstall one-liners. Pure functions: every value that reaches a script is checked
 * against a strict pattern first, so no value can break out of its quotes.
 *
 * The scripts contain only the single-use code the URL carries and the tenant's slug. They verify the SHA-256 of the downloaded binary against a value templated in at
 * serve time, and then hand over to `manar-edge install`, which enrols and installs the service.
 */
export interface ScriptParams {
  version?: string;
  releaseBase: string;
  consoleUrl: string;
  hostUrl: string;
  /** The short code (the install key's secret) and the tenant slug it belongs to. */
  code: string;
  tenantSlug: string;
  sha256: {
    windowsAmd64?: string;
    linuxAmd64?: string;
    linuxArm64?: string;
  };
}

export class ScriptUnavailableError extends Error {}

export const NOT_VALID_MESSAGE =
  'This install code is not valid or has expired. Open Add device in the Manar console to get a new one.';
export const NOT_AVAILABLE_MESSAGE =
  'The Manar installer is not available yet. Please try again in a few minutes.';

const URL_OK = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[A-Za-z0-9._/-]*)?$/;
const CODE_OK = /^[A-HJKMNP-Z2-9]{10}$/;
// Same rule as manar-edge: no trailing '-'.
const SLUG_OK = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const VERSION_OK = /^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/;
const SHA_OK = /^[0-9a-f]{64}$/;

function check(ok: boolean, what: string): void {
  if (!ok) throw new ScriptUnavailableError(`${what} is not set or malformed`);
}

function validated(p: ScriptParams) {
  check(!!p.version && VERSION_OK.test(p.version), 'MANAR_EDGE_VERSION');
  check(URL_OK.test(p.releaseBase), 'MANAR_EDGE_RELEASE_BASE');
  check(URL_OK.test(p.consoleUrl), 'MANAR_CONSOLE_URL');
  check(URL_OK.test(p.hostUrl), 'MANAR_HOST_URL');
  check(CODE_OK.test(p.code), 'install code');
  check(SLUG_OK.test(p.tenantSlug), 'tenant slug');
  return {
    version: p.version!,
    base: p.releaseBase.replace(/\/$/, ''),
    api: p.consoleUrl.replace(/\/$/, ''),
    host: p.hostUrl.replace(/\/$/, ''),
    code: p.code,
    slug: p.tenantSlug,
  };
}

/**
 * manar-edge from v0.1.3 reads the install code from MANAR_INSTALL_CODE, so it is not on a command
 * line other local users can list while the install runs. Older releases only take --code.
 */
export function codeFromEnv(version: string): boolean {
  const [maj, min, pat] = version
    .slice(1)
    .split(/[.-]/)
    .map((n) => Number(n));
  return maj! > 0 || min! > 1 || (min === 1 && pat! >= 3);
}

function sum(value: string | undefined, name: string): string {
  check(!!value && SHA_OK.test(value), name);
  return value!;
}

/** `irm https://.../i/<code> | iex` */
export function renderPowerShell(p: ScriptParams): string {
  const v = validated(p);
  const sha = sum(p.sha256.windowsAmd64, 'MANAR_EDGE_SHA256_WINDOWS_AMD64');
  return `# Manar device installer. Source: https://github.com/manarhq/manar-edge
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tmp = $null
try {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw 'Open PowerShell as Administrator (right-click, Run as administrator) and paste the line again.' }
  $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  if ($arch -ne 'AMD64') { throw "Manar supports 64-bit Intel/AMD Windows for now (this computer is $arch)." }
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  # A fresh folder only SYSTEM and Administrators can touch, created with that access list already in
  # place (ProgramData lets any user add files to a folder that inherits from it), then checked: owned
  # by Administrators or SYSTEM, protected, and empty. Nothing else can swap the file between the
  # checksum and the elevated run (a folder in %TEMP% would be writable by the user's other programs).
  $tmp = Join-Path $env:ProgramData ('manar-setup-' + [guid]::NewGuid().ToString('N'))
  $sec = New-Object System.Security.AccessControl.DirectorySecurity
  $sec.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  if ($PSVersionTable.PSEdition -eq 'Core') { [System.IO.FileSystemAclExtensions]::CreateDirectory($sec, $tmp) | Out-Null }
  else { [System.IO.Directory]::CreateDirectory($tmp, $sec) | Out-Null }
  $acl = Get-Acl -LiteralPath $tmp
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (($owner -ne 'S-1-5-32-544' -and $owner -ne 'S-1-5-18') -or -not $acl.AreAccessRulesProtected -or (Get-ChildItem -Force -LiteralPath $tmp)) {
    throw 'Could not lock the download folder, so nothing was installed.'
  }
  $exe = Join-Path $tmp 'manar-edge.exe'
  Write-Host 'Downloading Manar ${v.version}...'
  Invoke-WebRequest -UseBasicParsing -Uri '${v.base}/${v.version}/manar-edge-windows-amd64.exe' -OutFile $exe
  $got = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLower()
  if ($got -ne '${sha}') { throw 'The download does not match its checksum, so it was not installed.' }
  ${
    codeFromEnv(v.version)
      ? `$env:MANAR_INSTALL_CODE = '${v.code}'
  & $exe install --tenant '${v.slug}' --api '${v.api}' --host-url '${v.host}'`
      : `& $exe install --code '${v.code}' --tenant '${v.slug}' --api '${v.api}' --host-url '${v.host}'`
  }
  if ($LASTEXITCODE -ne 0) { throw "The installer stopped (exit code $LASTEXITCODE)." }
} catch {
  Write-Host ('Manar install failed: ' + $_.Exception.Message) -ForegroundColor Red
} finally {
  Remove-Item Env:MANAR_INSTALL_CODE -ErrorAction SilentlyContinue
  if ($tmp) { Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue }
}
`;
}

/** `curl -fsSL https://.../i/<code>.sh | sudo sh` */
export function renderSh(p: ScriptParams): string {
  const v = validated(p);
  const amd = sum(p.sha256.linuxAmd64, 'MANAR_EDGE_SHA256_LINUX_AMD64');
  const arm = sum(p.sha256.linuxArm64, 'MANAR_EDGE_SHA256_LINUX_ARM64');
  return `#!/bin/sh
# Manar device installer. Source: https://github.com/manarhq/manar-edge
set -eu
fail() { echo "Manar install failed: $1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "run this line with sudo."
[ "$(uname -s)" = Linux ] || fail "this installer is for Linux."
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; sum='${amd}' ;;
  aarch64|arm64) arch=arm64; sum='${arm}' ;;
  *) fail "unsupported CPU: $(uname -m)." ;;
esac
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
url='${v.base}/${v.version}/manar-edge-linux-'"$arch"
echo "Downloading Manar ${v.version}..."
if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$tmp/manar-edge" "$url" || fail "download failed."
elif command -v wget >/dev/null 2>&1; then wget -q -O "$tmp/manar-edge" "$url" || fail "download failed."
else fail "curl or wget is needed."; fi
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is needed."
echo "$sum  $tmp/manar-edge" | sha256sum -c - >/dev/null 2>&1 || fail "the download does not match its checksum, so it was not installed."
chmod 755 "$tmp/manar-edge"
${
  codeFromEnv(v.version)
    ? `MANAR_INSTALL_CODE='${v.code}' "$tmp/manar-edge" install --tenant '${v.slug}' --api '${v.api}' --host-url '${v.host}' || fail "the installer stopped."`
    : `"$tmp/manar-edge" install --code '${v.code}' --tenant '${v.slug}' --api '${v.api}' --host-url '${v.host}' || fail "the installer stopped."`
}
`;
}

/** What a script prints when there is nothing to install (unknown or expired code, no release). */
export function renderError(kind: 'ps' | 'sh', message: string): string {
  const safe = message.replace(/[^A-Za-z0-9 .,:;()'/-]/g, ' ');
  return kind === 'ps'
    ? `Write-Host '${safe.replace(/'/g, "''")}' -ForegroundColor Red\n`
    : `#!/bin/sh\necho '${safe.replace(/'/g, '')}' >&2\nexit 1\n`;
}

export function renderUninstallPowerShell(): string {
  return `# Manar device uninstaller.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:ProgramFiles 'manar-edge'
$exe = Join-Path $dir 'manar-edge.exe'
try {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw 'Open PowerShell as Administrator and paste the line again.' }
  if (-not (Test-Path $exe)) { Write-Host 'Manar is not installed on this computer.'; return }
  & $exe uninstall
  $code = $LASTEXITCODE
  Remove-Item -Recurse -Force -Path $dir -ErrorAction SilentlyContinue
  if ($code -ne 0) { throw "Some steps need a look (exit code $code)." }
} catch {
  Write-Host ('Manar uninstall: ' + $_.Exception.Message) -ForegroundColor Red
}
`;
}

export function renderUninstallSh(): string {
  return `#!/bin/sh
# Manar device uninstaller.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Manar uninstall: run this line with sudo." >&2; exit 1; }
bin=/usr/local/bin/manar-edge
[ -x "$bin" ] || { echo "Manar is not installed on this computer."; exit 0; }
"$bin" uninstall
`;
}

/** The one-liners the console shows. `base` is the public console URL, `code` the short code. */
export function oneLiners(base: string, code: string) {
  const b = base.replace(/\/$/, '');
  return {
    windows: `irm ${b}/i/${code} | iex`,
    linux: `curl -fsSL ${b}/i/${code}.sh | sudo sh`,
    uninstallWindows: `irm ${b}/i/uninstall | iex`,
    uninstallLinux: `curl -fsSL ${b}/i/uninstall.sh | sudo sh`,
  };
}
