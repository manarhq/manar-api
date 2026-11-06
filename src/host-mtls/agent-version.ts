/**
 * What a device says about itself in the User-Agent of its requests:
 * `manar-edge/<version> (<os>; <arch>)` (shared contract: src/contract/host-contract.json, section
 * userAgent). Agents from before this existed send `Go-http-client/...`; they parse to null and
 * keep working. The value is self-reported by a device that already holds a valid certificate, so
 * it is stored for support and fleet planning only and never used for a decision.
 */
export interface AgentVersion {
  version: string;
  os: string;
  arch: string;
}

const AGENT_UA =
  /^manar-edge\/([0-9A-Za-z][0-9A-Za-z.+_-]{0,31}) \((linux|windows|darwin); (amd64|arm64|386|arm)\)$/;

export function parseAgentUserAgent(
  header: string | undefined,
): AgentVersion | null {
  const m = header ? AGENT_UA.exec(header) : null;
  return m ? { version: m[1]!, os: m[2]!, arch: m[3]! } : null;
}

/** True when the reported value differs from what the host row holds (so it is worth one write). */
export function agentVersionChanged(
  seen: AgentVersion,
  stored: {
    agentVersion?: string | null;
    agentOs?: string | null;
    agentArch?: string | null;
  },
): boolean {
  return (
    seen.version !== stored.agentVersion ||
    seen.os !== stored.agentOs ||
    seen.arch !== stored.agentArch
  );
}
