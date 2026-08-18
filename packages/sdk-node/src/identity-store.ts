/**
 * An agent's enrolled identity: the issued certificate, the CA chain it
 * was signed under, and the private key generated locally at enrollment
 * time (see `csr.ts` — this key is never transmitted anywhere; only the
 * CSR built from its public half is).
 */
export interface AgentIdentity {
  /** PEM-encoded leaf certificate returned by `POST /agents/enroll`. */
  certificatePem: string;
  /** PEM-encoded CA trust chain (intermediate + root), for the agent to pin what it trusts. */
  caChainPem: string;
  /** PEM-encoded (PKCS#8) private key — generated locally, never sent over the network. */
  privateKeyPem: string;
  /** ISO-8601 timestamp of when `enroll()` completed. */
  enrolledAt: string;
}

/**
 * Storage abstraction for an agent's enrolled identity (Section 15 of the
 * master prompt). Deliberately shaped broadly enough that a Linux
 * keyring, macOS Keychain, TPM, Kubernetes Secret, or HSM-backed
 * implementation can be dropped in later without any caller
 * (`ManarAgent`) changing — this phase ships exactly one concrete
 * implementation, `FileIdentityStore` (see file-identity-store.ts).
 */
export interface IdentityStore {
  save(identity: AgentIdentity): Promise<void>;
  load(): Promise<AgentIdentity | null>;
  clear(): Promise<void>;
}
