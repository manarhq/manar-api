/**
 * Thrown when an enrollment CSR fails Manar's own validation —
 * `CertificateAuthorityService`'s actual security boundary, checked
 * *before* OpenBao is ever called (see that service's doc comment). Never
 * exposes OpenBao internals; this is purely about what the CSR itself
 * contains vs. what the enrolling agent is allowed to claim.
 */
export class CsrValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CsrValidationError';
  }
}
