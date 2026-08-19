/** Thrown by `ComplianceService.listControls` when `frameworkId` doesn't resolve within the caller's tenant database. */
export class ComplianceFrameworkNotFoundError extends Error {
  constructor(frameworkId: string) {
    super(`Compliance framework "${frameworkId}" was not found`);
    this.name = 'ComplianceFrameworkNotFoundError';
  }
}
