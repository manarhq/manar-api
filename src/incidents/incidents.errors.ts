/** Thrown when an `Incident` ID doesn't resolve within the caller's tenant database. */
export class IncidentNotFoundError extends Error {
  constructor(incidentId: string) {
    super(`Incident "${incidentId}" was not found`);
    this.name = 'IncidentNotFoundError';
  }
}
