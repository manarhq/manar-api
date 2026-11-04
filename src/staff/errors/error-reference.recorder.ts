import { Injectable, Logger } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { ControlPrismaService } from '../../database/control-prisma.service';

export const ERROR_REFERENCE_SINK = Symbol('ERROR_REFERENCE_SINK');

export interface ErrorReferenceSink {
  record(e: {
    reference: string;
    status: number;
    code?: string;
    correlationId?: string;
    request: FastifyRequest;
  }): void;
}

type Authed = FastifyRequest & {
  authContext?: {
    issuer: string;
    user: { keycloakSubject: string };
    tenant: { id: string };
  };
  identity?: { issuer: string; subject: string };
  staff?: { staffId: string };
};

/**
 * Keeps every 5xx, and every 4xx on an authenticated request, by its `MNR-` reference, so staff
 * can look a reference up (DESK spec §7.4, AC-11). Never blocks or changes the response; a failed
 * write is logged. Purged after 30 days by the staff jobs.
 */
@Injectable()
export class ErrorReferenceRecorder implements ErrorReferenceSink {
  private readonly logger = new Logger(ErrorReferenceRecorder.name);
  constructor(private readonly control: ControlPrismaService) {}

  record(e: Parameters<ErrorReferenceSink['record']>[0]): void {
    const r = e.request as Authed;
    const issuer =
      r.authContext?.issuer ??
      r.identity?.issuer ??
      (r.staff ? 'staff' : undefined);
    const subject =
      r.authContext?.user.keycloakSubject ??
      r.identity?.subject ??
      r.staff?.staffId;
    if (e.status < 500 && !subject) return;
    void this.control.staffErrorReference
      .create({
        data: {
          reference: e.reference,
          status: e.status,
          code: e.code?.slice(0, 100),
          correlationId: e.correlationId,
          issuer,
          subject,
          tenantId: r.authContext?.tenant.id,
          route: `${r.method} ${r.routeOptions?.url ?? 'unmatched'}`,
        },
      })
      .catch((err: unknown) =>
        this.logger.warn(
          `error reference ${e.reference} not stored: ${String(err)}`,
        ),
      );
  }
}
