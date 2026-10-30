import { Injectable, Logger } from '@nestjs/common';

/** A secret file was opened by an AI tool on a device. No secret content, a masked path. */
export interface SecretAlert {
  tenantId: string;
  hostId: string;
  toolId: string;
  process: string;
  pathClass: string;
  maskedPath: string;
  blocked: boolean;
  at: Date;
}

/**
 * The seam the approvals/notifications track subscribes to for push and WARDEN prompts:
 * `bus.subscribe((alert) => ...)`. A subscriber that throws never affects ingestion.
 */
@Injectable()
export class SecretAlertBus {
  private readonly logger = new Logger(SecretAlertBus.name);
  private readonly subscribers = new Set<(alert: SecretAlert) => unknown>();

  subscribe(fn: (alert: SecretAlert) => unknown): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  emit(alert: SecretAlert): void {
    for (const fn of this.subscribers) {
      try {
        void Promise.resolve(fn(alert)).catch((e: unknown) =>
          this.logger.warn(`secret alert subscriber failed: ${String(e)}`),
        );
      } catch (e) {
        this.logger.warn(`secret alert subscriber failed: ${String(e)}`);
      }
    }
  }
}
