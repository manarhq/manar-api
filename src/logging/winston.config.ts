import * as winston from 'winston';
import { getCorrelationId } from './correlation-id.store';

/**
 * Injects the request's correlation ID (if any) into every log entry's
 * metadata, so every log line written during a request carries the same
 * ID regardless of which service/logger call produced it.
 */
const correlationIdFormat = winston.format((info) => {
  const correlationId = getCorrelationId();
  if (correlationId) {
    info.correlationId = correlationId;
  }
  return info;
});

export function createWinstonOptions(logLevel: string): winston.LoggerOptions {
  return {
    level: logLevel,
    format: winston.format.combine(
      correlationIdFormat(),
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json(),
    ),
    transports: [new winston.transports.Console()],
  };
}
