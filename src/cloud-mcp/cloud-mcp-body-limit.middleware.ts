import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Runs before Fastify reads the body of a public MCP request: a POST must
 * declare its length (411 otherwise, so a chunked body cannot slip past) and
 * that length must be at most `maxBytes` (413). Fastify then refuses a body
 * longer than its declared length.
 */
export function cloudMcpBodyLimit(maxBytes: number) {
  return (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    if (req.method !== 'POST') return next();
    const declared = req.headers['content-length'];
    const length = declared === undefined ? NaN : Number(declared);
    const status = Number.isNaN(length) ? 411 : length > maxBytes ? 413 : 0;
    if (!status) return next();
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        statusCode: status,
        reason: status === 411 ? 'length_required' : 'payload_too_large',
      }),
    );
  };
}
