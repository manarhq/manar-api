import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { Logger } from '@nestjs/common';
import { Runtime } from '@temporalio/worker';
import { describe, expect, it, vi } from 'vitest';
import { installWorkerMetrics } from './worker-metrics';

describe('installWorkerMetrics', () => {
  it('port 0 installs nothing', () => {
    expect(installWorkerMetrics(0, new Logger('test'))).toBe(false);
  });

  it('a port already in use is logged and the worker can still create its runtime', async () => {
    const taken = createServer();
    await new Promise<void>((r) => taken.listen(0, '0.0.0.0', r));
    const { port } = taken.address() as AddressInfo;
    const logger = new Logger('test');
    const error = vi.spyOn(logger, 'error').mockImplementation(() => undefined);

    expect(installWorkerMetrics(port, logger)).toBe(false);
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining('continuing without metrics'),
    );
    // What NativeConnection.connect does next: the default runtime starts.
    expect(() => Runtime.instance()).not.toThrow();
    taken.close();
  });
});
