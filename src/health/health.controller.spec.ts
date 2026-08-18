import { Test, TestingModule } from '@nestjs/testing';
import { describe, it, expect, beforeEach } from 'vitest';
import { HealthController } from './health.controller';

describe('HealthController', () => {
  let controller: HealthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
    }).compile();

    controller = module.get<HealthController>(HealthController);
  });

  it('GET /health/live reports ok', () => {
    expect(controller.live()).toEqual({ status: 'ok' });
  });

  it('GET /health/ready reports ok', () => {
    expect(controller.ready()).toEqual({ status: 'ok' });
  });
});
