import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { OpenBaoConfigSchema } from '../openbao/openbao.config';
import { OpenFgaConfigSchema } from './openfga.config';

// The Helm charts ship their own env defaults. They must point at the same
// model file the app's config defaults to (and the image copies), and at the
// OpenBao PKI mounts the app and the configure scripts use.
const charts = ['manar-api', 'manar-api-worker'];
const envValue = (chart: string, key: string): string | undefined => {
  const values = readFileSync(
    join(__dirname, '../../deploy/helm', chart, 'values.yaml'),
    'utf8',
  );
  return new RegExp(`^\\s+${key}:\\s*(\\S+)\\s*$`, 'm').exec(values)?.[1];
};

describe('Helm chart defaults', () => {
  it.each(charts)(
    '%s points OPENFGA_MODEL_FILE_PATH at the model file the image ships',
    (chart) => {
      const path = envValue(chart, 'OPENFGA_MODEL_FILE_PATH');
      expect(path).toBe(
        OpenFgaConfigSchema.shape.OPENFGA_MODEL_FILE_PATH.parse(undefined),
      );
      expect(existsSync(join(__dirname, '../..', path!))).toBe(true);
      const dockerfile = readFileSync(
        join(__dirname, '../../Dockerfile'),
        'utf8',
      );
      expect(dockerfile).toMatch(
        new RegExp(
          `^COPY (?:.*\\s)?${path!.replace(/\./g, '\\.')}\\s+\\./${path!.replace(/\./g, '\\.')}$`,
          'm',
        ),
      );
    },
  );

  it.each(charts)(
    '%s uses the OpenBao PKI mounts the app defaults to',
    (chart) => {
      expect(envValue(chart, 'OPENBAO_PKI_ROOT_PATH')).toBe(
        OpenBaoConfigSchema.shape.OPENBAO_PKI_ROOT_PATH.parse(undefined),
      );
      expect(envValue(chart, 'OPENBAO_PKI_INTERMEDIATE_PATH')).toBe(
        OpenBaoConfigSchema.shape.OPENBAO_PKI_INTERMEDIATE_PATH.parse(
          undefined,
        ),
      );
    },
  );
});
