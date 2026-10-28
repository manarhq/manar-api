import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { makeCa, makeLeaf } from '../../../test/support/test-pki';
import { templateOidOf } from './cert-template.util';

describe('templateOidOf', () => {
  it('reads the AD CS template OID, including multi-byte arcs', async () => {
    const ca = await makeCa('Template CA');
    for (const oid of [
      '1.3.6.1.4.1.311.21.8.1234.5678.1',
      '1.3.6.1.4.1.311.21.8.16187918.14',
      '2.5.4.3',
    ]) {
      expect(templateOidOf((await makeLeaf(ca, { template: oid })).cert)).toBe(
        oid,
      );
    }
  });

  it('is null without the extension', async () => {
    const ca = await makeCa('Template CA 2');
    expect(templateOidOf((await makeLeaf(ca)).cert)).toBeNull();
  });
});
