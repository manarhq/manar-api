import { classifyQuery } from './search';
import { maskEmail, maskIp } from './masking';

describe('classifyQuery', () => {
  it.each([
    ['MNR-7KQ2XD', 'reference', 'MNR-7KQ2XD'],
    ['  mnr-7kq2xd ', 'reference', 'MNR-7KQ2XD'],
    ['MNR-7KQ2X', 'text', 'MNR-7KQ2X'],
    ['MNR-7KQ2XI', 'text', 'MNR-7KQ2XI'],
    ['in_1QabcDEF234', 'stripe_invoice', 'in_1QabcDEF234'],
    ['A1B2C3D4-0001', 'stripe_invoice', 'A1B2C3D4-0001'],
    ['cus_Qx12ab', 'stripe_id', 'cus_Qx12ab'],
    ['sub_1Ab2', 'stripe_id', 'sub_1Ab2'],
    ['Layla.H+x@Example.com', 'email', 'layla.h@example.com'],
    [
      '7d1e0c42-0000-4000-8000-00000000c42f',
      'uuid',
      '7d1e0c42-0000-4000-8000-00000000c42f',
    ],
    ["'; drop table accounts; --", 'text', "'; drop table accounts; --"],
    ['   ', 'empty', ''],
    ['Layla Haddad', 'text', 'Layla Haddad'],
  ])('%j is %s', (q, kind, value) => {
    expect(classifyQuery(q)).toEqual({ kind, value });
  });

  it('keeps Gmail dots normalised in an email query', () => {
    expect(classifyQuery('j.doe@gmail.com')).toEqual({
      kind: 'email',
      value: 'jdoe@gmail.com',
    });
  });

  it('caps very long input', () => {
    expect(classifyQuery('x'.repeat(500)).value.length).toBe(120);
  });
});

describe('masking', () => {
  it('shows the first character of the local part and the domain (AC-39)', () => {
    expect(maskEmail('mohamed@fixio.ae')).toBe('m•••@fixio.ae');
    expect(maskEmail('a@x.io')).toBe('a•••@x.io');
    expect(maskEmail('not-an-email')).toBe('•••');
    expect(maskEmail(null)).toBeNull();
  });
  it('cuts IPv4 to /24 and IPv6 to /48', () => {
    expect(maskIp('203.0.113.77')).toBe('203.0.113.0/24');
    expect(maskIp('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48');
    expect(maskIp('garbage')).toBeNull();
  });
});
