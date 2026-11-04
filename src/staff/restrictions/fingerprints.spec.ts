import { fingerprint, normalizeEmail } from './fingerprints';

describe('normalizeEmail (AC-25)', () => {
  it.each([
    ['  John.Doe+x@GoogleMail.com ', 'johndoe@gmail.com'],
    ['j.o.h.n@gmail.com', 'john@gmail.com'],
    ['a.b+c@fixio.ae', 'a.b@fixio.ae'],
    ['MIXED@Example.ORG', 'mixed@example.org'],
    ['ａｌｉ@fixio.ae', 'ali@fixio.ae'],
    ['user+tag+more@outlook.com', 'user@outlook.com'],
  ])('%s -> %s', (raw, want) => expect(normalizeEmail(raw)).toBe(want));

  it('returns null for something that is not an address', () => {
    expect(normalizeEmail('no-at-sign')).toBeNull();
    expect(normalizeEmail('@fixio.ae')).toBeNull();
    expect(normalizeEmail('a@')).toBeNull();
  });
});

describe('fingerprint', () => {
  const key = 'k'.repeat(32);
  it('is a stable HMAC that depends on the key and the kind', () => {
    const a = fingerprint('EMAIL', 'jdoe@gmail.com', key);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(fingerprint('EMAIL', 'jdoe@gmail.com', key)).toBe(a);
    expect(fingerprint('EMAIL', 'jdoe@gmail.com', 'x'.repeat(32))).not.toBe(a);
    expect(fingerprint('IDP_EMAIL', 'jdoe@gmail.com', key)).not.toBe(a);
  });
});
