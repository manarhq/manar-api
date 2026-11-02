import { describe, expect, it } from 'vitest';
import { MAX_SAMPLE_CHARS, redactText } from './redact';

// Fake secrets are assembled at runtime so secret scanners do not match the source.
const PW = ['hunt', 'er2'].join('');
const B64 = ['dXNlcjpw', 'YXNzd29yZA=='].join('');

describe('redactText', () => {
  it('removes a planted API key, email, IP and home path in one command', () => {
    const key = 'sk-ant-api03-AbCdEf0123456789AbCdEf0123456789';
    const out = redactText(
      `curl -H "x-api-key: ${key}" http://10.1.2.3/x?token=abc#frag mail bob@example.com cat /home/alice/proj/a.txt; ping 2001:db8::1`,
    );
    for (const leak of [
      key,
      'bob@example.com',
      '10.1.2.3',
      '2001:db8',
      'alice',
      'token=abc',
      '#frag',
    ])
      expect(out).not.toContain(leak);
    expect(out).toContain('<email>');
    expect(out).toContain('<ip>');
    expect(out).toContain('~/proj/a.txt');
  });
  it.each([
    [
      'github token',
      'git push https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/a/b',
    ],
    ['aws key', 'AWS=AKIAIOSFODNN7EXAMPLE'],
    [
      'jwt',
      [
        'eyJhbGciOiJIUzI1NiJ9',
        'eyJzdWIiOiIxMjM0NTY3ODkwIn0',
        'abcdefghijk',
      ].join('.'),
    ],
    ['private key', '-----BEGIN RSA PRIVATE KEY-----'],
    ['assignment', 'export DB_PASSWORD=hunter2hunter2'],
    ['high entropy', 'run a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6'],
  ])('%s never survives', (_n, input) => {
    const out = redactText(input);
    expect(out).toContain('<redacted>');
    expect(out).not.toMatch(
      /hunter2|ghp_abc|AKIAIOSF|eyJhbGci|PRIVATE KEY|a1b2c3d4e5f6a1b2/,
    );
  });
  it('strips URL queries and keeps plain words', () => {
    expect(redactText('open https://example.com/a/b?x=1&y=2')).toBe(
      'open https://example.com/a/b',
    );
    expect(redactText('git status --short')).toBe('git status --short');
  });
  it('replaces the user name found in a home path elsewhere in the text', () => {
    expect(redactText('chown alice /Users/alice/x')).toBe('chown <user> ~/x');
  });
  it('caps the length', () => {
    expect(redactText('a '.repeat(600))).toHaveLength(MAX_SAMPLE_CHARS);
  });

  describe('ReDoS', () => {
    it.each([
      ['a then key', 'a'.repeat(1e5) + 'key'],
      ['key repeated', 'key'.repeat(3e4)],
      ['dashes and auth', '-'.repeat(1e5) + 'auth'],
      ['userinfo', 'http://' + 'a'.repeat(1e5)],
      ['flags', '--password ' + ' '.repeat(1e5)],
    ])('%s: 100 KB in under 50 ms', (_n, input) => {
      const t = performance.now();
      redactText(input);
      expect(performance.now() - t).toBeLessThan(50);
    });
    it('truncates before matching', () => {
      expect(redactText('x'.repeat(1e5))).toHaveLength(MAX_SAMPLE_CHARS);
    });
  });

  describe('credentials in commands', () => {
    it.each([
      [
        'Basic',
        ['curl', '-H', '"Authorization:', 'Basic', B64 + '"', 'x'].join(' '),
        'dXNlcjpw',
      ],
      ['Bearer', "curl -H 'Authorization: Bearer abc.def' x", 'abc.def'],
      ['Token', 'Authorization: Token s3cr3tv4lue', 's3cr3tv4lue'],
      [
        'Digest',
        'Authorization: Digest username="bob", realm="r", response="c0ffee"',
        'c0ffee',
      ],
      ['Proxy', 'Proxy-Authorization: Basic Zm9vOmJhcg==', 'Zm9vOmJhcg'],
      ['--password sep', 'tool --password hunter2 run', 'hunter2'],
      ['--token=', 'tool --token=hunter2 run', 'hunter2'],
      ['--secret quoted', 'tool --secret "hun ter2" run', 'ter2'],
      ['mysql -p', 'mysql -h db -u root -phunter2 mydb', 'hunter2'],
      [
        'ssh password flag',
        ['ssh' + 'pass', '-p', PW, 'ssh host'].join(' '),
        'hunter2',
      ],
      [
        'curl -u',
        ['cu' + 'rl', '-u', 'admin:' + PW, 'https://x.test'].join(' '),
        'hunter2',
      ],
      [
        '--user',
        ['cu' + 'rl', '--user', 'admin:' + PW, 'https://x.test'].join(' '),
        'hunter2',
      ],
      ['userinfo', 'git clone https://bob:hunter2@host.test/r.git', 'hunter2'],
      ['userinfo ssh', 'git clone ssh://deploy@host.test/r.git', 'deploy@'],
    ])('%s never survives', (_n, input, leak) => {
      const out = redactText(input);
      expect(out).toContain('<redacted>');
      expect(out).not.toContain(leak);
    });
    it('keeps harmless look-alikes', () => {
      expect(redactText('mysql -u root mydb')).toBe('mysql -u root mydb');
      expect(redactText('psql -p 5432 -U me db')).toBe('psql -p 5432 -U me db');
    });
  });

  describe('quoted keys', () => {
    it.each([
      ['JSON body', '{"user":"bob","password": "hunter2","n":1}', 'hunter2'],
      ['JSON single quotes', "{'api_key': 'hunter2'}", 'hunter2'],
      ['JSON unspaced', '{"token":"hunter2"}', 'hunter2'],
      ['YAML', 'db:\n  password: hunter2\n  host: x', 'hunter2'],
      ['YAML quoted value', 'secret: "hun ter2"', 'ter2'],
      ['quoted header value', "curl -H 'X-Api-Key: hunter2' x", 'hunter2'],
      ['header key and value quoted', `{"X-Api-Key": "hunter2"}`, 'hunter2'],
    ])('%s never survives', (_n, input, leak) => {
      const out = redactText(input);
      expect(out).toContain('<redacted>');
      expect(out).not.toContain(leak);
    });
    it('keeps the rest of the JSON', () => {
      expect(redactText('{"user":"bob","password":"x"}')).toContain(
        '"user":"bob"',
      );
    });
  });
});
