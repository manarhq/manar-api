import { clientIpOf, trustedPeers } from './client-ip';

describe('clientIpOf', () => {
  const desk = trustedPeers('10.42.0.0/16,fd00::/64');

  it('takes the header only from a peer inside the DESK range', () => {
    expect(clientIpOf('10.42.3.4', '203.0.113.9', desk)).toEqual({
      clientIp: '203.0.113.9',
      peerIp: '10.42.3.4',
    });
    expect(clientIpOf('::ffff:10.42.3.4', '203.0.113.9', desk)).toEqual({
      clientIp: '203.0.113.9',
      peerIp: '10.42.3.4',
    });
  });

  it('ignores the header from any other peer (a spoofed address never reaches the audit row)', () => {
    expect(clientIpOf('10.99.0.1', '203.0.113.9', desk)).toEqual({
      clientIp: '10.99.0.1',
      peerIp: '10.99.0.1',
    });
  });

  it('ignores a header that is not one IP address', () => {
    for (const bad of [
      'not-an-ip',
      '203.0.113.9, 10.0.0.1',
      '',
      ['203.0.113.9', '1.1.1.1'],
    ])
      expect(clientIpOf('10.42.3.4', bad, desk)).toEqual({
        clientIp: '10.42.3.4',
        peerIp: '10.42.3.4',
      });
  });

  it('trusts nobody when no range is configured', () => {
    expect(
      clientIpOf('10.42.3.4', '203.0.113.9', trustedPeers(undefined)),
    ).toEqual({ clientIp: '10.42.3.4', peerIp: '10.42.3.4' });
  });
});
