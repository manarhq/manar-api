import { describe, expect, it } from 'vitest';
import { computeBillable } from './billable';

describe('computeBillable', () => {
  it('counts a user with a device but no sign-in, and a sign-in-only admin', () => {
    expect(computeBillable(['alice'], ['admin'])).toEqual({
      users: 2,
      extraDevices: 0,
    });
  });
  it('counts a user once when they own devices and signed in', () => {
    expect(computeBillable(['a', 'a'], ['a'])).toEqual({
      users: 1,
      extraDevices: 0,
    });
  });
  it('bills devices beyond 3 per user, per user', () => {
    const owners = ['a', 'a', 'a', 'a', 'a', 'b', 'b'];
    expect(computeBillable(owners, [])).toEqual({ users: 2, extraDevices: 2 });
  });
  it('does not bill ownerless devices', () => {
    expect(computeBillable([null, null, null, null], [])).toEqual({
      users: 0,
      extraDevices: 0,
    });
  });
});
