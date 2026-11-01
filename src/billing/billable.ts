import { DEVICES_PER_USER } from './plans';

/**
 * Company billing (spec 4.3): a billable user owns an enrolled device or signed in this calendar
 * month; every device a user owns beyond 3 is an extra device. Devices with no owner are not
 * billed (ponytail: ownerless hosts, e.g. AD-joined servers, are Enterprise territory).
 */
export function computeBillable(
  deviceOwners: (string | null)[],
  signedIn: string[],
): { users: number; extraDevices: number } {
  const perOwner = new Map<string, number>();
  for (const owner of deviceOwners)
    if (owner) perOwner.set(owner, (perOwner.get(owner) ?? 0) + 1);
  const users = new Set([...perOwner.keys(), ...signedIn]);
  let extraDevices = 0;
  for (const n of perOwner.values())
    extraDevices += Math.max(0, n - DEVICES_PER_USER);
  return { users: users.size, extraDevices };
}

/** Start of the current calendar month, UTC. */
export function monthStart(now = new Date()): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}
