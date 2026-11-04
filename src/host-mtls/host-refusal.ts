import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Why Manar will not answer a genuine device certificate. Every one is 423 Locked: the device keeps
 * its hooks and denies AI actions ("cannot ask"), it never unprotects. A bare 401 is not used for a
 * device certificate at all: manar-edge 0.1.6 and older take Manar's hooks out after three 401 or
 * 403 replies in a row, which would leave a revoked (stolen) laptop's AI tools unguarded. Only 410
 * `device_removed` tells a device to give the person their tools back.
 *
 * - `device_revoked`: an admin revoked (or rejected) the device. manar-edge 0.1.7+ locks its AI
 *   tools and wipes its secret vault.
 * - `certificate_revoked`: this certificate is revoked or unknown, the device itself is not.
 * - `account_suspended`: the workspace is suspended.
 * - `workspace_deleted`: the workspace is being deleted, or is gone.
 */
export type HostRefusal =
  | 'device_revoked'
  | 'certificate_revoked'
  | 'account_suspended'
  | 'workspace_deleted';

export function hostRefused(code: HostRefusal, message: string): HttpException {
  return new HttpException(
    { statusCode: HttpStatus.LOCKED, code, message },
    HttpStatus.LOCKED,
  );
}
