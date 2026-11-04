import { SetMetadata, UnauthorizedException } from '@nestjs/common';

export const STEP_UP_KEY = 'staff:step-up';
/** The route needs a passkey sign-in no older than STEP_UP_MAX_AGE_S (spec §11.2). */
export const StepUp = () => SetMetadata(STEP_UP_KEY, true);
export const STEP_UP_MAX_AGE_S = 300;

/** Throws 401 `step_up_required` unless acr=passkey and auth_time is within 300 s of `nowS`. */
export function checkStepUp(
  token: { acr?: string; authTime?: number },
  nowS = Math.floor(Date.now() / 1000),
): void {
  const fresh =
    token.acr === 'passkey' &&
    typeof token.authTime === 'number' &&
    nowS - token.authTime <= STEP_UP_MAX_AGE_S &&
    token.authTime <= nowS + 60;
  if (!fresh)
    throw new UnauthorizedException({
      code: 'step_up_required',
      message: 'Confirm it is you with your passkey to continue.',
    });
}
