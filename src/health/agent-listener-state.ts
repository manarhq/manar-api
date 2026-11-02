/**
 * Whether this process serves the agent mTLS listener and whether it is bound yet. `main.ts`
 * starts the human listener first, so without this readiness passed (and the pod took device
 * traffic on the Service) before port 3443 was listening. Processes that never start the agent
 * listener (the worker, e2e apps) never call `expectAgentListener`, and the probe passes.
 */
let state: 'not-served' | 'starting' | 'bound' = 'not-served';

export function expectAgentListener(): void {
  if (state === 'not-served') state = 'starting';
}

export function agentListenerBound(): void {
  state = 'bound';
}

export function agentListenerReady(): boolean {
  return state !== 'starting';
}
