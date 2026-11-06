import { proxyActivities } from '@temporalio/workflow';
import type {
  PolicySuggestActivities,
  PolicySuggestJobInput,
} from '../activities/policy-suggest-activities.interface';

/**
 * One attempt only, on purpose: a retry would draft a second policy and spend a second AI action.
 * The activity writes its own outcome (ready, failed, cancelled) to the job store, so a crash that
 * loses the worker shows as `stalled` to the person watching (the store notices missing progress).
 */
const activities = proxyActivities<PolicySuggestActivities>({
  startToCloseTimeout: '15 minutes',
  retry: { maximumAttempts: 1 },
});

/** Suggest Policy as a background job (decision 6): it can take minutes, far past the 100 s proxy limit. */
export async function PolicySuggestWorkflow(
  input: PolicySuggestJobInput,
): Promise<void> {
  await activities.runPolicySuggestionJob(input);
}
