export interface PolicySuggestJobInput {
  tenantId: string;
  jobId: string;
}

/** The Activity contract `PolicySuggestWorkflow` calls through (type only: erased from the workflow bundle). */
export interface PolicySuggestActivities {
  /** Runs the whole job and records its outcome in the job store; it does not throw for model failures. */
  runPolicySuggestionJob(input: PolicySuggestJobInput): Promise<void>;
}
