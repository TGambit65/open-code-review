# Bounded rollback: S04.RB and S05.RB

All execution entry points are already refused. Rollback does not invoke a scanner, network request, installer, provider or repository action.

## S04

1. Stop using the new assessment entry point; retain source/qualification receipts and private raw output in the authorized local evidence area. Do not delete prior reports or replace exact pins with latest tags.
2. Select only the previously approved, externally pinned update set whose digest is recorded by the current manifest. If absent, retain an absent/incomplete state. Never fetch replacements from analysis.
3. Recompute dataset state with rollback=True and current time. Even a still-dated prior set is visibly rollback, not current intelligence. Expired/missing/unsupported data remains explicit. Withhold target acceptance until corrected and qualified.
4. Keep original detector confirmations, finding decisions and all prior/current manifest hashes. Invalid or expired exceptions cannot survive a policy/source/snapshot change by copying booleans.

## S05

Disable/remove only any separately adopted integration-specific workflow reference. This source has installed none. Retain receipts, held-path records, review intents and uncertain-action state. Do not reset a request ledger to make a duplicate request possible. Existing scheduler, AGENTS, hooks, CI, repository protections and unrelated project tasks stay unchanged.

Standard OCR continues through its existing path, with security coverage visibly missing/NOT_RUN while this integration is disabled. Repeated rollback returns the same disabled state; it does not imply prior scanner qualification or erase evidence.
