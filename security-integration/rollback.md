# S00 rollback: preserve the baseline, keep integration inactive

## Starting state and owner

S00 adds only the six regular non-executable files enumerated in
`scope.json / allowed_changed_paths`. There is no wrapper command,
registration, install step, CI/hook, scanner process or enforcement switch to
disable. Existing OpenCodeReview operation and the separately approved pinned
binary are unchanged. **The runtime rollback is therefore a no-op**, not a
successful disable test.

Only the coordinator/publisher may authorize and preserve a source rollback.
The writer must not reset main, rewrite history, alter the installed binary,
change platform protections or delete other project work. No rollback action
has been executed by S00.

## Bounded procedure

1. **Freeze and identify.** Stop advancement to dependent integration sprints.
   Record the owned repository, exact base/head or unpublished diff, the
   six-path candidate hashes, current review/validation state, actor, time,
   reason and requested rollback scope. Reconcile any uncertain remote write
   before acting. Do not guess a branch/head/PR or reuse the unrelated ImgBot
   PR #1.
2. **Retain evidence before source changes.** Preserve the exact candidate,
   full diff, `tool-lock.json`, `scope.json`, capability/provenance and notices,
   authority record, review outcomes and any later validation receipts in
   access-controlled external custody. Keep original and transformed hashes
   where applicable; for S00 no target transformation or scanner input exists.
   Exclude raw private coordination/credentials from the public payload.
3. **Establish the actual state.** For this exact S00 scope, record
   `integration_active=false` and `activation_artifacts=none`. Do not run a
   scanner, package wrapper, installer, login or test to manufacture a disable
   result. If actual runtime registrations or changes outside the six files
   are discovered, this runbook does not authorize deleting them: reconcile
   their owner and obtain the exact separate rollback scope first.
4. **Prefer retaining the inert records.** Leaving the six documentation and
   provenance files in place while withholding activation is the normal S00
   rollback. Mark the external acceptance record withdrawn/on hold and record
   why; do not erase historical review or claim it still covers changed bytes.
   Preserve lock and scope records, even if no future implementation proceeds.
5. **If an explicitly requested source revert is necessary, make it narrow.**
   Root selects the verified S00-only preservation commit or the exact six
   newly added paths after confirming no later/user edits are mixed in. Prepare
   a new ordinary revert/correction, not a force push or reset. Remove only
   authorized newly introduced integration references; S00 has none outside
   this subtree. Retain the baseline/evidence externally before a source
   removal. If the commit contains unrelated work, do not revert it wholesale;
   prepare and independently review a path-bounded correction instead.
6. **Review before preservation.** Independently review the complete rollback
   diff and retained evidence. Root preserves it under the same applicable
   draft/one-review controls, reconciles the actual remote result, and records
   exact commit/tree/PR receipts. Review-pending preservation, if applicable,
   must say so. A denied or uncertain write is not a successful rollback and
   must not be bypassed through another action.
7. **Record the resulting coverage honestly.** The result is
   `security_coverage_added_by_s00=false`, `integration_active=false`,
   `target_security_acceptance=NOT_ASSESSED`, with sprint acceptance withdrawn
   or held if appropriate. Existing standard OCR behavior is unchanged and
   is not upgraded to a security guarantee. Any authorized post-preservation
   read-only consistency check gets its actual outcome; unrun runtime checks
   remain unrun.

## Recovery and reopening

Reopen only after root establishes an eligible coherent scope, sole writer,
current independent reviewer, unchanged/explicitly reapproved external policy,
exact source/binary provenance and the specific permissions for the next
action. Preserve the old evidence rather than overwriting failure history.
Restoring the native OCR binary is outside this runbook: S00.04R requires both
an absent/invalid approved binary and separate exact restoration authority.

Never use rollback to weaken required review, restore an untrusted candidate
policy, remove security controls, silently enable a fallback, change a
scheduler/CI setting, erase custom fork history, or inspect protected source.
