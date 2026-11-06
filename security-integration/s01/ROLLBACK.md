# S01 bounded rollback

No adapter, provider, hook or CI integration is automatically enabled by S01.
The normal operational fallback is the externally approved **disabled S00
configuration**, not an unisolated scanner or raw model read.

1. Stop admitting new analysis actions and retain the exact failed source/run
   identity, current policy/profile/tool pins, actor/time, source/diff hashes,
   raw private output and original/transformed mappings. Reconcile uncertain
   execution/publication before any repeat. No blanket retry authority exists.
2. Supply a trusted exact failed-evidence reference, a new private evidence
   destination and an external exact rollback-selection reference. The library
   makes an exclusive hash-named copy, fsyncs and verifies the retained bytes
   **before** considering the prior configuration. Existing copies are not
   overwritten. A retention error refuses rollback rather than losing evidence.
3. The selection must match the exact prior configuration canonically pinned
   inside the independently adopted runtime policy. The supported schema is
   `s00-disabled-v1`, with scanner/model lists empty, automatic execution false
   and raw-model fallback false. Merely putting an older version string or
   `approved` flag in candidate data does not authorize it.
4. An unsupported/missing/mismatched prior configuration returns a hold while
   retaining failed evidence. No old schema is interpreted permissively, no
   unsanitized source is exposed, and no scanner is retried under weaker flags.
   Successful selection also leaves completeness unknown and target acceptance
   `NOT_ASSESSED`; it is an inert configuration decision, not a runtime pass.
5. Preserve failed and rollback receipts in access-controlled custody and
   independently review any correction. Root alone preserves the result under
   the same-DRAFT/source-preservation controls. Keep denied/uncertain actions
   separate and preserve their exact outcomes; do not route around them.
6. If root explicitly chooses a source revert, retain all exact evidence first,
   prepare a narrow new ordinary correction/revert and independently review it.
   Do not reset/rewrite history, alter installed OCR, remove accepted S00 bytes
   or unrelated repository entries, change platform settings, disable review
   gates, delete user data or replay a held historical payload.
7. Reopen only with current independent review, verified preservation, applicable
   passed qualification and fresh exact external execution authority. The
   approved policy remains outside the candidate. No raw-source/Git model
   fallback or self-waiver is available during rollback or recovery.

The authored V04 synthetic cases cover an approved disabled prior, an
unsupported old schema/raw fallback, exact retained failed bytes and refusal to
overwrite evidence. They have no run claim until their post-preservation receipt.
