# Bounded rollback

## S06.RB: optional candidates

No optional implementation or live registration was adopted in this freeze. The present rollback is therefore idempotent: keep all three optional entries disabled and all seven conditional IDs explicitly deferred. registry.disable_optional returns that state only; it does not change settings or delete files. Baseline OCR/Opengrep/Gitleaks/OSV source, mandatory policy/coverage, platform controls and all evidence remain unchanged.

If a separately authorized future integration adopts an optional registration, record its exact reversible change before adoption. Roll back only that specific registration under its authority, retain source/assets/receipts and recompute visible coverage honestly. Do not remove a mandatory baseline, invalidate unresolved findings or erase an uncertain publication record. A failed rollback is a recorded failure, not a claim of restored state.

## S07.RB: integration entrypoint

No live entrypoint/hook/scheduler/protection has been installed here. The current native entrypoint already refuses. registry.disable_integration returns an explicit disabled/not-run/missing-coverage state and standard OCR unchanged, with no side effects. The integration status artifact must continue to show the missing-security-coverage notice; no empty or pass state substitutes for it.

For a separately adopted future host reference, record the exact integration-only reference and reversible prior value, then disable/revert that reference under its original authority. Preserve standard OCR, all source and evidence, baseline rules/history, platform controls and publication/review ledgers. Do not uninstall unrelated tooling, clear credentials, change networking/protections, delete evidence or bypass denied actions. A supplied evidence evaluation remains possible as data analysis, without enabling native execution.

Rollback success needs actual evidence for the affected adopted host reference. The pure returned state and authored tests are not proof that a live system was changed. Current source execution, activation, native qualification and acceptance remain held.
