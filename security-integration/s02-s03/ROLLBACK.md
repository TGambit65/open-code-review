# Bounded rollback for S02 and S03

## S02.RB

1. Leave the specialist execution boundary disabled. In this provisional package all run calls already refuse unconditionally.
2. Remove only a separately authorized application reference to this package if one was later added. This package adds none. Do not modify ordinary OCR installation or behavior.
3. Retain policy/asset pins, original and sanitized evidence, review records, source identities and all failed/unrun outcomes.
4. Report SECURITY REVIEW NOT RUN with missing semantic coverage. Never fall back to raw source, direct Git, a hosted provider or an assumed native plugin.

## S03.RB

1. Disable only the selected adapter in trusted orchestration. Its registration remains visible as skipped/incomplete. In this source package all adapters already remain disabled.
2. Keep other adapters' evidence separate. Do not turn a partial aggregate into success because one adapter is absent.
3. Retain acquired assets under their existing custody policy. This package installs, deletes or upgrades nothing and has no cleanup command.
4. Preserve the exact database/rule/binary identity and freshness of old receipts. Rollback does not make an old database current or revive expired authorization.
5. Do not substitute an online scanner, Gitleaks Action, registry rules or package-manager resolution.

The rollback helper returns data-only disable receipts; it does not change account, network, repository or host settings. No rollback has been executed or tested during source authoring.
