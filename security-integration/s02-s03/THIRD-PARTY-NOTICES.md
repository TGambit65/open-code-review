# Additional component and procedure notices

Original adapter Python and synthetic fixture code in this directory is Apache-2.0. This statement does not relicense third-party binaries, rules, databases or adapted documentation. Existing repository notices remain unchanged. No binary, third-party scanner ruleset, real vulnerability database, plugin, hook or Action is bundled.

## Adapted procedure documents

reviewer/differential-review.md and reviewer/false-positive-challenge.md are adapted from Trail of Bits skills, commit 2be6433b39e009cd2b6fd3be1895f6b1faa5af9a, and distributed as CC-BY-SA-4.0. Each document identifies the exact source, license link and changes. Shared adaptations retain that license; no claim is made that scanner/application code is thereby relicensed. Original license: https://github.com/trailofbits/skills/blob/2be6433b39e009cd2b6fd3be1895f6b1faa5af9a/LICENSE

reviewer/security-checklist.md is adapted from OWASP secure-agent-playbook, commit 65d4efd2cd0b081d52101e9708792b944e4ddebb, under CC-BY-4.0. It contains its exact source attribution and modifications. Original license: https://github.com/OWASP/secure-agent-playbook/blob/65d4efd2cd0b081d52101e9708792b944e4ddebb/LICENSE.md

## Source-derived CLI/schema contracts

- Alibaba OpenCodeReview v1.13.3, source 375f64cd6f67a48a135da83cfcf59c52669a09cb: Apache-2.0. Existing S00 capability record retains the exact binary digest and source schemas. No native plugin API is assumed.
- Opengrep v1.33.1, source 092c80faa0817840228349f93eff12a50fb9cf6b: LGPL-2.1 engine license record. Separate ruleset provenance/license/adoption remains required. JSON schema is source-pinned through semgrep-interfaces submodule 5e705660dc7381d4c4c247fa83c4c5860e61d555. No third-party source file is copied into this package.
- Gitleaks CLI v8.30.1, source 83d9cd684c87d95d656c1458ef04895a7f1cbd8e: MIT, Copyright (c) 2019 Zachary Rice. The separately licensed Gitleaks Action is not used. Separate custom/default rule obligations remain an asset-adoption gate.
- OSV-Scanner v2.7.0, source bfe2f84abd2f09fe0b83ba7f6dad40d296762f40: Apache-2.0. Vulnerability database licenses are separate and unresolved until exact datasets are selected.

Source-contracts.json identifies the source inputs used to author flags and parsers. Reading source establishes neither installed binary equivalence nor release runtime behavior. Any future redistribution must satisfy the exact acquired component/rule/data terms. No legal-compliance completion claim is made from these source license observations alone.
