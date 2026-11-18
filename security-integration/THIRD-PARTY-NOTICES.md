# Third-party provenance and adoption holds

This is the **S00 inventory**, not a license-clearance opinion or permission to
install, scan, redistribute or activate a component. `tool-lock.json` is the
machine-readable pin index. No third-party procedure, scanner rule, database,
binary or report template is newly copied or redistributed in this subtree.
Existing repository dependencies, source and licensing are unchanged.

## Material used for this foundation

### OpenCodeReview

Source: Alibaba OpenCodeReview, contributors, release `v1.13.3`, commit
`375f64cd6f67a48a135da83cfcf59c52669a09cb`.

- License: [Apache-2.0 at the pinned source](https://github.com/alibaba/open-code-review/blob/375f64cd6f67a48a135da83cfcf59c52669a09cb/LICENSE).
  The existing repository license is retained at [`../LICENSE`](../LICENSE).
- The new capability record describes CLI fields and behavior from
  `cmd/opencodereview/delegate_cmd.go`, `shared_flags.go`, `shared.go`,
  `internal/delegate/`, `internal/agent/preview.go`, `internal/model/preview.go`
  and `internal/config/rules/`. Individual exact source URLs, blob identities
  and SHA-256 values are in `tool-lock.json`.
- Attribution for that source-derived description: **Copyright 2026
  alibaba/open-code-review Contributors**. These new records summarize the
  inspected source and add owner-specific inert-scope, custody and permission
  boundaries. They do not modify or redistribute those implementation files.
- The host-agent delegation skill is referenced, not installed or copied into
  an active skill/hook location. Its upgrade, raw-context and optional fix
  instructions do not override the current authorization boundaries.
- The preexisting approved Linux-amd64 native binary is only identified by
  digest in these records. It is not included in the public payload or modified.
  A digest match does not prove a reproducible build or verified signature.
- No report template is taken from upstream. The Markdown baseline documents
  are newly authored; S00 implements no report renderer.

## Planned baseline components, not adopted by S00

The distinction between source, binary, rule, data and wrapper terms is
intentional. A source repository's license does not automatically license a
different binary bundle, remote ruleset, database, Action, service or report
template. Every unfilled digest/prerequisite remains an adoption hold.

| Component and exact source | Recorded source license | Hold before adoption/copying |
| --- | --- | --- |
| Trail of Bits skills, `2be6433b39e009cd2b6fd3be1895f6b1faa5af9a` | [CC-BY-SA-4.0](https://github.com/trailofbits/skills/blob/2be6433b39e009cd2b6fd3be1895f6b1faa5af9a/LICENSE) | Select exact differential-review/false-positive procedure files and hashes; preserve attribution, license and change notices; resolve the share-alike boundary for adapted material. No hook or bundled runtime is adopted. |
| OWASP secure-agent-playbook, `65d4efd2cd0b081d52101e9708792b944e4ddebb` | [CC-BY-4.0](https://github.com/OWASP/secure-agent-playbook/blob/65d4efd2cd0b081d52101e9708792b944e4ddebb/LICENSE.md) | Select exact play/procedure content and hashes; preserve attribution, license link and modification notice when adapting. No procedure content is copied by S00. |
| Opengrep `v1.33.1`, `092c80faa0817840228349f93eff12a50fb9cf6b` | [LGPL-2.1 source license](https://github.com/opengrep/opengrep/blob/092c80faa0817840228349f93eff12a50fb9cf6b/LICENSE) | Approve exact binary provenance/digest and separate local rule content/licenses. No auto/registry profile, remote rules or ruleset redistribution. |
| Gitleaks CLI `v8.30.1`, `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` | [MIT; Copyright (c) 2019 Zachary Rice](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE) | Approve binary/rule/config pins and notice retention for any later redistribution. The separate `gitleaks-action` wrapper and its terms/default uploads are not adopted. No credential validation. |
| OSV-Scanner `v2.7.0`, `bfe2f84abd2f09fe0b83ba7f6dad40d296762f40` | [Apache-2.0 source license](https://github.com/google/osv-scanner/blob/bfe2f84abd2f09fe0b83ba7f6dad40d296762f40/LICENSE) | Approve binary provenance and distinct offline vulnerability-database content, licenses, timestamps and hashes. Engine license is not a database freshness or data-use clearance. |

No adapted Trail of Bits or OWASP material is relicensed as Apache merely by
listing it here. Before any later copy, retain the exact material's copyright
and license text/link as applicable, record changed portions and source hashes,
and resolve incompatible or ambiguous obligations with the authorized owner.
If unresolved, leave the component unadopted; do not substitute an unpinned
copy, strip notices or silently enable an alternative.

## Separate rule, Action, engine and service boundaries

- **Opengrep/Semgrep rules:** engine compatibility does not grant rights in
  third-party rule text. The previously researched
  [opengrep-rules snapshot](https://github.com/opengrep/opengrep-rules/blob/f1d2b562b414783763fd02a6ed2736eaed622efa/LICENSE)
  is not selected. Semgrep-hosted rules, Pro engine/rules and hosted service
  terms require separate current review. No such rules are copied here.
- **Gitleaks Action:** the separate
  [wrapper license snapshot](https://github.com/gitleaks/gitleaks-action/blob/bcfb9cce635345aac9996cedc19b2de8e01b894f/LICENSE.txt)
  is not the CLI's MIT license. No Action, organization key, PR comment or SARIF
  upload is enabled.
- **CodeQL:** query/library licenses and CLI/engine/private-code entitlement are
  separate. The [researched engine terms](https://github.com/github/codeql-cli-binaries/blob/b8920d6194a72a8c567808f64943929acbd9a3d9/LICENSE.md)
  do not constitute Acorn entitlement evidence. No extractor/build/upload is
  permitted by this inventory.
- **Bearer, Semgrep, Trivy and Betterleaks:** prior release/source pins are
  retained as research only in `tool-lock.json`. Current selected binary,
  rules/data, license/service obligations, provenance and execution controls
  are unresolved for this integration. No new decision or pilot is completed.
- **AgentShield, Anthropic security review, Snyk Agent Scan, Strix and Shannon:**
  source research is not provider/service authorization or a right to process
  target data. Exact selected code and terms, account/spending, target scope,
  outbound effects and credential boundaries remain separate prerequisites.
  Active pentesting would require a separate explicitly authorized disposable
  target project; S00 authorizes none.
- **Report formats/templates:** a format such as SARIF is not permission to
  upload reports or copy a renderer/template. No third-party report assets,
  remote scripts, fonts or template code are included.

## Change and retention record

S00 creates six inert baseline records. The source-derived OCR schema/command
description is newly summarized and explicitly limited; no upstream source
code, scanner rules or other procedure text is modified. Exact consulted
source files and observed license-text hashes are recorded in `tool-lock.json`.
The complete additive diff and candidate hashes are retained in the external
S00.M freeze. Later adopted material must add its own exact source, license,
copyright, modification record and artifact digest before use. Ambiguous
obligations remain named holds, never a blanket approval inferred from this
file's presence.
