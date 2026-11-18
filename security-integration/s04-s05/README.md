# S04–S05: Security gate and operating workflow

This is provisional disabled source for the approved combined 40-task endpoint. It consumes the preserved S01 and S02–S03 Python interfaces. It contains no native runner, provider client, installer, uploader, Git client, scheduler integration or activation switch. S01 and earlier sprint qualification remain held. A computed `pass` is only a data evaluation backed by the caller's independently adopted evidence; it cannot run a tool or confer permission.

## Implemented source

- `contracts.py` binds exact repository/base/head/frozen-diff/snapshot/source/policy identities and mandatory baseline policy. Trusted references must be supplied by the authorized host with forbidden candidate/input/output roots.
- `updates.py` loads approved pinned manifests, checks already-supplied bytes, retains the exact previous approved set and describes current/absent/unsupported/expired/future/acquisition-failed/rollback intelligence. It never acquires, installs or adopts an artifact.
- `orchestrator.py` composes five exact prior operation plans: paired OCR preview/rule plus Opengrep, supported Gitleaks and OSV. The OCR pair must share its policy, snapshot, projection, tool and assets. Its execute function always refuses. A separately implemented, independently qualified native boundary is still needed before any real automation. There is no callback or enable parameter that changes this.
- `evidence.py` parses bounded normalized scanner output through S01, and combines exact OCR selection/rules with separate S02 semantic accounting. It rebuilds the sanitized handoff rather than trusting an arbitrary clean summary. External rule-body authority binds the exact native rule asset, snapshot, bundle and explicit truthful projection suffix map. Native `.txt`/`.md` exclusions remain gaps, without a forced code suffix. Native preview alone remains incomplete; separate deep review and independent identity evidence are required. Rejected inputs retain bounded digest-only provenance and expected scope, never raw content.
- `observations.py` gives every observation an exact evidence identity and stable conservative fingerprint. It never guesses cross-tool equivalence; separately approved correlations keep every confirmation, highest retained severity, conflicting claims and history. A policy-pinned prior history cannot silently disappear. Missing or lower-severity current observations do not resolve a retained High finding.
- `exceptions.py` admits only pinned, authorized-owner, expiring decisions covering every retained and current observation of the fingerprint and bound to the current subject and trusted policy. No coverage, freshness, permissions or isolation can be waived. Candidate controls have no policy path.
- `gate.py` distinguishes not-run/error/incomplete/with-findings/pass. Missing tools/review, stale intelligence, incomplete coverage, nonzero/error processes, unknown outputs or unsupported attestation fail closed. Claimed finding resolution does not count. External qualified-run attestations must bind all four evidence hashes, the selected identity denominator, current dataset receipt, source policy, independent context assignment and actual prior qualification receipts.
- `reports.py` constructs a separate sanitized public projection after binding full Views, Snapshot, model identity and accepted-evidence transformation digests. Original paths, raw scanner text, rule bodies, actor names, private artifact locations and free-text reasons are withheld. Optional excerpts come only from the corresponding validated sanitized Broker. Effective and current severity and blocking state remain distinct. JSON, Markdown and HTML represent exactly the same complete public document. HTML has no links, remote assets or executable content; Markdown puts all dynamic content inside an indented code block. Static responsive/print styles require later real rendering checks.
- `qualification.py` evaluates explicitly seeded fixture expectations separately from target policy. Detecting a positive fixture can qualify a detector while that target remains blocked.
- `workflow.py`, `batching.py` and `review_gate.py` produce root-only handoffs. They keep source preservation, review, validation and acceptance distinct; retain held payloads; reconcile uncertain actions; constrain retries; track whole-PR distinct paths; and prevent intentional review duplication. They do not mutate live AGENTS, scheduler, CI, hooks or branch protections.
- `entrypoint.py` returns a private decision separately from the three named public artifact byte strings. It neither writes nor shares them. Never forward `Assessment.private_decision`, `Evidence.private_document`, `Views.scanner_inputs` or private finding history to a model or public recipient.

## Trust and boundary limits

The authorized host chooses TrustedRef values and a TrustContext outside the candidate, input and output trees. Candidate-supplied paths/hashes/owners/booleans cannot choose this trust root. SHA-256 pins provide identity, not signing or legal approval. External approval, independent assignment, native coverage and qualification receipts must be genuine and reviewed by the host; a matching actor string is not proof of independence. Python dataclasses are data containers, not isolation capabilities, and trusted callers must not fabricate them as authority.

No approved S04 policy, update set, exception or run attestation is supplied in this source. `update-manifest.json` explicitly records missing prerequisites and is deliberately not accepted as an approved update set. Synthetic tests use fictional receipts and fixed time, never real qualification. S04.08S SARIF is not selected and export refuses.

Gate comparisons are conservative. Native finding/nonzero exits retained as error/partial by S03 cannot become clean through this layer. OSV unrated findings/coverage remain incomplete. Exception expiry and denied/failed/uncertain actions remain visible. Failed publication requires reconciliation, not automatic retry. External histories retain prior observations without asserting that a disappeared or downgraded finding was fixed. Historical observations never supply current coverage.

## Sequence and status

Complete all selected source and rollback → seal → independent full-diff review/coherent fixes → root preserves the exact eligible source in the same draft → admitted end checks → preserve reviewed outcomes → independent acceptance or explicit hold. No tests, imports, compilation, lint, rendering or review were performed while this endpoint was being authored. See VALIDATION.md for deferred checks and WORKFLOW.md for operator steps.

S06–S07 is the next approved source batch, not part of this endpoint. All 82 remaining original IDs are retained in the sequencing overlay. The original C01–C08 authority, root-only actions, B01–B07 review/merge controls and exact denials remain effective.

## Database-set and outcome binding

The gate requires exact equality between the approved `required_datasets` set
and the OSV scan's lockfile ecosystem database set. It compares the digest of the
complete sorted ecosystem, artifact, creation and expiry tuples. Extra required
datasets without scanned lockfiles, extra scanned ecosystems, or changed metadata
are rejected as `database_evidence_mismatch`; absent/expired required data also
remains `dataset_not_current`. This is deliberate conservative refusal, not a
reason to weaken either dataset set to obtain a pass. Mixed source/lockfile
snapshots separately remain `incomplete_osv` under the full-input coverage rule.

Outcome callers must supply `authorization_sha256` naming the exact attempt
covered by the receipt. It must match the record's latest used authorization;
missing or stale attempt identity refuses before any state transition, including
reconciliation of uncertain outcomes. The host still verifies the receipt's
authenticity, target and payload. Matching an input digest does not authenticate
a receipt or authorize publication. Native and external action entrypoints remain
disabled.

### Aggregate capacity and retained evidence

The group/report/history boundary has a shared ceiling of 1024 groups and
4096 observations per retained group, plus the existing bounded JSON byte/node
limits. Composition never truncates evidence to fit. The gate retains its full
private groups and original evidence references, but marks excess composition
`error` with `aggregate_capacity_exceeded`. Public projection returns an explicit
bounded error summary with retained group count/digest and original evidence
references, not an empty-clean finding claim. Full findings and excerpts are not
projected in this overflow summary. Retain the complete private decision and
input evidence; the summary is not a replacement history artifact.

History export validates the complete serialized envelope and shared row checks
before returning a proposed document. Overflow or malformed history refuses;
callers must retain the existing history and failed composition, never silently
reset history or adopt a partial replacement. Output remains data-only and does
not enable native execution, publication or policy changes. Capacity regressions
are authored in `tests/test_aggregate_capacity.py`; no new execution is claimed
by this documentation.
