# OCR S07 private fictional examiner handoff

Scope: three new detached files only, with no public or qualification change. The verified sprint card is SHA-256 d0c8bb571cff74f779349dc7961d6421b7762e7c0538c13a48486deac969718e. Exact retained source pins checked: qualification b650d4185a5d0814f9ae85eebce50a618a430c28, entrypoint efdbace3c3891e271ab3e0f55940a51a65c87362, test d288cc890898766c9e91f6a0ef2f0545d0559071. These sources were read as text only. The retained qualification inventory and public output are not equivalent: neither provides this private examiner rendering. S05 is untouched.

Contract: project() and render() consume a tuple of at most eight fictional dictionaries with exactly stage and result; stage order/dependencies are fixed from the pinned inventory. Duplicates, unknown tokens and extra fields fail without echoing input. Supplied passed renders as complete, failed/partial/blocked as blocked, explicit unrun stays unrun, and an absent row is missing. Prerequisite labels compare caller-supplied statuses only. Ready for human evidence means only that listed prerequisites look complete in the supplied rows, not that activity is permitted, recommended, scheduled or qualified. Rendering receives records, not a free-form model and never carries actor names, receipt digests, paths or free text. Both APIs always return/display HELD. No control flow dispatches stage work.

Acceptance: python -B -m unittest -v test_projection ran exactly one ordinary fictional case, passed (one test, zero failures). It checks mixed complete/blocked/unrun/missing statuses, deterministic ordering, explicit prerequisite groups, full supplied data retaining HELD, bounded rendered output and extra-field refusal. No integration, live data, target actions, scanners, providers, network or remote writes.

Private additions only; to view the exact patch, run git diff --no-index -- /dev/null FILE for each of projection.py, test_projection.py and HANDOFF.md. No draft write, qualification, readiness, merge or external review was performed.

`project_supported(records)` is an opt-in private projection. Each row exposes both the caller's `reported_status` and the effective `status`. A reported completion is blocked unless every listed prerequisite has a supported completion of its own, so a contradictory report cannot satisfy a later dependency. The unmet list contains direct dependencies that lack support, not a duplicate transitive list. All results remain fictional, no external evidence is validated, and qualification always remains HELD. Existing `project` and `render` retain their caller-reported interpretation.

`render_supported(records)` explicitly opts in to a different private examiner note. It displays the closed declared status and the status supported by the fixed fictional dependency list separately. Each line lists direct unmet prerequisites only, including dependencies whose own reported completions lack support. Headers always say HELD and no authority. The note provides neither a readiness queue nor recommendations to act, and does not check real evidence. The original renderer and both projections are unchanged. An isolated stdlib fixture freezes the pinned legacy bytes for two ordinary inputs and exercises opt-in contradiction, all/none, deterministic order and closed-field refusal. No real stage, scanner, provider, network, or qualification test is involved.

For a private examiner who needs to distinguish the closed input tokens behind
a normalized status, use `render_supported(records, include_result_token=True)`.
This shows the validated input token (or `none supplied` for a missing record)
without adding fields to the accepted record shape or changing the default
renderer bytes. For example, `partial` and `failed` both project to `blocked`
but are not interchangeable as descriptions of what was declared. No text,
identity, digest or evidence is accepted or checked, and qualification is HELD.
