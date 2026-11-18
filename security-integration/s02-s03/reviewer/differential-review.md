# Bounded differential security review

License: CC-BY-SA-4.0. Adapted from Trail of Bits skills at commit 2be6433b39e009cd2b6fd3be1895f6b1faa5af9a:
- https://github.com/trailofbits/skills/blob/2be6433b39e009cd2b6fd3be1895f6b1faa5af9a/plugins/differential-review/skills/differential-review/SKILL.md
- https://github.com/trailofbits/skills/blob/2be6433b39e009cd2b6fd3be1895f6b1faa5af9a/plugins/differential-review/skills/differential-review/methodology.md
License: https://creativecommons.org/licenses/by-sa/4.0/

Changes: this adaptation removes tool grants, shell/Git/history commands, checkout instructions, size-based selective-review shortcuts, installation and test permissions. It uses a preselected sanitized snapshot, requires complete change/context accounting and retains uncertainty. No endorsement is implied.

1. State the change's intended behavior and the baseline security invariants visible in the authorized handoff. If baseline/context is missing, record that gap.
2. Enumerate every supplied changed item and context chunk. Keep original change/content identity in trusted bookkeeping. The reviewer sees opaque IDs and released ranges only. Do not infer the denominator from native preview counts.
3. Identify trust boundaries, attacker-controlled inputs, sensitive operations and permission decisions. Include data/configuration/JSON values, not only executable statements.
4. Trace each potentially consequential change from input through validation and transformations to its sink. Cite released line ranges and the conditions needed to reach the sink. Do not replace a trace with a pattern label.
5. Compare safeguards and invariants across supplied baseline/head content. Consider changed callers, errors, deletes, secondary context, defaults, concurrency and cleanup. Missing evidence means incomplete review, not permission to retrieve raw files.
6. Record depth for each chunk: deep, surface, skipped, unsupported or insufficient context. Retain omissions, redactions, truncation and disagreement explicitly.
7. Report findings with evidence, severity, confidence and preconditions. Distinguish a supported defect from an unverified hypothesis. A clean subset cannot certify the whole change.

This document is inert reviewer procedure content. It confers no authority or executable tools.
