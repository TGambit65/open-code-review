# Bounded false-positive challenge

License: CC-BY-SA-4.0. Adapted from Trail of Bits, commit 2be6433b39e009cd2b6fd3be1895f6b1faa5af9a:
https://github.com/trailofbits/skills/blob/2be6433b39e009cd2b6fd3be1895f6b1faa5af9a/plugins/fp-check/skills/fp-check/SKILL.md
License: https://creativecommons.org/licenses/by-sa/4.0/

Changes: removes Write/Edit/Bash/Task/tool permissions, execution examples and forced binary true/false verdicts. Only the supplied main procedure concepts are adapted; unseen referenced playbooks are not incorporated. Challenges use the existing sanitized evidence and cannot self-close a finding or acquire more source.

For each claim, state the alleged root cause, trigger, impact, attacker capabilities, privilege boundary and normal caller constraints. Trace the supplied data path. Look for visible validation, invariants, unreachable conditions and counterexamples that would defeat the claim.

Provide exact supporting and contradicting chunk/range references. Do not infer severity from a dramatic pattern name or a similar historical bug. Separate observed facts from assumptions.

If the relevant caller, invariant or sink is unavailable, choose unresolved/needs context. Preserve both the original finding and challenge. A model assertion or counterargument does not grant an exception, close a security finding or authorize a proof-of-concept. Only the independently authorized acceptance process may resolve it.
