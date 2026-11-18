# Concrete semantic and configuration-weakening inputs

Authored synthetic data only. Not executed, independently reviewed by a model,
passed, or adopted as runtime policy. No credential or genuine advisory appears.

S02.06: authorization-before.json and authorization-after.json represent the
base and head of the same modified security-policy.json. Keys and structure stay
fixed; required_role changes administrator to anyone and allow_anonymous changes
false to true. A future independent semantic review must discuss that weakening,
its caller/enforcement preconditions, and any missing context. A topic label is
not proof that this reasoning occurred. This fixture alone proves no exploit.

S02.07 / S03.06: candidate-gitignore.txt, candidate-gitleaksignore.txt and
candidate-gitleaks-policy.toml are selected candidate content under original
names .gitignore, .gitleaksignore and .gitleaks.toml. They express attempts to omit
sample.py/security-policy.json or suppress findings. Original names and content
hashes remain private identities; content must remain review input with opaque
aliases, never functional scanner config/ignore files or trusted policy.
The fictional Gitleaks fingerprint is illustrative, not observed native output.

The companion tests/test_semantic_fixtures.py checks data structure, paired
base/head identity, complete selected-item retention, inert aliases and mandatory
review topics. It builds synthetic Snapshot and ModelBundle objects directly.
It does not establish S01 custody/release, a genuinely independent reviewer,
semantic detection, native ignore/config precedence, or actual scanner selection.
Native and separate-context expectations remain future S02.V01–V03 / S03.V01–V04
qualification work subject to their existing gates.
