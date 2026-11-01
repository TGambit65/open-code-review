# S01 validation: authored, not automatically executed

These commands are a later plan, **not authorization and not a pass receipt**.
No test, compiler check, sandbox probe, scanner or provider invocation precedes
full implementation, independent complete-diff review/coherent fixes and root's
verified same-DRAFT source preservation. Root must then separately approve the
exact synthetic check, source/profile/tool identities and artifact locations.

Keep five stages separate. A failed, skipped, unsupported, denied, partial,
unknown or unrun check remains evidence and holds S01.A. Do not install or change
kernel/cgroup/network/security settings to make the tests pass. No real scanner,
private/production input, credential or paid API is used by these fixtures.

## Required assets and custody

1. Root supplies the external adopted policy/adoption record at their pinned
   digests from `../S01-contract.md`. Do not copy candidate policy to create trust.
2. Freeze all 26 proposed paths and retain complete source/diff/hash evidence.
   Independent review must cover full contents, including unsupported files;
   native OCR delegation selection alone is not a security pass.
3. After verified DRAFT preservation, root issues a specific compilation
   authorization for the authored `fixtures/recording_stub.c`. Select an existing
   compiler by absolute verified executable identity, not ambient PATH, and
   approve its exact command and output directory. Do not install a compiler.
4. The intended compile recipe is a small freestanding static x86_64 executable:

   ```text
   <approved-absolute-cc> -Os -ffreestanding -fno-builtin -fno-stack-protector \
     -fno-pie -no-pie -static -nostdlib -Wl,-z,noexecstack -Wl,--build-id=none \
     <exact-source>/security-integration/s01/fixtures/recording_stub.c \
     -o <new-private-trusted-tool-directory>/recording-stub
   ```

   Root records compiler/source/recipe/output SHA-256 and actual compiler
   outcome. Compilation is not isolation qualification. The binary must fit
   1 MiB, match the explicitly adopted artifact digest and satisfy the static
   ELF constraints. No downloaded binary is substituted.
5. Root creates an outside-candidate `reviewed-harness-manifest` version1.0 with
   exact `source_root`, `files` (`path`,`sha256` for all 26 paths), completed
   `independent_review_receipt_sha256` and `verified_preservation_commit`.
   Full-content source review and remote commit are evidence, not placeholders.
6. Root independently pins a regular, non-setuid, non-hardlinked system Python
   executable path/digest. Python/stdlib are trusted host setup dependencies;
   they are never mounted into the analysis namespace. Python 3.10+ is needed
   for source syntax. Native backend is the pinned installed bwrap only.

## V02/V03/V04 standard-library cases

Only after the above preservation and explicit permission, invoke using the
approved Python absolute path with `-I -B`; do not use a package installer or
ambient test runner:

```text
<python> -I -B <source>/security-integration/s01/tests/test_snapshot_views.py \
  --policy <external-policy> --adoption <external-adoption> -v
<python> -I -B <source>/security-integration/s01/tests/test_results_policy.py \
  --policy <external-policy> --adoption <external-adoption> -v
<python> -I -B <source>/security-integration/s01/tests/test_rollback.py \
  --policy <external-policy> --adoption <external-adoption> -v
```

These create only conspicuously synthetic temporary files. They exercise safe
released source alongside secret-bearing originals across primary, secondary,
base, deleted, history, rules/background, tool-error, filename and search paths;
default no-release; private hashes/mapping; escape/symlink/hardlink/FIFO and
changed-source rejection; distinct deletion/recreation identity; stale,
truncated, partial, malformed and exit-zero errors; candidate/missing policy;
required findings; independent stage receipts; and retained-failure rollback.
Coverage fixtures include malformed unexpected and excluded rows: those rows
must pass enum/digest/range/type checks before identity matching, while a
well-formed unexpected row remains an incomplete gap. Both minimum/maximum
year UTC-offset overflow cases must produce parser_error, not an escaped
exception. Verdict fixtures reject CPU watchdog/unrelated failures and missing,
truncated or changed sixteen-input recordings.

The refusal/evidence bookkeeping fixtures mock `run_fixture`; no native process
is started by those cases. They cover later authority expiry, missing authority,
bad snapshot digest, post-run release refusal, uncertain launch, duplicate
attempt protection, evidence-write failure and interrupted launch intent. Mock
outcomes are not V01 enforcement or permission to execute the real fixture.
They author synthetic authority documents only within their explicitly approved
fixture scope, not a trust adoption for user data or real tools.

Runtime validators are strict standard-library code. The three JSON Schema
files are portable descriptions; they are not a dependency or a substitute for
cross-record authority/content/range checks. Schema version/type/field and
failure semantics are exercised through the actual parser, not merely JSON
syntax. No unsupported third-party schema engine is silently installed.

## V01 plus recording-stub portion of V02

`test_isolation.py prepare` creates fixtures and **requests only**, never runs a
process or adopts its own requested authority. It requires a new private
workspace and exact independently adopted assets:

```text
<python> -I -B <source>/security-integration/s01/tests/test_isolation.py prepare \
  --workspace <new-private-fixture-workspace> \
  --policy <external-policy> --adoption <external-adoption> \
  --harness <external-harness-manifest> --harness-sha256 <exact-digest> \
  --python <approved-python-file> --python-sha256 <exact-digest> \
  --tool <approved-compiled-fixture> --tool-sha256 <exact-digest> \
  --recipe <external-compile-recipe-record> --recipe-sha256 <exact-digest>
```

Root reads the exact generated selection/release/tool/action requests and
hashes. Requests do not imply permission. Root independently records an actual
outside-candidate authority document for each exact case with current actor,
issuance/expiry, action ID and unchanged exact bindings. The supplied compiled
source/recipe/artifact, harness/bootstrap/Python/backend/profile/filter,
snapshot/policy/argv and independent review/preservation must match. Bindings
cannot be filled from a candidate `approved:true` field.

Root adopts a separate exact `synthetic-execution-set`, retaining the request
history, setting `state=ROOT_ADOPTED_EXACT_CASES` only in its externally supplied
record and supplying each actual `authority_ref` path/digest. Its exact digest
is supplied on the later explicit command line:

```text
<python> -I -B <source>/security-integration/s01/tests/test_isolation.py run \
  --execution-set <outside-candidate-adopted-set> \
  --execution-set-sha256 <independently-approved-exact-digest>
```

The eight cases are record, containment at the sixteen-input maximum, memory,
file limit, CPU, wall timeout, output flood and whole-run refusal of seventeen
inputs. Synthetic parent environment and inheritable local socketpair test
ambient exclusion. The native stub checks actual descriptor inventory, fixed
environment, PID namespace, missing host paths, read-only inputs, single output
slot, no socket/process/mount/namespace/ptrace/mode/inode creation, no executable
writable memory and non-executable output. It never invokes a real scanner or
model. The maximum-sixteen containment case additionally reads and records
**every** selected original in order; the parent compares the entire exact byte
stream plus the final marker. A missing input, marker-only result, truncation or
changed byte cannot pass. The separate eight-input recording case verifies
original seed bytes and inspects the useful safely released model bundle.
Original-bearing output stays private. Secrets are synthetic only.

The CPU/wall/flood outcomes are deliberately non-success process states and
must be distinguished from setup failure. CPU requires the pinned bwrap
monitor's signal-derived exit code **137**, completed execution, the exact
CPU_STARTED marker, empty stderr and elapsed time at least 1,500 ms but strictly
less than 5,000 ms. The lower bound is conservative tolerance around the fixed
two-second hard CPU budget; the upper bound excludes the wall watchdog. A
wall_limit outcome, outer-process -9, other exit status, invalid timing or
unconfirmed termination fails CPU qualification. These are source-authored
assertions, not a claim that CPU enforcement has already been demonstrated.
Required positive containment,
recording, memory and file tests must genuinely run successfully. If the kernel
cannot support the required sandbox, preserve the failure and keep S01.A held;
unsupported is not a passing substitute for positive isolation evidence.

### Durable attempt journal and refusal accounting

Each exact adopted execution set creates a new private
`evidence/attempt-<execution-set-sha256>/` directory. Creation and all artifact
writes are exclusive, no-follow and fsynced; an existing attempt is retained and
refused, never overwritten or automatically retried. The journal records a
bound attempt intent, then a case intent before preflight, snapshot-bound
prepared evidence and a launch intent immediately before the native launcher.
Records bind exact execution set/case and known policy/harness/selection/tool/
authority/release hashes; launch intent includes the launcher's complete exact
runtime bindings. A missing or expired authority is not execution permission.

Raw receipt/stdout/stderr are retained **before** post-run verdicts, parsing or
model-release transformation. A later refusal cannot erase earlier raw results.
Terminal refused/failed cases and explicit unrun successors are retained, with
all eight cases in the final `validation-outcomes.json`. Raw originals,
transformations, intent and per-run receipts remain in this private directory;
ordinary summaries expose outcomes and digest references, not original bytes.

`not_started` means known nonexecution; `process_completed` means a returned,
reaped execution, not a passing verdict. `launch_uncertain`, `process_started`
without a confirmed return and `termination_unconfirmed` require reconciliation
and never assert executed=false. The launcher annotates known refusal phases;
an unannotated exception after entering it is conservatively uncertain. An
interruption can leave an intent without a terminal record: treat that attempt
as unresolved, not clean or safe to repeat. No automatic recovery execution is
provided, and absence of a terminal record is never success.

If the approved evidence destination cannot be opened or durable writing fails,
stop: do not execute another case or invent a fallback destination. A failure
before a trusted destination exists can provide only a digest-bound safe refusal
summary. A write failure after journal creation reports evidence_complete=false
and, where available, a bounded **unpersisted** outcome summary, never a durable
pass. Files already retained, including partial writes, stay for reconciliation.
This does not claim storage or an abruptly killed process can always write a
terminal record. Repair/retry requires root reconciliation and a new exact
authorization; never erase a failed run or reuse its action as blanket permission.

No auto-generated evidence approves itself; a separate reviewer assesses all
V01-V04 and root preserves reviewed outcomes/corrections before S01.A.

## Scope exclusions and honest outcomes

Not tested here: real secret-detector accuracy, third-party scanners, models,
Go application integration, provider/credential access, general-purpose language
scanner compatibility, arbitrary process trees, Windows/macOS, hostile same-UID
host mutation, kernel compromise, side channels or production readiness. A
successful S01 harness result is never target security acceptance or permission
to activate an adapter. Source review, preservation, validation and acceptance
remain separate receipts bound to the current exact source.
