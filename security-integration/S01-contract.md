# S01: isolated snapshot and evidence foundation

This is an **inert, explicitly invoked Python standard-library foundation**.
It does not wire a scanner/model into the Go application, alter installed OCR,
install packages, activate hooks/CI, or claim target security clearance. Source
was authored as one complete sprint; execution evidence is a separate gate.

## Source, scope and authority

- Owned fork: `TGambit65/open-code-review`, repository ID `1434220736`.
- S00 predecessor: commit `9aed8be496c1b6ba7d64acc8b8f2d8e64cf40546`, tree
  `6ce8e022b671284d40946597c8517eea00b694d7`; existing DRAFT PR #2 on
  `security/integration-sprints-20261101`. Existing ancestry and all seven
  accepted S00 files remain unchanged.
- Accepted S00.A receipt SHA-256:
  `73a38c0f559f3eccd1c7f7b91f02887c74625587e891dbde1e213188968f8be7`.
- S01 includes all twelve implementation tasks and rollback, with 26 new paths
  listed in `s01-scope.json`. There is no selected-task deferral or reduced
  mini-sprint. Whole-PR path targets do not justify padding.
- Writer and independent reviewers were requested as `gpt-6-astra`, `xhigh`;
  actual runtime identity is unexposed. A task identifier is not a MAX claim.
  Root alone publishes, requests the included final external review and merges.

The root coordinator adopted exact external runtime policy bytes, after a
separate clean design review, **for local implementation only**:

| External reference | SHA-256 |
| --- | --- |
| Runtime policy v4 (`security-acceptance.proposed-v4.json`) | `51653fb23403f441afec8cb0fc2780a6f649a089d119b0cf79e66e9f9622bf16` |
| Root technical adoption record | `67ba0b9e8136a79e46f66d0c2fafd8dd1e372331c820486183ac70195cdbdb45` |
| Detailed reviewed design v4 | `8932be22dddfe7dff3316a42b683bad3ea3033f2a2e8292622c9d1452283c4c2` |
| Standalone runtime profile v4 | `9e6db8a390ae3511bb989b468281178cb43f0925b55dce1044e5040583b07b79` |
| Canonical embedded runtime profile | `8ffc7fe96029598fdd219a2e16aba7e7beea7c81be7e4c8f7b78753c499d5108` |

These are references, not trusted candidate copies. The externally retained
proposal label records authoring history; only the independent exact adoption
receipt confers bounded technical adoption. No policy file or `approved` flag
inside candidate input can adopt itself. Missing/mismatched/inside-input policy
refuses. Trust references come from the trusted caller, not discovery, cwd,
environment, model requests or candidate configuration. This is a caller-held
capability contract, not a signature service: a malicious trusted caller or
compromised reviewed harness is outside its threat model.

## Original input and exclusively sanitized model data

`build_snapshot` consumes an externally approved complete selection inventory,
explicit root inode/device, repository/base/head/diff identity, content digests,
selected/excluded reasons and path/change-kind/blob/side/ranges. It performs
no Git, home or directory discovery. Named no-follow descriptor traversal
rejects escape, symlinks, hardlinks, nonregular files, changed bytes and limits.
The snapshot freezes bytes, not a writable bind of the author's worktree.
An optional explicit private materialization creates a new evidence directory;
analysis receives sealed memfds, never these mutable host paths.

The snapshot limit is 256 records, 1 MiB per selected file, 16 MiB total. The
narrow execution profile supports **at most 16 selected files**; larger requests
refuse entirely, never run a partial subset. Excluded entries remain coverage
gaps. This distinction is explicit policy, not silent loss of selected scope.

`materialize_views` retains exact scanner bytes and constructs a different model
bundle. No text is released by default. Useful safe lines require a separately
approved exact snapshot/content/line release manifest; unreleased lines are
redacted with mappings and gaps. Binary/invalid/unsafe content is omitted with
gaps. Model materialization caps each entry at 4096 mapped lines, total mappings
at 16384 lines and total model text at 1 MiB; overflow is a whole-entry gap,
never silent truncation or loss of original scanner bytes. No regex is claimed to prove absence of arbitrary secrets. Paths, original
digests, blobs and raw error text stay private; model-visible IDs are opaque.
Original and transformed hashes and complete mapping remain in private evidence.

`Broker` has only sanitized data and supports primary/secondary/base/deleted/
history/search/filename/rules/background/tool-error reads. Errors are fixed
codes; filenames are opaque; search operates only on released text. The broker
has no source root, Git object, original byte reference or read fallback. Code,
comments, skills, rules and tool text remain inert data, not authority.

There is no provider integration in S01. An integration that gives a model
arbitrary host Python, filesystem, Git or other tools beside these broker
operations is **unsupported**, not secured by this library. Sanitation happens
in the trusted preparation boundary, never by giving the model originals merely
so it can redact them. Caller logging and future transports need the same
mediated boundary; raw private evidence is not a public report API.

## Narrow enforced execution profile

Only a separately adopted synthetic fixture may execute under a later exact
root action authorization. Real scanners/models remain disabled and the backend
remains unqualified until actual successful containment evidence. Installed
non-setuid `/usr/bin/bwrap` must match
`573236e5328ac2ebb08f59ae3a9805b4f8d12bdef14be8af4450d5463294985f`.
System Python executable, reviewed harness/bootstrap, compiled static fixture,
source/compile recipe, policy/profile/filter, snapshot, exact argv and prior
review/preservation are independently pinned per action. No shell/PATH/provider
fallback exists; unsupported setup refuses.

Mandatory Linux x86_64 user/mount/PID/network/IPC/UTS isolation, disabled further
user namespaces, dropped capabilities, no-new-privileges through pinned bwrap,
read-only root and sealed read-only per-file inputs protect the host boundary.
There are no host directory, proc/sys/dev/home or credential/socket mounts.
Only fixed locale/HOME/TMPDIR/PWD values reach analysis; stdin is null, outputs
are bounded pipes, and input/tool/filter setup descriptors are consumed before
analysis. Bootstrap and interpreter descriptors close; backend exec FD is
CLOEXEC. No ambient token or agent socket is intentionally inherited.

The fixed BPF filter SHA-256 is
`face557219d5ab2c901cacbf92ee8894a6a34fa5939a221796a75d1b0d25e9a9`.
It checks architecture/x32, defaults to denial, and forbids process/thread
creation, all sockets, mount/namespaces, ptrace, inode creation/metadata changes,
new executable mappings and resource-limit changes. Seccomp complements the
other mechanisms; it is not described as a complete sandbox by itself.

The initial tool is static ELF64 x86_64 ET_EXEC, at most 1 MiB, without dynamic
segments/interpreter, writable-executable loads or executable GNU stack. The
bootstrap refuses nonzero inherited personality. `execve` is needed for initial
launch and may re-execute the immutable `/tool`; writable outputs cannot become
executable. A compromised process may still run arbitrary instructions/ROP.
This design contains hostile analysis; it does not prove absence of compromise.

A sealed stdlib-only bootstrap, executed by pinned Python with `-I -S -B`, sets
hard+soft CPU 2s, address space 128 MiB, file size 1 MiB, 32 FDs, zero core dumps.
The parent enforces a monotonic 5s wall deadline and combined 1 MiB output cap,
kill/reap and explicit unconfirmed-termination failure. This bounds one analysis
process, not arbitrary process trees. Multithreaded/multiprocess scanners are
unsupported until a separately reviewed enforceable profile is adopted.

The only writable filesystem is an 8 MiB tmpfs containing one precreated 0600
result slot in a 0500 directory. Creation, linking, renaming, unlinking and mode
changes are denied; fixed slots bound inode count separately from tmpfs bytes.
The slot is ephemeral and never exported to the host. Only capped stdout/stderr
are returned privately. No unreviewed file exporter is implied.

Trusted platform/kernel/Python/stdlib/bwrap and non-hostile same-UID orchestration
are assumptions. The library does not contain a compromised kernel/platform,
same-UID host attacker or side channels. Exact backend bytes plus flags are
not runtime proof: V01 must establish positive support, otherwise S01.A stays
held. No installation, escalation or security setting change is a remedy here.

## Evidence, acceptance and rollback

Result schema/runtime validators separate process status, completeness and all
five stages. Malformed, unknown, timeout, partial, skipped, stale, parser/error,
unsupported and exit-zero-but-unparsed outcomes cannot become full coverage.
Coverage keys include snapshot/path/change kind/base-head blobs/side/ranges;
staged deletion and untracked recreation at one path are distinct. Findings
retain severity, confidence, preconditions and evidence provenance. These are
private records; candidate stage booleans cannot grant acceptance.

Qualification requires independent current externally supplied stage evidence,
verified preservation, all V01-V04 and a separate independent decision. S01's
`target_security_acceptance` is always `NOT_ASSESSED`. Critical/High/Medium
findings require current external resolution or separately approved scoped,
expiring exceptions; policy currently authorizes none. No exception can waive
permission, secrets, isolation or coverage requirements.

Rollback retains exact failed-run evidence before selecting only an approved
supported prior configuration. The supported prior is the inert S00 disabled
configuration, not an unapproved old scanner. Unknown schemas hold while
retaining evidence; no raw-model fallback, evidence overwrite or false target
acceptance is possible. See `s01/ROLLBACK.md` and `s01/VALIDATION.md`.

The fixed sequence is full implementation/fixtures -> complete independent
source review/coherent fixes -> root same-DRAFT preservation labelled untested
-> separately authorized end checks -> reviewed outcomes/corrections preserved
-> independent acceptance. All source/validation states are distinct. Existing
whole-PR limits, root-only publication and one included final external review
remain binding; this source is not a review request or permission expansion.
