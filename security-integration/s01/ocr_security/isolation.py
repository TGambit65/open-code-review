# SPDX-License-Identifier: Apache-2.0
"""Explicit synthetic-only execution; unsupported enforcement has no fallback."""

import fcntl
import os
import platform
import selectors
import signal
import struct
import subprocess
import time
from dataclasses import dataclass

from .common import (Refusal, canonical, digest, fields, git_id, now_utc,
                     relative_path, sha, text)
from .policy import (BACKEND_SHA256, FILTER_SHA256, TrustedRef, execution_authority,
                     open_regular, read_descriptor, read_ref, resolve_document)
from .seccomp import filter_bytes
from .snapshot import validate_snapshot

PROFILE_SHA256 = "8ffc7fe96029598fdd219a2e16aba7e7beea7c81be7e4c8f7b78753c499d5108"
MODULES = frozenset(("__init__.py", "common.py", "policy.py", "snapshot.py", "views.py",
                     "broker.py", "seccomp.py", "bootstrap.py", "isolation.py", "results.py",
                     "coverage.py", "acceptance.py", "rollback.py"))


@dataclass(frozen=True)
class RunOutput:
    process_status: str
    code: str
    stdout: bytes
    stderr: bytes
    receipt: bytes


def sealed_bytes(data):
    if not hasattr(os, "memfd_create"):
        raise Refusal("unsupported_platform")
    fd = os.memfd_create("ocr-sealed", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
            raise Refusal("sealing_failed")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def check_static_elf(raw):
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise Refusal("unsupported_tool")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    _, kind, machine, version, entry, phoff, _, _, ehsize, phsize, count, _, _, _ = header
    if kind != 2 or machine != 62 or version != 1 or ehsize != 64 or phsize != 56 or not 1 <= count <= 128:
        raise Refusal("unsupported_tool")
    if phoff < 64 or phoff + count * phsize > len(raw):
        raise Refusal("unsupported_tool")
    stack, entry_ok = False, False
    for index in range(count):
        ptype, flags, offset, virtual, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phsize)
        if ptype in (2, 3) or (ptype == 1 and flags & 3 == 3):
            raise Refusal("unsupported_tool")
        if size > memory or offset + size > len(raw):
            raise Refusal("unsupported_tool")
        if ptype == 0x6474E551:
            if stack or flags & 1:
                raise Refusal("unsupported_tool")
            stack = True
        if ptype == 1 and flags & 1 and virtual <= entry < virtual + memory:
            entry_ok = True
    if not stack or not entry_ok:
        raise Refusal("unsupported_tool")


def _verified_fd(path, expected, maximum, executable=False):
    fd = open_regular(path, maximum, executable)
    try:
        raw = read_descriptor(fd, maximum)
        if digest(raw) != sha(expected):
            raise Refusal("executable_mismatch")
        return fd, raw
    except BaseException:
        os.close(fd)
        raise


def _harness(ref, context):
    manifest = resolve_document(ref, context, "reviewed-harness-manifest")
    fields(manifest, ("schema_version", "kind", "source_root", "files",
                      "independent_review_receipt_sha256", "verified_preservation_commit"))
    sha(manifest["independent_review_receipt_sha256"])
    git_id(manifest["verified_preservation_commit"])
    package = os.path.dirname(os.path.abspath(__file__))
    expected_root = os.path.dirname(os.path.dirname(os.path.dirname(package)))
    if manifest["source_root"] != expected_root or expected_root not in context.candidate_roots:
        raise Refusal("harness_mismatch")
    if type(manifest["files"]) is not list or len(manifest["files"]) != 26:
        raise Refusal("harness_mismatch")
    seen, source_bytes = set(), {}
    for item in manifest["files"]:
        fields(item, ("path", "sha256"))
        relative = relative_path(item["path"])
        if relative in seen:
            raise Refusal("harness_mismatch")
        seen.add(relative)
        fd, raw = _verified_fd(expected_root + "/" + relative, item["sha256"], 4194304)
        os.close(fd)
        source_bytes[relative] = raw
    needed = {"security-integration/s01/ocr_security/" + name for name in MODULES}
    needed.update("security-integration/" + path for path in (
        "S01-contract.md", "s01-scope.json", "s01/VALIDATION.md", "s01/ROLLBACK.md",
        "s01/fixtures/recording_stub.c", "s01/fixtures/cases.json",
        "s01/schemas/result-v1.schema.json", "s01/schemas/sprint-qualification-v1.schema.json",
        "s01/schemas/target-acceptance-v1.schema.json", "s01/tests/test_snapshot_views.py",
        "s01/tests/test_results_policy.py", "s01/tests/test_isolation.py", "s01/tests/test_rollback.py"))
    if needed != seen:
        raise Refusal("harness_mismatch")
    return manifest, source_bytes


def _capture(process, seconds, maximum, started):
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    status, code = "unknown", "unparsed_output"
    killed = False
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                status, code, killed = "timeout", "wall_limit", True
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                used = sum(len(value) for value in streams.values())
                try:
                    part = os.read(key.fileobj.fileno(), min(65536, maximum + 1 - used))
                except BlockingIOError:
                    continue
                if not part:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.fileobj].extend(part)
                if sum(len(value) for value in streams.values()) > maximum:
                    status, code, killed = "partial", "output_limit", True
                    break
            if killed:
                break
        if not killed:
            returncode = process.wait(timeout=max(0.01, seconds - (time.monotonic() - started)))
            status = "success" if returncode == 0 else "error"
            code = "unparsed_output" if returncode == 0 else "process_failed"
    except (OSError, subprocess.TimeoutExpired):
        status, code, killed = "error", "capture_failed", True
    finally:
        if killed or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                status, code = "error", "termination_unconfirmed"
        selector.close()
        for stream in streams:
            stream.close()
    output = bytes(streams[process.stdout])[:maximum]
    error = bytes(streams[process.stderr])[:max(0, maximum - len(output))]
    return status, code, output, error, process.returncode, int((time.monotonic() - started) * 1000)


class ExecutionRefusal(Refusal):
    def __init__(self, code, execution_state):
        super().__init__(code)
        self.execution_state = execution_state


def run_fixture(snapshot, policy, context, authority_ref, harness_ref, tool_ref, python_ref, launch_observer=None):
    progress = {"execution_state": "not_started"}
    try:
        return _run_fixture(snapshot, policy, context, authority_ref, harness_ref, tool_ref, python_ref,
                            launch_observer, progress)
    except Refusal as error:
        raise ExecutionRefusal(error.code, progress["execution_state"]) from None


def _run_fixture(snapshot, policy, context, authority_ref, harness_ref, tool_ref, python_ref, launch_observer, progress):
    """Trust references are supplied by orchestration, never decoded from candidate data."""
    if launch_observer is not None and not callable(launch_observer):
        raise Refusal("invalid_observer")
    validate_snapshot(snapshot)
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Refusal("unsupported_platform")
    if not isinstance(python_ref, TrustedRef):
        raise Refusal("missing_authority")
    if not 1 <= len(snapshot.selected) <= 16:
        raise Refusal("runtime_input_limit")
    if snapshot.policy_sha256 != policy.sha256 or digest(canonical(policy.profile)) != PROFILE_SHA256:
        raise Refusal("profile_mismatch")
    manifest, source = _harness(harness_ref, context)
    tool = resolve_document(tool_ref, context, "compiled-synthetic-fixture")
    fields(tool, ("schema_version", "kind", "artifact_path", "artifact_sha256", "fixture_source_sha256",
                  "compile_recipe_sha256", "argv"))
    fixture_source = source["security-integration/s01/fixtures/recording_stub.c"]
    if sha(tool["fixture_source_sha256"]) != digest(fixture_source):
        raise Refusal("tool_source_mismatch")
    sha(tool["compile_recipe_sha256"])
    argv = tool["argv"]
    if type(argv) is not list or not 1 <= len(argv) <= 32:
        raise Refusal("invalid_arguments")
    for arg in argv:
        text(arg, 512)
    bootstrap = source["security-integration/s01/ocr_security/bootstrap.py"]
    filter_data = filter_bytes()
    expected = {"harness_file_manifest_sha256": harness_ref.sha256,
                "bootstrap_source_sha256": digest(bootstrap), "system_python_executable_sha256": python_ref.sha256,
                "backend_sha256": BACKEND_SHA256, "profile_canonical_sha256": PROFILE_SHA256,
                "seccomp_filter_sha256": FILTER_SHA256, "fixture_source_sha256": digest(fixture_source),
                "compile_recipe_sha256": tool["compile_recipe_sha256"], "compiled_fixture_sha256": tool["artifact_sha256"],
                "snapshot_id": snapshot.snapshot_id, "policy_sha256": policy.sha256, "exact_argv": ["/tool"] + argv,
                "purpose": "synthetic_fixture", "independent_review_receipt_sha256": manifest["independent_review_receipt_sha256"],
                "verified_preservation_commit": manifest["verified_preservation_commit"]}
    current = now_utc()
    authority = execution_authority(authority_ref, context, policy, expected, current)
    # A digest alone is not adoption: the preceding external action binds this exact artifact.
    tool_bytes = read_ref(TrustedRef(tool["artifact_path"], tool["artifact_sha256"]), context)
    check_static_elf(tool_bytes)
    python_bytes = read_ref(python_ref, context, 33554432)
    descriptors, process = [], None
    try:
        backend_fd, _ = _verified_fd("/usr/bin/bwrap", BACKEND_SHA256, 1048576, True)
        descriptors.append(backend_fd)
        interpreter_fd, checked_python = _verified_fd(python_ref.path, python_ref.sha256, 33554432, True)
        descriptors.append(interpreter_fd)
        if checked_python != python_bytes:
            raise Refusal("executable_mismatch")
        for data in (bootstrap, tool_bytes, filter_data, b""):
            descriptors.append(sealed_bytes(data))
        bootstrap_fd, tool_fd, filter_fd, empty_fd = descriptors[2:6]
        inputs = []
        for entry in snapshot.selected:
            fd = sealed_bytes(entry.content)
            descriptors.append(fd)
            inputs.append((fd, "/input/" + entry.opaque_id))
        if max(descriptors) >= 32:
            raise Refusal("descriptor_limit")
        command = ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
                   "--disable-userns", "--assert-userns-disabled", "--cap-drop", "ALL", "--die-with-parent", "--as-pid-1",
                   "--clearenv", "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C", "--setenv", "HOME", "/nonexistent",
                   "--setenv", "TMPDIR", "/output", "--perms", "0500", "--dir", "/input",
                   "--perms", "0500", "--ro-bind-data", str(tool_fd), "/tool"]
        for fd, destination in inputs:
            command += ["--perms", "0400", "--ro-bind-data", str(fd), destination]
        command += ["--perms", "0700", "--size", "8388608", "--tmpfs", "/output", "--perms", "0600", "--file",
                    str(empty_fd), "/output/result.bin", "--chmod", "0500", "/output", "--remount-ro", "/",
                    "--chdir", "/output", "--seccomp", str(filter_fd), "--", "/tool"] + argv
        start_command = ["/proc/self/fd/" + str(interpreter_fd), "-I", "-S", "-B", "/proc/self/fd/" + str(bootstrap_fd),
                         str(bootstrap_fd), str(interpreter_fd), str(backend_fd),
                         ",".join(str(fd) for fd in descriptors if fd not in (bootstrap_fd, interpreter_fd))] + command
        if launch_observer is not None:
            launch_observer(dict(expected))
        progress["execution_state"] = "launch_uncertain"
        started = time.monotonic()
        process = subprocess.Popen(start_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True, pass_fds=tuple(descriptors), start_new_session=True, env={}, cwd="/")
        progress["execution_state"] = "process_started"
        status, code, stdout, stderr, returncode, elapsed = _capture(process, 5, 1048576, started)
        progress["execution_state"] = "termination_unconfirmed" if code == "termination_unconfirmed" else "process_completed"
    except OSError:
        raise Refusal("isolation_unavailable") from None
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        for fd in descriptors:
            os.close(fd)
    receipt = canonical({"schema_version": "1.0", "kind": "private-isolation-run", "bindings": expected,
                         "repository": {"name": snapshot.repository_name, "id": snapshot.repository_id},
                         "base_commit": snapshot.base_commit, "head_commit": snapshot.head_commit,
                         "frozen_diff_sha256": snapshot.frozen_diff_sha256, "actor": authority["authorized_actor"],
                         "action_id": authority["action_id"], "at": current.isoformat(), "process_status": status,
                         "code": code, "exit_code": returncode, "elapsed_ms": elapsed, "completeness": "unknown",
                         "execution_state": progress["execution_state"], "backend_pid": process.pid,
                         "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
                         "original_inputs": [{"id": x.opaque_id, "sha256": x.sha256} for x in snapshot.selected],
                         "rule_pin": "not_applicable", "database_pin": "not_applicable",
                         "artifact_location": "memory:RunOutput; persist privately before qualification",
                         "transformation": "not_applicable_scanner_originals",
                         "target_security_acceptance": "NOT_ASSESSED"})
    return RunOutput(status, code, stdout, stderr, receipt)
