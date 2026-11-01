# SPDX-License-Identifier: Apache-2.0
"""Prepare explicit requests, then run only separately adopted synthetic cases."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import sys

sys.path.insert(0, str(Path(__file__).absolute().parent))
import test_snapshot_views as support
from ocr_security.broker import Broker
from ocr_security.common import Refusal, canonical, digest, fields, parse_json, relative_path, sha
from ocr_security.isolation import ExecutionRefusal, PROFILE_SHA256, run_fixture
from ocr_security.policy import (BACKEND_SHA256, FILTER_SHA256, TrustContext, TrustedRef,
                                 open_directory, read_ref, resolve_document, resolve_policy)
from ocr_security.snapshot import build_snapshot
from ocr_security.views import materialize_views

MODES = ("record", "containment", "memory", "file", "cpu", "wall", "flood", "seventeen")


def reference(value):
    fields(value, ("path", "sha256"))
    return TrustedRef(value["path"], value["sha256"])


def ref_data(value):
    return {"path": value.path, "sha256": value.sha256}


def prepare(args):
    fixture = support.Fixture(args.workspace, args.policy, args.adoption)
    harness_ref = TrustedRef(args.harness, args.harness_sha256)
    manifest = resolve_document(harness_ref, fixture.context, "reviewed-harness-manifest")
    python_ref = TrustedRef(args.python, args.python_sha256)
    read_ref(python_ref, fixture.context, 33554432)
    read_ref(TrustedRef(args.tool, args.tool_sha256), fixture.context)
    read_ref(TrustedRef(args.recipe, args.recipe_sha256), fixture.context)
    source_root = Path(manifest["source_root"])
    fixture_source = source_root / "security-integration/s01/fixtures/recording_stub.c"
    bootstrap_source = source_root / "security-integration/s01/ocr_security/bootstrap.py"
    original_entries = list(fixture.entries)
    for ordinal in range(8, 17):
        raw = ("synthetic extra %d\n" % ordinal).encode()
        storage = "extra-%02d.txt" % ordinal
        (fixture.inputs / storage).write_bytes(raw)
        fixture.entries.append({"path": storage, "source": storage, "change_kind": "added", "base_blob": None,
                                "head_blob": "3" * 40, "side": "head", "required_ranges": [[1, 1]],
                                "surfaces": ["primary"], "selected": True, "reason": "synthetic_maximum",
                                "sha256": digest(raw), "bytes": len(raw)})
    now = datetime.now(timezone.utc)
    cases = []
    selections = {}
    for size in (8, 16, 17):
        selection_ref = fixture.selection(fixture.entries[:size])
        selections[size] = (selection_ref, build_snapshot(selection_ref, fixture.context, fixture.policy))
    for mode in MODES:
        size = 8 if mode == "record" else 17 if mode == "seventeen" else 16
        selection_ref, snapshot = selections[size]
        command_mode = "containment" if mode == "seventeen" else mode
        argv = [command_mode] + (["/input/" + entry.opaque_id for entry in snapshot.selected] if command_mode in ("record", "containment") else [])
        tool_ref = fixture.write_ref({"schema_version": "1.0", "kind": "compiled-synthetic-fixture",
                                      "artifact_path": args.tool, "artifact_sha256": args.tool_sha256,
                                      "fixture_source_sha256": digest(fixture_source.read_bytes()),
                                      "compile_recipe_sha256": args.recipe_sha256, "argv": argv}, "tool-" + mode)
        bindings = {"harness_file_manifest_sha256": harness_ref.sha256, "bootstrap_source_sha256": digest(bootstrap_source.read_bytes()),
                    "system_python_executable_sha256": python_ref.sha256, "backend_sha256": BACKEND_SHA256,
                    "profile_canonical_sha256": PROFILE_SHA256, "seccomp_filter_sha256": FILTER_SHA256,
                    "fixture_source_sha256": digest(fixture_source.read_bytes()), "compile_recipe_sha256": args.recipe_sha256,
                    "compiled_fixture_sha256": args.tool_sha256, "snapshot_id": snapshot.snapshot_id, "policy_sha256": fixture.policy.sha256,
                    "exact_argv": ["/tool"] + argv, "purpose": "synthetic_fixture",
                    "independent_review_receipt_sha256": manifest["independent_review_receipt_sha256"],
                    "verified_preservation_commit": manifest["verified_preservation_commit"]}
        request = {"schema_version": "1.0", "kind": "synthetic-execution-authority", "authorized_actor": "ROOT_TO_ADOPT",
                   "issued_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
                   "action_id": "S01-" + mode + "-ROOT_TO_ADOPT", "bindings": bindings}
        release_ref = None
        if mode == "record":
            release_ref = fixture.write_ref({"schema_version": "1.0", "kind": "approved-line-release", "snapshot_id": snapshot.snapshot_id,
                                             "entries": [{"opaque_id": entry.opaque_id, "original_sha256": entry.sha256, "ranges": [[1, 1], [3, 3]]}
                                                         for entry in snapshot.selected]}, "synthetic-release")
        cases.append({"mode": mode, "selection_ref": ref_data(selection_ref), "tool_ref": ref_data(tool_ref),
                      "release_ref": ref_data(release_ref) if release_ref else None, "authority_ref": None, "authority_request": request})
    document = {"schema_version": "1.0", "kind": "synthetic-execution-set", "state": "REQUESTS_ONLY_NOT_ADOPTED",
                "workspace": str(fixture.root), "candidate_root": fixture.candidate, "policy_ref": ref_data(fixture.policy_ref),
                "adoption_ref": ref_data(fixture.adoption_ref), "harness_ref": ref_data(harness_ref), "python_ref": ref_data(python_ref), "cases": cases}
    destination = fixture.authority / "execution-requests.json"
    destination.write_bytes(canonical(document))
    print(json.dumps({"state": "REQUESTS_ONLY_NOT_ADOPTED", "path": str(destination), "sha256": digest(destination.read_bytes()), "executions": 0}))


def cpu_limit_passed(output):
    receipt = parse_json(output.receipt)
    return (output.process_status == "error" and output.code == "process_failed"
            and receipt.get("process_status") == "error" and receipt.get("code") == "process_failed"
            and type(receipt.get("exit_code")) is int and receipt["exit_code"] == 137
            and type(receipt.get("elapsed_ms")) is int and 1500 <= receipt["elapsed_ms"] < 5000
            and receipt.get("execution_state") == "process_completed"
            and output.stdout == b"CPU_STARTED\n" and not output.stderr)


def expected_recording(snapshot):
    return b"".join(b"INPUT\n" + entry.content for entry in snapshot.selected)


def containment_passed(output, snapshot):
    return (len(snapshot.selected) == 16 and output.process_status == "success"
            and output.stdout == expected_recording(snapshot) + b"CONTAINMENT_OK\n" and not output.stderr)


class RetentionError(Exception):
    pass


class EvidenceJournal:
    def __init__(self, workspace, set_sha256):
        self.root = open_directory(str(workspace / "evidence"))
        self.directory = None
        self.path = workspace / "evidence" / ("attempt-" + sha(set_sha256))
        try:
            os.mkdir(self.path.name, 0o700, dir_fd=self.root)
            self.directory = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.root)
            os.fsync(self.root)
        except FileExistsError:
            self.close()
            raise Refusal("attempt_already_recorded") from None
        except OSError:
            self.close()
            raise RetentionError() from None

    def write(self, name, raw):
        relative_path(name)
        if "/" in name or type(raw) is not bytes:
            raise Refusal("invalid_evidence_artifact")
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError()
                view = view[count:]
            os.fsync(fd)
            os.fsync(self.directory)
        except OSError:
            raise RetentionError() from None
        finally:
            if fd is not None:
                os.close(fd)
        return {"path": str(self.path / name), "sha256": digest(raw)}

    def close(self):
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
        if self.root is not None:
            os.close(self.root)
            self.root = None


def case_binding(document, set_ref, case, mode, index):
    try:
        case_sha256 = digest(canonical(case))
    except Refusal:
        case_sha256 = None
    row = {"mode": mode, "case_index": index, "execution_set_sha256": set_ref.sha256,
           "case_sha256": case_sha256, "actor": "synthetic-validation-harness",
           "at": datetime.now(timezone.utc).isoformat(), "execution_state": "not_started", "executed": False,
           "target_security_acceptance": "NOT_ASSESSED"}
    for field in ("policy_ref", "harness_ref"):
        try:
            row[field + "_sha256"] = sha(document[field]["sha256"])
        except (Refusal, TypeError, KeyError):
            pass
    for field in ("selection_ref", "tool_ref", "release_ref", "authority_ref"):
        try:
            row[field + "_sha256"] = sha(case[field]["sha256"])
        except (Refusal, TypeError, KeyError):
            pass
    return row


def execution_mark(row, state):
    if state not in ("not_started", "launch_uncertain", "process_started", "process_completed", "termination_unconfirmed"):
        state = "launch_uncertain"
    row["execution_state"] = state
    row["executed"] = False if state == "not_started" else True if state == "process_completed" else None
    if row["executed"] is None:
        row["reconciliation_required"] = True
    else:
        row.pop("reconciliation_required", None)


def evaluate_case(mode, output, snapshot, case, context, journal):
    if mode == "containment":
        return containment_passed(output, snapshot)
    if mode in ("memory", "file"):
        expected = b"MEMORY_LIMIT_OK\n" if mode == "memory" else b"FILE_LIMIT_OK\n"
        return output.process_status == "success" and output.stdout == expected and not output.stderr
    if mode == "record":
        views = materialize_views(snapshot, context, reference(case["release_ref"]))
        broker = Broker(views.model)
        bundle = canonical([broker.read(surface, entry.opaque_id) for entry in snapshot.selected for surface in entry.surfaces])
        journal.write("record-transformation.json", views.private_evidence)
        return (output.process_status == "success" and output.stdout == expected_recording(snapshot) and not output.stderr
                and b"SYNTHETIC_SECRET" not in bundle and b"safe_primary" in bundle
                and all(item.gaps for item in views.model.items))
    if mode == "cpu":
        return cpu_limit_passed(output)
    if mode == "wall":
        return output.process_status == "timeout" and output.code == "wall_limit" and output.stdout == b"WALL_STARTED\n" and not output.stderr
    if mode == "flood":
        return output.process_status == "partial" and output.code == "output_limit" and output.stdout == b"x" * 1048576 and not output.stderr
    return False


def execute_cases(document, set_ref, context, policy, journal):
    rows, stopped, storage_failed = [], False, False
    for index, (case, mode) in enumerate(zip(document["cases"], MODES)):
        row = case_binding(document, set_ref, case, mode, index)
        output, call_entered = None, False
        if stopped:
            row.update(outcome="unrun", code="prior_case_incomplete")
        else:
            try:
                journal.write(mode + "-intent.json", canonical(dict(row, outcome="pending")))
                if row["case_sha256"] is None:
                    raise Refusal("invalid_case_binding")
                if case["authority_ref"] is None:
                    raise Refusal("missing_authority")
                snapshot = build_snapshot(reference(case["selection_ref"]), context, policy)
                row["snapshot_id"] = snapshot.snapshot_id
                journal.write(mode + "-prepared.json", canonical(dict(row, outcome="pending")))

                def observe_launch(bindings):
                    journal.write(mode + "-launch-intent.json", canonical(dict(row, outcome="pending", launch_bindings=bindings,
                                                                             execution_state="launch_uncertain", executed=None)))
                    execution_mark(row, "launch_uncertain")

                left, right = socket.socketpair()
                try:
                    left.set_inheritable(True); right.set_inheritable(True)
                    if "S01_SYNTHETIC_TOKEN" in os.environ:
                        raise Refusal("synthetic_environment_collision")
                    os.environ["S01_SYNTHETIC_TOKEN"] = "SYNTHETIC_SECRET_ONLY_ENVIRONMENT"
                    try:
                        call_entered = True
                        output = run_fixture(snapshot, policy, context, reference(case["authority_ref"]), reference(document["harness_ref"]),
                                             reference(case["tool_ref"]), reference(document["python_ref"]), launch_observer=observe_launch)
                    finally:
                        os.environ.pop("S01_SYNTHETIC_TOKEN", None)
                finally:
                    left.close(); right.close()
                execution_mark(row, "termination_unconfirmed" if output.code == "termination_unconfirmed" else "process_completed")
                row.update(run_receipt_sha256=digest(output.receipt), process_status=output.process_status, code=output.code, artifacts={})
                for suffix, raw in (("receipt.json", output.receipt), ("stdout.raw", output.stdout), ("stderr.raw", output.stderr)):
                    row["artifacts"][suffix] = journal.write(mode + "-" + suffix, raw)
                receipt = parse_json(output.receipt)
                execution_mark(row, receipt.get("execution_state", "launch_uncertain"))
                passed = row["execution_state"] == "process_completed" and evaluate_case(mode, output, snapshot, case, context, journal)
                row["outcome"] = "passed" if passed else "failed"
            except ExecutionRefusal as error:
                execution_mark(row, error.execution_state)
                expected = mode == "seventeen" and error.code == "runtime_input_limit" and row["execution_state"] == "not_started"
                row.update(outcome="passed" if expected else "refused", code=error.code)
            except Refusal as error:
                if call_entered and output is None:
                    execution_mark(row, "launch_uncertain")
                row.update(outcome="refused", code=error.code)
            except RetentionError:
                storage_failed = True
                row.update(outcome="error", code="evidence_retention_failed")
            except Exception:
                if call_entered and output is None:
                    execution_mark(row, "launch_uncertain")
                row.update(outcome="error", code="unexpected_fixture_failure")
        if not storage_failed:
            try:
                journal.write(mode + "-outcome.json", canonical(row))
            except RetentionError:
                storage_failed = True
                row.update(outcome="error", code="evidence_retention_failed")
        rows.append(row)
        stopped = stopped or storage_failed or row["outcome"] != "passed"
    return rows, storage_failed


def unrun_cases(document, set_ref, journal, code):
    rows, storage_failed = [], False
    cases = document.get("cases", [])
    for index, mode in enumerate(MODES):
        case = cases[index] if type(cases) is list and index < len(cases) else None
        row = case_binding(document, set_ref, case, mode, index)
        row.update(outcome="unrun", code=code)
        if not storage_failed:
            try:
                journal.write(mode + "-outcome.json", canonical(row))
            except RetentionError:
                storage_failed = True
        rows.append(row)
    return rows, storage_failed


def run(args):
    candidate = str(Path(__file__).absolute().parents[3])
    outer_context = TrustContext((candidate,), ())
    set_ref = TrustedRef(args.execution_set, args.execution_set_sha256)
    document = resolve_document(set_ref, outer_context, "synthetic-execution-set")
    fields(document, ("schema_version", "kind", "state", "workspace", "candidate_root", "policy_ref", "adoption_ref", "harness_ref", "python_ref", "cases"))
    if document["state"] != "ROOT_ADOPTED_EXACT_CASES" or document["candidate_root"] != candidate:
        raise Refusal("missing_authority")
    workspace = Path(document["workspace"])
    context = TrustContext((candidate,), (str(workspace / "inputs"),), (str(workspace / "evidence"),))
    read_ref(set_ref, context)
    journal = EvidenceJournal(workspace, set_ref.sha256)
    attempt_code, storage_failed, receipt_ref = "complete", False, None
    try:
        try:
            journal.write("attempt-intent.json", canonical({"schema_version": "1.0", "kind": "synthetic-validation-intent",
                                                           "execution_set_sha256": set_ref.sha256, "actor": "synthetic-validation-harness",
                                                           "at": datetime.now(timezone.utc).isoformat(), "execution_state": "not_started"}))
            if type(document["cases"]) is not list or len(document["cases"]) != len(MODES):
                raise Refusal("incomplete_fixture_set")
            for case, mode in zip(document["cases"], MODES):
                fields(case, ("mode", "selection_ref", "tool_ref", "release_ref", "authority_ref", "authority_request"))
                if case["mode"] != mode:
                    raise Refusal("incomplete_fixture_set")
            policy = resolve_policy(reference(document["policy_ref"]), reference(document["adoption_ref"]), context)
            rows, storage_failed = execute_cases(document, set_ref, context, policy, journal)
        except Refusal as error:
            attempt_code = error.code
            rows, storage_failed = unrun_cases(document, set_ref, journal, "attempt_refused")
        except RetentionError:
            attempt_code, storage_failed = "evidence_retention_failed", True
            rows = [dict(case_binding(document, set_ref, None, mode, index), outcome="unrun", code="evidence_retention_failed")
                    for index, mode in enumerate(MODES)]
        if attempt_code == "complete" and (storage_failed or any(row["outcome"] != "passed" for row in rows)):
            attempt_code = "cases_incomplete"
        report = {"schema_version": "1.0", "kind": "synthetic-validation-outcomes", "execution_set_sha256": set_ref.sha256,
                  "attempt_code": attempt_code, "cases": rows, "evidence_complete": not storage_failed,
                  "all_passed": not storage_failed and len(rows) == len(MODES) and all(row["outcome"] == "passed" for row in rows),
                  "target_security_acceptance": "NOT_ASSESSED"}
        if not storage_failed:
            try:
                receipt_ref = journal.write("validation-outcomes.json", canonical(report))
            except RetentionError:
                report.update(evidence_complete=False, all_passed=False, attempt_code="evidence_retention_failed")
        summary = {"all_passed": report["all_passed"], "execution_set_sha256": set_ref.sha256,
                   "receipt": receipt_ref, "durable_report": receipt_ref is not None, "target_security_acceptance": "NOT_ASSESSED"}
        if receipt_ref is None:
            summary["unpersisted_outcome"] = report
        print(json.dumps(summary))
        return 0 if report["all_passed"] else 1
    finally:
        journal.close()


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    preparation = modes.add_parser("prepare")
    for name in ("workspace", "policy", "adoption", "harness", "harness-sha256", "python", "python-sha256", "tool", "tool-sha256", "recipe", "recipe-sha256"):
        preparation.add_argument("--" + name, required=True)
    execution = modes.add_parser("run")
    execution.add_argument("--execution-set", required=True)
    execution.add_argument("--execution-set-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "prepare":
            prepare(args)
            return 0
        return run(args)
    except (Refusal, RetentionError) as error:
        set_digest = None
        if args.mode == "run":
            try:
                set_digest = sha(args.execution_set_sha256)
            except Refusal:
                pass
        print(json.dumps({"all_passed": False, "outcome": "refused", "code": error.code if isinstance(error, Refusal) else "evidence_retention_failed",
                          "execution_set_sha256": set_digest, "durable_report": False,
                          "execution_state": "not_started" if args.mode == "prepare" else "launch_uncertain",
                          "reconciliation_required": args.mode == "run", "target_security_acceptance": "NOT_ASSESSED"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
