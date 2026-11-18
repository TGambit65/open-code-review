# SPDX-License-Identifier: Apache-2.0
"""Failure and authority fixtures; no scanner or provider invocation."""

import copy
from datetime import datetime, timezone
import unittest

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).absolute().parent))
import test_snapshot_views as support
from ocr_security.acceptance import qualify_sprint, target_security_acceptance
from ocr_security.common import Refusal, STAGES, canonical, digest
from ocr_security.coverage import assess_coverage
from ocr_security.policy import TrustedRef, execution_authority, resolve_policy
from ocr_security.results import parse_or_error, parse_result


class ResultsPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.Fixture()
        self.addCleanup(self.fixture.close)
        self.snapshot = self.fixture.snapshot()
        self.views = self.fixture.views(self.snapshot)
        self.result, self.pins = self.fixture.result(self.snapshot, self.views)
        self.now = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)

    def test_valid_process_is_not_target_acceptance(self):
        result = parse_result(canonical(self.result), self.snapshot, self.views, self.pins)
        decision = target_security_acceptance(result, self.fixture.policy, self.fixture.context, [], [], self.now)
        self.assertEqual(decision["target_security_acceptance"], "NOT_ASSESSED")
        self.assertEqual(result["stages"]["acceptance"], "pending")

    def test_malformed_partial_stale_unknown_and_exit_zero_errors(self):
        self.assertEqual(parse_or_error(b"not json", self.snapshot, self.views, self.pins)["process_status"], "parser_error")
        for status in ("unknown", "timeout", "partial", "skipped", "stale", "parser_error", "error", "unsupported"):
            value = copy.deepcopy(self.result); value["process"]["status"] = status
            with self.subTest(status=status), self.assertRaises(Refusal):
                parse_result(canonical(value), self.snapshot, self.views, self.pins)
        mutations = [lambda x: x["coverage"].pop(), lambda x: x["coverage"][0].update(truncated=True),
                     lambda x: x["coverage"][0].update(analyzed_ranges=[[1, 1]]),
                     lambda x: x["coverage"][0].update(snapshot_id="0" * 64),
                     lambda x: x["identity"].update(snapshot_id="0" * 64),
                     lambda x: x["process"].update(code="parser_error"),
                     lambda x: x["coverage"].append(copy.deepcopy(x["coverage"][0])),
                     lambda x: x.update(untrusted_extra=True)]
        for index, mutate in enumerate(mutations):
            value = copy.deepcopy(self.result); mutate(value)
            with self.subTest(index=index), self.assertRaises(Refusal):
                parse_result(canonical(value), self.snapshot, self.views, self.pins)

    def test_all_coverage_rows_obey_schema_before_identity_matching(self):
        mutations = ({"change_kind": "invented"}, {"side": "invented"}, {"original_sha256": None},
                     {"original_sha256": "bad"}, {"snapshot_id": None}, {"analyzed_ranges": "all"},
                     {"analyzed_ranges": [["1", 2]]}, {"analyzed_ranges": [[2, 1]]},
                     {"analyzed_ranges": [[1, 2], [2, 3]]}, {"truncated": "false"},
                     {"truncated": 0}, {"omissions": None}, {"omissions": [42]})
        entries = copy.deepcopy(self.fixture.entries[:2]); entries[1]["selected"] = False
        excluded_snapshot = self.fixture.snapshot(entries)
        excluded_views = self.fixture.views(excluded_snapshot)
        excluded_result, excluded_pins = self.fixture.result(excluded_snapshot, excluded_views)
        for variant in ("unexpected", "excluded"):
            snapshot, views, pins, base = ((self.snapshot, self.views, self.pins, self.result) if variant == "unexpected"
                                           else (excluded_snapshot, excluded_views, excluded_pins, excluded_result))
            for mutation in mutations:
                value = copy.deepcopy(base); value["completeness"] = "incomplete"
                row = copy.deepcopy(self.result["coverage"][1])
                row["snapshot_id"] = snapshot.snapshot_id
                if variant == "unexpected":
                    row["path"] = "unknown.c"
                row.update(mutation); value["coverage"].append(row)
                with self.subTest(variant=variant, mutation=mutation):
                    outcome = parse_or_error(canonical(value), snapshot, views, pins)
                    self.assertEqual(outcome["process_status"], "parser_error")
                    self.assertEqual(outcome["completeness"], "unknown")
            value = copy.deepcopy(base); value["completeness"] = "incomplete"
            row = copy.deepcopy(self.result["coverage"][1]); row["snapshot_id"] = snapshot.snapshot_id
            if variant == "unexpected": row["path"] = "unknown.c"
            value["coverage"].append(row)
            self.assertEqual(parse_or_error(canonical(value), snapshot, views, pins)["process_status"], "parsed")
            coverage = assess_coverage(snapshot, value["coverage"])
            self.assertFalse(coverage.complete)
            self.assertIn("unexpected_identity" if variant == "unexpected" else "excluded", [gap[1] for gap in coverage.gaps])

    def test_utc_extreme_offsets_produce_parser_error(self):
        from ocr_security.common import utc
        for at in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            value = copy.deepcopy(self.result); value["event"]["at"] = at
            with self.subTest(at=at):
                self.assertEqual(parse_or_error(canonical(value), self.snapshot, self.views, self.pins)["process_status"], "parser_error")
                with self.assertRaises(Refusal) as refused: utc(at)
                self.assertEqual(refused.exception.code, "invalid_time")

    def test_cpu_verdict_requires_specific_cause_and_timing(self):
        from test_isolation import cpu_limit_passed
        from ocr_security.isolation import RunOutput
        def output(status="error", code="process_failed", exit_code=137, elapsed_ms=2200, state="process_completed"):
            return RunOutput(status, code, b"CPU_STARTED\n", b"", canonical({"process_status": status, "code": code,
                             "exit_code": exit_code, "elapsed_ms": elapsed_ms, "execution_state": state}))
        self.assertTrue(cpu_limit_passed(output()))
        self.assertFalse(cpu_limit_passed(output("timeout", "wall_limit", -9, 5000)))
        for exit_code in (-9, 0, 125, 139):
            self.assertFalse(cpu_limit_passed(output(exit_code=exit_code)))
        for elapsed in (-1, 0, 1499, 5000, True):
            self.assertFalse(cpu_limit_passed(output(elapsed_ms=elapsed)))
        self.assertFalse(cpu_limit_passed(output(state="termination_unconfirmed")))

    def test_maximum_input_verdict_rejects_missing_truncated_or_wrong_bytes(self):
        from test_isolation import containment_passed, expected_recording
        from ocr_security.isolation import RunOutput
        entries = copy.deepcopy(self.fixture.entries)
        for index in range(8):
            item = copy.deepcopy(self.fixture.entries[index]); item["path"] = "maximum-%d.c" % index
            entries.append(item)
        snapshot = self.fixture.snapshot(entries)
        expected = expected_recording(snapshot) + b"CONTAINMENT_OK\n"
        def output(raw): return RunOutput("success", "unparsed_output", raw, b"", b"{}")
        self.assertTrue(containment_passed(output(expected), snapshot))
        missing = b"".join(b"INPUT\n" + entry.content for entry in snapshot.selected[:-1]) + b"CONTAINMENT_OK\n"
        for raw in (b"CONTAINMENT_OK\n", missing, expected[:-1], expected.replace(b"safe_primary", b"wrong_source", 1)):
            self.assertFalse(containment_passed(output(raw), snapshot))
        self.assertFalse(containment_passed(output(expected), self.snapshot))

    def test_model_redaction_cannot_be_full_coverage(self):
        value = copy.deepcopy(self.result); value["identity"]["view"] = "model"
        pins = dict(self.pins, view="model")
        with self.assertRaises(Refusal): parse_result(canonical(value), self.snapshot, self.views, pins)

    def test_duplicate_path_changes_remain_distinct(self):
        entries = copy.deepcopy(self.fixture.entries[:2])
        entries[0].update(path="same.c", change_kind="staged_deleted", side="base", head_blob=None, base_blob="1" * 40)
        entries[1].update(path="same.c", change_kind="untracked", side="head", base_blob=None, head_blob="2" * 40)
        snapshot = self.fixture.snapshot(entries)
        records = self.fixture.coverage(snapshot)
        self.assertTrue(assess_coverage(snapshot, records).complete)
        self.assertFalse(assess_coverage(snapshot, records[:1]).complete)
        self.assertNotEqual(snapshot.entries[0].identity, snapshot.entries[1].identity)

    def test_exclusion_stays_gap(self):
        entries = copy.deepcopy(self.fixture.entries[:2]); entries[1]["selected"] = False
        snapshot = self.fixture.snapshot(entries)
        self.assertFalse(assess_coverage(snapshot, self.fixture.coverage(snapshot)).complete)

    def test_candidate_and_missing_policy_refuse(self):
        candidate_path = self.fixture.inputs / "policy.json"
        candidate_path.write_bytes(self.fixture.policy.raw)
        with self.assertRaises(Refusal):
            resolve_policy(TrustedRef(str(candidate_path), self.fixture.policy.sha256), self.fixture.adoption_ref, self.fixture.context)
        with self.assertRaises(Refusal):
            resolve_policy(TrustedRef(str(self.fixture.authority / "missing"), self.fixture.policy.sha256), self.fixture.adoption_ref, self.fixture.context)
        with self.assertRaises(Refusal):
            resolve_policy(TrustedRef(self.fixture.policy_ref.path, "0" * 64), self.fixture.adoption_ref, self.fixture.context)

    def test_expired_action_and_unapproved_exception_refuse(self):
        expected = {"policy_sha256": self.fixture.policy.sha256, "purpose": "synthetic_fixture"}
        ref = self.fixture.write_ref({"schema_version": "1.0", "kind": "synthetic-execution-authority", "authorized_actor": "synthetic-root",
                                      "issued_at": "2026-10-31T00:00:00Z", "expires_at": "2026-11-01T00:00:00Z",
                                      "action_id": "expired", "bindings": expected})
        with self.assertRaises(Refusal): execution_authority(ref, self.fixture.context, self.fixture.policy, expected, self.now)
        with self.assertRaises(Refusal):
            target_security_acceptance(self.result, self.fixture.policy, self.fixture.context, [], [ref], self.now)

    def test_required_findings_need_external_evidence(self):
        for severity in ("Critical", "High", "Medium"):
            value = copy.deepcopy(self.result)
            value["findings"] = [{"id": "synthetic-finding", "severity": severity, "resolution_state": "claimed_resolved"}]
            result = target_security_acceptance(value, self.fixture.policy, self.fixture.context, [], [], self.now)
            self.assertIn("unresolved_required_finding", result["blockers"])
            self.assertEqual(result["target_security_acceptance"], "NOT_ASSESSED")

    def test_independent_qualification_requires_all_current_stage_refs(self):
        subject = {"repository": {"name": "synthetic/fixture", "id": 123}, "base_commit": "1" * 40,
                   "head_commit": "2" * 40, "frozen_diff_sha256": "3" * 64, "source_manifest_sha256": "4" * 64}
        refs = {}
        for stage in STAGES[:-1]:
            refs[stage] = self.fixture.write_ref({"schema_version": "1.0", "kind": "sprint-stage-evidence", "stage": stage,
                                                 "subject_sha256": digest(canonical(subject)), "policy_sha256": self.fixture.policy.sha256,
                                                 "state": "complete", "actor": "writer" if stage == "implementation" else "independent-" + stage,
                                                 "at": "2026-11-01T00:00:00Z", "artifact_sha256": "5" * 64,
                                                 "validation_ids": ["S01.V01", "S01.V02", "S01.V03", "S01.V04"] if stage == "applicable_validation" else []})
        decision = self.fixture.write_ref({"schema_version": "1.0", "kind": "independent-sprint-decision",
                                           "subject_sha256": digest(canonical(subject)), "policy_sha256": self.fixture.policy.sha256,
                                           "stage_refs": {stage: ref.sha256 for stage, ref in refs.items()}, "actor": "independent-reviewer",
                                           "at": "2026-11-01T00:00:00Z", "decision": "QUALIFIED_S01"})
        qualified = qualify_sprint(subject, self.fixture.policy, self.fixture.context, refs, decision, self.now)
        self.assertEqual(qualified["sprint_qualification"], "QUALIFIED_S01")
        self.assertEqual(qualified["target_security_acceptance"], "NOT_ASSESSED")
        incomplete = dict(refs); incomplete.pop("applicable_validation")
        with self.assertRaises(Refusal): qualify_sprint(subject, self.fixture.policy, self.fixture.context, incomplete, decision, self.now)


class HarnessEvidenceTests(unittest.TestCase):
    """Bookkeeping simulations only; run_fixture is always mocked, never launched."""

    def setUp(self):
        import test_isolation as harness
        self.harness = harness
        self.fixture = support.Fixture()
        self.addCleanup(self.fixture.close)
        self.snapshot = self.fixture.snapshot()
        self.selection_ref = self.fixture.selection()
        self.unit_ref = self.fixture.write_ref({"kind": "unit-only-never-executable", "schema_version": "1.0"})

    def document(self):
        ref = self.harness.ref_data
        return {"schema_version": "1.0", "kind": "synthetic-execution-set", "state": "ROOT_ADOPTED_EXACT_CASES",
                "workspace": str(self.fixture.root), "candidate_root": self.fixture.candidate,
                "policy_ref": ref(self.fixture.policy_ref), "adoption_ref": ref(self.fixture.adoption_ref),
                "harness_ref": ref(self.unit_ref), "python_ref": ref(self.unit_ref),
                "cases": [{"mode": mode, "selection_ref": ref(self.selection_ref), "tool_ref": ref(self.unit_ref),
                           "release_ref": ref(self.unit_ref), "authority_ref": ref(self.unit_ref),
                           "authority_request": {"unit_only": True}} for mode in self.harness.MODES]}

    def invoke(self, document, runner, evaluation=True):
        from contextlib import redirect_stdout
        import io
        from types import SimpleNamespace
        from unittest.mock import patch
        set_ref = self.fixture.write_ref(document, "unit-execution-set")
        args = SimpleNamespace(execution_set=set_ref.path, execution_set_sha256=set_ref.sha256)
        stream = io.StringIO()
        with patch.object(self.harness, "run_fixture", side_effect=runner) as native:
            with redirect_stdout(stream):
                if evaluation:
                    with patch.object(self.harness, "evaluate_case", return_value=True):
                        status = self.harness.run(args)
                else:
                    status = self.harness.run(args)
        import json
        summary = json.loads(stream.getvalue())
        directory = self.fixture.output / ("attempt-" + set_ref.sha256)
        report = json.loads((directory / "validation-outcomes.json").read_bytes()) if summary["durable_report"] else summary["unpersisted_outcome"]
        return status, report, directory, native.call_count, args, summary

    def completed(self, snapshot, *args, launch_observer=None, **kwargs):
        from ocr_security.isolation import RunOutput
        if launch_observer is not None:
            launch_observer({"unit_only": True, "snapshot_id": snapshot.snapshot_id})
        return RunOutput("success", "unparsed_output", self.harness.expected_recording(snapshot), b"", canonical({
                         "execution_state": "process_completed", "process_status": "success", "code": "unparsed_output", "exit_code": 0}))

    def test_later_expiry_retains_previous_raw_refusal_and_all_unrun_cases(self):
        from ocr_security.isolation import ExecutionRefusal
        attempts = []
        def runner(snapshot, *args, **kwargs):
            index = len(attempts); attempts.append(index)
            if index == 4: raise ExecutionRefusal("expired_authority", "not_started")
            return self.completed(snapshot, *args, **kwargs)
        status, report, directory, calls, _, _ = self.invoke(self.document(), runner)
        self.assertEqual(status, 1); self.assertEqual(calls, 5)
        self.assertEqual([row["outcome"] for row in report["cases"]], ["passed"] * 4 + ["refused"] + ["unrun"] * 3)
        refused = report["cases"][4]
        self.assertEqual(refused["code"], "expired_authority"); self.assertIs(refused["executed"], False)
        self.assertEqual(refused["snapshot_id"], self.snapshot.snapshot_id)
        self.assertFalse((directory / "cpu-launch-intent.json").exists())
        for mode in self.harness.MODES:
            self.assertTrue((directory / (mode + "-outcome.json")).exists())
        for mode in self.harness.MODES[:4]:
            self.assertTrue((directory / (mode + "-receipt.json")).exists())
            self.assertTrue((directory / (mode + "-stdout.raw")).exists())
        self.assertFalse(report["all_passed"])

    def test_missing_authority_and_bad_snapshot_are_known_nonexecution(self):
        document = self.document(); document["cases"][0]["authority_ref"] = None
        status, report, _, calls, _, _ = self.invoke(document, self.completed)
        self.assertEqual(calls, 0); self.assertEqual(status, 1)
        self.assertEqual(report["cases"][0]["code"], "missing_authority")
        self.assertIs(report["cases"][0]["executed"], False)
        document = self.document(); document["cases"][0]["selection_ref"] = {"path": self.selection_ref.path, "sha256": "0" * 64}
        _, report, _, calls, _, _ = self.invoke(document, self.completed)
        self.assertEqual(calls, 0); self.assertEqual(report["cases"][0]["outcome"], "refused")
        self.assertIs(report["cases"][0]["executed"], False)
        self.assertEqual([row["outcome"] for row in report["cases"]][1:], ["unrun"] * 7)

    def test_post_run_release_refusal_retains_raw_first(self):
        stale = self.fixture.write_ref({"schema_version": "1.0", "kind": "approved-line-release", "snapshot_id": "0" * 64, "entries": []})
        document = self.document(); document["cases"][0]["release_ref"] = self.harness.ref_data(stale)
        _, report, directory, calls, _, summary = self.invoke(document, self.completed, evaluation=False)
        self.assertEqual(calls, 1)
        row = report["cases"][0]
        self.assertEqual(row["outcome"], "refused"); self.assertEqual(row["code"], "stale_release")
        self.assertIs(row["executed"], True)
        self.assertNotIn("reconciliation_required", row)
        self.assertEqual((directory / "record-stdout.raw").read_bytes(), self.harness.expected_recording(self.snapshot))
        self.assertTrue((directory / "record-receipt.json").exists())
        self.assertEqual([item["outcome"] for item in report["cases"]][1:], ["unrun"] * 7)
        self.assertNotIn("SYNTHETIC_SECRET", str(summary))

    def test_unknown_launch_is_not_reported_as_known_nonexecution(self):
        def runner(snapshot, *args, launch_observer=None, **kwargs):
            launch_observer({"unit_only": True, "snapshot_id": snapshot.snapshot_id})
            raise Refusal("isolation_unavailable")
        _, report, directory, calls, _, _ = self.invoke(self.document(), runner)
        row = report["cases"][0]
        self.assertEqual(calls, 1); self.assertIsNone(row["executed"])
        self.assertEqual(row["execution_state"], "launch_uncertain")
        self.assertTrue(row["reconciliation_required"])
        self.assertTrue((directory / "record-launch-intent.json").exists())
        self.assertEqual([item["outcome"] for item in report["cases"]][1:], ["unrun"] * 7)

    def test_duplicate_attempt_never_overwrites_or_runs_again(self):
        from unittest.mock import patch
        document = self.document(); document["cases"][0]["authority_ref"] = None
        _, _, directory, _, args, _ = self.invoke(document, self.completed)
        before = (directory / "validation-outcomes.json").read_bytes()
        with patch.object(self.harness, "run_fixture") as native:
            with self.assertRaises(Refusal) as refused: self.harness.run(args)
            self.assertEqual(refused.exception.code, "attempt_already_recorded")
            native.assert_not_called()
        self.assertEqual(before, (directory / "validation-outcomes.json").read_bytes())

    def test_retention_failure_stops_before_execution_and_is_not_durable_success(self):
        from unittest.mock import patch
        original = self.harness.EvidenceJournal.write
        def fail_intent(journal, name, raw):
            if name == "record-intent.json": raise self.harness.RetentionError()
            return original(journal, name, raw)
        with patch.object(self.harness.EvidenceJournal, "write", new=fail_intent):
            status, report, _, calls, _, summary = self.invoke(self.document(), self.completed)
        self.assertEqual(status, 1); self.assertEqual(calls, 0)
        self.assertFalse(summary["durable_report"]); self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["cases"][0]["code"], "evidence_retention_failed")
        self.assertEqual([item["outcome"] for item in report["cases"]][1:], ["unrun"] * 7)

    def test_raw_retention_failure_keeps_completed_state_and_stops(self):
        from unittest.mock import patch
        original = self.harness.EvidenceJournal.write
        def fail_stdout(journal, name, raw):
            if name == "record-stdout.raw": raise self.harness.RetentionError()
            return original(journal, name, raw)
        with patch.object(self.harness.EvidenceJournal, "write", new=fail_stdout):
            _, report, directory, calls, _, summary = self.invoke(self.document(), self.completed)
        self.assertEqual(calls, 1); self.assertFalse(summary["durable_report"])
        self.assertIs(report["cases"][0]["executed"], True)
        self.assertEqual(report["cases"][0]["code"], "evidence_retention_failed")
        self.assertTrue((directory / "record-receipt.json").exists())
        self.assertEqual([row["outcome"] for row in report["cases"]][1:], ["unrun"] * 7)

    def test_unconfirmed_return_is_never_a_completed_verdict(self):
        from ocr_security.isolation import RunOutput
        def runner(snapshot, *args, launch_observer=None, **kwargs):
            launch_observer({"unit_only": True, "snapshot_id": snapshot.snapshot_id})
            return RunOutput("error", "termination_unconfirmed", b"", b"", canonical({
                             "execution_state": "termination_unconfirmed", "process_status": "error", "code": "termination_unconfirmed"}))
        _, report, directory, calls, _, _ = self.invoke(self.document(), runner)
        self.assertEqual(calls, 1)
        self.assertEqual(report["cases"][0]["outcome"], "failed")
        self.assertIsNone(report["cases"][0]["executed"])
        self.assertTrue(report["cases"][0]["reconciliation_required"])
        self.assertTrue((directory / "record-receipt.json").exists())
        self.assertEqual([row["outcome"] for row in report["cases"]][1:], ["unrun"] * 7)

    def test_interrupted_launch_intent_survives_without_a_false_completion(self):
        from contextlib import redirect_stdout
        import io
        from types import SimpleNamespace
        from unittest.mock import patch
        document = self.document(); set_ref = self.fixture.write_ref(document, "interrupted-set")
        args = SimpleNamespace(execution_set=set_ref.path, execution_set_sha256=set_ref.sha256)
        def interrupt(snapshot, *unused, launch_observer=None, **kwargs):
            launch_observer({"unit_only": True, "snapshot_id": snapshot.snapshot_id})
            raise KeyboardInterrupt()
        with patch.object(self.harness, "run_fixture", side_effect=interrupt) as native:
            with redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt): self.harness.run(args)
            self.assertEqual(native.call_count, 1)
        directory = self.fixture.output / ("attempt-" + set_ref.sha256)
        self.assertTrue((directory / "record-launch-intent.json").exists())
        self.assertFalse((directory / "validation-outcomes.json").exists())
        self.assertFalse((directory / "containment-intent.json").exists())


if __name__ == "__main__":
    support.configure()
    unittest.main()
