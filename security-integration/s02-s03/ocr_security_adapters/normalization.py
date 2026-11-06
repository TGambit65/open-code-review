# SPDX-License-Identifier: Apache-2.0
"""Private S01-schema normalization. Raw native strings never become findings.

Execution evidence and independent coverage are explicit inputs, not inferred
from an empty report. This module cannot grant target acceptance.
"""

from ocr_security.common import Refusal, canonical, digest, fields, integer, sha, text, utc
from ocr_security.coverage import assess_coverage
from ocr_security.policy import TrustedRef, read_ref
from ocr_security.results import parse_result
from .data import bounded_json, choice, sequence
from .inputs import coverage_record, input_manifest


def execution_evidence(value, raw, inventory, snapshot, policy, expected_plan_sha256):
    fields(value, ("at", "actor", "action_id", "artifact_location", "report_sha256", "stderr_sha256",
                   "exit_code", "process_status", "profile_sha256", "tool_sha256", "snapshot_id", "policy_sha256",
                   "native_execution_receipt_sha256", "adapter_policy_sha256", "plan_sha256"))
    if sha(value["plan_sha256"]) != sha(expected_plan_sha256):
        raise Refusal("stale_execution_plan")
    utc(value["at"])
    for key in ("actor", "action_id", "artifact_location"):
        text(value[key], 4096 if key == "artifact_location" else 256)
    for key in ("report_sha256", "stderr_sha256", "profile_sha256", "tool_sha256", "snapshot_id", "policy_sha256", "adapter_policy_sha256", "native_execution_receipt_sha256"):
        sha(value[key])
    if value["report_sha256"] != digest(raw) or value["tool_sha256"] != inventory.one("binary").sha256 or value["snapshot_id"] != snapshot.snapshot_id or value["policy_sha256"] != snapshot.policy_sha256 or value["adapter_policy_sha256"] != policy.sha256:
        raise Refusal("stale_execution_evidence")
    integer(value["exit_code"], -255, 255)
    choice(value["process_status"], ("success", "error", "timeout", "partial", "unknown"))
    if value["process_status"] == "success" and value["exit_code"] != 0:
        raise Refusal("invalid_process_success")
    return value


def coverage_attestation(ref, context, evidence, inventory, snapshot, mapped_inputs):
    """Only an externally pinned per-run coverage receipt may supplement native gaps."""
    if ref is None:
        return frozenset()
    if not isinstance(ref, TrustedRef):
        raise Refusal("missing_external_coverage")
    value = bounded_json(read_ref(ref, context))
    fields(value, ("schema_version", "kind", "snapshot_id", "tool_sha256", "policy_sha256", "profile_sha256",
                   "report_sha256", "input_manifest_sha256", "native_execution_receipt_sha256", "qualified_harness_sha256",
                   "complete_ids", "all_rules_accounted", "no_silent_skips", "adapter_policy_sha256", "plan_sha256"))
    if value["schema_version"] != "1.0" or value["kind"] != "independent-adapter-coverage":
        raise Refusal("invalid_coverage_attestation")
    for key in ("snapshot_id", "tool_sha256", "policy_sha256", "profile_sha256", "report_sha256", "native_execution_receipt_sha256", "adapter_policy_sha256", "plan_sha256"):
        if sha(value[key]) != evidence[key]:
            raise Refusal("stale_coverage_attestation")
    if value["input_manifest_sha256"] != input_manifest(snapshot)[1]:
        raise Refusal("stale_coverage_attestation")
    sha(value["qualified_harness_sha256"])
    if value["all_rules_accounted"] is not True or value["no_silent_skips"] is not True:
        return frozenset()
    complete = sequence(value["complete_ids"], 256)
    known = {item.opaque_id for item in mapped_inputs}
    if any(type(x) is not str or x not in known for x in complete) or len(set(complete)) != len(complete):
        raise Refusal("invalid_coverage_attestation")
    return frozenset(complete)


def finding(adapter, item, snapshot, inventory, raw, rule_id, severity, start=None, end=None, ordinal=0):
    """The caller supplies only allowlisted/fixed identifiers, never raw report text."""
    text(rule_id, 128)
    integer(ordinal, 0, 1048576)
    choice(severity, ("Critical", "High", "Medium", "Low", "Info"))
    positions = []
    if start is not None or end is not None:
        integer(start, 1, item.lines)
        integer(end, start, item.lines)
        positions = [[start, end]]
    path, change, base_blob, head_blob, side = item.identity
    record = {"id": adapter + ":" + digest(canonical([item.opaque_id, rule_id, positions, ordinal]))[:32],
              "severity": severity, "confidence": "unknown",
              "preconditions": ["Detector match requires independent source-to-sink and reachability review."],
              "provenance": {"tool_sha256": inventory.one("binary").sha256, "rule_id": rule_id, "artifact_sha256": digest(raw)},
              "evidence_identity": {"snapshot_id": snapshot.snapshot_id, "path": path, "change_kind": change,
                                    "base_blob": base_blob, "head_blob": head_blob, "side": side, "ranges": positions},
              "resolution_state": "open"}
    return record


def result(adapter, raw, snapshot, views, policy, inventory, evidence, inputs, findings, complete_ids, gaps, rule_pin, database_pin, expected_plan_sha256):
    """Preserve native exit status, including expected nonzero finding exits."""
    if inventory.adapter != adapter:
        raise Refusal("wrong_adapter_inventory")
    execution_evidence(evidence, raw, inventory, snapshot, policy, expected_plan_sha256)
    if snapshot.policy_sha256 != policy.snapshot_policy_sha256:
        raise Refusal("snapshot_policy_mismatch")
    process_status = evidence["process_status"]
    code = "ok" if process_status == "success" and evidence["exit_code"] == 0 else "native_nonzero_or_incomplete"
    if gaps and process_status == "success":
        process_status, code = "partial", "native_coverage_gaps"
    coverage = []
    for item in inputs:
        complete = item.opaque_id in complete_ids and not gaps and process_status == "success"
        coverage.append(coverage_record(snapshot, item, complete, () if complete else ("not_independently_covered",)))
    assessment = assess_coverage(snapshot, coverage)
    identity = {"repository": {"name": snapshot.repository_name, "id": snapshot.repository_id},
                "base_commit": snapshot.base_commit, "head_commit": snapshot.head_commit,
                "frozen_diff_sha256": snapshot.frozen_diff_sha256, "snapshot_id": snapshot.snapshot_id,
                "policy_sha256": snapshot.policy_sha256, "tool_sha256": inventory.one("binary").sha256,
                "profile_sha256": evidence["profile_sha256"], "rule_pin": rule_pin, "database_pin": database_pin,
                "transformation_sha256": digest(views.private_evidence), "view": "scanner"}
    document = {"schema_version": "1.0", "kind": "analysis-result", "identity": identity,
                "event": {"at": evidence["at"], "actor": evidence["actor"], "action_id": evidence["action_id"],
                          "artifact_sha256": digest(raw), "artifact_location": evidence["artifact_location"]},
                "process": {"status": process_status, "exit_code": evidence["exit_code"], "code": code},
                "completeness": "complete" if assessment.complete and process_status == "success" else "incomplete",
                "stages": {"implementation": "pending", "independent_review": "pending", "remote_preservation": "pending",
                           "applicable_validation": "pending", "acceptance": "held"},
                "coverage": coverage, "findings": findings}
    pins = {key: identity[key] for key in ("tool_sha256", "profile_sha256", "rule_pin", "database_pin", "transformation_sha256", "view")}
    parsed = parse_result(canonical(document), snapshot, views, pins)
    return {"adapter": adapter, "process_status": process_status, "completeness": parsed["completeness"],
            "result": parsed, "gaps": list(gaps), "raw_report_forwarded": False,
            "native_execution_receipt_sha256": evidence["native_execution_receipt_sha256"],
            "plan_sha256": evidence["plan_sha256"],
            "adapter_policy_sha256": policy.sha256,
            "target_security_acceptance": "NOT_ASSESSED"}


def parser_failure(adapter):
    return {"adapter": adapter, "process_status": "parser_error", "completeness": "unknown",
            "code": "untrusted_output_rejected", "raw_report_forwarded": False,
            "target_security_acceptance": "NOT_ASSESSED"}
