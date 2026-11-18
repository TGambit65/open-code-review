# SPDX-License-Identifier: Apache-2.0
"""Strict private evidence parser. A valid process exit is not a coverage result."""

from .common import (CHANGES, STAGES, STATUSES, Refusal, canonical, fields, git_id,
                     integer, parse_json, ranges, relative_path, sha, text, utc)
from .coverage import assess_coverage

SEVERITIES = frozenset(("Critical", "High", "Medium", "Low", "Info"))
STAGE_STATES = frozenset(("pending", "complete", "failed", "held", "not_assessed"))
IDENTITY_FIELDS = ("repository", "base_commit", "head_commit", "frozen_diff_sha256", "snapshot_id", "policy_sha256",
                   "tool_sha256", "profile_sha256", "rule_pin", "database_pin", "transformation_sha256", "view")


def validate_identity(value):
    fields(value, IDENTITY_FIELDS)
    fields(value["repository"], ("name", "id"))
    text(value["repository"]["name"])
    integer(value["repository"]["id"], 1)
    git_id(value["base_commit"])
    git_id(value["head_commit"])
    for key in ("frozen_diff_sha256", "snapshot_id", "policy_sha256", "tool_sha256", "profile_sha256", "transformation_sha256"):
        sha(value[key])
    for key in ("rule_pin", "database_pin"):
        if value[key] != "not_applicable":
            sha(value[key])
    if value["view"] not in ("scanner", "model"):
        raise Refusal("invalid_view")


def validate_finding(item, snapshot):
    fields(item, ("id", "severity", "confidence", "preconditions", "provenance", "evidence_identity", "resolution_state"))
    text(item["id"], 128)
    if item["severity"] not in SEVERITIES or item["confidence"] not in ("high", "medium", "low", "unknown"):
        raise Refusal("invalid_finding")
    if type(item["preconditions"]) is not list or len(item["preconditions"]) > 32:
        raise Refusal("invalid_finding")
    for condition in item["preconditions"]:
        text(condition, 1024)
    provenance = fields(item["provenance"], ("tool_sha256", "rule_id", "artifact_sha256"))
    sha(provenance["tool_sha256"])
    sha(provenance["artifact_sha256"])
    text(provenance["rule_id"], 128)
    evidence = fields(item["evidence_identity"], ("snapshot_id", "path", "change_kind", "base_blob", "head_blob", "side", "ranges"))
    if sha(evidence["snapshot_id"]) != snapshot.snapshot_id or evidence["change_kind"] not in CHANGES:
        raise Refusal("stale_finding")
    key = (relative_path(evidence["path"]), evidence["change_kind"], git_id(evidence["base_blob"], True),
           git_id(evidence["head_blob"], True), evidence["side"])
    entry = next((entry for entry in snapshot.selected if entry.identity == key), None)
    if entry is None:
        raise Refusal("unbound_finding")
    ranges(evidence["ranges"], entry.lines)
    if item["resolution_state"] not in ("open", "claimed_resolved", "exception_requested"):
        raise Refusal("self_approved_finding")


def parse_result(raw, snapshot, views, expected_pins):
    result = parse_json(raw)
    fields(result, ("schema_version", "kind", "identity", "event", "process", "completeness", "stages", "coverage", "findings"))
    if result["schema_version"] != "1.0" or result["kind"] != "analysis-result":
        raise Refusal("unsupported_result")
    identity = result["identity"]
    validate_identity(identity)
    expected = {"repository": {"name": snapshot.repository_name, "id": snapshot.repository_id},
                "base_commit": snapshot.base_commit, "head_commit": snapshot.head_commit,
                "frozen_diff_sha256": snapshot.frozen_diff_sha256, "snapshot_id": snapshot.snapshot_id,
                "policy_sha256": snapshot.policy_sha256}
    fields(expected_pins, ("tool_sha256", "profile_sha256", "rule_pin", "database_pin", "transformation_sha256", "view"))
    expected.update(expected_pins)
    if identity != expected:
        raise Refusal("stale_result")
    from .common import digest
    transformation = parse_json(views.private_evidence, 8388608)
    if transformation.get("snapshot_id") != snapshot.snapshot_id or transformation.get("model_bundle_id") != views.model.bundle_id:
        raise Refusal("stale_transformation")
    if tuple(views.scanner_inputs) != tuple((entry.opaque_id, entry.content) for entry in snapshot.selected):
        raise Refusal("stale_transformation")
    if identity["transformation_sha256"] != digest(views.private_evidence):
        raise Refusal("stale_transformation")
    event = fields(result["event"], ("at", "actor", "action_id", "artifact_sha256", "artifact_location"))
    utc(event["at"])
    text(event["actor"])
    text(event["action_id"])
    sha(event["artifact_sha256"])
    text(event["artifact_location"], 4096)
    process = fields(result["process"], ("status", "exit_code", "code"))
    if process["status"] not in STATUSES:
        raise Refusal("invalid_process")
    if process["exit_code"] is not None:
        integer(process["exit_code"], -255, 255)
    text(process["code"], 64)
    if process["status"] == "success" and (process["exit_code"] != 0 or process["code"] != "ok"):
        raise Refusal("invalid_success")
    if result["completeness"] not in ("complete", "incomplete", "unknown"):
        raise Refusal("invalid_completeness")
    fields(result["stages"], STAGES)
    if any(state not in STAGE_STATES for state in result["stages"].values()):
        raise Refusal("invalid_stage")
    coverage = assess_coverage(snapshot, result["coverage"])
    model_gaps = identity["view"] == "model" and any(item.gaps for item in views.model.items)
    if result["completeness"] == "complete" and (process["status"] != "success" or not coverage.complete or model_gaps):
        raise Refusal("false_complete")
    if type(result["findings"]) is not list or len(result["findings"]) > 1024:
        raise Refusal("invalid_findings")
    seen = set()
    for finding in result["findings"]:
        validate_finding(finding, snapshot)
        if finding["id"] in seen:
            raise Refusal("duplicate_finding")
        seen.add(finding["id"])
        if finding["provenance"]["tool_sha256"] != identity["tool_sha256"]:
            raise Refusal("unbound_finding")
    return result


def parse_or_error(raw, snapshot, views, expected_pins):
    try:
        return {"process_status": "parsed", "result": parse_result(raw, snapshot, views, expected_pins)}
    except (Refusal, TypeError, KeyError):
        return {"process_status": "parser_error", "completeness": "unknown", "target_security_acceptance": "NOT_ASSESSED"}
