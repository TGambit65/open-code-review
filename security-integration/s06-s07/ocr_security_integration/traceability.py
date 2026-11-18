# SPDX-License-Identifier: Apache-2.0
"""Account for original obligations without turning locators into coverage."""
from ocr_security.common import Refusal, digest, fields, sha, text
from ocr_security_adapters.data import bounded_json, choice, sequence
from .plan_ids import TASK_IDS, RECOMMENDATION_IDS, TASK_CONTRACTS, RECOMMENDATION_TASKS, PLAN_MANIFEST_SHA256


def _unique_strings(rows, maximum):
    rows = sequence(rows, maximum)
    if any(type(row) is not str for row in rows) or len(rows) != len(set(rows)):
        raise Refusal("invalid_traceability_list")
    for row in rows:
        text(row, 1024)
    return rows


def parse_ledger(raw, expected_sha256):
    if type(raw) is not bytes or len(raw) > 1048576 or digest(raw) != sha(expected_sha256):
        raise Refusal("traceability_identity_mismatch")
    value = bounded_json(raw)
    fields(value, ("schema_version", "kind", "original_contract_manifest_sha256", "qualification", "tasks", "recommendations"))
    if (value["schema_version"], value["kind"], value["qualification"]) != (
        "1.0", "recommendation-execution-traceability", "HELD"):
        raise Refusal("invalid_traceability_document")
    if sha(value["original_contract_manifest_sha256"]) != PLAN_MANIFEST_SHA256:
        raise Refusal("changed_original_contract_manifest")
    task_ids = set()
    for row in sequence(value["tasks"], len(TASK_IDS)):
        fields(row, ("id", "title", "applicability", "condition", "original_dependencies", "disposition",
                     "source_artifacts", "evidence_locations", "qualification", "contract_sha256"))
        identity = choice(row["id"], TASK_IDS)
        if identity in task_ids:
            raise Refusal("duplicate_traceability_task")
        task_ids.add(identity)
        text(row["title"], 512); sha(row["contract_sha256"])
        choice(row["applicability"], ("required", "conditional"))
        if row["condition"] is not None:
            text(row["condition"], 2048)
        dependencies = _unique_strings(row["original_dependencies"], 64)
        if not set(dependencies) <= set(TASK_IDS):
            raise Refusal("unknown_traceability_dependency")
        expected = TASK_CONTRACTS[identity]
        if (row["contract_sha256"] != expected["sha256"] or tuple(dependencies) != expected["dependencies"] or
            row["applicability"] != expected["applicability"] or row["condition"] != expected["condition"]):
            raise Refusal("changed_original_task_contract")
        choice(row["disposition"], ("preserved_provisional_source", "source_authored", "deferred_not_selected",
                                     "qualification_held", "root_batch_gate_pending", "recorded_prior_scope"))
        if row["qualification"] != "not_asserted_by_this_ledger":
            raise Refusal("traceability_is_not_qualification")
        sources = _unique_strings(row["source_artifacts"], 32)
        evidence = _unique_strings(row["evidence_locations"], 32)
        if not sources and not evidence:
            raise Refusal("orphan_traceability_task")
    if task_ids != set(TASK_IDS):
        raise Refusal("missing_original_task")
    seen = set()
    for row in sequence(value["recommendations"], len(RECOMMENDATION_IDS)):
        fields(row, ("id", "recommendation", "required_disposition", "original_plan_mapping", "task_ids",
                     "disposition", "source_artifacts", "evidence_locations", "limitations"))
        identity = choice(row["id"], RECOMMENDATION_IDS)
        if identity in seen:
            raise Refusal("duplicate_recommendation")
        seen.add(identity)
        for key in ("recommendation", "required_disposition", "original_plan_mapping", "disposition"):
            text(row[key], 2048)
        linked = _unique_strings(row["task_ids"], 64)
        if not linked or not set(linked) <= task_ids:
            raise Refusal("unmapped_recommendation")
        if tuple(linked) != RECOMMENDATION_TASKS[identity]:
            raise Refusal("changed_recommendation_mapping")
        for key in ("source_artifacts", "evidence_locations", "limitations"):
            if not _unique_strings(row[key], 32):
                raise Refusal("missing_recommendation_context")
    if seen != set(RECOMMENDATION_IDS):
        raise Refusal("missing_recommendation")
    return value


def summary(raw, expected_sha256):
    value = parse_ledger(raw, expected_sha256)
    return {"task_count": len(value["tasks"]), "recommendation_count": len(value["recommendations"]),
            "ledger_sha256": expected_sha256, "mapping_complete": True, "requirements_satisfied": False,
            "qualification": "HELD", "execution_enabled": False,
            "limit": "Complete mapping is not evidence of complete implementation, execution, coverage or acceptance."}
