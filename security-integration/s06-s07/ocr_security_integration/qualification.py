# SPDX-License-Identifier: Apache-2.0
"""Current independent receipt accounting, explicitly short of native acceptance."""
from ocr_security.common import Refusal, canonical, digest, fields, sha, text, utc
from ocr_security_gate.contracts import pinned, timestamp
from ocr_security_adapters.data import choice

STEPS = ("implementation", "independent_source_review", "remote_preservation", "offline_fixtures",
         "native_baseline", "sanitized_review", "rendering", "independent_evidence_review")


def inventory(refs, context, source_sha256, scope_sha256, now):
    """Read only host-supplied independent references; no candidate paths are chosen.

    Even a complete receipt inventory cannot enable the unimplemented native
    entry point. Authenticity and independence remain host-custody prerequisites.
    Raw locations and actor identities are withheld from this status result.
    """
    sha(source_sha256); sha(scope_sha256); now = timestamp(now)
    if type(refs) is not tuple or len(refs) > len(STEPS):
        raise Refusal("invalid_qualification_refs")
    receipts = {}
    for ref in refs:
        row, pin = pinned(ref, context, "independent-integration-stage-receipt")
        fields(row, ("schema_version", "kind", "source_sha256", "scope_sha256", "stage", "result", "actor",
                     "independence_receipt_sha256", "artifact_sha256", "artifact_location", "issued_at", "expires_at",
                     "authority_receipt_sha256", "actual_action", "input_receipts"))
        stage = choice(row["stage"], STEPS)
        if stage in receipts or row["source_sha256"] != source_sha256 or row["scope_sha256"] != scope_sha256:
            raise Refusal("stale_or_duplicate_integration_receipt")
        if not utc(row["issued_at"]) <= now < utc(row["expires_at"]):
            raise Refusal("expired_integration_receipt")
        if (now - utc(row["issued_at"])).total_seconds() > 7 * 86400:
            raise Refusal("stale_integration_receipt")
        for key in ("actor", "artifact_location", "actual_action"):
            text(row[key], 1024)
        for key in ("independence_receipt_sha256", "artifact_sha256", "authority_receipt_sha256"):
            sha(row[key])
        result = choice(row["result"], ("passed", "failed", "blocked", "partial", "unrun"))
        inputs = row["input_receipts"]
        if type(inputs) is not dict or not set(inputs) <= set(STEPS) - {stage}:
            raise Refusal("invalid_stage_input_receipts")
        for identity in inputs.values():
            sha(identity)
        receipts[stage] = {"result": result, "receipt_sha256": pin,
                           "artifact_sha256": row["artifact_sha256"], "issued_at": row["issued_at"],
                           "input_receipts": inputs}
    dependencies = {"implementation": (), "independent_source_review": ("implementation",),
                    "remote_preservation": ("implementation",), "offline_fixtures": ("remote_preservation",),
                    "native_baseline": ("remote_preservation",), "sanitized_review": ("remote_preservation",),
                    "rendering": ("remote_preservation",), "independent_evidence_review": STEPS[:-1]}
    for stage, row in receipts.items():
        if row["result"] != "passed":
            continue
        required = dependencies[stage]
        if any(key not in receipts or receipts[key]["result"] != "passed" for key in required):
            raise Refusal("incomplete_stage_prerequisites")
        if not set(required) <= set(row["input_receipts"]):
            raise Refusal("missing_stage_input_receipts")
        for key, identity in row["input_receipts"].items():
            prior = receipts.get(key)
            if prior is None or prior["receipt_sha256"] != identity or utc(prior["issued_at"]) > utc(row["issued_at"]):
                raise Refusal("stale_stage_input_receipt")
        if stage == "independent_evidence_review" and set(row["input_receipts"]) != set(required):
            raise Refusal("incomplete_final_review_scope")
    stages = {stage: receipts.get(stage, {"result": "unrun", "receipt_sha256": None,
                                        "artifact_sha256": None, "issued_at": None, "input_receipts": {}}) for stage in STEPS}
    blockers = ["missing_or_incomplete_" + stage for stage in STEPS if stages[stage]["result"] != "passed"]
    blockers.append("qualified_native_entrypoint_not_implemented")
    value = {"schema_version": "1.0", "kind": "integration-qualification-inventory",
             "source_sha256": source_sha256, "scope_sha256": scope_sha256, "stages": stages,
             "blockers": blockers, "sprint_qualification": "HELD", "target_clearance_granted": False,
             "execution_enabled": False, "code_rabbit_gate": "separate_root_batch_requirement",
             "at": now.isoformat()}
    return dict(value, inventory_sha256=digest(canonical(value)))
