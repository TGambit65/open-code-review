# SPDX-License-Identifier: Apache-2.0
"""Independent qualification evidence never implies target clearance."""

from .common import STAGES, Refusal, fields, sha, text, utc
from .policy import resolve_document


def qualify_sprint(subject, policy, context, stage_refs, decision_ref, now):
    """All refs are independently supplied; result stage booleans are ignored."""
    fields(subject, ("repository", "base_commit", "head_commit", "frozen_diff_sha256", "source_manifest_sha256"))
    from .common import canonical, digest, git_id, integer
    fields(subject["repository"], ("name", "id"))
    text(subject["repository"]["name"])
    integer(subject["repository"]["id"], 1)
    git_id(subject["base_commit"])
    git_id(subject["head_commit"])
    sha(subject["frozen_diff_sha256"])
    sha(subject["source_manifest_sha256"])
    stages = {stage: "held" for stage in STAGES}
    subject_digest = digest(canonical(subject))
    if set(stage_refs) != set(STAGES[:-1]):
        raise Refusal("missing_stage_evidence")
    actors = {}
    refs = {}
    for stage, ref in stage_refs.items():
        evidence = resolve_document(ref, context, "sprint-stage-evidence")
        fields(evidence, ("schema_version", "kind", "stage", "subject_sha256", "policy_sha256", "state",
                          "actor", "at", "artifact_sha256", "validation_ids"))
        if evidence["stage"] != stage or evidence["subject_sha256"] != subject_digest or evidence["policy_sha256"] != policy.sha256:
            raise Refusal("stale_stage_evidence")
        text(evidence["actor"])
        sha(evidence["artifact_sha256"])
        if utc(evidence["at"]) > now or evidence["state"] != "complete":
            raise Refusal("incomplete_stage_evidence")
        expected_ids = ["S01.V01", "S01.V02", "S01.V03", "S01.V04"] if stage == "applicable_validation" else []
        if evidence["validation_ids"] != expected_ids:
            raise Refusal("incomplete_validation")
        actors[stage], refs[stage], stages[stage] = evidence["actor"], ref.sha256, "complete"
    if actors["implementation"] == actors["independent_review"]:
        raise Refusal("review_not_independent")
    decision = resolve_document(decision_ref, context, "independent-sprint-decision")
    fields(decision, ("schema_version", "kind", "subject_sha256", "policy_sha256", "stage_refs", "actor", "at", "decision"))
    if decision["subject_sha256"] != subject_digest or decision["policy_sha256"] != policy.sha256 or decision["stage_refs"] != refs:
        raise Refusal("stale_acceptance")
    if decision["actor"] == actors["implementation"] or decision["decision"] != "QUALIFIED_S01" or utc(decision["at"]) > now:
        raise Refusal("acceptance_not_independent")
    text(decision["actor"])
    stages["acceptance"] = "complete"
    return {"schema_version": "1.0", "kind": "sprint-qualification", "subject": subject,
            "policy_sha256": policy.sha256, "stage_refs": refs, "decision_ref_sha256": decision_ref.sha256,
            "stages": stages, "sprint_qualification": "QUALIFIED_S01", "target_security_acceptance": "NOT_ASSESSED"}


def target_security_acceptance(result, policy, context, resolution_refs, exception_refs, now):
    """S01 can report blockers but has no route to target acceptance."""
    blockers = []
    if result.get("process", {}).get("status") != "success" or result.get("completeness") != "complete":
        blockers.append("incomplete_assessment")
    snapshot_id = result.get("identity", {}).get("snapshot_id")
    resolutions, exceptions = {}, {}
    for ref in resolution_refs:
        document = resolve_document(ref, context, "finding-resolution")
        fields(document, ("schema_version", "kind", "finding_id", "snapshot_id", "policy_sha256", "evidence_sha256", "actor", "at", "state"))
        if document["finding_id"] in resolutions or document["snapshot_id"] != snapshot_id or document["policy_sha256"] != policy.sha256:
            raise Refusal("stale_resolution")
        if document["state"] != "resolved" or utc(document["at"]) > now:
            raise Refusal("unresolved_finding")
        sha(document["evidence_sha256"])
        text(document["actor"])
        resolutions[document["finding_id"]] = ref.sha256
    approved = policy.data["acceptance"]["authorized_exceptions"]
    for ref in exception_refs:
        if ref.sha256 not in approved:
            raise Refusal("unapproved_exception")
        document = resolve_document(ref, context, "finding-exception")
        fields(document, ("schema_version", "kind", "finding_id", "snapshot_id", "policy_sha256", "actor", "reason",
                          "issued_at", "expires_at", "scope", "waives_controls"))
        if document["finding_id"] in exceptions or document["snapshot_id"] != snapshot_id or document["policy_sha256"] != policy.sha256:
            raise Refusal("stale_exception")
        if not utc(document["issued_at"]) <= now < utc(document["expires_at"]):
            raise Refusal("expired_exception")
        if document["scope"] != "finding_only" or document["waives_controls"] is not False:
            raise Refusal("control_waiver_forbidden")
        text(document["actor"])
        text(document["reason"], 1024)
        exceptions[document["finding_id"]] = ref.sha256
    for finding in result.get("findings", []):
        if finding["severity"] in ("Critical", "High", "Medium") and finding["id"] not in resolutions and finding["id"] not in exceptions:
            blockers.append("unresolved_required_finding")
    return {"schema_version": "1.0", "kind": "target-security-acceptance", "snapshot_id": snapshot_id,
            "policy_sha256": policy.sha256, "target_security_acceptance": "NOT_ASSESSED",
            "reason": "s01_is_harness_qualification_only", "blockers": sorted(set(blockers)),
            "resolution_refs": resolutions, "exception_refs": exceptions}
