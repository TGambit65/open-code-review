# SPDX-License-Identifier: Apache-2.0
"""Compose supplied evidence through the preserved public/private boundary."""
from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest
from ocr_security_gate.entrypoint import assess as assess_baseline, artifact_receipts as baseline_receipts
from .registry import manifest, MISSING_SECURITY_NOTICE
from .dispositions import Catalog, summary as disposition_summary


@dataclass(frozen=True)
class Assessment:
    """Private decision remains private; public artifact bytes come only from S04."""
    baseline: object
    registration_document: bytes
    disposition_document: bytes
    notice: str


def evaluate_evidence(target, policy, evidence, snapshot, views, current_set, previous_set, now, catalog,
                      excerpt_ranges=(), **evidence_options):
    """No file discovery, native invocation, provider, upload or optional adapter.

    Inputs and independent authority are the preserved S04 contract. This pure
    evaluation does not turn on the integration and does not replace native
    qualification, per-run evidence or the independent acceptance decision.
    """
    if not isinstance(catalog, Catalog):
        raise Refusal("disposition_catalog_required")
    decisions = disposition_summary(catalog)
    baseline = assess_baseline(target, policy, evidence, snapshot, views, current_set,
                               previous_set, now, excerpt_ranges, **evidence_options)
    return Assessment(baseline, canonical(manifest()), canonical(decisions), MISSING_SECURITY_NOTICE)


def status_artifact(assessment):
    if not isinstance(assessment, Assessment):
        raise Refusal("integration_assessment_required")
    value = {"schema_version": "1.0", "kind": "disabled-integration-status", "notice": MISSING_SECURITY_NOTICE,
             "registration_sha256": digest(assessment.registration_document),
             "disposition_summary_sha256": digest(assessment.disposition_document),
             "execution_enabled": False, "sprint_qualification": "HELD", "target_clearance_granted": False,
             "standard_ocr": "unchanged", "security_coverage": "not_established_by_offline_evaluation"}
    return "security-integration-status.json", canonical(value)


def public_artifacts(assessment):
    if not isinstance(assessment, Assessment):
        raise Refusal("integration_assessment_required")
    # Never copy baseline.private_decision into a report or status notice.
    return assessment.baseline.public_artifacts + (status_artifact(assessment),)


def receipts(assessment):
    if not isinstance(assessment, Assessment):
        raise Refusal("integration_assessment_required")
    value = baseline_receipts(assessment.baseline)
    name, raw = status_artifact(assessment)
    return {"kind": "offline-integration-evidence-receipt", "baseline": value,
            "registration_sha256": digest(assessment.registration_document),
            "disposition_summary_sha256": digest(assessment.disposition_document),
            "status_file": {"name": name, "sha256": digest(raw), "bytes": len(raw)},
            "execution_enabled": False, "qualification": "HELD", "target_clearance_granted": False,
            "notice": assessment.notice, "files_written": False, "uploaded": False}
