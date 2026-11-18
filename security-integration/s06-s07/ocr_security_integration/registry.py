# SPDX-License-Identifier: Apache-2.0
"""Describe only actual source interfaces; registration never enables execution."""
from ocr_security.common import Refusal, canonical, digest

BASELINE = ("ocr", "opengrep", "gitleaks", "osv")
OPTIONAL = ("betterleaks", "trivy", "agentshield")
ALTERNATIVES = ("semgrep", "bearer", "codeql", "anthropic_review", "snyk_agent_scan", "strix", "shannon")
MISSING_SECURITY_NOTICE = (
    "Security integration is disabled. Standard OpenCodeReview remains unchanged; "
    "required security coverage is missing and no security acceptance is asserted."
)


def manifest():
    """Static data, not imported plugins, executable paths, hooks or settings."""
    modes = {"ocr": ("preview", "rule"), "opengrep": ("files",),
             "gitleaks": ("files", "history", "stdin"), "osv": ("lockfiles",)}
    rows = []
    for tool in BASELINE:
        rows.append({"tool": tool, "category": "baseline", "registration_enabled": False,
                     "source_state": "provisional_source_available", "native_runtime": "NOT_QUALIFIED",
                     "interfaces": ["security-integration/s02-s03/ocr_security_adapters/" + tool + ".py"],
                     "supported_plan_operations": list(modes[tool]), "execution_supported": False,
                     "qualification": "HELD"})
    for tool in OPTIONAL + ALTERNATIVES:
        rows.append({"tool": tool, "category": "optional" if tool in OPTIONAL else "alternative",
                     "registration_enabled": False, "source_state": "disposition_only_no_adapter",
                     "native_runtime": "NOT_IMPLEMENTED", "interfaces": [],
                     "supported_plan_operations": [], "execution_supported": False,
                     "qualification": "NOT_QUALIFIED"})
    value = {"schema_version": "1.0", "kind": "disabled-integration-registration",
             "adoption_authority": False, "execution_enabled": False, "tools": rows,
             "baseline_operations": [["ocr", "preview"], ["ocr", "rule"], ["opengrep", "files"],
                                     ["gitleaks", "one_of_files_history_stdin"], ["osv", "lockfiles"]],
             "semantic_review": "separate_sanitized_deep_accounting_and_independent_evidence_required",
             "notice": MISSING_SECURITY_NOTICE}
    return dict(value, registration_sha256=digest(canonical(value)))


def disable_optional():
    """Idempotent proposed disposition; never change installed registration."""
    return {"optional_tools": list(OPTIONAL), "registration_enabled": False,
            "baseline": "unchanged", "evidence": "retained", "platform_controls": "unchanged",
            "actions_executed": False, "qualification": "NOT_QUALIFIED"}


def disable_integration():
    """Describe the bounded rollback without touching standard OCR or evidence."""
    return {"integration_entrypoint": "disabled", "standard_ocr": "unchanged",
            "notice": MISSING_SECURITY_NOTICE, "security_review": "NOT_RUN",
            "coverage": "missing", "target_acceptance": "not-run", "evidence": "retained",
            "actions_executed": False}


def execute(*args, **kwargs):
    raise Refusal("integration_execution_unqualified")


def activate(*args, **kwargs):
    raise Refusal("integration_activation_not_implemented")


def acquire(*args, **kwargs):
    raise Refusal("separate_acquisition_authority_required")
