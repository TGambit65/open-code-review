# SPDX-License-Identifier: Apache-2.0
"""Retain failed evidence before selecting a separately approved inert baseline."""

import os

from .common import Refusal, canonical, digest, fields
from .policy import TrustContext, open_directory, open_regular, read_descriptor, read_ref, resolve_document


def retain_failed_evidence(failed_ref, context, evidence_directory):
    raw = read_ref(failed_ref, TrustContext(context.candidate_roots, context.input_roots), 8388608)
    if evidence_directory not in context.output_roots:
        raise Refusal("unapproved_evidence_root")
    directory = open_directory(evidence_directory)
    name = failed_ref.sha256 + ".failed-evidence"
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=directory)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.fsync(directory)
        check_fd = open_regular(evidence_directory + "/" + name, 8388608)
        try:
            if digest(read_descriptor(check_fd, 8388608)) != failed_ref.sha256:
                raise Refusal("evidence_mismatch")
        finally:
            os.close(check_fd)
        return {"sha256": failed_ref.sha256, "artifact": name, "artifact_location": evidence_directory + "/" + name}
    except OSError:
        raise Refusal("evidence_retention_failed") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def rollback(policy, context, failed_ref, config_ref, evidence_directory):
    retained = retain_failed_evidence(failed_ref, context, evidence_directory)
    try:
        configuration = resolve_document(config_ref, context, "rollback-selection")
        fields(configuration, ("schema_version", "kind", "config"))
        config = configuration["config"]
        approved = policy.data["rollback"]["approved_prior_configurations"]
        if not any(item["config"] == config and item["canonical_sha256"] == digest(canonical(config)) for item in approved):
            raise Refusal("unapproved_prior_config")
        if config.get("schema_version") != "s00-disabled-v1" or config.get("raw_model_fallback") is not False:
            raise Refusal("unsupported_prior_schema")
        return {"schema_version": "1.0", "kind": "rollback-receipt", "state": "disabled_prior_selected",
                "config_sha256": digest(canonical(config)), "retained_failed_evidence": retained,
                "policy_sha256": policy.sha256, "completeness": "unknown", "target_security_acceptance": "NOT_ASSESSED"}
    except (Refusal, TypeError, KeyError):
        return {"schema_version": "1.0", "kind": "rollback-receipt", "state": "held",
                "retained_failed_evidence": retained, "policy_sha256": policy.sha256,
                "completeness": "unknown", "target_security_acceptance": "NOT_ASSESSED"}
