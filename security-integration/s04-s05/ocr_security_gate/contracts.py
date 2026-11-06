# SPDX-License-Identifier: Apache-2.0
"""Bounded, versioned inert contracts; all original native boundaries remain held."""
from dataclasses import dataclass
from datetime import datetime, timezone
from ocr_security.common import Refusal, canonical, digest, fields, sha, git_id, integer, text, utc
from ocr_security.policy import TrustedRef, read_ref
from ocr_security_adapters.data import bounded_json, sequence, choice, token

ADAPTERS = ("ocr", "opengrep", "gitleaks", "osv")
STAGES = ("implementation", "independent_review", "remote_preservation", "applicable_validation", "acceptance")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SUBJECT_KEYS = ("repository_id", "repository_name", "base_commit", "head_commit", "frozen_diff_sha256", "snapshot_id",
                "snapshot_policy_sha256", "adapter_policy_sha256", "source_sha256")


def timestamp(now):
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise Refusal("invalid_time")
    return now.astimezone(timezone.utc)


def unique(values, maximum=256):
    values = sequence(values, maximum)
    if any(type(x) is not str for x in values) or len(values) != len(set(values)):
        raise Refusal("invalid_unique_values")
    return values


def subject(value):
    fields(value, SUBJECT_KEYS)
    integer(value["repository_id"], 1)
    text(value["repository_name"], 256)
    git_id(value["base_commit"]); git_id(value["head_commit"])
    for key in SUBJECT_KEYS[4:]: sha(value[key])
    return dict(value)


def pinned(ref, context, kind):
    if not isinstance(ref, TrustedRef):
        raise Refusal("trusted_external_reference_required")
    raw = read_ref(ref, context)
    value = bounded_json(raw)
    if type(value) is not dict or value.get("schema_version") != "1.0" or value.get("kind") != kind:
        raise Refusal("unsupported_document")
    return value, digest(raw)


@dataclass(frozen=True)
class GatePolicy:
    """Construct through load_policy; this value is not an execution capability."""
    sha256: str
    document: bytes

    def value(self):
        if digest(self.document) != sha(self.sha256):
            raise Refusal("policy_identity_mismatch")
        return parse_policy(self.document)


def parse_policy(raw):
    value = bounded_json(raw)
    fields(value, ("schema_version", "kind", "owner", "repository_id", "repository_name", "required_adapters",
                   "blocking_severities", "exception_owners", "maximum_exception_seconds", "maximum_evidence_age_seconds",
                   "candidate_controls", "source_sha256", "adapter_policy_sha256", "required_datasets",
                   "history_scope_sha256", "prior_history_sha256"))
    if (value["schema_version"], value["kind"], value["candidate_controls"]) != ("1.0", "approved-gate-policy", "inert"):
        raise Refusal("unsafe_gate_policy")
    text(value["owner"]); integer(value["repository_id"], 1); text(value["repository_name"])
    if set(unique(value["required_adapters"],4)) != set(ADAPTERS):
        raise Refusal("missing_baseline_adapter")
    blocking = unique(value["blocking_severities"],5)
    if not {"Critical","High","Medium"} <= set(blocking) or not set(blocking) <= set(SEVERITIES):
        raise Refusal("unsafe_findings_policy")
    for owner in unique(value["exception_owners"],64): text(owner)
    datasets = unique(value["required_datasets"],128)
    if not datasets: raise Refusal("missing_dataset_requirements")
    for dataset in datasets: token(dataset)
    integer(value["maximum_exception_seconds"],1,31*86400)
    integer(value["maximum_evidence_age_seconds"],1,7*86400)
    sha(value["source_sha256"]); sha(value["adapter_policy_sha256"])
    sha(value["history_scope_sha256"])
    if value["prior_history_sha256"] is not None: sha(value["prior_history_sha256"])
    return value


def load_policy(ref, context):
    value, pin = pinned(ref, context, "approved-gate-policy")
    raw = canonical(value)
    parse_policy(raw)
    # Preserve the exact external document identity, including its formatting.
    original = read_ref(ref, context)
    if digest(original) != pin:
        raise Refusal("external_policy_changed")
    return GatePolicy(pin, original)


def bind_policy(policy, target):
    if not isinstance(policy, GatePolicy): raise Refusal("missing_gate_policy")
    value = policy.value(); subject(target)
    for key in ("repository_id","repository_name","source_sha256","adapter_policy_sha256"):
        if value[key] != target[key]: raise Refusal("gate_policy_scope_mismatch")
    return value
