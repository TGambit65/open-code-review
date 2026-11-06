# SPDX-License-Identifier: Apache-2.0
"""Validate external policy intent without loading candidate configuration.

Effective-policy receipts describe a required isolated layout, not proof that
native selection occurred. Actual execution and qualification are still blocked.
"""

from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest, fields, sha, text
from ocr_security.policy import TrustedRef, read_ref
from .data import bounded_json, sequence, token

FORBIDDEN_ENV = ("GIT_CONFIG", "GIT_DIR", "GIT_WORK_TREE", "GITLEAKS_CONFIG", "SEMGREP_APP_TOKEN", "OPENAI_API_KEY")


@dataclass(frozen=True)
class Policy:
    sha256: str
    snapshot_policy_sha256: str
    owner: str
    review_checklist_sha256: str
    required_review_topics: tuple
    adapter_asset_documents: tuple
    max_output_bytes: int


def load_policy(ref, context):
    if not isinstance(ref, TrustedRef):
        raise Refusal("missing_external_policy")
    raw = read_ref(ref, context)
    value = bounded_json(raw)
    fields(value, ("schema_version", "kind", "owner", "snapshot_policy_sha256", "review_checklist_sha256", "required_review_topics",
                   "adapter_asset_documents", "candidate_controls", "ambient_config", "network", "max_output_bytes"))
    if value["schema_version"] != "1.0" or value["kind"] != "s02-s03-external-policy":
        raise Refusal("unsupported_policy")
    if (value["candidate_controls"], value["ambient_config"], value["network"]) != ("inert", "absent", "denied"):
        raise Refusal("unsafe_policy")
    text(value["owner"])
    sha(value["review_checklist_sha256"])
    sha(value["snapshot_policy_sha256"])
    topics = tuple(token(x) for x in sequence(value["required_review_topics"], 32))
    required = {"authorization", "trust_boundaries", "secrets", "dependencies", "business_logic", "json_values", "policy_content"}
    if not required <= set(topics) or len(topics) != len(set(topics)):
        raise Refusal("incomplete_review_policy")
    pins = value["adapter_asset_documents"]
    fields(pins, ("ocr", "opengrep", "gitleaks", "osv"))
    for pin in pins.values():
        sha(pin)
    if type(value["max_output_bytes"]) is not int or not 1 <= value["max_output_bytes"] <= 1048576:
        raise Refusal("unsafe_output_limit")
    return Policy(digest(raw), value["snapshot_policy_sha256"], value["owner"], value["review_checklist_sha256"], topics,
                  tuple(sorted(pins.items())), value["max_output_bytes"])


def bind_inventory(policy, inventory):
    if not isinstance(policy, Policy) or dict(policy.adapter_asset_documents).get(inventory.adapter) != inventory.external_document_sha256:
        raise Refusal("unadopted_asset_inventory")


def receipt(policy, snapshot_id, selected_ids, candidate_controls):
    """Candidate controls are opaque IDs for review, never config values or paths."""
    if not isinstance(policy, Policy):
        raise Refusal("missing_external_policy")
    sha(snapshot_id)
    if type(selected_ids) is not tuple or len(selected_ids) > 256 or len(set(selected_ids)) != len(selected_ids):
        raise Refusal("invalid_selection")
    if type(candidate_controls) is not tuple or any(item not in selected_ids for item in candidate_controls):
        raise Refusal("unbound_candidate_control")
    for item in selected_ids:
        token(item, 32)
    return {"kind": "effective-policy-requirements", "policy_sha256": policy.sha256,
            "snapshot_id": snapshot_id, "selected_ids": list(selected_ids),
            "candidate_control_ids": list(candidate_controls), "candidate_controls": "inert_review_data",
            "isolated_home": "/empty-home", "isolated_config": "/empty-config",
            "ambient_git_overrides": "absent", "network": "denied",
            "native_effective_config_observed": False, "qualified": False}
