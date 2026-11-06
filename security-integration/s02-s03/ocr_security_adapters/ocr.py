# SPDX-License-Identifier: Apache-2.0
"""Pinned OCR preview/rule plans and strict schema handling; no native execution."""

from ocr_security.common import Refusal, fields, integer, text
from .assets import Inventory
from .boundary import Plan, execute
from .data import bounded_json, choice, sequence
from .effective_policy import bind_inventory
from .projection import Projection, validate_projection

STATUS = ("binary", "added", "deleted", "renamed", "modified")
EXCLUSIONS = ("", "user_exclude", "unsupported_ext", "default_path", "secret_exclude", "provider_directory", "deleted", "binary", "too_large")


def plan(operation, snapshot_id, projection, policy, inventory):
    if not isinstance(projection, Projection) or not isinstance(inventory, Inventory) or inventory.adapter != "ocr":
        raise Refusal("invalid_ocr_inputs")
    bind_inventory(policy, inventory)
    validate_projection(projection)
    if operation == "preview":
        argv = ("/tool/ocr", "delegate", "preview", "--repo", "/review", "--from", projection.base_commit,
                "--to", projection.head_commit, "--format", "json")
    elif operation == "rule":
        aliases = tuple(name for name, _ in projection.alias_items)
        if not aliases:
            raise Refusal("empty_rule_selection")
        argv = ("/tool/ocr", "delegate", "rule", "--repo", "/review", "--rule", "/policy/ocr-rules.json", "--format", "json", "--") + aliases
    else:
        raise Refusal("unsupported_operation")
    return Plan("ocr", operation, argv, inventory.one("binary").sha256, policy.sha256, snapshot_id, "model",
                inventory.pins() + (("model_projection", projection.identity),),
                ("s01_acceptance_pending", "ocr_isolated_runner_unqualified", "effective_selection_unqualified"))


def parse_preview(raw, projection):
    if not isinstance(projection, Projection):
        raise Refusal("invalid_projection")
    validate_projection(projection)
    value = bounded_json(raw)
    fields(value, ("schema_version", "mode", "repository", "total_files", "reviewable_count", "excluded_count",
                   "total_insertions", "total_deletions", "reviewable_files", "excluded_files"),
           ("from", "to", "commit", "merge_base", "background"))
    if value["schema_version"] != "1" or value["mode"] != "range" or value["repository"] != "/review":
        raise Refusal("unsupported_ocr_schema")
    if value.get("from") != projection.base_commit or value.get("to") != projection.head_commit or "commit" in value or "background" in value:
        raise Refusal("stale_ocr_projection")
    known = dict(projection.alias_items)
    seen, selected, gaps = set(), [], []
    for field, excluded in (("reviewable_files", False), ("excluded_files", True)):
        for item in sequence(value[field], 256):
            fields(item, ("path", "status", "insertions", "deletions"), ("exclude_reason",))
            path = item["path"]
            if type(path) is not str or path not in known or path in seen:
                raise Refusal("unexpected_or_duplicate_ocr_path")
            seen.add(path)
            choice(item["status"], STATUS)
            integer(item["insertions"])
            integer(item["deletions"])
            reason = item.get("exclude_reason", "")
            choice(reason, EXCLUSIONS)
            if excluded or reason:
                gaps.append({"id": known[path], "reason": "native_excluded"})
            else:
                selected.append(known[path])
    if integer(value["total_files"]) != len(seen) or integer(value["reviewable_count"]) != len(value["reviewable_files"]) or integer(value["excluded_count"]) != len(value["excluded_files"]):
        raise Refusal("ocr_count_mismatch")
    for alias in known.keys() - seen:
        gaps.append({"id": known[alias], "reason": "missing_from_native_preview"})
    integer(value["total_insertions"])
    integer(value["total_deletions"])
    return {"adapter": "ocr", "selected_ids": selected, "gaps": gaps, "preview_only": True,
            "completeness": "incomplete", "semantic_review_performed": False,
            "target_security_acceptance": "NOT_ASSESSED"}


def parse_rules(raw, projection, approved_rule_text):
    """Only the explicit externally approved custom rule may be effective."""
    if type(approved_rule_text) is not str or not 1 <= len(approved_rule_text) <= 65536:
        raise Refusal("invalid_rule_text")
    if any((ord(ch) < 32 and ch not in "\n\r\t") or ord(ch) == 127 for ch in approved_rule_text):
        raise Refusal("invalid_rule_text")
    validate_projection(projection)
    value = bounded_json(raw)
    fields(value, ("schema_version", "groups"))
    if value["schema_version"] != "1":
        raise Refusal("unsupported_ocr_schema")
    known, covered, groups = dict(projection.alias_items), set(), []
    group_ids = set()
    for group in sequence(value["groups"], 256):
        fields(group, ("group_id", "source", "pattern", "files", "rule"))
        number = integer(group["group_id"])
        if number in group_ids:
            raise Refusal("duplicate_rule_group")
        group_ids.add(number)
        if group["source"] != "custom" or group["rule"] != approved_rule_text:
            raise Refusal("unapproved_effective_rules")
        text(group["pattern"], 4096)
        ids = []
        for name in sequence(group["files"], 256):
            if type(name) is not str or name not in known or name in covered:
                raise Refusal("unbound_rule_selection")
            covered.add(name)
            ids.append(known[name])
        groups.append({"group_id": number, "ids": ids, "source": "custom"})
    return {"groups": groups, "missing_ids": [known[x] for x in sorted(known.keys() - covered)],
            "effective_policy_matches": covered == set(known), "semantic_review_performed": False}


def run(*args, **kwargs):
    return execute(None)
