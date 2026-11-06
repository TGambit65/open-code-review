# SPDX-License-Identifier: Apache-2.0
"""Pinned local-rule Opengrep plans and bounded private normalization."""

from ocr_security.common import Refusal, fields, integer
from .boundary import Plan, execute
from .data import bounded_json, choice, sequence
from .effective_policy import bind_inventory
from .inputs import scanner_inputs
from .normalization import coverage_attestation, finding, result, parser_failure

SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info",
            "ERROR": "High", "WARNING": "Medium", "EXPERIMENT": "Info", "INVENTORY": "Info"}


def plan(snapshot, policy, inventory):
    if inventory.adapter != "opengrep":
        raise Refusal("wrong_adapter_inventory")
    bind_inventory(policy, inventory)
    inputs = scanner_inputs(snapshot)
    if not inputs:
        raise Refusal("empty_selection")
    argv = ("/tool/opengrep", "scan", "--config", "/policy/opengrep.yaml", "--json", "--output", "/output/report.json",
            "--disable-version-check", "--no-rewrite-rule-ids", "--disable-nosem", "--no-git-ignore", "--strict",
            "--timeout", "2", "--max-memory", "128", "--max-target-bytes", "1048576", "--")
    return Plan("opengrep", "files", argv + tuple(x.mount_path for x in inputs), inventory.one("binary").sha256,
                policy.sha256, snapshot.snapshot_id, "scanner", inventory.pins(),
                ("s01_acceptance_pending", "native_runner_unqualified", "rule_coverage_unqualified", "version_contact_unmeasured"))


def normalize(raw, snapshot, views, policy, inventory, evidence, context=None, coverage_ref=None):
    try:
        expected_plan_sha256 = plan(snapshot, policy, inventory).identity
        bind_inventory(policy, inventory)
        value = bounded_json(raw, policy.max_output_bytes)
        fields(value, ("results", "errors", "paths"), ("version", "time", "explanations", "rules_by_engine", "engine_requested", "interfile_languages_used", "skipped_rules"))
        fields(value["paths"], ("scanned",), ("skipped",))
        inputs = scanner_inputs(snapshot)
        by_path = {item.mount_path: item for item in inputs}
        scanned = sequence(value["paths"]["scanned"], 256)
        if any(type(x) is not str or x not in by_path for x in scanned) or len(set(scanned)) != len(scanned):
            raise Refusal("unbound_scanned_path")
        gaps = []
        if sequence(value["errors"], 4096):
            gaps.append("native_errors_present")
        if "skipped" not in value["paths"]:
            gaps.append("native_skips_unreported")
        elif sequence(value["paths"]["skipped"], 4096):
            gaps.append("native_skipped_inputs")
        if sequence(value.get("skipped_rules", []), 4096):
            gaps.append("native_skipped_rules")
        findings, seen = [], set()
        for ordinal, native in enumerate(sequence(value["results"], 1024)):
            fields(native, ("check_id", "path", "start", "end", "extra"))
            if type(native["path"]) is not str or native["path"] not in by_path or native["check_id"] not in inventory.allowed_rule_ids:
                raise Refusal("unbound_native_finding")
            item = by_path[native["path"]]
            for coordinate in (native["start"], native["end"]):
                fields(coordinate, ("line", "col"), ("offset",))
                integer(coordinate["line"], 1, item.lines)
                integer(coordinate["col"], 1)
                if "offset" in coordinate:
                    integer(coordinate["offset"], -1)
            extra = native["extra"]
            if type(extra) is not dict or "severity" not in extra:
                raise Refusal("invalid_native_finding")
            severity = choice(extra["severity"], SEVERITY)
            if extra.get("is_ignored", False) is not False:
                gaps.append("native_suppression_present")
            record = finding("opengrep", item, snapshot, inventory, raw, native["check_id"], SEVERITY[severity],
                             native["start"]["line"], native["end"]["line"], ordinal)
            if record["id"] not in seen:
                seen.add(record["id"])
                findings.append(record)
        complete = coverage_attestation(coverage_ref, context, evidence, inventory, snapshot, inputs)
        # Native skipped_rules=[] is not reliable at this pinned source revision.
        if not complete:
            gaps.append("independent_rule_coverage_missing")
        complete = complete & {by_path[path].opaque_id for path in scanned}
        return result("opengrep", raw, snapshot, views, policy, inventory, evidence, inputs, findings,
                      complete, tuple(gaps), inventory.one("rules").sha256, "not_applicable", expected_plan_sha256)
    except (Refusal, TypeError, KeyError, ValueError, AttributeError):
        return parser_failure("opengrep")


def run(*args, **kwargs):
    return execute(None)
