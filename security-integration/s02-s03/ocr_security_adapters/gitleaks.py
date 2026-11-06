# SPDX-License-Identifier: Apache-2.0
"""Gitleaks CLI, not its Action. No credential validation or native activation."""

from ocr_security.common import Refusal, fields, integer
from .boundary import Plan, execute
from .data import bounded_json, sequence
from .effective_policy import bind_inventory
from .inputs import scanner_inputs
from .private_history import original_history
from .normalization import coverage_attestation, finding, result, parser_failure

COMMON = ("--config", "/policy/gitleaks.toml", "--redact=100", "--report-format=json", "--report-path=/output/report.json",
          "--no-banner", "--no-color", "--log-level=error", "--ignore-gitleaks-allow", "--gitleaks-ignore-path=/policy/empty.gitleaksignore",
          "--max-archive-depth=0", "--max-decode-depth=0", "--timeout=5", "--exit-code=10")


def plan(snapshot, policy, inventory, mode="files", stdin_item=None):
    if inventory.adapter != "gitleaks":
        raise Refusal("wrong_adapter_inventory")
    bind_inventory(policy, inventory)
    inputs = scanner_inputs(snapshot)
    if not inputs:
        raise Refusal("empty_selection")
    blockers = ["s01_acceptance_pending", "native_runner_unqualified", "complete_report_redaction_unqualified"]
    pins = inventory.pins()
    if mode == "files":
        if stdin_item is not None:
            raise Refusal("unexpected_stdin")
        argv = ("/tool/gitleaks", "dir") + COMMON + ("--", "/input")
    elif mode == "stdin":
        if stdin_item not in {x.opaque_id for x in inputs}:
            raise Refusal("unbound_stdin")
        argv = ("/tool/gitleaks", "stdin") + COMMON
    elif mode == "history":
        if stdin_item is not None:
            raise Refusal("unexpected_stdin")
        history = original_history(snapshot)
        argv = ("/tool/gitleaks", "git") + COMMON + ("--log-opts=" + history.base_commit + ".." + history.head_commit, "--", "/history")
        pins += (("history_projection", history.identity),)
        blockers.append("isolated_git_runtime_unqualified")
    else:
        raise Refusal("unsupported_operation")
    return Plan("gitleaks", mode, argv, inventory.one("binary").sha256, policy.sha256, snapshot.snapshot_id,
                "scanner", pins, tuple(blockers), stdin_item)


def normalize(raw, snapshot, views, policy, inventory, evidence, context=None, coverage_ref=None, stdin_item=None, mode="files"):
    try:
        expected_plan_sha256 = plan(snapshot, policy, inventory, mode, stdin_item).identity
        bind_inventory(policy, inventory)
        native_results = sequence(bounded_json(raw, policy.max_output_bytes), 1024)
        inputs = scanner_inputs(snapshot)
        by_path = {item.mount_path: item for item in inputs}
        by_id = {item.opaque_id: item for item in inputs}
        if mode not in ("files", "stdin", "history") or (mode == "stdin") != (stdin_item is not None):
            raise Refusal("invalid_gitleaks_mode")
        history_map = {(commit, path): by_id[item] for commit, path, item in original_history(snapshot).commit_items} if mode == "history" else {}
        if stdin_item is not None and stdin_item not in by_id:
            raise Refusal("unbound_stdin")
        findings, seen = [], set()
        for ordinal, native in enumerate(native_results):
            if type(native) is not dict or not {"RuleID", "StartLine", "EndLine", "File", "Secret", "Match"} <= set(native):
                raise Refusal("invalid_gitleaks_schema")
            if native["Secret"] != "REDACTED":
                raise Refusal("native_report_not_redacted")
            if native["RuleID"] not in inventory.allowed_rule_ids:
                raise Refusal("unapproved_rule")
            path = native["File"]
            if type(path) is not str:
                raise Refusal("unbound_native_finding")
            if mode == "stdin":
                selected = by_id[stdin_item]
                item = selected if path in ("stdin", "", "<stdin>", selected.mount_path) else None
            else:
                item = history_map.get((native.get("Commit"), path)) if mode == "history" else by_path.get(path)
            if item is None:
                raise Refusal("unbound_native_finding")
            # Deliberately discard Match, Description, Fragment, Git metadata,
            # Tags, Fingerprint, Entropy and all other untrusted strings.
            record = finding("gitleaks", item, snapshot, inventory, raw, native["RuleID"], "High", native["StartLine"], native["EndLine"], ordinal)
            if record["id"] not in seen:
                seen.add(record["id"])
                findings.append(record)
        operation_inputs = (by_id[stdin_item],) if mode == "stdin" else inputs
        complete = coverage_attestation(coverage_ref, context, evidence, inventory, snapshot, operation_inputs)
        gaps = () if complete else ("native_report_has_no_coverage_ledger",)
        if evidence["exit_code"] == 10:
            gaps += ("findings_exit_requires_detector_qualification",)
        return result("gitleaks", raw, snapshot, views, policy, inventory, evidence, inputs, findings,
                      complete, gaps, inventory.one("rules").sha256, "not_applicable", expected_plan_sha256)
    except (Refusal, TypeError, KeyError, ValueError, AttributeError):
        return parser_failure("gitleaks")


def run(*args, **kwargs):
    return execute(None)
