# SPDX-License-Identifier: Apache-2.0
"""One fail-closed boundary shared by all provisional native adapters.

This module deliberately has no process, filesystem, network or provider capability.
Plans are data. No configuration value or caller-supplied receipt can enable a run.
"""

from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest, integer, sha, text

ADAPTERS = frozenset(("ocr", "opengrep", "gitleaks", "osv"))
OPERATIONS = {
    "ocr": frozenset(("preview", "rule")),
    "opengrep": frozenset(("files",)),
    "gitleaks": frozenset(("files", "history", "stdin")),
    "osv": frozenset(("lockfiles",)),
}


@dataclass(frozen=True)
class Plan:
    adapter: str
    operation: str
    argv: tuple
    tool_sha256: str
    policy_sha256: str
    snapshot_id: str
    view: str
    asset_pins: tuple
    blockers: tuple
    stdin_item: str | None = None

    def document(self):
        if self.adapter not in ADAPTERS or self.operation not in OPERATIONS[self.adapter]:
            raise Refusal("unsupported_operation")
        if self.view not in ("scanner", "model"):
            raise Refusal("invalid_view")
        if type(self.argv) is not tuple or not 1 <= len(self.argv) <= 512:
            raise Refusal("invalid_arguments")
        for arg in self.argv:
            text(arg, 4096)
        sha(self.tool_sha256)
        sha(self.policy_sha256)
        sha(self.snapshot_id)
        if type(self.asset_pins) is not tuple or len(self.asset_pins) > 256:
            raise Refusal("invalid_assets")
        for name, value in self.asset_pins:
            text(name, 128)
            sha(value)
        if len({name for name, _ in self.asset_pins}) != len(self.asset_pins):
            raise Refusal("duplicate_asset")
        if type(self.blockers) is not tuple or len(self.blockers) > 64:
            raise Refusal("invalid_blockers")
        for blocker in self.blockers:
            text(blocker, 128)
        if self.stdin_item is not None:
            text(self.stdin_item, 32)
        return {
            "schema_version": "1.0", "kind": "disabled-native-plan",
            "adapter": self.adapter, "operation": self.operation,
            "argv": list(self.argv), "tool_sha256": self.tool_sha256,
            "policy_sha256": self.policy_sha256, "snapshot_id": self.snapshot_id,
            "view": self.view, "asset_pins": dict(self.asset_pins),
            "stdin_item": self.stdin_item, "blockers": list(self.blockers),
            "execution_enabled": False, "qualified": False,
            "target_security_acceptance": "NOT_ASSESSED",
        }

    @property
    def identity(self):
        return digest(canonical(self.document()))


def execute(plan, *args, **kwargs):
    """Refuse even apparently qualified plans; activation requires new reviewed code.

    S01 presently admits synthetic static fixtures only. It does not expose a
    qualified scanner/OCR runner. Calling its fixture runner with real tool bytes
    or accepting a callback here would silently expand that security boundary.
    """
    raise Refusal("provisional_execution_disabled")


def disabled_result(adapter, reason="provisional_execution_disabled"):
    if adapter not in ADAPTERS:
        raise Refusal("unsupported_adapter")
    text(reason, 128)
    return {"adapter": adapter, "process_status": "skipped", "code": reason,
            "completeness": "incomplete", "coverage": [], "findings": [],
            "security_review": "NOT_RUN", "target_security_acceptance": "NOT_ASSESSED"}


def aggregate(results, expected=("ocr", "opengrep", "gitleaks", "osv")):
    """Combine evidence state without manufacturing coverage or target acceptance."""
    if type(results) is not list or len(results) > len(ADAPTERS):
        raise Refusal("invalid_results")
    if type(expected) is not tuple or not expected or len(set(expected)) != len(expected):
        raise Refusal("invalid_expected_adapters")
    if any(name not in ADAPTERS for name in expected):
        raise Refusal("unsupported_adapter")
    seen, states, gaps = set(), [], []
    for item in results:
        if type(item) is not dict or item.get("adapter") not in expected:
            raise Refusal("unexpected_adapter")
        name = item["adapter"]
        if name in seen:
            raise Refusal("duplicate_adapter")
        seen.add(name)
        status = item.get("process_status")
        if status not in ("success", "unknown", "timeout", "partial", "skipped", "stale", "parser_error", "error", "unsupported"):
            raise Refusal("invalid_process")
        completeness = item.get("completeness")
        if completeness not in ("complete", "incomplete", "unknown"):
            raise Refusal("invalid_completeness")
        states.append({"adapter": name, "process_status": status, "completeness": completeness})
        if status != "success" or completeness != "complete":
            gaps.append({"adapter": name, "reason": "incomplete_adapter"})
    for name in expected:
        if name not in seen:
            gaps.append({"adapter": name, "reason": "missing_adapter"})
    return {"kind": "adapter-state-summary", "adapters": states, "gaps": gaps,
            "reported_complete": not gaps, "verified_coverage": False,
            "completeness": "unknown" if not gaps else "incomplete",
            "target_security_acceptance": "NOT_ASSESSED"}
