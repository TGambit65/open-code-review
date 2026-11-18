# SPDX-License-Identifier: Apache-2.0
"""Virtual read-only mount data for a future independently qualified executor.

No directories, sockets, executables, process, or network are accessed here.
The actual S01 synthetic runner is not generalized or silently reused.
"""

from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest
from .assets import Inventory
from .boundary import Plan
from .inputs import scanner_inputs
from .private_history import original_history
from .projection import Projection, validate_projection
from .osv import lock_inputs


@dataclass(frozen=True)
class Mount:
    destination: str
    content: bytes
    sha256: str
    role: str
    read_only: bool = True


def build_layout(plan, snapshot, inventory, asset_bytes, projection=None, lockfile_selection=None):
    if not isinstance(plan,Plan) or not isinstance(inventory,Inventory) or plan.adapter != inventory.adapter:
        raise Refusal("invalid_layout")
    plan.document()
    if plan.snapshot_id != snapshot.snapshot_id or plan.tool_sha256 != inventory.one("binary").sha256:
        raise Refusal("stale_layout")
    if type(asset_bytes) is not dict or set(asset_bytes) != {x.asset_id for x in inventory.assets}:
        raise Refusal("missing_asset_bytes")
    expected_pins = dict(inventory.pins())
    if plan.adapter == "ocr":
        validate_projection(projection)
        expected_pins["model_projection"] = projection.identity
    elif plan.adapter == "gitleaks" and plan.operation == "history":
        expected_pins["history_projection"] = original_history(snapshot).identity
    if dict(plan.asset_pins) != expected_pins:
        raise Refusal("stale_layout_assets")
    if plan.adapter == "osv":
        mapped = lock_inputs(snapshot, lockfile_selection)
        expected_targets = tuple("--lockfile=" + path.rsplit("/", 1)[-1] + ":" + path for path, _, _ in mapped)
        if tuple(arg for arg in plan.argv if arg.startswith("--lockfile=")) != expected_targets:
            raise Refusal("stale_lockfile_selection")
    mounts=[]
    binary_path={"ocr":"/tool/ocr","opengrep":"/tool/opengrep","gitleaks":"/tool/gitleaks","osv":"/tool/osv-scanner"}[plan.adapter]
    rule_path={"ocr":"/policy/ocr-rules.json","opengrep":"/policy/opengrep.yaml","gitleaks":"/policy/gitleaks.toml","osv":"/policy/osv.toml"}[plan.adapter]
    def mount(path,raw,role):
        if type(raw) is not bytes:
            raise Refusal("invalid_mount_bytes")
        mounts.append(Mount(path,raw,digest(raw),role))
    for asset in inventory.assets:
        raw=asset_bytes[asset.asset_id]
        if type(raw) is not bytes or digest(raw)!=asset.sha256:
            raise Refusal("asset_bytes_mismatch")
        if asset.kind=="binary":
            destination=binary_path
        elif asset.kind in ("rules","policy"):
            destination=rule_path
        elif asset.kind=="database":
            if not asset.ecosystem or any(x in asset.ecosystem for x in ("/","\\","..")):
                raise Refusal("unsafe_database_path")
            destination="/database/osv-scanner/"+asset.ecosystem+"/all.zip"
        else:
            raise Refusal("unsupported_asset_kind")
        mount(destination,raw,"trusted_asset")
    if plan.adapter=="ocr":
        if not isinstance(projection,Projection):
            raise Refusal("sanitized_projection_required")
        for path,raw in projection.files:
            mount("/review/"+path,raw,"sanitized_model_view")
    elif plan.adapter=="osv":
        for path,_,item in lock_inputs(snapshot,lockfile_selection):
            mount(path,item.content,"approved_scanner_original")
    elif plan.adapter=="gitleaks" and plan.operation=="history":
        history=original_history(snapshot)
        if dict(plan.asset_pins).get("history_projection")!=history.identity:
            raise Refusal("stale_history_projection")
        for path,raw in history.files:
            mount("/history/"+path,raw,"approved_scanner_original")
    else:
        for item in scanner_inputs(snapshot):
            mount(item.mount_path,item.content,"approved_scanner_original")
    if plan.adapter=="gitleaks":
        mount("/policy/empty.gitleaksignore",b"","trusted_empty_ignore")
    if len({x.destination for x in mounts})!=len(mounts) or sum(len(x.content) for x in mounts)>268435456:
        raise Refusal("layout_collision_or_limit")
    return tuple(mounts)


def requirements(plan):
    plan.document()
    return {"kind":"unqualified-isolated-execution-requirements","plan_id":plan.identity,
            "mounts_read_only":True,"output":"dedicated_bounded_tmpfs","network":"denied",
            "environment":"explicit_allowlist_only","home":"empty","working_directory":"trusted_empty",
            "credentials_and_agent_sockets":"absent","cpu_memory_wall_output_limits":"mandatory",
            "dynamic_runtime_closure":"unqualified","native_runner":"unsupported_until_separately_implemented_and_qualified",
            "execution_enabled":False}


def stdin_bytes(plan, snapshot):
    """Select exact already-approved original bytes; never open a target path."""
    if not isinstance(plan, Plan) or plan.adapter != "gitleaks" or plan.operation != "stdin" or plan.snapshot_id != snapshot.snapshot_id:
        raise Refusal("invalid_stdin_plan")
    selected = [item for item in scanner_inputs(snapshot) if item.opaque_id == plan.stdin_item]
    if len(selected) != 1:
        raise Refusal("unbound_stdin")
    return selected[0].content
