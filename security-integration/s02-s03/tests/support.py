# SPDX-License-Identifier: Apache-2.0
"""Pure in-memory synthetic data. No filesystem selection or native authorization."""

from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
sys.path.insert(0, str(Path(__file__).absolute().parents[2] / "s01"))
from ocr_security.common import ModelBundle, ModelItem, canonical, digest
from ocr_security.snapshot import Entry, Snapshot
from ocr_security.views import Views
from ocr_security_adapters.assets import Asset, Inventory, SOURCES
from ocr_security_adapters.effective_policy import Policy
from ocr_security_adapters.reviewer import TOPICS

NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


def inventory(adapter="gitleaks", expires="2026-11-06T00:00:00Z"):
    binary = "843be0e56fdff0a5ca6f86c5866f942d6a372dff1c0ca19e7893d72495abf45c" if adapter == "ocr" else "a" * 64
    assets = [Asset("binary", "binary", binary, "synthetic-only", "b"*64, "c"*64, SOURCES[adapter][1], None, None, None)]
    if adapter == "osv":
        assets.append(Asset("db-npm", "database", "d"*64, "synthetic-only", "b"*64, "c"*64, "synthetic-fixture", "npm", "2026-11-01T00:00:00Z", expires))
        assets.append(Asset("policy", "policy", "d"*64, "synthetic-only", "b"*64, "c"*64, "synthetic-fixture", None, None, None))
    else:
        assets.append(Asset("rules", "rules", "d"*64, "synthetic-only", "b"*64, "c"*64, "synthetic-fixture", None, None, None))
    return Inventory(adapter, SOURCES[adapter][0], SOURCES[adapter][1], digest(adapter.encode()), tuple(assets),
                     ("fixture-rule",), ("npm",), "e"*64, "f"*64)


def policy():
    return Policy("7"*64, "8"*64, "synthetic-owner", "9"*64, TOPICS,
                  tuple((name, digest(name.encode())) for name in SOURCES), 1048576)


def sample(raw=b'eval(input())\n', suffix="py", redact=False):
    blob = "2" * 40
    item = {"path": "sample."+suffix, "source": "fixture", "change_kind": "added", "base_blob": None,
            "head_blob": blob, "side": "head", "selected": True, "reason": "synthetic_only",
            "sha256": digest(raw), "bytes": len(raw), "surfaces": ["primary", "search", "filename"],
            "required_ranges": [[1, len(raw.splitlines())]] if raw else []}
    selection = {"repository": {"name": "synthetic/only", "id": 1}, "base_commit": "1"*40,
                 "head_commit": "2"*40, "frozen_diff_sha256": "3"*64, "entries": [item]}
    manifest = canonical({"selection_sha256": "4"*64, "policy_sha256": "8"*64, "selection": selection})
    entry = Entry(0,item["path"],"fixture","added",None,blob,"head",tuple(tuple(x) for x in item["required_ranges"]),
                  tuple(item["surfaces"]),True,"synthetic_only",digest(raw),raw,len(raw.splitlines()))
    snapshot = Snapshot(digest(manifest),"4"*64,"8"*64,"synthetic/only",1,"1"*40,"2"*40,"3"*64,(entry,),manifest)
    content = "[REDACTED]\n" if redact else raw.decode()
    lines = content.splitlines(keepends=True)
    maps = tuple((i,i,"redacted" if redact else "released") for i in range(1,len(lines)+1))
    gaps = ((1,1,"not_released"),) if redact else ()
    model_item = ModelItem(entry.opaque_id,entry.surfaces,content,maps,gaps)
    serial = [{"id": model_item.opaque_id, "surfaces": model_item.surfaces, "content": content, "line_map": maps, "gaps": gaps}]
    bundle = ModelBundle(digest(canonical(serial)),(model_item,))
    private = canonical({"snapshot_id":snapshot.snapshot_id,"model_bundle_id":bundle.bundle_id})
    return snapshot, Views(((entry.opaque_id,raw),),bundle,private)


def evidence(raw, snapshot, adapter="gitleaks", exit_code=0, status="success", mode="files", stdin_item=None, selection=None):
    from ocr_security_adapters import gitleaks, opengrep, osv
    inv, pol = inventory(adapter), policy()
    if adapter == "gitleaks":
        operation = gitleaks.plan(snapshot, pol, inv, mode, stdin_item)
    elif adapter == "opengrep":
        operation = opengrep.plan(snapshot, pol, inv)
    elif adapter == "osv":
        operation = osv.plan(snapshot, pol, inv, selection, NOW)
    else:
        raise ValueError("unsupported synthetic evidence adapter")
    return {"at": NOW.isoformat(), "actor":"synthetic-only", "action_id":"not-an-authorization",
            "artifact_location":"memory:synthetic", "report_sha256":digest(raw),"stderr_sha256":digest(b""),
            "exit_code":exit_code,"process_status":status,"profile_sha256":"5"*64,
            "tool_sha256":inventory(adapter).one("binary").sha256,"snapshot_id":snapshot.snapshot_id,
            "policy_sha256":snapshot.policy_sha256,"adapter_policy_sha256":policy().sha256,
            "native_execution_receipt_sha256":"6"*64, "plan_sha256":operation.identity}
