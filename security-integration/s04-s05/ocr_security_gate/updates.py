# SPDX-License-Identifier: Apache-2.0
"""Approved immutable data sets; no downloader, installer, or adoption side effect."""
from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest, fields, sha, git_id, integer, utc
from .contracts import pinned, timestamp, sequence, unique, choice, token
from ocr_security_adapters.data import bounded_json


@dataclass(frozen=True)
class UpdateSet:
    sha256: str
    document: bytes

    def value(self):
        if digest(self.document) != sha(self.sha256): raise Refusal("update_identity_mismatch")
        return parse_manifest(self.document)


def parse_manifest(raw):
    value = bounded_json(raw)
    fields(value,("schema_version","kind","set_id","approved_at","approval_receipt_sha256","previous_set_sha256","assets"))
    if (value["schema_version"],value["kind"]) != ("1.0","approved-offline-update-set"):
        raise Refusal("unsupported_update_manifest")
    token(value["set_id"]); utc(value["approved_at"]); sha(value["approval_receipt_sha256"])
    if value["previous_set_sha256"] is not None: sha(value["previous_set_sha256"])
    seen=set()
    for item in sequence(value["assets"],256):
        fields(item,("id","adapter","kind","version","source_commit","sha256","bytes","verification_receipt_sha256",
                     "provenance_sha256","license_receipt_sha256","dataset","created_at","expires_at"))
        token(item["id"]); choice(item["adapter"],("ocr","opengrep","gitleaks","osv"))
        choice(item["kind"],("binary","rules","database","policy")); token(item["version"])
        if item["version"].lower() in ("latest","main","master","head","nightly"):
            raise Refusal("mutable_asset_reference")
        git_id(item["source_commit"]); integer(item["bytes"],1,2**32)
        for key in ("sha256","verification_receipt_sha256","provenance_sha256","license_receipt_sha256"):sha(item[key])
        if item["id"] in seen:raise Refusal("duplicate_asset")
        seen.add(item["id"])
        if item["kind"]=="database":
            token(item["dataset"])
            if not utc(item["created_at"]) < utc(item["expires_at"]):raise Refusal("invalid_freshness_window")
        elif any(item[key] is not None for key in ("dataset","created_at","expires_at")):
            raise Refusal("unexpected_freshness_fields")
    datasets=[x["dataset"] for x in value["assets"] if x["kind"]=="database"]
    if len(set(datasets))!=len(datasets):raise Refusal("ambiguous_dataset")
    return value


def load_manifest(ref, context):
    from ocr_security.policy import read_ref, TrustedRef
    if not isinstance(ref,TrustedRef):raise Refusal("trusted_external_reference_required")
    raw=read_ref(ref,context);parse_manifest(raw)
    return UpdateSet(digest(raw),raw)


def verify_supplied_bytes(update_set, supplied):
    """Check already-supplied local bytes only; never fetch, write or execute assets."""
    value=update_set.value()
    if type(supplied) is not dict or set(supplied)!={x["id"] for x in value["assets"]}:
        raise Refusal("asset_set_mismatch")
    for item in value["assets"]:
        raw=supplied[item["id"]]
        if type(raw) is not bytes or len(raw)!=item["bytes"] or digest(raw)!=item["sha256"]:
            raise Refusal("unverified_asset_bytes")
    return {"set_sha256":update_set.sha256,"bytes_match":True,"runtime_qualified":False,"execution_enabled":False}


def freshness(current, previous, required_datasets, now, acquisition_status="not_requested", rollback=False):
    now=timestamp(now);choice(acquisition_status,("not_requested","succeeded","failed","not_authorized"))
    if type(rollback) is not bool:raise Refusal("invalid_rollback")
    required=unique(required_datasets,128)
    for dataset in required:token(dataset)
    cur=current.value() if isinstance(current,UpdateSet) else None
    old=previous.value() if isinstance(previous,UpdateSet) else None
    if current is not None and cur is None or previous is not None and old is None:raise Refusal("invalid_update_set")
    for value in (cur,old):
        if value and utc(value["approved_at"])>now:raise Refusal("future_asset_approval")
    if old and (not cur or cur["previous_set_sha256"]!=previous.sha256):raise Refusal("unbound_previous_set")
    if rollback and old is None:raise Refusal("missing_previous_approved_set")
    active=old if rollback else cur
    records=[]
    for dataset in required:
        found=next((x for x in (active or {}).get("assets",[]) if x["kind"]=="database" and x["dataset"]==dataset),None)
        status="absent" if active is None else "unsupported" if found is None else "current"
        if found:
            if utc(found["created_at"])>now:status="future"
            elif now>=utc(found["expires_at"]):status="expired"
            elif rollback:status="rollback"
        if acquisition_status=="failed" and status=="current":status="acquisition_failed"
        records.append({"dataset":dataset,"state":status,"artifact_sha256":found["sha256"] if found else None,
                        "created_at":found["created_at"] if found else None,"expires_at":found["expires_at"] if found else None})
    result={"kind":"dataset-freshness","current_set_sha256":current.sha256 if cur else None,
            "previous_set_sha256":previous.sha256 if old else None,"active_set_sha256":previous.sha256 if rollback else current.sha256 if cur else None,
            "checked_at":now.isoformat(),"rollback":rollback,"acquisition_status":acquisition_status,"datasets":records,
            "intelligence_current":bool(records) and all(x["state"]=="current" for x in records),"execution_enabled":False}
    return dict(result,receipt_sha256=digest(canonical(result)))


def acquire(*args,**kwargs):
    raise Refusal("separate_acquisition_authority_required")
