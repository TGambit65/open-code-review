# SPDX-License-Identifier: Apache-2.0
"""Fictional in-memory test records. These are not approvals or qualification receipts."""
from pathlib import Path
import sys
ROOT=Path(__file__).absolute().parents[1]
for directory in (ROOT,ROOT.parent/'s01',ROOT.parent/'s02-s03'):
    sys.path.insert(0,str(directory))
from datetime import datetime,timezone
from ocr_security.common import canonical,digest,ModelBundle,ModelItem
from ocr_security.snapshot import Entry,Snapshot
from ocr_security.views import Views
from ocr_security_gate.contracts import GatePolicy
from ocr_security_gate.updates import UpdateSet
from ocr_security_gate.evidence import Evidence

NOW=datetime(2026,11,6,1,tzinfo=timezone.utc)

def policy(**changes):
    value={"schema_version":"1.0","kind":"approved-gate-policy","owner":"fixture-owner","repository_id":1,
           "repository_name":"synthetic/only","required_adapters":["ocr","opengrep","gitleaks","osv"],
           "blocking_severities":["Critical","High","Medium"],"exception_owners":["fixture-owner"],
           "maximum_exception_seconds":86400,"maximum_evidence_age_seconds":86400,
           "candidate_controls":"inert","source_sha256":"a"*64,"adapter_policy_sha256":"b"*64,"required_datasets":["npm"],
           "history_scope_sha256":"6"*64,"prior_history_sha256":None}
    value.update(changes);raw=canonical(value);return GatePolicy(digest(raw),raw)

def snapshot(content=b'print("public fixture")\n',path="private-path.py"):
    item={"path":path,"source":"fixture","change_kind":"added","base_blob":None,"head_blob":"2"*40,
          "side":"head","selected":True,"reason":"fixture","sha256":digest(content),"bytes":len(content),
          "surfaces":["primary","search","filename"],"required_ranges":[[1,len(content.splitlines())]]}
    selection={"repository":{"name":"synthetic/only","id":1},"base_commit":"1"*40,"head_commit":"2"*40,
               "frozen_diff_sha256":"3"*64,"entries":[item]}
    raw=canonical({"selection_sha256":"4"*64,"policy_sha256":"5"*64,"selection":selection})
    entry=Entry(0,item["path"],"fixture","added",None,"2"*40,"head",tuple(tuple(x) for x in item["required_ranges"]),
                tuple(item["surfaces"]),True,"fixture",digest(content),content,len(content.splitlines()))
    snap=Snapshot(digest(raw),"4"*64,"5"*64,"synthetic/only",1,"1"*40,"2"*40,"3"*64,(entry,),raw)
    return snap,views_for_snapshot(snap)

def views_for_snapshot(snap):
    # Fictional receipts bind the actual fixture bytes, never a shared fake pin.
    models=tuple(ModelItem(entry.opaque_id,entry.surfaces,entry.content.decode(),
                 tuple((i,i,"released") for i in range(1,entry.lines+1)),()) for entry in snap.selected)
    serial=[{"id":item.opaque_id,"surfaces":item.surfaces,"content":item.content,
             "line_map":item.line_map,"gaps":item.gaps} for item in models]
    bundle=ModelBundle(digest(canonical(serial)),models)
    return Views(tuple((entry.opaque_id,entry.content) for entry in snap.selected),bundle,
                 canonical({"snapshot_id":snap.snapshot_id,"model_bundle_id":bundle.bundle_id}))

def target(snap):
    return {"repository_id":snap.repository_id,"repository_name":snap.repository_name,"base_commit":snap.base_commit,
            "head_commit":snap.head_commit,"frozen_diff_sha256":snap.frozen_diff_sha256,"snapshot_id":snap.snapshot_id,
            "snapshot_policy_sha256":snap.policy_sha256,"adapter_policy_sha256":"b"*64,"source_sha256":"a"*64}

def update(expires="2026-11-07T00:00:00Z",previous=None,version="fixture-v1"):
    value={"schema_version":"1.0","kind":"approved-offline-update-set","set_id":"fictional-set","approved_at":"2026-11-06T00:00:00Z",
           "approval_receipt_sha256":"6"*64,"previous_set_sha256":previous,"assets":[
           {"id":"db-npm","adapter":"osv","kind":"database","version":version,"source_commit":"1"*40,
            "sha256":digest(b"fictional-database"),"bytes":len(b"fictional-database"),"verification_receipt_sha256":"7"*64,
            "provenance_sha256":"8"*64,"license_receipt_sha256":"9"*64,"dataset":"npm",
            "created_at":"2026-11-05T00:00:00Z","expires_at":expires}]}
    raw=canonical(value);return UpdateSet(digest(raw),raw)

def database_pin(update_set):
    item=update_set.value()["assets"][0]
    return digest(canonical([[item["dataset"],item["sha256"],item["created_at"],item["expires_at"]]]))

def evidence(snap,adapter="gitleaks",findings=(),state="success",complete="complete",current=None,views=None):
    current=current or update()
    views=views or views_for_snapshot(snap)
    value={"adapter":adapter,"snapshot_id":snap.snapshot_id,"adapter_policy_sha256":"b"*64,"model_bundle_id":views.model.bundle_id,
           "process_status":state,"completeness":complete,"private_findings":list(findings),"at":NOW.isoformat(),
           "pins":{"tool_sha256":"c"*64,"profile_sha256":"d"*64,"rule_pin":"e"*64,
                   "database_pin":database_pin(current) if adapter=="osv" else "not_applicable",
                   "transformation_sha256":digest(views.private_evidence),"view":"scanner"},"plan_sha256":"1"*64,
           "native_execution_receipt_sha256":"2"*64,"raw_output_forwarded":False}
    if adapter=="ocr":value.update(transformation_sha256=digest(views.private_evidence),events={"preview":{"at":NOW.isoformat()},"rule":{"at":NOW.isoformat()}},chunks=[],asset_pins=[],accounting_sha256="3"*64,handoff_id="4"*64)
    raw=canonical(value);return Evidence(adapter,digest(raw),raw)

def finding(snap,severity="High",rule="fixture-rule",identity="one"):
    entry=snap.entries[0]
    return {"id":identity,"severity":severity,"confidence":"unknown","preconditions":["fictional only"],
            "provenance":{"tool_sha256":"c"*64,"rule_id":rule,"artifact_sha256":"6"*64},
            "evidence_identity":{"snapshot_id":snap.snapshot_id,"path":entry.path,"change_kind":entry.change_kind,
                                 "base_blob":entry.base_blob,"head_blob":entry.head_blob,"side":entry.side,"ranges":[[1,1]]},
            "resolution_state":"open"}

def all_evidence(snap,findings=(),current=None,views=None):
    return tuple(evidence(snap,name,findings if name=="gitleaks" else (),current=current,views=views) for name in ("ocr","opengrep","gitleaks","osv"))

def attestation(snap,pol,items,dataset):
    identities=[{"id":x.opaque_id,"identity":x.identity,"sha256":x.sha256,"ranges":x.required_ranges} for x in snap.selected]
    return {"schema_version":"1.0","kind":"independent-qualified-run-attestation","subject_sha256":digest(canonical(target(snap))),
            "gate_policy_sha256":pol.sha256,"evidence_sha256":{x.adapter:x.sha256 for x in items},
            "freshness_sha256":dataset["receipt_sha256"],"selected_identity_sha256":digest(canonical(identities)),
            "coverage_receipts":{x.adapter:"7"*64 for x in items},"qualification_receipts":{s:"8"*64 for s in ("S01","S02","S03")},
            "independent_context_receipt_sha256":"9"*64,"implementation_actor":"fixture-writer","reviewer_actor":"fixture-reviewer",
            "issued_at":"2026-11-06T00:00:00Z","expires_at":"2026-11-07T00:00:00Z","state":"complete"}


def adapter_policy(snap):
    from ocr_security_adapters.effective_policy import Policy
    from ocr_security_adapters.reviewer import TOPICS
    return Policy("b"*64,snap.policy_sha256,"fixture-owner","a"*64,TOPICS,
                  tuple((name,digest(name.encode())) for name in ("ocr","opengrep","gitleaks","osv")),1048576)


def normalized(snap,views,findings=()):
    entry=snap.entries[0]
    pins={"tool_sha256":"c"*64,"profile_sha256":"d"*64,"rule_pin":"e"*64,"database_pin":"not_applicable",
          "transformation_sha256":digest(views.private_evidence),"view":"scanner"}
    identity={"repository":{"name":snap.repository_name,"id":snap.repository_id},"base_commit":snap.base_commit,
              "head_commit":snap.head_commit,"frozen_diff_sha256":snap.frozen_diff_sha256,"snapshot_id":snap.snapshot_id,
              "policy_sha256":snap.policy_sha256,**pins}
    coverage={"snapshot_id":snap.snapshot_id,"path":entry.path,"change_kind":entry.change_kind,"base_blob":entry.base_blob,
              "head_blob":entry.head_blob,"side":entry.side,"original_sha256":entry.sha256,
              "analyzed_ranges":[list(x) for x in entry.required_ranges],"truncated":False,"omissions":[]}
    result={"schema_version":"1.0","kind":"analysis-result","identity":identity,
            "event":{"at":NOW.isoformat(),"actor":"fixture-writer","action_id":"fictional-only","artifact_sha256":"3"*64,
                     "artifact_location":"private:DO_NOT_PUBLISH"},"process":{"status":"success","exit_code":0,"code":"ok"},
            "completeness":"complete","stages":{k:"pending" for k in ("implementation","independent_review","remote_preservation","applicable_validation","acceptance")},
            "coverage":[coverage],"findings":list(findings)}
    value={"adapter":"gitleaks","process_status":"success","completeness":"complete","result":result,"gaps":[],
           "raw_report_forwarded":False,"native_execution_receipt_sha256":"4"*64,"plan_sha256":"5"*64,
           "adapter_policy_sha256":"b"*64,"target_security_acceptance":"NOT_ASSESSED"}
    return value,pins
