# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evaluation of independently pinned evidence, never activation."""
from ocr_security.common import Refusal, canonical, digest, fields, sha, text, utc
from .contracts import ADAPTERS, subject, bind_policy, pinned, timestamp
from .evidence import index
from .updates import freshness
from .observations import collect, group, load_correlations, load_history
from .exceptions import decisions


def verify_attestation(ref,context,policy,target,evidence,freshness_receipt,snapshot,now):
    """The caller must supply an independently authorized ref, never a candidate locator."""
    value,pin=pinned(ref,context,"independent-qualified-run-attestation")
    fields(value,("schema_version","kind","subject_sha256","gate_policy_sha256","evidence_sha256","freshness_sha256",
                  "selected_identity_sha256","coverage_receipts","qualification_receipts","independent_context_receipt_sha256",
                  "implementation_actor","reviewer_actor","issued_at","expires_at","state"))
    if value["subject_sha256"]!=digest(canonical(target)) or value["gate_policy_sha256"]!=policy.sha256:
        raise Refusal("stale_run_attestation")
    if value["evidence_sha256"]!={name:e.sha256 for name,e in index(evidence).items()} or set(value["evidence_sha256"])!=set(ADAPTERS):
        raise Refusal("unbound_run_evidence")
    for pin_value in value["evidence_sha256"].values():sha(pin_value)
    if value["freshness_sha256"]!=freshness_receipt["receipt_sha256"]:raise Refusal("stale_dataset_attestation")
    identities=[{"id":x.opaque_id,"identity":x.identity,"sha256":x.sha256,"ranges":x.required_ranges} for x in snapshot.selected]
    if value["selected_identity_sha256"]!=digest(canonical(identities)):raise Refusal("coverage_denominator_mismatch")
    fields(value["coverage_receipts"],ADAPTERS)
    fields(value["qualification_receipts"],("S01","S02","S03"))
    for receipts in (value["coverage_receipts"],value["qualification_receipts"]):
        for receipt in receipts.values():sha(receipt)
    sha(value["independent_context_receipt_sha256"])
    for role in ("implementation_actor","reviewer_actor"):text(value[role])
    if value["implementation_actor"]==value["reviewer_actor"]:raise Refusal("review_not_independent")
    approved=policy.value();begin,end=utc(value["issued_at"]),utc(value["expires_at"])
    if not begin<=now<end or (now-begin).total_seconds()>approved["maximum_evidence_age_seconds"] or value["state"]!="complete":
        raise Refusal("incomplete_or_expired_attestation")
    return pin


def _bind_snapshot(target,snapshot):
    expected={"repository_id":snapshot.repository_id,"repository_name":snapshot.repository_name,
              "base_commit":snapshot.base_commit,"head_commit":snapshot.head_commit,
              "frozen_diff_sha256":snapshot.frozen_diff_sha256,"snapshot_id":snapshot.snapshot_id,
              "snapshot_policy_sha256":snapshot.policy_sha256}
    if any(target[k]!=v for k,v in expected.items()):raise Refusal("stale_gate_snapshot")


def evaluate(target,policy,evidence,snapshot,current_set,previous_set,now,context=None,attestation_ref=None,
             exception_refs=(),resolution_refs=(),correlation_ref=None,history_ref=None,acquisition_status="not_requested",rollback=False):
    """Return an assessment with explicit gaps. Caller data cannot select a weaker policy."""
    now=timestamp(now);subject(target);approved=bind_policy(policy,target);_bind_snapshot(target,snapshot)
    indexed=index(evidence);gaps=[];errors=[];external={};exception_decisions={};resolutions={}
    bundle_ids=set()
    dataset=freshness(current_set,previous_set,approved["required_datasets"],now,acquisition_status,rollback)
    if not dataset["intelligence_current"]:gaps.append("dataset_not_current")
    for name in ADAPTERS:
        item=indexed.get(name)
        if item is None:gaps.append("missing_"+name);continue
        value=item.value()
        bundle_id=value.get("model_bundle_id")
        if bundle_id is None:gaps.append("missing_bundle_binding_"+name)
        else:bundle_ids.add(sha(bundle_id))
        if value["process_status"] in ("parser_error","error","timeout"):errors.append("failed_"+name)
        if value["process_status"]!="success" or value["completeness"]!="complete":gaps.append("incomplete_"+name)
        if value.get("snapshot_id")!=target["snapshot_id"] or value.get("adapter_policy_sha256")!=target["adapter_policy_sha256"]:
            gaps.append("unbound_"+name)
        times=[x["at"] for x in value.get("events",{}).values()] if name=="ocr" else [value.get("at")]
        if not times or any(t is None or utc(t)>now or (now-utc(t)).total_seconds()>approved["maximum_evidence_age_seconds"] for t in times):
            gaps.append("stale_"+name)
    osv=indexed.get("osv")
    if len(bundle_ids)>1:gaps.append("conflicting_model_bundles")
    model_bundle_id=next(iter(bundle_ids)) if len(bundle_ids)==1 else None
    if osv and osv.value().get("pins"):
        db_pin=digest(canonical([[x["dataset"],x["artifact_sha256"],x["created_at"],x["expires_at"]]
                                 for x in sorted(dataset["datasets"],key=lambda x:x["dataset"])]))
        if osv.value()["pins"]["database_pin"]!=db_pin:gaps.append("database_evidence_mismatch")
    observations=collect(evidence,snapshot,now)
    correlations=None
    if correlation_ref is not None:
        try:
            correlations,pin=load_correlations(correlation_ref,context,policy,target,observations)
            external["correlations"]=pin
        except Refusal:errors.append("invalid_correlation_authority")
    previous=None
    if approved["prior_history_sha256"] is not None and history_ref is None:
        gaps.append("required_finding_history_missing")
    if history_ref is not None:
        try:
            previous,pin=load_history(history_ref,context,policy,target,now)
            external["history"]=pin
        except (Refusal,TypeError,KeyError):errors.append("invalid_history")
    groups=group(observations,correlations,previous)
    try:
        exception_decisions=decisions(exception_refs,context,policy,target,groups,now)
        resolutions=decisions(resolution_refs,context,policy,target,groups,now,"finding-resolution")
        if set(exception_decisions)&set(resolutions):raise Refusal("conflicting_finding_decisions")
    except (Refusal,TypeError,KeyError):
        errors.append("invalid_finding_decision");exception_decisions={};resolutions={}
    if attestation_ref is None:gaps.append("independent_run_attestation_missing")
    else:
        try:external["run_attestation"]=verify_attestation(attestation_ref,context,policy,target,evidence,dataset,snapshot,now)
        except (Refusal,TypeError,KeyError):gaps.append("independent_run_attestation_invalid")
    blocking=[]
    for item in groups:
        fp=item["fingerprint"]
        if fp in resolutions:item["resolution"]="independently_resolved"
        elif fp in exception_decisions:item["resolution"]="exception_approved"
        elif item["effective_severity"] in approved["blocking_severities"]:blocking.append(fp)
    status="not-run" if not indexed else "error" if errors else "incomplete" if gaps else "with-findings" if blocking else "pass"
    value={"schema_version":"1.0","kind":"target-security-decision","subject_sha256":digest(canonical(target)),
           "snapshot_id":target["snapshot_id"],"source_sha256":target["source_sha256"],"policy_sha256":policy.sha256,
           "model_bundle_id":model_bundle_id,
           "status":status,"blocking_fingerprints":blocking,"errors":sorted(set(errors)),"gaps":sorted(set(gaps)),
           "evidence_sha256":{k:v.sha256 for k,v in sorted(indexed.items())},"freshness":dataset,"groups":groups,
           "exceptions":exception_decisions,"resolutions":resolutions,"external_receipts":external,
           "evaluation_only":True,"execution_enabled":False,"at":now.isoformat()}
    return dict(value,decision_sha256=digest(canonical(value)))
