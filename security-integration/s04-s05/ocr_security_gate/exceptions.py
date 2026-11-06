# SPDX-License-Identifier: Apache-2.0
"""Only explicit externally pinned, owned, exact-scope decisions may affect findings."""
from ocr_security.common import Refusal, canonical, digest, fields, sha, text, utc
from .contracts import pinned, bind_policy, timestamp, sequence, unique


def decisions(refs,context,policy,target,groups,now,kind="finding-exception"):
    approved=bind_policy(policy,target);now=timestamp(now)
    if kind not in ("finding-exception","finding-resolution"):raise Refusal("unsupported_decision_kind")
    if type(refs) is not tuple or len(refs)>1024:raise Refusal("invalid_decision_refs")
    current={g["fingerprint"]:set(g["required_observation_ids"]) for g in groups}
    result={}
    for ref in refs:
        value,pin=pinned(ref,context,"s04-"+kind)
        fields(value,("schema_version","kind","policy_sha256","subject_sha256","fingerprint","observation_ids","owner","reason",
                      "issued_at","expires_at","scope","waives_controls","authorization_receipt_sha256","evidence_sha256","state"))
        fp=sha(value["fingerprint"])
        if value["policy_sha256"]!=policy.sha256 or value["subject_sha256"]!=digest(canonical(target)):
            raise Refusal("stale_finding_decision")
        ids={sha(x) for x in unique(value["observation_ids"],256)}
        if fp not in current or ids!=current[fp] or fp in result:raise Refusal("wrong_finding_scope")
        if value["owner"] not in approved["exception_owners"]:raise Refusal("unauthorized_finding_owner")
        text(value["owner"]);text(value["reason"],1024)
        begin,end=utc(value["issued_at"]),utc(value["expires_at"])
        if not begin<=now<end or (end-begin).total_seconds()>approved["maximum_exception_seconds"]:
            raise Refusal("expired_or_excess_decision")
        if value["scope"]!="exact_finding_observations" or value["waives_controls"] is not False:
            raise Refusal("control_waiver_forbidden")
        sha(value["authorization_receipt_sha256"]);sha(value["evidence_sha256"])
        expected="exception_approved" if kind=="finding-exception" else "independently_resolved"
        if value["state"]!=expected:raise Refusal("unsupported_resolution_claim")
        result[fp]={"state":expected,"receipt_sha256":pin,"owner_sha256":digest(value["owner"].encode()),
                    "reason_sha256":digest(value["reason"].encode()),"expires_at":value["expires_at"],
                    "evidence_sha256":value["evidence_sha256"],"observation_ids":sorted(ids)}
    return result
