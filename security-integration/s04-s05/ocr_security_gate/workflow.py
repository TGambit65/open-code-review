# SPDX-License-Identifier: Apache-2.0
"""Root handoff data, not a scheduler, Git client, policy editor or action executor."""
from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest, fields, sha, git_id, relative_path, text
from .contracts import choice, sequence, unique

OUTCOMES=("not_attempted","in_flight","succeeded","failed","denied","uncertain","cancelled")


def payload(entries):
    rows=sequence(entries,4096);seen=set();eligible=[];held=[]
    for item in rows:
        fields(item,("path","sha256","eligible","hold_code"))
        path=relative_path(item["path"]);sha(item["sha256"])
        if path in seen:raise Refusal("duplicate_payload_path")
        seen.add(path)
        if type(item["eligible"]) is not bool:raise Refusal("invalid_payload_eligibility")
        if item["eligible"]:
            if item["hold_code"] is not None:raise Refusal("conflicting_payload_hold")
            eligible.append({"path":path,"sha256":item["sha256"]})
        else:
            text(item["hold_code"],128);held.append({"path_sha256":digest(path.encode()),"hold_code":item["hold_code"]})
    return {"eligible":sorted(eligible,key=lambda x:x["path"]),"held":held,
            "eligible_payload_sha256":digest(canonical(sorted(eligible,key=lambda x:x["path"])))}


def preservation_handoff(repository_id,branch,draft_pr,expected_head,entries,source_sha256,review_state,action_state="not_attempted"):
    from .contracts import integer,token
    integer(repository_id,1);text(branch,256);integer(draft_pr,1);git_id(expected_head);sha(source_sha256)
    choice(review_state,("pending","clean","findings","failed","unavailable"));choice(action_state,OUTCOMES)
    selected=payload(entries)
    action="root_preserve_eligible_source"
    if not selected["eligible"]:action="nothing_eligible"
    elif action_state in ("in_flight","uncertain","failed"):action="reconcile_exact_outcome"
    elif action_state in ("denied","cancelled"):action="retain_exact_hold"
    elif action_state=="succeeded":action="verify_preserved_identity"
    result={"kind":"root-preservation-handoff","repository_id":repository_id,"branch":branch,"draft_pr":draft_pr,
            "expected_head":expected_head,"source_sha256":source_sha256,**selected,"review_state":review_state,
            "next_action":action,"source_label":"untested" if review_state=="clean" else "untested_review_pending",
            "acceptance":"held","requires_root":True,"external_action_executed":False,
            "wait_for_batch_size":False,"review_lookup_required_for_preservation":False}
    return dict(result,handoff_sha256=digest(canonical(result)))


@dataclass(frozen=True)
class ActionRecord:
    target_sha256: str
    payload_sha256: str
    action: str
    outcome: str="not_attempted"
    attempts: int=0
    last_evidence_sha256: str | None=None
    known_not_executed: bool=False
    used_authorizations: tuple=()


def record_outcome(record,outcome,receipt_sha256,known_not_executed=False):
    if not isinstance(record,ActionRecord):raise Refusal("action_record_required")
    sha(record.target_sha256);sha(record.payload_sha256);sha(receipt_sha256)
    choice(record.action,("publish","request_review","merge"));choice(outcome,OUTCOMES)
    if type(known_not_executed) is not bool:raise Refusal("invalid_execution_knowledge")
    if outcome in ("uncertain","in_flight","succeeded") and known_not_executed:raise Refusal("contradictory_outcome")
    if outcome=="not_attempted" or record.outcome=="succeeded":raise Refusal("invalid_action_transition")
    from dataclasses import replace
    return replace(record,outcome=outcome,last_evidence_sha256=receipt_sha256,known_not_executed=known_not_executed)


def action_handoff(record,new_authorization_sha256=None):
    if not isinstance(record,ActionRecord):raise Refusal("action_record_required")
    sha(record.target_sha256);sha(record.payload_sha256);choice(record.action,("publish","request_review","merge"))
    choice(record.outcome,OUTCOMES)
    if record.outcome in ("uncertain","in_flight"):action="reconcile_exact_outcome"
    elif record.outcome=="succeeded":action="do_not_repeat"
    elif record.outcome in ("denied","cancelled","failed"):
        if not record.known_not_executed:action="reconcile_exact_outcome"
        elif new_authorization_sha256 is None or new_authorization_sha256==record.last_evidence_sha256 or new_authorization_sha256 in record.used_authorizations:
            action="retain_exact_hold"
        else:
            sha(new_authorization_sha256);action="root_consider_one_supported_retry"
    else:action="root_consider_initial_action"
    return {"action":action,"target_sha256":record.target_sha256,"payload_sha256":record.payload_sha256,
            "operation":record.action,"new_evidence_sha256":new_authorization_sha256,
            "requires_root":True,"permission_granted":False,"external_action_executed":False}


def begin_attempt(record,authorization_sha256):
    from dataclasses import replace
    sha(authorization_sha256)
    handoff=action_handoff(record,authorization_sha256)
    if handoff["action"] not in ("root_consider_initial_action","root_consider_one_supported_retry"):
        raise Refusal("action_not_retryable")
    return replace(record,outcome="in_flight",attempts=record.attempts+1,last_evidence_sha256=authorization_sha256,
                   known_not_executed=False,used_authorizations=record.used_authorizations+(authorization_sha256,))


def stage_summary(implementation,review,preservation,validation,acceptance="held"):
    choice(implementation,("pending","complete","failed"));choice(review,("pending","clean","findings","failed","unavailable"))
    choice(preservation,("pending","verified","failed","denied","uncertain"));choice(validation,("unrun","passed","failed","partial","blocked"))
    # Only independently authorized qualification can provide an acceptance decision.
    if acceptance!="held":raise Refusal("independent_acceptance_required")
    return {"implementation":implementation,"independent_review":review,"remote_preservation":preservation,
            "applicable_validation":validation,"acceptance":"held"}


def rollback():
    return {"integration_references":"disabled","existing_scheduler":"unchanged","hooks_ci_and_protections":"unchanged",
            "receipts":"retained","standard_ocr":"unchanged","security_coverage":"missing_visible","actions_executed":False}


def execute(*args,**kwargs):
    raise Refusal("root_external_action_required")
