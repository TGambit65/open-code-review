# SPDX-License-Identifier: Apache-2.0
"""Exactly-one consolidated review intent; no review client or repository mutation."""
from ocr_security.common import Refusal, canonical, digest, fields, git_id, sha, text
from .contracts import sequence, choice, unique


def reconcile_reviews(entries,head,final_freeze):
    git_id(head)
    if type(final_freeze) is not bool:raise Refusal("invalid_final_freeze")
    rows=sequence(entries,1024);seen=set();manual=0;current=False;pending=False;prior=False
    for item in rows:
        fields(item,("event_id","origin","head","state","receipt_sha256","intent_sha256"))
        text(item["event_id"]);git_id(item["head"]);sha(item["receipt_sha256"])
        choice(item["origin"],("automatic","root_intentional"));choice(item["state"],("in_flight","uncertain","complete","failed","cancelled","denied"))
        if item["event_id"] in seen:raise Refusal("duplicate_review_event")
        seen.add(item["event_id"])
        if item["origin"]=="root_intentional":sha(item["intent_sha256"]);manual+=1
        elif item["intent_sha256"] is not None:raise Refusal("unexpected_review_intent")
        pending=pending or item["state"] in ("in_flight","uncertain")
        current=current or item["state"]=="complete" and item["head"]==head
        prior=True
    if manual>1:decision="hold_duplicate_intentional_reviews"
    elif not final_freeze:decision="defer_lookup_until_final_freeze"
    elif pending:decision="reconcile_existing_review_no_request"
    elif current:decision="current_head_coverage_present"
    elif prior:decision="hold_review_history_or_current_head_conflict"
    else:decision="root_may_consider_single_included_review"
    return {"kind":"consolidated-review-decision","head":head,"decision":decision,"current_head_covered":current and not pending and manual<=1,
            "intentional_requests":manual,"additional_request_permitted":False,"requires_root":True,"request_sent":False,
            "review_ledger_sha256":digest(canonical(rows))}


def review_intent(review_decision,repository_id,draft_pr,authorization_sha256):
    from .contracts import integer
    if review_decision["decision"]!="root_may_consider_single_included_review":raise Refusal("review_request_not_eligible")
    integer(repository_id,1);integer(draft_pr,1);sha(authorization_sha256)
    value={"kind":"root-only-review-intent","repository_id":repository_id,"draft_pr":draft_pr,
           "head":git_id(review_decision["head"]),"review_ledger_sha256":sha(review_decision["review_ledger_sha256"]),
           "authorization_sha256":authorization_sha256,"exactly_one":True,"sent":False}
    return dict(value,intent_sha256=digest(canonical(value)))


def merge_handoff(head,review_decision,checks,required_checks,conflicts,permission_receipt_sha256,holds,qualification):
    git_id(head)
    if type(conflicts) is not bool:raise Refusal("invalid_merge_state")
    required=unique(required_checks,256);rows=sequence(checks,1024);observed={};blockers=[]
    for item in rows:
        fields(item,("name","head","status","receipt_sha256"));text(item["name"]);git_id(item["head"]);sha(item["receipt_sha256"])
        choice(item["status"],("passed","failed","pending","skipped","cancelled","unknown"))
        if item["name"] in observed:raise Refusal("duplicate_check_state")
        observed[item["name"]]=item
    for name in required:
        if name not in observed or observed[name]["head"]!=head or observed[name]["status"]!="passed":blockers.append("required_check_unsatisfied")
    if review_decision.get("head")!=head or review_decision.get("current_head_covered") is not True:blockers.append("current_head_review_missing")
    if conflicts:blockers.append("merge_conflicts")
    if permission_receipt_sha256 is None:blockers.append("merge_authority_missing")
    else:sha(permission_receipt_sha256)
    for hold in sequence(holds,256):text(hold,128)
    if holds:blockers.append("exact_action_holds")
    if qualification!="qualified":blockers.append("integration_qualification_held")
    return {"kind":"root-only-merge-handoff","head":head,"status":"held" if blockers else "ready_for_root_reconciliation",
            "blockers":sorted(set(blockers)),"requires_root":True,"merge_executed":False,"protections_changed":False,
            "extra_review_requested":False,"paid_capacity_used":False}
