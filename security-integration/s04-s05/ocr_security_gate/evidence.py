# SPDX-License-Identifier: Apache-2.0
"""Private bounded ingestion. Evidence does not become public by parsing it."""
from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest, fields, sha, integer, utc
from ocr_security.results import parse_result
from ocr_security.coverage import assess_coverage
from ocr_security_adapters.data import bounded_json, choice, sequence
from ocr_security_adapters import reviewer, projection, ocr
from .contracts import ADAPTERS, pinned


@dataclass(frozen=True)
class Evidence:
    adapter: str
    sha256: str
    private_document: bytes

    def value(self):
        if self.adapter not in ADAPTERS or digest(self.private_document)!=sha(self.sha256):
            raise Refusal("evidence_identity_mismatch")
        return bounded_json(self.private_document)


def _evidence(adapter,value):
    raw=canonical(value)
    return Evidence(adapter,digest(raw),raw)


def _failed_input_identity(raw):
    if type(raw) is not bytes:
        return {"sha256":None,"bytes":None,"state":"not_byte_input"}
    if len(raw)>16777216:
        return {"sha256":None,"bytes":len(raw),"state":"full_digest_unavailable_oversize",
                "prefix_sha256":digest(raw[:65536]),"prefix_bytes":65536}
    return {"sha256":digest(raw),"bytes":len(raw),"state":"exact_digest"}


def failure(adapter,code="untrusted_output_rejected",inputs=None,snapshot=None,adapter_policy=None,expected_pins=None):
    choice(adapter,ADAPTERS)
    identities={}
    if inputs is not None:
        fields(inputs,("preview","rule") if adapter=="ocr" else ("scanner",))
        identities={name:_failed_input_identity(raw) for name,raw in inputs.items()}
    pins={}
    if type(expected_pins) is dict:
        for name in ("tool_sha256","profile_sha256","rule_pin","database_pin","transformation_sha256","view"):
            value=expected_pins.get(name)
            try:
                pins[name]=(choice(value,("scanner","model")) if name=="view" else
                            value if value=="not_applicable" and name in ("rule_pin","database_pin") else sha(value))
            except Refusal:pins[name]=None
    return _evidence(adapter,{"adapter":adapter,"process_status":"parser_error","completeness":"unknown",
                              "failure_code":Refusal(code).code,"private_findings":[],"raw_output_forwarded":False,
                              "input_identities":identities,"expected_pins":pins,
                              "snapshot_id":snapshot.snapshot_id if snapshot is not None else None,
                              "snapshot_policy_sha256":snapshot.policy_sha256 if snapshot is not None else None,
                              "adapter_policy_sha256":adapter_policy.sha256 if adapter_policy is not None else None,
                              "full_input_identity_available":bool(identities) and all(x["sha256"] is not None for x in identities.values())})


def scanner(raw,adapter,snapshot,views,expected_pins,adapter_policy):
    """No automatic parser fallback or partial coercion. Pins come from trusted setup."""
    choice(adapter,("opengrep","gitleaks","osv"))
    try:
        value=bounded_json(raw)
        fields(value,("adapter","process_status","completeness","result","gaps","raw_report_forwarded",
                      "native_execution_receipt_sha256","plan_sha256","adapter_policy_sha256","target_security_acceptance"))
        if value["adapter"]!=adapter or value["raw_report_forwarded"] is not False or value["target_security_acceptance"]!="NOT_ASSESSED":
            raise Refusal("untrusted_adapter_envelope")
        if value["adapter_policy_sha256"]!=adapter_policy.sha256 or snapshot.policy_sha256!=adapter_policy.snapshot_policy_sha256:
            raise Refusal("stale_adapter_policy")
        sha(value["native_execution_receipt_sha256"]);sha(value["plan_sha256"])
        sequence(value["gaps"],4096)
        parsed=parse_result(canonical(value["result"]),snapshot,views,expected_pins)
        if (value["process_status"],value["completeness"])!=(parsed["process"]["status"],parsed["completeness"]):
            raise Refusal("conflicting_adapter_state")
        coverage=assess_coverage(snapshot,parsed["coverage"])
        complete=parsed["completeness"]=="complete" and coverage.complete and not value["gaps"]
        return _evidence(adapter,{"adapter":adapter,"input_sha256":digest(raw),"snapshot_id":snapshot.snapshot_id,
              "model_bundle_id":views.model.bundle_id,
              "adapter_policy_sha256":adapter_policy.sha256,"process_status":parsed["process"]["status"],
              "exit_code":parsed["process"]["exit_code"],"completeness":"complete" if complete else "incomplete",
              "pins":dict(expected_pins),"plan_sha256":value["plan_sha256"],
              "native_execution_receipt_sha256":value["native_execution_receipt_sha256"],"at":parsed["event"]["at"],
              "private_coverage":parsed["coverage"],"private_findings":parsed["findings"],
              "gap_count":len(value["gaps"]),"raw_output_forwarded":False})
    except (Refusal,KeyError,TypeError,ValueError,OverflowError):
        return failure(adapter,inputs={"scanner":raw},snapshot=snapshot,adapter_policy=adapter_policy,expected_pins=expected_pins)


def independent_review(preview_raw,rules_raw,events,snapshot,views,adapter_policy,inventory,approved_rule,records,writer_id,reviewer_id,
                       rule_authority_ref=None,context=None):
    """Compose actual OCR parser outputs and separate reviewer accounting, never run either."""
    try:
        reviewer.validate_bundle(views.model)
        authority,authority_pin=pinned(rule_authority_ref,context,"approved-ocr-rule-body")
        fields(authority,("schema_version","kind","adapter_policy_sha256","rules_asset_sha256","body_sha256",
                          "snapshot_id","model_bundle_id","projection_suffixes"))
        if (type(approved_rule) is not str or authority["body_sha256"]!=digest(approved_rule.encode("utf-8"))
            or authority["rules_asset_sha256"]!=inventory.one("rules").sha256 or authority["adapter_policy_sha256"]!=adapter_policy.sha256
            or authority["snapshot_id"]!=snapshot.snapshot_id or authority["model_bundle_id"]!=views.model.bundle_id):
            raise Refusal("unbound_review_rules")
        transformation=bounded_json(views.private_evidence)
        if (transformation.get("snapshot_id")!=snapshot.snapshot_id or transformation.get("model_bundle_id")!=views.model.bundle_id
            or tuple(views.scanner_inputs)!=tuple((x.opaque_id,x.content) for x in snapshot.selected)
            or {x.opaque_id for x in views.model.items}!={x.opaque_id for x in snapshot.selected}):
            raise Refusal("stale_review_transformation")
        view=review_projection(views.model,authority["projection_suffixes"])
        preview=ocr.parse_preview(preview_raw,view)
        rules=ocr.parse_rules(rules_raw,view,approved_rule)
        plans=[ocr.plan(op,snapshot.snapshot_id,view,adapter_policy,inventory) for op in ("preview","rule")]
        packet=reviewer.handoff(views.model,adapter_policy,writer_id,reviewer_id)
        accounting=reviewer.assess_review(packet,records,reviewer_id)
        fields(events,("preview","rule"))
        native_ok=True
        for op,raw in (("preview",preview_raw),("rule",rules_raw)):
            fields(events[op],("at","exit_code","process_status","report_sha256","native_execution_receipt_sha256"))
            ev=events[op];utc(ev["at"]);integer(ev["exit_code"],-255,255)
            choice(ev["process_status"],("success","error","partial","timeout","unknown"))
            if sha(ev["report_sha256"])!=digest(raw):raise Refusal("stale_ocr_output")
            sha(ev["native_execution_receipt_sha256"])
            native_ok=native_ok and ev["process_status"]=="success" and ev["exit_code"]==0
        # Native preview is deliberately always labelled incomplete by S02: it is not
        # semantic review. Combine its exact selection with separate deep accounting.
        selected_complete=not preview["gaps"] and set(preview["selected_ids"])=={x.opaque_id for x in snapshot.selected}
        complete=native_ok and selected_complete and rules["effective_policy_matches"] is True and accounting["completeness"]=="complete"
        return _evidence("ocr",{"adapter":"ocr","snapshot_id":snapshot.snapshot_id,"adapter_policy_sha256":adapter_policy.sha256,
             "process_status":"success" if native_ok else "error","completeness":"complete" if complete else "incomplete",
             "events":events,"plans":[x.identity for x in plans],"asset_pins":inventory.pins(),
             "handoff_id":packet["handoff_id"],"model_bundle_id":views.model.bundle_id,"writer_id":writer_id,"reviewer_id":reviewer_id,
             "rule_authority_sha256":authority_pin,"transformation_sha256":digest(views.private_evidence),
             "projection_sha256":view.identity,"projection_suffixes":authority["projection_suffixes"],
             "accounting_sha256":digest(canonical(accounting)),"chunks":packet["chunks"],
             "private_findings":accounting["findings"],"gap_count":len(accounting["gaps"])+len(preview["gaps"]),
             "independent_identity_attested_externally":False,"raw_output_forwarded":False})
    except (Refusal,KeyError,TypeError,ValueError,OverflowError):
        return failure("ocr",inputs={"preview":preview_raw,"rule":rules_raw},snapshot=snapshot,adapter_policy=adapter_policy)


def index(evidence):
    if type(evidence) is not tuple or len(evidence)>4:raise Refusal("invalid_evidence_set")
    result={}
    for item in evidence:
        if not isinstance(item,Evidence) or item.adapter in result:raise Refusal("duplicate_or_invalid_evidence")
        value=item.value()
        if value.get("adapter")!=item.adapter:raise Refusal("wrong_evidence_adapter")
        result[item.adapter]=item
    return result


def review_projection(bundle,suffixes):
    """Use an exact externally approved suffix map, never relabel to force selection.

    .txt and .md are excluded by pinned OCR. Their actual exclusions stay gaps.
    The host approves truthful type correspondence before native use.
    """
    reviewer.validate_bundle(bundle)
    if type(suffixes) is not dict or set(suffixes)!={item.opaque_id for item in bundle.items}:
        raise Refusal("explicit_projection_suffixes_required")
    return projection.sanitized_projection(bundle,suffixes)
