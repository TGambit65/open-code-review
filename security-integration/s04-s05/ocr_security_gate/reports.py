# SPDX-License-Identifier: Apache-2.0
"""Explicit public projection and inert local formats. No file writes or uploads."""
from dataclasses import dataclass
import html
import json
from ocr_security.broker import Broker
from ocr_security.common import Refusal, canonical, digest, fields, sha, integer, utc, parse_json
from ocr_security.views import Views
from ocr_security.snapshot import Snapshot, validate_snapshot
from ocr_security_adapters.reviewer import validate_bundle
from .contracts import ADAPTERS, SEVERITIES, choice, sequence, token
from .evidence import index


@dataclass(frozen=True)
class PublicReport:
    document: bytes
    sha256: str

    def value(self):
        from ocr_security_adapters.data import bounded_json
        if digest(self.document)!=sha(self.sha256):raise Refusal("public_report_identity_mismatch")
        value=bounded_json(self.document)
        fields(value,("schema_version","kind","decision","evidence","datasets","findings","excerpts","limitations"))
        if value["kind"]!="sanitized-combined-security-report" or value["schema_version"]!="1.0":raise Refusal("invalid_public_report")
        return value


def project(decision,evidence,views,snapshot,excerpt_ranges=()):
    if not isinstance(views,Views) or not isinstance(snapshot,Snapshot):raise Refusal("bound_report_views_required")
    validate_snapshot(snapshot)
    bundle=views.model
    validate_bundle(bundle)
    expected=dict(decision);identity=expected.pop("decision_sha256",None)
    if digest(canonical(expected))!=sha(identity):raise Refusal("stale_decision")
    fields(expected,("schema_version","kind","subject_sha256","snapshot_id","source_sha256","policy_sha256","model_bundle_id","status",
                     "blocking_fingerprints","errors","gaps","evidence_sha256","freshness","groups","exceptions","resolutions",
                     "external_receipts","evaluation_only","execution_enabled","at"))
    choice(decision["status"],("pass","with-findings","incomplete","error","not-run"));utc(decision["at"])
    if decision["execution_enabled"] is not False or decision["evaluation_only"] is not True:raise Refusal("unsafe_decision")
    indexed=index(evidence)
    if decision["evidence_sha256"]!={name:item.sha256 for name,item in indexed.items()}:raise Refusal("report_evidence_mismatch")
    private=parse_json(views.private_evidence,8388608)
    if (type(private) is not dict or decision["snapshot_id"]!=snapshot.snapshot_id or private.get("snapshot_id")!=snapshot.snapshot_id
        or private.get("model_bundle_id")!=bundle.bundle_id
        or tuple(views.scanner_inputs)!=tuple((item.opaque_id,item.content) for item in snapshot.selected)
        or {item.opaque_id for item in bundle.items}!={item.opaque_id for item in snapshot.selected}):
        raise Refusal("report_transformation_mismatch")
    transformation_sha256=digest(views.private_evidence)
    if decision["model_bundle_id"] is None:
        if excerpt_ranges or any(item.value()["private_findings"] for item in indexed.values()):
            raise Refusal("report_bundle_binding_missing")
    elif sha(decision["model_bundle_id"])!=bundle.bundle_id:
        raise Refusal("report_bundle_mismatch")
    for item in indexed.values():
        record=item.value()
        if record.get("snapshot_id") not in (None,snapshot.snapshot_id):raise Refusal("report_snapshot_mismatch")
        if record["process_status"]!="parser_error" and record.get("snapshot_id") is None:raise Refusal("report_snapshot_binding_missing")
        recorded=record.get("model_bundle_id")
        if recorded is not None and recorded!=bundle.bundle_id:raise Refusal("report_bundle_mismatch")
        if record["process_status"]!="parser_error" and recorded is None:raise Refusal("report_bundle_binding_missing")
        transformed=record.get("transformation_sha256") if item.adapter=="ocr" else record.get("pins",{}).get("transformation_sha256")
        if transformed is not None and transformed!=transformation_sha256:raise Refusal("report_transformation_mismatch")
        if record["process_status"]!="parser_error" and transformed is None:raise Refusal("report_transformation_binding_missing")
    model_ids={x.opaque_id for x in bundle.items}
    summaries=[]
    for name,item in sorted(indexed.items()):
        value=item.value()
        pins={}
        for key,pin in value.get("pins",{}).items():
            if key=="view":pins[key]=choice(pin,("scanner","model"))
            elif pin=="not_applicable" and key in ("rule_pin","database_pin"):pins[key]=pin
            else:pins[key]=sha(pin)
        if name=="ocr":pins={token(k):sha(v) for k,v in value.get("asset_pins",[])}
        summaries.append({"adapter":name,"evidence_sha256":item.sha256,"process_status":choice(value["process_status"],
            ("success","unknown","timeout","partial","skipped","stale","parser_error","error","unsupported")),
            "completeness":choice(value["completeness"],("complete","incomplete","unknown")),"pins":pins})
    findings=[]
    for group in sequence(decision["groups"],1024):
        confirmations=[]
        for observation in sequence(group["observations"],4096):
            # No path, rule body, reason, actor, original text or native message is copied.
            location=observation["location"];locations=[]
            current_evidence=indexed.get(observation["adapter"])
            current_location=(observation["snapshot_id"]==decision["snapshot_id"] and current_evidence is not None
                              and observation["evidence_sha256"]==current_evidence.sha256)
            if not current_location:
                pass  # Historical locations are not released by the current bundle.
            elif observation["adapter"]=="ocr":
                for ref in location["references"]:
                    if ref["item_id"] not in model_ids:raise Refusal("unreleased_report_location")
                    locations.append({"item_id":ref["item_id"],"role":choice(ref["role"],("source_lines","sink_lines")),
                                      "line":integer(ref["line"],1,2**31)})
            else:
                if location["item_id"] not in model_ids:raise Refusal("unreleased_report_location")
                positions=[]
                for pair in sequence(location["ranges"],4096):
                    if type(pair) is not list or len(pair)!=2:raise Refusal("invalid_report_range")
                    positions.append([integer(pair[0],1,2**31),integer(pair[1],pair[0],2**31)])
                locations.append({"item_id":location["item_id"],"ranges":positions})
            confirmations.append({"observation_id":sha(observation["observation_id"]),"adapter":choice(observation["adapter"],ADAPTERS),
                "severity":choice(observation["severity"],SEVERITIES),"confidence":choice(observation["confidence"],("high","medium","low","unknown")),
                "rule_sha256":sha(observation["rule_sha256"]),"evidence_sha256":sha(observation["evidence_sha256"]),"locations":locations,
                "location_state":"current_opaque_ids" if current_location else "historical_withheld"})
        findings.append({"fingerprint":sha(group["fingerprint"]),"severity":choice(group["effective_severity"],SEVERITIES) if group["effective_severity"] else None,
                         "current_severity":choice(group["current_severity"],SEVERITIES) if group["current_severity"] else None,
                         "effective_severity":choice(group["effective_severity"],SEVERITIES) if group["effective_severity"] else None,
                         "blocking":group["fingerprint"] in decision["blocking_fingerprints"],
                         "first_seen":utc(group["first_seen"]).isoformat(),"current":group["current"],
                         "resolution":choice(group["resolution"],("unresolved","independently_resolved","exception_approved","not_observed_currently_unresolved")),
                         "independent_detector_count":integer(group["independent_detector_count"],0,4),"confirmations":confirmations})
    if type(excerpt_ranges) is not tuple or len(excerpt_ranges)>64:raise Refusal("invalid_excerpt_selection")
    excerpts=[];broker=Broker(bundle);total=0
    for item_id,surface,start,end in excerpt_ranges:
        if item_id not in model_ids or surface in ("filename","search"):raise Refusal("unsupported_excerpt")
        value=broker.read(surface,item_id,start,end)
        if value["status"] not in ("success","partial"):raise Refusal("broker_refused")
        content=value["content"];total+=len(content.encode("utf-8"))
        if total>65536:raise Refusal("report_excerpt_limit")
        excerpts.append({"item_id":item_id,"start":start,"end":end,"content":content,"state":value["status"]})
    datasets=[]
    for item in decision["freshness"]["datasets"]:
        # Dataset labels are approved policy tokens; hashes/timestamps are explicit.
        datasets.append({"dataset":token(item["dataset"]),"state":choice(item["state"],
                         ("current","absent","unsupported","future","expired","rollback","acquisition_failed")),
                         "artifact_sha256":sha(item["artifact_sha256"]) if item["artifact_sha256"] else None,
                         "created_at":utc(item["created_at"]).isoformat() if item["created_at"] else None,
                         "expires_at":utc(item["expires_at"]).isoformat() if item["expires_at"] else None})
    public={"schema_version":"1.0","kind":"sanitized-combined-security-report",
            "decision":{"status":decision["status"],"decision_sha256":identity,"snapshot_id":sha(decision["snapshot_id"]),
                        "policy_sha256":sha(decision["policy_sha256"]),"source_sha256":sha(decision["source_sha256"]),
                        "model_bundle_id":decision["model_bundle_id"],
                        "at":utc(decision["at"]).isoformat(),"gaps":[token(x) for x in sequence(decision["gaps"],128)],
                        "errors":[token(x) for x in sequence(decision["errors"],128)],"execution_enabled":False},
            "evidence":summaries,"datasets":datasets,"findings":findings,"excerpts":excerpts,
            "limitations":["Original paths, native free text and raw outputs withheld.",
                           "Excerpts come only from the approved sanitized broker.",
                           "Evaluation is not execution authority or production certification.",
                           "SARIF not selected; no upload or remote assets."]}
    raw=canonical(public)
    if len(raw)>1048576:raise Refusal("report_output_limit")
    return PublicReport(raw,digest(raw))


def render(report,format):
    if not isinstance(report,PublicReport):raise Refusal("sanitized_report_required")
    value=report.value();choice(format,("json","markdown","html"))
    payload=json.dumps(value,sort_keys=True,ensure_ascii=True,indent=2,allow_nan=False)
    # Also safe if a JSON document is accidentally embedded into HTML later.
    payload=payload.replace("<","\\u003c").replace(">","\\u003e").replace("&","\\u0026")
    if format=="json":output=payload+"\n"
    elif format=="markdown":
        # Every dynamic character is inside an indented code block, including newlines.
        output="# Security evidence report\n\n"+"\n".join("    "+line for line in payload.splitlines())+"\n"
    else:
        status=html.escape(value["decision"]["status"],quote=True)
        output='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Security evidence report</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#182230;background:#fff}h1{font-size:1.6rem}.status{border:2px solid #555;padding:.7rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font:13px/1.5 ui-monospace,monospace;background:#f3f5f7;padding:1rem;border:1px solid #ddd}@media print{body{margin:0;max-width:none;font-size:11pt}pre{background:white;font-size:8pt;break-inside:auto}}</style></head><body><h1>Security evidence report</h1><p class="status">Assessment: '''+status+'''</p><p>Local inert report. No links, scripts, remote assets or automatic uploads. Original paths and raw scanner text are withheld.</p><h2>Complete evidence</h2><pre>'''+html.escape(payload,quote=True)+'''</pre></body></html>\n'''
    if len(output.encode("utf-8"))>8*1048576:raise Refusal("rendered_output_limit")
    return output.encode("utf-8")


def export_sarif(*args,**kwargs):
    raise Refusal("sarif_not_selected")


def upload(*args,**kwargs):
    raise Refusal("separate_upload_authority_required")
