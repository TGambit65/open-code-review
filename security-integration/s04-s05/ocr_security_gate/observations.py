# SPDX-License-Identifier: Apache-2.0
"""Exact, conservative grouping. Independent confirmations are never discarded."""
from ocr_security.common import Refusal, canonical, digest, fields, sha, utc
from .contracts import pinned, timestamp, sequence, choice, SEVERITIES
from .evidence import index


def collect(evidence,snapshot,now):
    timestamp(now)
    output=[]
    for adapter,item in sorted(index(evidence).items()):
        value=item.value()
        if value.get("snapshot_id")!=snapshot.snapshot_id:
            if value["process_status"]=="parser_error":continue
            raise Refusal("observation_snapshot_mismatch")
        for finding in value["private_findings"]:
            if adapter=="ocr":
                chunks={x["chunk_id"]:x for x in value["chunks"]}
                own=chunks[finding["chunk_id"]]
                references=[]
                for role in ("source_lines","sink_lines"):
                    for position in finding[role]:
                        part=chunks[position["chunk_id"]] if type(position) is dict else own
                        line=position["line"] if type(position) is dict else position
                        entry=next((x for x in snapshot.selected if x.opaque_id==part["id"]),None)
                        if entry is None:raise Refusal("unbound_observation")
                        references.append({"role":role,"item_id":part["id"],"line":line,
                                           "path_sha256":digest(entry.path.encode()),"side":entry.side})
                location={"references":references}
                rule_hash=digest(canonical(["semantic",finding["id"]]))
                state=finding["disposition"]
                provenance={"accounting_sha256":value["accounting_sha256"],"handoff_id":value["handoff_id"]}
            else:
                identity=finding["evidence_identity"]
                key=tuple(identity[k] for k in ("path","change_kind","base_blob","head_blob","side"))
                entry=next((x for x in snapshot.selected if x.identity==key),None)
                if entry is None:raise Refusal("unbound_observation")
                location={"item_id":entry.opaque_id,"path_sha256":digest(identity["path"].encode()),
                          "change_kind":identity["change_kind"],"side":identity["side"],"ranges":identity["ranges"]}
                rule_hash=digest(finding["provenance"]["rule_id"].encode())
                state=finding["resolution_state"]
                provenance={k:v for k,v in finding["provenance"].items() if k!="rule_id"}
            # Default grouping never guesses equivalence between tools or different rules.
            stable_location=({"references":[{k:v for k,v in r.items() if k!="item_id"} for r in location["references"]]}
                             if adapter=="ocr" else {k:v for k,v in location.items() if k!="item_id"})
            stable=digest(canonical([snapshot.repository_id,adapter,rule_hash,stable_location]))
            record={"adapter":adapter,"fingerprint":stable,"severity":finding["severity"],"confidence":finding["confidence"],
                    "location":location,"rule_sha256":rule_hash,"claimed_resolution":state,"provenance":provenance,
                    "evidence_sha256":item.sha256,"snapshot_id":snapshot.snapshot_id,
                    "observed_at":max((e["at"] for e in value["events"].values()),key=utc) if adapter=="ocr" else value["at"]}
            record["observation_id"]=digest(canonical([item.sha256,finding]))
            output.append(record)
    if len(output)>4096 or len({x["observation_id"] for x in output})!=len(output):raise Refusal("duplicate_or_excess_observation")
    return output


def load_correlations(ref,context,policy,target,observations):
    value,pin=pinned(ref,context,"approved-finding-correlations")
    fields(value,("schema_version","kind","policy_sha256","subject_sha256","approval_receipt_sha256","groups"))
    if value["policy_sha256"]!=policy.sha256 or value["subject_sha256"]!=digest(canonical(target)):
        raise Refusal("stale_correlation")
    sha(value["approval_receipt_sha256"])
    known={x["observation_id"] for x in observations}; seen=set();mapping={}
    for group in sequence(value["groups"],1024):
        fields(group,("fingerprint","observation_ids","equivalence_evidence_sha256"));fp=sha(group["fingerprint"])
        sha(group["equivalence_evidence_sha256"])
        ids=sequence(group["observation_ids"],256)
        if len(ids)<2:raise Refusal("empty_corroboration")
        for identity in ids:
            sha(identity)
            if identity not in known or identity in seen:raise Refusal("unbound_correlation")
            seen.add(identity);mapping[identity]=fp
    return mapping,pin


def group(observations,correlations=None,previous=None):
    correlations={} if correlations is None else correlations
    previous=[] if previous is None else previous
    if type(correlations) is not dict:raise Refusal("invalid_correlation")
    known={x["observation_id"] for x in observations}
    if not set(correlations)<=known:raise Refusal("unbound_correlation")
    old={}
    for row in sequence(previous,1024):
        fields(row,("fingerprint","first_seen","observations"));fp=sha(row["fingerprint"]);utc(row["first_seen"])
        if fp in old:raise Refusal("duplicate_history")
        # History is retained evidence only, never a resolution or coverage source.
        old[fp]={"first_seen":row["first_seen"],"observations":sequence(row["observations"],4096)}
    buckets={}
    for observation in sequence(observations,4096):
        fp=sha(correlations.get(observation["observation_id"],observation["fingerprint"]))
        buckets.setdefault(fp,[]).append(observation)
    output=[]
    for fp in sorted(set(buckets)|set(old)):
        current=buckets.get(fp,[]);history=old.get(fp,{"observations":[],"first_seen":None})
        seen={};timeline=[]
        for item in history["observations"]+current:
            identity=sha(item["observation_id"])
            if identity in seen:
                if canonical(seen[identity])!=canonical(item):raise Refusal("conflicting_observation_identity")
                continue
            seen[identity]=item;timeline.append(item)
        dates=[utc(x["observed_at"]) for x in timeline]
        if history["first_seen"]:dates.append(utc(history["first_seen"]))
        severity=min((x["severity"] for x in current),key=SEVERITIES.index) if current else None
        effective_severity=min((x["severity"] for x in timeline),key=SEVERITIES.index) if timeline else None
        output.append({"fingerprint":fp,"first_seen":min(dates).isoformat() if dates else None,
                       "current_observation_ids":[x["observation_id"] for x in current],"observations":timeline,
                       "current_severity":severity,"effective_severity":effective_severity,
                       "required_observation_ids":sorted(seen),"current":bool(current),
                       "resolution":"unresolved" if current else "not_observed_currently_unresolved",
                       "independent_detector_count":len({x["adapter"] for x in current}),
                       "conflicting_claims":len({x["claimed_resolution"] for x in current})>1})
    return output


def history_document(groups,policy,target,now):
    """A proposed private retention document. Saving/adopting it is a separate action."""
    timestamp(now)
    return {"schema_version":"1.0","kind":"private-finding-history","policy_sha256":policy.sha256,
            "history_scope_sha256":policy.value()["history_scope_sha256"],
            "repository_id":target["repository_id"],"source_sha256":target["source_sha256"],"at":now.isoformat(),
            "groups":[{"fingerprint":g["fingerprint"],"first_seen":g["first_seen"],"observations":g["observations"]} for g in groups]}


def load_history(ref,context,policy,target,now):
    value,pin=pinned(ref,context,"private-finding-history")
    fields(value,("schema_version","kind","policy_sha256","history_scope_sha256","repository_id","source_sha256","at","groups"))
    approved=policy.value()
    if (pin!=approved["prior_history_sha256"] or value["history_scope_sha256"]!=approved["history_scope_sha256"]
        or value["repository_id"]!=target["repository_id"]):
        raise Refusal("stale_history_scope")
    # Historical source and policy are retained, not confused with the new run.
    sha(value["policy_sha256"]);sha(value["source_sha256"])
    if utc(value["at"])>timestamp(now):raise Refusal("future_history")
    for row in sequence(value["groups"],1024):
        fields(row,("fingerprint","first_seen","observations"));sha(row["fingerprint"])
        if utc(row["first_seen"])>now:raise Refusal("future_observation")
        for item in sequence(row["observations"],4096):
            fields(item,("adapter","fingerprint","severity","confidence","location","rule_sha256","claimed_resolution","provenance",
                         "evidence_sha256","snapshot_id","observed_at","observation_id"))
            choice(item["adapter"],("ocr","opengrep","gitleaks","osv"));choice(item["severity"],SEVERITIES)
            choice(item["confidence"],("high","medium","low","unknown"))
            choice(item["claimed_resolution"],("open","claimed_resolved","exception_requested","contested","needs_context","claimed_false_positive"))
            for key in ("fingerprint","rule_sha256","evidence_sha256","snapshot_id","observation_id"):sha(item[key])
            if utc(item["observed_at"])>now:raise Refusal("future_observation")
    return value["groups"],pin
