# SPDX-License-Identifier: Apache-2.0
"""Bounded proposed decisions are documentation, never adoption authority."""
from dataclasses import dataclass
from ocr_security.common import Refusal, canonical, digest, fields, sha, git_id, text
from ocr_security_adapters.data import bounded_json, choice, sequence
from .registry import OPTIONAL, ALTERNATIVES

TASKS = {"betterleaks": "S06.01", "trivy": "S06.02", "agentshield": "S06.03",
         "semgrep": "S07.01", "bearer": "S07.02", "codeql": "S07.03", "anthropic_review": "S07.04",
         "snyk_agent_scan": "S07.05", "strix": "S07.06", "shannon": "S07.07"}
DECISIONS = {tool: "defer" for tool in OPTIONAL + ALTERNATIVES}
DECISIONS["semgrep"] = "alternative_only"
DECISIONS["strix"] = DECISIONS["shannon"] = "future_project"


@dataclass(frozen=True)
class Catalog:
    document: bytes
    sha256: str

    def value(self):
        return parse_catalog(self.document, self.sha256)


def _strings(value, maximum=64):
    rows = sequence(value, maximum)
    if not rows or any(type(row) is not str for row in rows) or len(set(rows)) != len(rows):
        raise Refusal("missing_or_duplicate_disposition_text")
    for row in rows:
        text(row, 2048)
    return rows


def parse_catalog(raw, expected_sha256):
    if type(raw) is not bytes or len(raw) > 1048576 or digest(raw) != sha(expected_sha256):
        raise Refusal("disposition_identity_mismatch")
    value = bounded_json(raw)
    fields(value, ("schema_version", "kind", "adoption_authority", "execution_enabled", "decisions"))
    if (value["schema_version"], value["kind"], value["adoption_authority"], value["execution_enabled"]) != (
        "1.0", "proposed-disabled-disposition-catalog", False, False):
        raise Refusal("unsafe_disposition_catalog")
    if value["adoption_authority"] is not False or value["execution_enabled"] is not False:
        raise Refusal("unsafe_disposition_catalog")
    seen = set()
    for row in sequence(value["decisions"], 10):
        fields(row, ("tool", "task_id", "decision", "implementation_selected", "registration_enabled", "qualification",
                     "source_repository", "research_commit", "research_release", "source_url", "license_observed",
                     "license_limit", "reason", "prohibited_modes", "reopen_conditions", "record", "protocol",
                     "availability", "evidence_basis"))
        tool = choice(row["tool"], OPTIONAL + ALTERNATIVES)
        if tool in seen or row["task_id"] != TASKS[tool] or row["decision"] != DECISIONS[tool]:
            raise Refusal("invalid_frozen_disposition")
        seen.add(tool)
        if row["implementation_selected"] is not False or row["registration_enabled"] is not False or row["qualification"] != "NOT_QUALIFIED":
            raise Refusal("candidate_adoption_forbidden")
        git_id(row["research_commit"])
        for key in ("source_repository", "source_url", "license_observed", "license_limit", "availability", "evidence_basis"):
            text(row[key], 2048)
        if row["research_release"] is not None:
            text(row["research_release"], 128)
        if row["record"] != "decisions/" + tool + ".json":
            raise Refusal("invalid_disposition_locator")
        if row["protocol"] != ("protocols/" + tool + ".json" if tool in OPTIONAL else None):
            raise Refusal("invalid_protocol_locator")
        for key in ("reason", "prohibited_modes", "reopen_conditions"):
            _strings(row[key])
    if seen != set(OPTIONAL + ALTERNATIVES):
        raise Refusal("missing_disposition")
    return value


def load_catalog(raw, expected_sha256):
    parse_catalog(raw, expected_sha256)
    return Catalog(raw, expected_sha256)


def summary(catalog):
    if not isinstance(catalog, Catalog):
        raise Refusal("disposition_catalog_required")
    rows = catalog.value()["decisions"]
    return {"catalog_sha256": catalog.sha256, "tools": [{"tool": row["tool"], "decision": row["decision"],
            "qualification": "NOT_QUALIFIED", "registration_enabled": False} for row in rows],
            "adoption_authority": False, "baseline_changed": False, "execution_enabled": False,
            "deferred_pilots_block_baseline_disposition": False}
