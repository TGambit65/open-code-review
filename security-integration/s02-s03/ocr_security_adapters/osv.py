# SPDX-License-Identifier: Apache-2.0
"""Explicit preloaded offline OSV lockfile plans. No fix or package execution."""

from dataclasses import dataclass
import re
from ocr_security.common import Refusal, canonical, digest, sha, text, utc
from .assets import required_databases
from .boundary import Plan, execute
from .data import bounded_json, fields, sequence, token
from .effective_policy import bind_inventory
from .inputs import scanner_inputs
from .normalization import coverage_attestation, finding, result, parser_failure

LOCKFILES = {
    "npm": ("package-lock.json", "npm"), "yarn": ("yarn.lock", "npm"),
    "pnpm": ("pnpm-lock.yaml", "npm"), "pip": ("requirements.txt", "PyPI"),
    "poetry": ("poetry.lock", "PyPI"), "go": ("go.mod", "Go"),
    "cargo": ("Cargo.lock", "crates.io"), "composer": ("composer.lock", "Packagist"),
    "gem": ("Gemfile.lock", "RubyGems"), "maven": ("pom.xml", "Maven"),
}


@dataclass(frozen=True)
class Lockfile:
    opaque_id: str
    format: str


def lock_inputs(snapshot, selection):
    inputs = {item.opaque_id: item for item in scanner_inputs(snapshot)}
    if type(selection) is not tuple or not selection or len(selection) > 256:
        raise Refusal("invalid_lockfile_selection")
    mapped, seen = [], set()
    for lock in selection:
        if not isinstance(lock, Lockfile) or lock.opaque_id not in inputs or lock.opaque_id in seen or lock.format not in LOCKFILES:
            raise Refusal("unsupported_lockfile")
        seen.add(lock.opaque_id)
        basename, ecosystem = LOCKFILES[lock.format]
        mapped.append(("/input/" + lock.opaque_id + "/" + basename, ecosystem, inputs[lock.opaque_id]))
    return tuple(mapped)


def plan(snapshot, policy, inventory, selection, at):
    if inventory.adapter != "osv":
        raise Refusal("wrong_adapter_inventory")
    bind_inventory(policy, inventory)
    inventory.one("policy")
    mapped = lock_inputs(snapshot, selection)
    databases = required_databases(inventory, tuple(sorted({eco for _, eco, _ in mapped})), at)
    argv = ("/tool/osv-scanner", "scan", "source", "--offline", "--download-offline-databases=false", "--no-call-analysis=all",
            "--config=/policy/osv.toml", "--local-db-path=/database", "--all-packages", "--no-ignore",
            "--format=json", "--output-file=/output/report.json")
    argv += tuple("--lockfile=" + path.rsplit("/", 1)[-1] + ":" + path for path, _, _ in mapped)
    return Plan("osv", "lockfiles", argv, inventory.one("binary").sha256, policy.sha256, snapshot.snapshot_id,
                "scanner", inventory.pins(), ("s01_acceptance_pending", "native_runner_unqualified", "offline_ecosystem_qualification_pending",
                                             "hidden_database_flag_unqualified", "lockfile_parser_qualification_pending"))


def advisory_id(value):
    text(value, 256)
    if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,9}", value) or re.fullmatch(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", value):
        return value
    return "osv-" + digest(value.encode("utf-8"))[:24]


def normalize(raw, snapshot, views, policy, inventory, evidence, selection, context=None, coverage_ref=None):
    try:
        expected_plan_sha256 = plan(snapshot, policy, inventory, selection, utc(evidence["at"])).identity
        bind_inventory(policy, inventory)
        mapped = lock_inputs(snapshot, selection)
        by_path = {path: (eco, item) for path, eco, item in mapped}
        inputs = scanner_inputs(snapshot)
        databases = required_databases(inventory, tuple(sorted({eco for _, eco, _ in mapped})), utc(evidence["at"]))
        value = bounded_json(raw, policy.max_output_bytes)
        fields(value, ("results", "experimental_config"), ("experimental_generic_findings", "image_metadata", "license_summary"))
        if value.get("image_metadata") or value.get("experimental_generic_findings"):
            raise Refusal("unsupported_osv_mode")
        findings, seen, sources = [], set(), set()
        for source in sequence(value["results"], 256):
            fields(source, ("source", "packages"), ("experimental_pes",))
            fields(source["source"], ("path", "type"))
            if source["source"]["type"] != "lockfile":
                raise Refusal("unsupported_osv_source_type")
            path = source["source"]["path"]
            if type(path) is not str or path not in by_path or path in sources:
                raise Refusal("unbound_osv_source")
            sources.add(path)
            ecosystem, item = by_path[path]
            for package in sequence(source["packages"], 4096):
                if type(package) is not dict or "package" not in package:
                    raise Refusal("invalid_osv_package")
                identity = package["package"]
                if type(identity) is not dict or identity.get("ecosystem") != ecosystem or identity.get("commit"):
                    raise Refusal("unsupported_osv_package")
                text(identity.get("name"), 256)
                text(identity.get("version"), 256)
                for vulnerability in sequence(package.get("vulnerabilities", []), 1024):
                    if type(vulnerability) is not dict:
                        raise Refusal("invalid_osv_advisory")
                    rule = advisory_id(vulnerability.get("id"))
                    # OSV has no source line location; [] means unknown file-level
                    # evidence. Info is explicitly unrated, not a low-risk verdict.
                    record = finding("osv", item, snapshot, inventory, raw, rule, "Info", ordinal=len(findings))
                    if record["id"] not in seen:
                        seen.add(record["id"])
                        findings.append(record)
        complete = coverage_attestation(coverage_ref, context, evidence, inventory, snapshot, inputs)
        complete = complete & {by_path[path][1].opaque_id for path in sources}
        gaps = []
        if not complete:
            gaps.append("native_report_has_no_coverage_ledger")
        if sources != set(by_path):
            gaps.append("missing_lockfile_result")
        if findings:
            gaps.append("advisory_severity_and_reachability_unrated")
        database_pin = digest(canonical([[db.ecosystem, db.sha256, db.created_at, db.expires_at] for db in databases]))
        return result("osv", raw, snapshot, views, policy, inventory, evidence, inputs, findings,
                      complete, tuple(gaps), "not_applicable", database_pin, expected_plan_sha256)
    except (Refusal, TypeError, KeyError, ValueError, AttributeError):
        return parser_failure("osv")


def run(*args, **kwargs):
    return execute(None)
