# SPDX-License-Identifier: Apache-2.0
"""Exact external asset declarations; this module never acquires an asset.

A declaration is not installation, binary verification, licensing advice or
execution authority. The absent native executor cannot use declarations to run.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from ocr_security.common import Refusal, canonical, digest, fields, sha, text, utc
from ocr_security.policy import TrustedRef, read_ref
from .data import bounded_json, choice, sequence, token

SOURCES = {
    "ocr": ("v1.13.3", "375f64cd6f67a48a135da83cfcf59c52669a09cb"),
    "opengrep": ("v1.33.1", "092c80faa0817840228349f93eff12a50fb9cf6b"),
    "gitleaks": ("v8.30.1", "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"),
    "osv": ("v2.7.0", "bfe2f84abd2f09fe0b83ba7f6dad40d296762f40"),
}


@dataclass(frozen=True)
class Asset:
    asset_id: str
    kind: str
    sha256: str
    license_id: str
    license_receipt_sha256: str
    provenance_receipt_sha256: str
    source_commit: str
    ecosystem: str | None
    created_at: str | None
    expires_at: str | None


@dataclass(frozen=True)
class Inventory:
    adapter: str
    release: str
    source_commit: str
    external_document_sha256: str
    assets: tuple
    allowed_rule_ids: tuple
    supported_ecosystems: tuple
    cli_contract_sha256: str
    adoption_receipt_sha256: str

    def one(self, kind):
        matches = tuple(item for item in self.assets if item.kind == kind)
        if len(matches) != 1:
            raise Refusal("missing_or_ambiguous_asset")
        return matches[0]

    def pins(self):
        return tuple(sorted((item.asset_id, item.sha256) for item in self.assets))


def load_inventory(ref, context, adapter):
    """Read only an explicitly pinned, outside-candidate reference via S01."""
    if not isinstance(ref, TrustedRef) or adapter not in SOURCES:
        raise Refusal("missing_external_inventory")
    raw = read_ref(ref, context)
    value = bounded_json(raw)
    fields(value, ("schema_version", "kind", "adapter", "release", "source_commit", "assets",
                   "allowed_rule_ids", "supported_ecosystems", "cli_contract_sha256", "adoption_receipt_sha256"))
    if value["schema_version"] != "1.0" or value["kind"] != "approved-adapter-assets" or value["adapter"] != adapter:
        raise Refusal("invalid_inventory")
    if (value["release"], value["source_commit"]) != SOURCES[adapter]:
        raise Refusal("unsupported_source_pin")
    sha(value["cli_contract_sha256"])
    sha(value["adoption_receipt_sha256"])
    assets, seen = [], set()
    for item in sequence(value["assets"], 256):
        fields(item, ("id", "kind", "sha256", "license", "license_receipt_sha256", "provenance_receipt_sha256",
                      "source_commit", "ecosystem", "created_at", "expires_at"))
        name = token(item["id"])
        if name in seen:
            raise Refusal("duplicate_asset")
        seen.add(name)
        kind = choice(item["kind"], ("binary", "rules", "database", "policy"))
        for field in ("sha256", "license_receipt_sha256", "provenance_receipt_sha256"):
            sha(item[field])
        text(item["license"], 128)
        text(item["source_commit"], 128)
        if kind == "binary" and item["source_commit"] != value["source_commit"]:
            raise Refusal("binary_source_mismatch")
        if kind == "database":
            token(item["ecosystem"])
            if utc(item["created_at"]) >= utc(item["expires_at"]):
                raise Refusal("invalid_database_window")
        elif any(item[key] is not None for key in ("ecosystem", "created_at", "expires_at")):
            raise Refusal("unexpected_database_metadata")
        assets.append(Asset(name, kind, item["sha256"], item["license"], item["license_receipt_sha256"],
                            item["provenance_receipt_sha256"], item["source_commit"], item["ecosystem"],
                            item["created_at"], item["expires_at"]))
    rules = tuple(token(x) for x in sequence(value["allowed_rule_ids"], 4096))
    ecosystems = tuple(token(x) for x in sequence(value["supported_ecosystems"], 256))
    if len(set(rules)) != len(rules) or len(set(ecosystems)) != len(ecosystems):
        raise Refusal("duplicate_inventory_entry")
    inventory = Inventory(adapter, value["release"], value["source_commit"], digest(raw), tuple(assets),
                          rules, ecosystems, value["cli_contract_sha256"], value["adoption_receipt_sha256"])
    inventory.one("binary")
    if adapter in ("ocr", "opengrep", "gitleaks"):
        inventory.one("rules")
    if adapter == "osv":
        inventory.one("policy")
    if adapter == "ocr" and inventory.one("binary").sha256 != "843be0e56fdff0a5ca6f86c5866f942d6a372dff1c0ca19e7893d72495abf45c":
        raise Refusal("ocr_binary_mismatch")
    return inventory


def required_databases(inventory, ecosystems, at):
    if not isinstance(inventory, Inventory) or inventory.adapter != "osv":
        raise Refusal("invalid_inventory")
    if not isinstance(at, datetime) or at.tzinfo is None:
        raise Refusal("invalid_time")
    if type(ecosystems) is not tuple or not ecosystems or len(set(ecosystems)) != len(ecosystems):
        raise Refusal("invalid_ecosystems")
    selected = []
    for ecosystem in ecosystems:
        token(ecosystem)
        if ecosystem not in inventory.supported_ecosystems:
            raise Refusal("unsupported_ecosystem")
        matches = [x for x in inventory.assets if x.kind == "database" and x.ecosystem == ecosystem]
        if len(matches) != 1:
            raise Refusal("missing_or_ambiguous_database")
        database = matches[0]
        if not utc(database.created_at) <= at.astimezone(timezone.utc) < utc(database.expires_at):
            raise Refusal("stale_database")
        selected.append(database)
    return tuple(selected)
