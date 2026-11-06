# SPDX-License-Identifier: Apache-2.0
"""Authored offline binding regressions. No native execution or file reads."""

from dataclasses import replace
import unittest
from unittest.mock import patch
import support
from ocr_security.common import ModelBundle, canonical, digest, parse_json
from ocr_security.policy import TrustedRef
from ocr_security.views import Views
from ocr_security_adapters import gitleaks, opengrep, osv
from ocr_security_adapters.inputs import input_manifest


def pair():
    """Two separately identified selected entries, with consistent in-memory views."""
    snap, views = support.sample()
    second = replace(snap.entries[0], ordinal=1, path="second.py", source="second-fixture")
    manifest = parse_json(snap.manifest)
    item = dict(manifest["selection"]["entries"][0])
    item.update(path=second.path, source=second.source)
    manifest["selection"]["entries"].append(item)
    raw = canonical(manifest)
    snap = replace(snap, snapshot_id=digest(raw), entries=snap.entries+(second,), manifest=raw)
    model_items = views.model.items + (replace(views.model.items[0], opaque_id=second.opaque_id),)
    serial = [{"id": x.opaque_id, "surfaces": x.surfaces, "content": x.content,
               "line_map": x.line_map, "gaps": x.gaps} for x in model_items]
    model = ModelBundle(digest(canonical(serial)), model_items)
    private = canonical({"snapshot_id": snap.snapshot_id, "model_bundle_id": model.bundle_id})
    return snap, Views(tuple((x.opaque_id, x.content) for x in snap.selected), model, private)


def receipt(evidence, snap, ids):
    keys = ("snapshot_id", "tool_sha256", "policy_sha256", "profile_sha256", "report_sha256",
            "native_execution_receipt_sha256", "adapter_policy_sha256", "plan_sha256")
    return dict({key: evidence[key] for key in keys}, schema_version="1.0",
                kind="independent-adapter-coverage", input_manifest_sha256=input_manifest(snap)[1],
                qualified_harness_sha256="f"*64, complete_ids=ids,
                all_rules_accounted=True, no_silent_skips=True)


class AdapterBindingTests(unittest.TestCase):
    def test_cross_adapter_inventory_rejected(self):
        snap, views = support.sample()
        reports = ((gitleaks, "opengrep", b"[]"),
                   (opengrep, "gitleaks", canonical({"results": [], "errors": [],
                    "paths": {"scanned": ["/input/item-0000.py"], "skipped": []}})))
        for module, wrong_adapter, raw in reports:
            with self.subTest(adapter=module.__name__):
                value = module.normalize(raw, snap, views, support.policy(),
                                         support.inventory(wrong_adapter), support.evidence(raw, snap, wrong_adapter))
                self.assertEqual(value["process_status"], "parser_error")

    def test_stdin_rejects_other_selected_file(self):
        snap, views = pair()
        for path, rejected in (("/input/item-0001.py", True), ("stdin", False),
                               ("/input/item-0000.py", False)):
            with self.subTest(path=path):
                raw = canonical([{"RuleID": "fixture-rule", "StartLine": 1, "EndLine": 1,
                                  "File": path, "Secret": "REDACTED", "Match": "REDACTED"}])
                evidence = support.evidence(raw, snap, mode="stdin", stdin_item="item-0000")
                value = gitleaks.normalize(raw, snap, views, support.policy(), support.inventory(),
                                          evidence, mode="stdin", stdin_item="item-0000")
                self.assertEqual(value["process_status"] == "parser_error", rejected)
                if not rejected:
                    self.assertEqual(value["result"]["findings"][0]["evidence_identity"]["path"], "sample.py")

    def test_execution_receipt_requires_exact_plan(self):
        snap, views = pair()
        raw = b"[]"
        evidence = support.evidence(raw, snap, mode="stdin", stdin_item="item-0000")
        for mode, stdin in (("files", None), ("history", None), ("stdin", "item-0001")):
            with self.subTest(mode=mode, stdin=stdin):
                value = gitleaks.normalize(raw, snap, views, support.policy(), support.inventory(),
                                          evidence, mode=mode, stdin_item=stdin)
                self.assertEqual(value["process_status"], "parser_error")
        del evidence["plan_sha256"]
        value = gitleaks.normalize(raw, snap, views, support.policy(), support.inventory(),
                                  evidence, mode="stdin", stdin_item="item-0000")
        self.assertEqual(value["process_status"], "parser_error")

    def test_stdin_coverage_is_operation_scoped_and_snapshot_stays_incomplete(self):
        snap, views = pair()
        evidence = support.evidence(b"[]", snap, mode="stdin", stdin_item="item-0000")
        cases = ((["item-0000"], False), (["item-0000", "item-0001"], True))
        for ids, rejected in cases:
            raw_receipt = canonical(receipt(evidence, snap, ids))
            ref = TrustedRef("/synthetic-coverage.json", digest(raw_receipt))
            # Mock only the trusted read boundary; its filesystem enforcement is not tested here.
            with patch("ocr_security_adapters.normalization.read_ref", return_value=raw_receipt):
                value = gitleaks.normalize(b"[]", snap, views, support.policy(), support.inventory(),
                                          evidence, coverage_ref=ref, mode="stdin", stdin_item="item-0000")
            self.assertEqual(value["process_status"] == "parser_error", rejected)
            if not rejected:
                self.assertEqual(value["completeness"], "incomplete")
                self.assertEqual(value["result"]["coverage"][1]["analyzed_ranges"], [])
                self.assertTrue(value["result"]["coverage"][1]["omissions"])

    def test_coverage_receipt_cannot_be_reused_for_other_operation(self):
        snap, views = pair()
        directory_evidence = support.evidence(b"[]", snap)
        stdin_evidence = support.evidence(b"[]", snap, mode="stdin", stdin_item="item-0000")
        # Even a receipt mentioning only the stdin item must match the actual operation.
        raw_receipt = canonical(receipt(directory_evidence, snap, ["item-0000"]))
        ref = TrustedRef("/synthetic-coverage.json", digest(raw_receipt))
        with patch("ocr_security_adapters.normalization.read_ref", return_value=raw_receipt):
            value = gitleaks.normalize(b"[]", snap, views, support.policy(), support.inventory(),
                                      stdin_evidence, coverage_ref=ref, mode="stdin", stdin_item="item-0000")
        self.assertEqual(value["process_status"], "parser_error")

    def test_osv_source_type_and_selection_bound(self):
        snap, views = support.sample(b'{"lockfileVersion":3}\n', "json")
        selection = (osv.Lockfile("item-0000", "npm"),)
        for source_type in (None, [], {}, 1, "git", "lockfile"):
            with self.subTest(source_type=source_type):
                raw = canonical({"results": [{"source": {"path": "/input/item-0000/package-lock.json",
                                  "type": source_type}, "packages": []}], "experimental_config": {}})
                evidence = support.evidence(raw, snap, "osv", selection=selection)
                value = osv.normalize(raw, snap, views, support.policy(), support.inventory("osv"),
                                      evidence, selection)
                self.assertEqual(value["process_status"] == "parser_error", source_type != "lockfile")
        # Same ecosystem and source bytes, different explicit parser: receipt must not transfer.
        raw = canonical({"results": [{"source": {"path": "/input/item-0000/yarn.lock",
                          "type": "lockfile"}, "packages": []}], "experimental_config": {}})
        evidence = support.evidence(raw, snap, "osv", selection=selection)
        value = osv.normalize(raw, snap, views, support.policy(), support.inventory("osv"),
                              evidence, (osv.Lockfile("item-0000", "yarn"),))
        self.assertEqual(value["process_status"], "parser_error")


if __name__ == "__main__":
    unittest.main()
