# SPDX-License-Identifier: Apache-2.0
"""Proposed data-only regressions. Authored, not executed or qualified."""
import unittest
from dataclasses import replace
import support
from ocr_security.common import ModelBundle, ModelItem, Refusal, canonical, digest
from ocr_security_adapters import reviewer, projection, layout, ocr, gitleaks, osv


def bundle_for(items):
    serial = [{"id": x.opaque_id, "surfaces": x.surfaces, "content": x.content,
               "line_map": x.line_map, "gaps": x.gaps} for x in items]
    return ModelBundle(digest(canonical(serial)), tuple(items))


class ReviewBindingRegressions(unittest.TestCase):
    def fixture_inventory(self, name):
        inv = support.inventory(name)
        values = {x.asset_id: ("synthetic-" + x.asset_id).encode() for x in inv.assets}
        return replace(inv, assets=tuple(replace(x, sha256=digest(values[x.asset_id])) for x in inv.assets)), values

    def test_changed_rules_cannot_be_mounted_under_old_plan(self):
        snap, _ = support.sample()
        inv, values = self.fixture_inventory("gitleaks")
        plan = gitleaks.plan(snap, support.policy(), inv)
        newer_bytes = dict(values, rules=b"different synthetic rules")
        newer = replace(inv, assets=tuple(replace(x, sha256=digest(newer_bytes[x.asset_id])) for x in inv.assets))
        with self.assertRaises(Refusal):
            layout.build_layout(plan, snap, newer, newer_bytes)

    def test_other_projection_cannot_be_mounted_under_old_plan(self):
        snap, first = support.sample(b"first sanitized input\n")
        _, second = support.sample(b"second sanitized input\n")
        a, b = projection.sanitized_projection(first.model), projection.sanitized_projection(second.model)
        inv, values = self.fixture_inventory("ocr")
        plan = ocr.plan("preview", snap.snapshot_id, a, support.policy(), inv)
        with self.assertRaises(Refusal):
            layout.build_layout(plan, snap, inv, values, projection=b)

    def test_projection_content_mutation_invalidates_identity(self):
        _, views = support.sample()
        view = projection.sanitized_projection(views.model)
        path, raw = view.files[0]
        changed = replace(view, files=((path, raw + b"altered"),) + view.files[1:])
        with self.assertRaises(Refusal):
            projection.validate_projection(changed)

    def test_projection_alias_inventory_is_part_of_identity(self):
        _, views = support.sample()
        view = projection.sanitized_projection(views.model)
        changed = replace(view, alias_items=())
        with self.assertRaises(Refusal):
            projection.validate_projection(changed)

    def test_osv_layout_selection_cannot_change_under_old_plan(self):
        snap, _ = support.sample(b'{"lockfileVersion":3}\n', "json")
        inv, values = self.fixture_inventory("osv")
        old = (osv.Lockfile("item-0000", "npm"),)
        changed = (osv.Lockfile("item-0000", "yarn"),)
        plan = osv.plan(snap, support.policy(), inv, old, support.NOW)
        with self.assertRaises(Refusal):
            layout.build_layout(plan, snap, inv, values, lockfile_selection=changed)

    def test_multiline_approved_rule_is_exact_inert_data(self):
        _, views = support.sample()
        view = projection.sanitized_projection(views.model)
        rule = "# Trusted checklist\nReview all JSON values.\n"
        raw = canonical({"schema_version": "1", "groups": [{"group_id": 1, "source": "custom",
                         "pattern": "*", "files": [view.alias_items[0][0]], "rule": rule}]})
        self.assertTrue(ocr.parse_rules(raw, view, rule)["effective_policy_matches"])
        with self.assertRaises(Refusal):
            ocr.parse_rules(raw, view, rule + "unexpected")
        for control in ("\x00", "\x1b", "\x7f"):
            with self.subTest(control=repr(control)), self.assertRaises(Refusal):
                ocr.parse_rules(raw, view, rule + control)

    def test_cross_item_trace_is_bound_to_supplied_released_chunks(self):
        items = (ModelItem("source", ("primary",), "input_value = external_input\n", ((1, 1, "released"),), ()),
                 ModelItem("sink", ("secondary",), "execute(input_value)\n", ((1, 1, "released"),), ()))
        packet = reviewer.handoff(bundle_for(items), support.policy(), "writer", "reviewer")
        first, second = packet["chunks"]
        finding = {"id": "cross-file", "severity": "Medium", "confidence": "high",
                   "source_lines": [{"chunk_id": first["chunk_id"], "line": 1}],
                   "sink_lines": [{"chunk_id": second["chunk_id"], "line": 1}],
                   "preconditions": ["External input reaches this illustrative sink."],
                   "reasoning": "Synthetic accounting fixture, not an observed security result.", "disposition": "open"}
        def record(chunk, findings):
            return {"handoff_id": packet["handoff_id"], "chunk_id": chunk["chunk_id"], "reviewer_context_id": "reviewer",
                    "depth": "deep", "topics": list(reviewer.TOPICS), "findings": findings,
                    "uncertainties": [], "truncated": False}
        result = reviewer.assess_review(packet, [record(first, [finding]), record(second, [])], "reviewer")
        self.assertEqual(result["completeness"], "complete")
        bad = dict(finding, sink_lines=[{"chunk_id": "0" * 64, "line": 1}])
        with self.assertRaises(Refusal):
            reviewer.assess_review(packet, [record(first, [bad]), record(second, [])], "reviewer")

    def test_trace_crosses_default_chunk_boundary_and_rejects_unreleased_sink(self):
        for released in (True, False):
            with self.subTest(released=released):
                lines = ["illustrative line %d\n" % n for n in range(1, 201)]
                if not released:
                    lines[-1] = "[REDACTED]\n"
                mapping = tuple((n, n, "released" if released or n != 200 else "redacted") for n in range(1, 201))
                item = ModelItem("item-0000", ("primary",), "".join(lines), mapping,
                                 () if released else ((200, 200, "not_released"),))
                packet = reviewer.handoff(bundle_for((item,)), support.policy(), "writer", "reviewer")
                first, second = packet["chunks"]
                finding = {"id": "across-boundary", "severity": "Medium", "confidence": "unknown",
                           "source_lines": [{"chunk_id": first["chunk_id"], "line": 5}],
                           "sink_lines": [{"chunk_id": second["chunk_id"], "line": 200}],
                           "preconditions": ["Synthetic illustrative flow; no real finding asserted."],
                           "reasoning": "Only the evidence-reference data contract is exercised.", "disposition": "open"}
                records = [{"handoff_id": packet["handoff_id"], "chunk_id": part["chunk_id"],
                            "reviewer_context_id": "reviewer", "depth": "deep", "topics": list(reviewer.TOPICS),
                            "findings": [finding] if index == 0 else [], "uncertainties": [], "truncated": False}
                           for index, part in enumerate(packet["chunks"])]
                if released:
                    result = reviewer.assess_review(packet, records, "reviewer")
                    self.assertEqual(result["completeness"], "complete")
                    self.assertEqual(len(result["findings"]), 1)
                else:
                    with self.assertRaises(Refusal):
                        reviewer.assess_review(packet, records, "reviewer")


if __name__ == "__main__":
    unittest.main()
