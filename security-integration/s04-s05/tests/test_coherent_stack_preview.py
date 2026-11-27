# SPDX-License-Identifier: Apache-2.0
import json
import unittest

import support
from coherent_stack_preview import (
    preview, preview_checked, preview_json, preview_compatible_280, preview_compatible_280_json,
)
from ocr_security.common import Refusal


def paths(start, stop):
    return [f"fixture/{index}.txt" for index in range(start, stop)]


class CoherentStackPreviewTests(unittest.TestCase):
    def test_compatible_json_preserves_mode_and_projection_only(self):
        existing = paths(0, 279)
        first = [paths(278, 280) + paths(279, 280), paths(280, 281)]
        second = [list(reversed(first[0])), first[1]]
        result = preview_compatible_280(existing, first, final_boundary="dependency_hold")
        wire = preview_compatible_280_json(existing, first, final_boundary="dependency_hold")
        self.assertEqual(json.loads(wire), result)
        self.assertEqual(wire, preview_compatible_280_json(
            list(reversed(existing)), second, final_boundary="dependency_hold"))
        self.assertEqual(result["stop"]["reason"], "stop_before_overflow")
        self.assertIsNone(result["stop"]["boundary_reason"])
        self.assertNotIn(b"fixture/", wire)
        self.assertTrue(wire.endswith(b"\n"))

    def test_order_overlap_and_aggregate_only(self):
        current = paths(0, 5)
        groups = [paths(3, 7), paths(6, 10)]
        result = preview(current, groups, final_boundary="final_scope")
        self.assertEqual(result["accepted_cohorts"], [
            {"cohort_index": 1, "new_distinct_paths": 2, "cumulative_distinct_paths": 7},
            {"cohort_index": 2, "new_distinct_paths": 3, "cumulative_distinct_paths": 10},
        ])
        self.assertEqual(result["stop"]["reason"], "document_smaller_boundary")
        self.assertEqual(result["stop"]["boundary_reason"], "final_scope")
        wire = preview_json(current, groups, final_boundary="final_scope")
        self.assertEqual(wire, preview_json(current, [list(reversed(g)) for g in groups],
                                            final_boundary="final_scope"))
        self.assertNotIn(b"fixture/", wire)
        self.assertFalse(result["new_draft_created"])
        self.assertFalse(result["preservation_delayed"])

    def test_exact_ceiling_then_overflow(self):
        result = preview(paths(0, 198), [paths(190, 280), paths(279, 281), paths(0, 3)])
        self.assertEqual(result["ending_distinct_paths"], 280)
        self.assertEqual(result["accepted_cohorts"][0]["new_distinct_paths"], 82)
        self.assertEqual(result["stop"], {
            "cohort_index": 2, "reason": "preserve_current_then_dependent_draft",
            "projected_distinct_paths": 281, "boundary_reason": None,
        })

    def test_freeze_below_hard_ceiling(self):
        result = preview(paths(0, 200), [paths(190, 220)])
        self.assertEqual(result["accepted_cohorts"], [])
        self.assertEqual(result["ending_distinct_paths"], 200)
        self.assertEqual(result["stop"]["reason"], "freeze_current_batch")
        self.assertEqual(result["stop"]["projected_distinct_paths"], 220)

    def test_opt_in_checks_bounded_manifest_beyond_stop(self):
        existing = paths(0, 200)
        groups = [paths(199, 201), [None]]
        ordinary = preview(existing, groups)
        self.assertEqual(ordinary["stop"]["reason"], "freeze_current_batch")
        self.assertEqual(ordinary["stop"]["cohort_index"], 1)
        with self.assertRaises(Refusal):
            preview_checked(existing, groups)
        with self.assertRaisesRegex(Refusal, "^preview_path_budget_exceeded$"):
            preview_checked(existing, [[None] * 9801])

    def test_opt_in_preserves_decisions_for_valid_manifests(self):
        for existing, groups in (
            (paths(0, 5), [paths(3, 7), paths(7, 10)]),
            (paths(0, 200), [paths(199, 201), paths(2, 5)]),
            (paths(0, 198), [paths(190, 280), paths(279, 281)]),
        ):
            with self.subTest(count=len(existing)):
                ordinary = preview(existing, groups, final_boundary="final_scope")
                checked = preview_checked(existing, groups, final_boundary="final_scope")
                self.assertEqual(ordinary, checked)
                self.assertNotIn("fixture/", repr(checked))

    def test_empty_proposal_can_document_the_final_boundary(self):
        expected = {
            "cohort_index": None, "reason": "document_smaller_boundary",
            "projected_distinct_paths": 0, "boundary_reason": "final_scope",
        }
        self.assertEqual(preview([], [], final_boundary="final_scope")["stop"], expected)
        self.assertEqual(preview_checked([], [], final_boundary="final_scope")["stop"], expected)

    def test_compatible_280_does_not_change_historical_freeze(self):
        existing = paths(0, 195)
        groups = [paths(195, 210), paths(210, 240), paths(240, 280), paths(280, 281)]
        planned = preview_compatible_280(existing, groups, final_boundary="final_scope")
        self.assertEqual(planned["ending_distinct_paths"], 280)
        self.assertEqual([x["cumulative_distinct_paths"] for x in planned["accepted_cohorts"]],
                         [210, 240, 280])
        self.assertEqual(planned["stop"], {"cohort_index": 4, "reason": "stop_before_overflow",
                                          "projected_distinct_paths": 281, "boundary_reason": None})
        self.assertEqual(preview(existing, groups)["ending_distinct_paths"], 210)
        self.assertEqual(preview_checked(existing, groups), preview(existing, groups))
        self.assertNotIn("fixture/", repr(planned))
        self.assertFalse(planned["padding_allowed"])
        self.assertFalse(planned["new_draft_created"])

    def test_compatible_counts_union_no_split_no_padding(self):
        dry = preview_compatible_280
        groups = [["fixture/279.txt"] * 2, ["fixture/279.txt"], ["fixture/0.txt", "fixture/281.txt"]]
        result = dry(paths(0, 279), groups, final_boundary="dependency_hold")
        self.assertEqual([r["new_distinct_paths"] for r in result["accepted_cohorts"]], [1, 0])
        self.assertEqual(result["stop"]["cohort_index"], 3)
        self.assertEqual(result, dry(list(reversed(paths(0, 279))), [g[::-1] for g in groups],
                                     final_boundary="dependency_hold"))
        exact = dry(paths(0, 279), groups[:1], final_boundary="final_scope")
        self.assertEqual(exact["stop"]["reason"], "at_cap")
        self.assertEqual(exact["stop"]["boundary_reason"], "final_scope")
        small = dry(paths(0, 4), [paths(4, 5)], final_boundary="dependency_hold")
        self.assertEqual(small["stop"], {"cohort_index": None, "reason": "smaller_boundary",
                                        "projected_distinct_paths": 5, "boundary_reason": "dependency_hold"})
        over = dry(paths(0, 281), [paths(0, 1)], final_boundary="no_eligible_work")
        self.assertEqual(over["stop"]["reason"], "hold_over_cap_existing_batch")
        self.assertEqual(over["accepted_cohorts"], [])
        self.assertEqual(over["ending_distinct_paths"], 281)

    def test_compatible_requires_known_boundary_and_checks_entire_manifest(self):
        dry = preview_compatible_280
        with self.assertRaises(TypeError):
            dry([], [])
        with self.assertRaisesRegex(Refusal, "^invalid_preview_final_boundary$"):
            dry([], [], final_boundary=None)
        with self.assertRaisesRegex(Refusal, "^preview_path_budget_exceeded$"):
            dry(paths(0, 280), [[None] * 9721], final_boundary="final_scope")
        with self.assertRaises(Refusal):
            dry(paths(0, 280), [paths(280, 281), [None]], final_boundary="final_scope")
