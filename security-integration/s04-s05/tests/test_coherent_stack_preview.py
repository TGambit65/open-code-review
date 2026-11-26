# SPDX-License-Identifier: Apache-2.0
import unittest

import support
from coherent_stack_preview import preview, preview_json


def paths(start, stop):
    return [f"fixture/{index}.txt" for index in range(start, stop)]


class CoherentStackPreviewTests(unittest.TestCase):
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
