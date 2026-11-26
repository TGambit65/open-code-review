"""One fictional handoff check; never imports the product."""
import unittest

from projection import project, render


class ProjectionTest(unittest.TestCase):
    def test_fictional_handoff(self):
        records = (
            {"stage": "native_baseline", "result": "unrun"},
            {"stage": "remote_preservation", "result": "blocked"},
            {"stage": "implementation", "result": "passed"},
        )
        handoff = project(records)
        self.assertEqual(handoff.qualification, "HELD")
        self.assertEqual(
            [row.status for row in handoff.stages],
            ["complete", "missing", "blocked", "missing", "unrun", "missing", "missing", "missing"],
        )
        text = render(records)
        self.assertEqual(text, render(records[::-1]))
        self.assertIn(
            "native_baseline: unrun; prerequisites: remote_preservation; unmet: remote_preservation.",
            text,
        )
        self.assertIn(
            "Ready for human evidence (listed prerequisites only): independent_source_review, remote_preservation.",
            text,
        )
        self.assertIn("Unmet prerequisite group: offline_fixtures, native_baseline", text)
        complete = tuple({"stage": row.stage, "result": "passed"} for row in handoff.stages)
        self.assertTrue(all(row.status == "complete" for row in project(complete).stages))
        self.assertTrue(render(complete).startswith("Qualification: HELD"))
        self.assertIn("Unmet prerequisite group: none.", render(complete))
        self.assertLess(len(text.encode()), 4096)
        with self.assertRaisesRegex(ValueError, "^Expected stage and result fields only"):
            render((records[0] | {"note": "invented private free text"},))


if __name__ == "__main__":
    unittest.main()
