"""One fictional handoff check; never imports the product."""
import unittest

from projection import project, project_supported, render


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

    def test_opt_in_blocks_transitively_unsupported_completion(self):
        records = (
            {"stage": "remote_preservation", "result": "passed"},
            {"stage": "offline_fixtures", "result": "passed"},
        )
        legacy = {row.stage: row for row in project(records).stages}
        checked = project_supported(records)
        rows = {row.stage: row for row in checked.stages}
        self.assertEqual(legacy["offline_fixtures"].status, "complete")
        self.assertEqual(legacy["offline_fixtures"].unmet_prerequisites, ())
        self.assertEqual(rows["implementation"].status, "missing")
        self.assertEqual(rows["remote_preservation"].reported_status, "complete")
        self.assertEqual(rows["remote_preservation"].status, "blocked")
        self.assertEqual(rows["remote_preservation"].unmet_prerequisites, ("implementation",))
        self.assertEqual(rows["offline_fixtures"].reported_status, "complete")
        self.assertEqual(rows["offline_fixtures"].status, "blocked")
        self.assertEqual(rows["offline_fixtures"].unmet_prerequisites, ("remote_preservation",))
        self.assertIn("offline_fixtures", rows["independent_evidence_review"].unmet_prerequisites)
        self.assertEqual(checked.qualification, "HELD")
        self.assertEqual(project_supported(records[::-1]), checked)

    def test_opt_in_agrees_when_all_reported_completions_are_supported(self):
        records = tuple(
            {"stage": row.stage, "result": "passed"} for row in project(()).stages
        )
        supported = project_supported(records)
        self.assertTrue(all(row.status == row.reported_status == "complete"
                            and not row.unmet_prerequisites for row in supported.stages))
        self.assertEqual(supported.qualification, "HELD")
        with self.assertRaisesRegex(ValueError, "^Unknown or duplicate stage"):
            project_supported((records[0], records[0]))


if __name__ == "__main__":
    unittest.main()
