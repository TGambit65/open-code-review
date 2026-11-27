"""One fictional handoff check; never imports the product."""
import unittest
from hashlib import sha256

from projection import project, project_supported, render, render_supported


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


    def test_supported_note_opt_in_distinguishes_incomplete_result_tokens(self):
        records = (
            {"stage": "implementation", "result": "partial"},
            {"stage": "remote_preservation", "result": "failed"},
            {"stage": "rendering", "result": "unrun"},
        )
        default = render_supported(records)
        detailed = render_supported(records, include_result_token=True)
        self.assertNotIn("declared result token:", default)
        self.assertEqual(detailed, render_supported(records[::-1], include_result_token=True))
        self.assertIn("implementation: declared result token: partial; declared: blocked;", detailed)
        self.assertIn("remote_preservation: declared result token: failed; declared: blocked;", detailed)
        self.assertIn("rendering: declared result token: unrun; declared: unrun;", detailed)
        self.assertIn("native_baseline: declared result token: none supplied; declared: missing;", detailed)
        self.assertIn("Qualification: HELD", detailed)
        self.assertLess(len(detailed.encode()), 4096)
        with self.assertRaisesRegex(ValueError, "^Unknown stage result"):
            render_supported(({"stage": "implementation", "result": "fictional free text"},),
                             include_result_token=True)

    def test_supported_note_distinguishes_reported_and_supported(self):
        records = (
            {"stage": "offline_fixtures", "result": "passed"},
            {"stage": "remote_preservation", "result": "passed"},
        )
        text = render_supported(records)
        self.assertEqual(text, render_supported(records[::-1]))
        self.assertIn(
            "remote_preservation: declared: complete; prerequisite-supported status: blocked; "
            "direct unmet prerequisites: implementation.",
            text,
        )
        self.assertIn(
            "offline_fixtures: declared: complete; prerequisite-supported status: blocked; "
            "direct unmet prerequisites: remote_preservation.",
            text,
        )
        self.assertNotIn("Ready for human evidence", text)

    def test_supported_note_is_fixed_bounded_and_held_for_all_or_none(self):
        rows = project(()).stages
        all_reported = tuple({"stage": row.stage, "result": "passed"} for row in reversed(rows))
        for records in ((), all_reported):
            with self.subTest(records=bool(records)):
                text = render_supported(records)
                lines = text.splitlines()
                self.assertEqual(lines[0], "Qualification: HELD (fictional declared metadata only; "
                                          "no external evidence checked; no authority).")
                self.assertEqual(len(lines), 1 + len(rows))
                self.assertEqual([line.split(":", 1)[0] for line in lines[1:]],
                                 [row.stage for row in rows])
                self.assertLess(len(text.encode()), 4096)
                for row, line in zip(rows, lines[1:]):
                    expected = "complete" if records else "missing"
                    self.assertIn(f"declared: {expected}; prerequisite-supported status: {expected};", line)
                    unmet = "none" if records else ", ".join(row.prerequisites) or "none"
                    self.assertTrue(line.endswith(f"direct unmet prerequisites: {unmet}."))

    def test_supported_note_rejects_malformed_closed_records(self):
        row = {"stage": "implementation", "result": "passed"}
        for records in ([row], (row, row), (row | {"extra": "fictional wording"},),
                        (row | {"result": "not a closed token"},),
                        (row | {"stage": "not a closed token"},)):
            with self.subTest(records=records):
                with self.assertRaises(ValueError) as err:
                    render_supported(records)
                self.assertNotIn("fictional wording", str(err.exception))
                self.assertNotIn("not a closed token", str(err.exception))

    def test_exact_retained_legacy_output(self):
        records = (
            {"stage": "native_baseline", "result": "unrun"},
            {"stage": "remote_preservation", "result": "blocked"},
            {"stage": "implementation", "result": "passed"},
        )
        for source, expected in (
            ((), "25c62a4be639892b2250fd34f73d81da6a796b4df69d179eedaea4bffcabc824"),
            (records, "9eb1a0d694cc7d5de635fb57e03fa3253638b96cd6a17a117a29767b0c5b699b"),
        ):
            self.assertEqual(sha256(render(source).encode()).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
