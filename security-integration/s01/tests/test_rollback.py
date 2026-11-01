# SPDX-License-Identifier: Apache-2.0
"""Rollback retains failures and cannot re-enable raw model access."""

import copy
import unittest

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).absolute().parent))
import test_snapshot_views as support
from ocr_security.common import Refusal, digest
from ocr_security.policy import TrustedRef
from ocr_security.rollback import rollback


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.Fixture()
        self.addCleanup(self.fixture.close)
        raw = b'{"status":"failed","seed":"SYNTHETIC_SECRET_ONLY_FAILURE"}'
        self.failed_path = self.fixture.authority / "failed.json"
        self.failed_path.write_bytes(raw)
        self.failed = TrustedRef(str(self.failed_path), digest(raw))

    def test_approved_disabled_prior_and_exact_evidence(self):
        config = self.fixture.policy.data["rollback"]["approved_prior_configurations"][0]["config"]
        ref = self.fixture.write_ref({"schema_version": "1.0", "kind": "rollback-selection", "config": config})
        receipt = rollback(self.fixture.policy, self.fixture.context, self.failed, ref, str(self.fixture.output))
        self.assertEqual(receipt["state"], "disabled_prior_selected")
        retained = self.fixture.output / receipt["retained_failed_evidence"]["artifact"]
        self.assertEqual(retained.read_bytes(), self.failed_path.read_bytes())
        self.assertEqual(receipt["completeness"], "unknown")
        self.assertEqual(receipt["target_security_acceptance"], "NOT_ASSESSED")
        with self.assertRaises(Refusal): rollback(self.fixture.policy, self.fixture.context, self.failed, ref, str(self.fixture.output))
        self.assertEqual(retained.read_bytes(), self.failed_path.read_bytes())

    def test_unsupported_old_schema_retains_failure(self):
        ref = self.fixture.write_ref({"schema_version": "1.0", "kind": "rollback-selection",
                                      "config": {"schema_version": "unsupported-v0", "raw_model_fallback": True}})
        receipt = rollback(self.fixture.policy, self.fixture.context, self.failed, ref, str(self.fixture.output))
        self.assertEqual(receipt["state"], "held")
        self.assertEqual((self.fixture.output / receipt["retained_failed_evidence"]["artifact"]).read_bytes(), self.failed_path.read_bytes())
        self.assertEqual(receipt["target_security_acceptance"], "NOT_ASSESSED")


if __name__ == "__main__":
    support.configure()
    unittest.main()
