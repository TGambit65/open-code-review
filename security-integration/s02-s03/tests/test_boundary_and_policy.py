# SPDX-License-Identifier: Apache-2.0
"""Authored only. No test has been run by the implementation writer."""
import unittest
from unittest.mock import patch
import support
from ocr_security.common import Refusal, canonical
from ocr_security.policy import TrustedRef
from ocr_security_adapters import boundary, registry, effective_policy, assets
from ocr_security_adapters.data import bounded_json

class BoundaryPolicyTests(unittest.TestCase):
    def test_all_runs_unconditionally_disabled(self):
        calls=[]
        for name in boundary.ADAPTERS:
            with self.subTest(adapter=name), self.assertRaises(Refusal):
                registry.run(name, enabled=True, executor=lambda: calls.append(name), accepted=True)
        self.assertEqual(calls, [])
        self.assertTrue(all(x["completeness"]=="incomplete" for x in registry.status()))

    def test_rollback_idempotent_and_visible(self):
        self.assertEqual(registry.rollback("ocr"),registry.rollback("ocr"))
        self.assertEqual(registry.rollback("ocr")["security_review"],"NOT_RUN")
        with self.assertRaises(Refusal): registry.rollback("hosted-fallback")

    def test_aggregate_missing_and_partial_not_complete(self):
        value=boundary.aggregate([boundary.disabled_result("ocr")])
        self.assertFalse(value["reported_complete"])
        self.assertEqual(value["target_security_acceptance"],"NOT_ASSESSED")
        with self.assertRaises(Refusal): boundary.aggregate([boundary.disabled_result("ocr")]*2)

    def test_even_reported_complete_does_not_verify_coverage(self):
        value=boundary.aggregate([{"adapter":"ocr","process_status":"success","completeness":"complete"}],("ocr",))
        self.assertTrue(value["reported_complete"])
        self.assertFalse(value["verified_coverage"])
        self.assertEqual(value["completeness"],"unknown")

    def test_json_duplicate_deep_and_oversize_refused(self):
        for raw in (b'{"x":1,"x":2}', b'['*40+b'0'+b']'*40, b' '*1048577, b'{"x":NaN}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(Refusal): bounded_json(raw)

    def test_external_policy_must_bind_inventory(self):
        from dataclasses import replace
        with self.assertRaises(Refusal):
            effective_policy.bind_inventory(support.policy(),replace(support.inventory(),external_document_sha256="0"*64))

    def test_missing_binary_and_unknown_pin_refused(self):
        value={"schema_version":"1.0","kind":"approved-adapter-assets","adapter":"gitleaks",
               "release":"v8.30.1","source_commit":assets.SOURCES["gitleaks"][1],"assets":[],
               "allowed_rule_ids":[],"supported_ecosystems":[],"cli_contract_sha256":"a"*64,"adoption_receipt_sha256":"b"*64}
        with patch.object(assets,"read_ref",return_value=canonical(value)), self.assertRaises(Refusal):
            assets.load_inventory(TrustedRef("/synthetic/pin","c"*64),None,"gitleaks")

    def test_candidate_controls_stay_data(self):
        value=effective_policy.receipt(support.policy(),"a"*64,("item-0000",),("item-0000",))
        self.assertEqual(value["candidate_controls"],"inert_review_data")
        self.assertFalse(value["native_effective_config_observed"])
        with self.assertRaises(Refusal): effective_policy.receipt(support.policy(),"a"*64,("item-0000",),("unknown",))

if __name__=="__main__": unittest.main()
