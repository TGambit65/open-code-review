# SPDX-License-Identifier: Apache-2.0
import copy
import unittest
from unittest.mock import patch
import support
from ocr_security.common import Refusal,canonical,digest
from ocr_security.policy import TrustedRef
from ocr_security_gate import observations,exceptions

class ObservationTests(unittest.TestCase):
    def setup_records(self):
        snap,_=support.snapshot();pol=support.policy();target=support.target(snap)
        a=support.evidence(snap,findings=(support.finding(snap),))
        b=support.evidence(snap,"opengrep",findings=(support.finding(snap,"Medium","other-rule"),))
        return snap,pol,target,observations.collect((a,b),snap,support.NOW)
    def test_default_grouping_preserves_independent_evidence(self):
        _,_,_,records=self.setup_records();groups=observations.group(records)
        self.assertEqual(len(groups),2)
        self.assertEqual(sum(len(g["observations"]) for g in groups),2)
    def test_explicit_correlations_keep_severity_and_confirmations(self):
        _,_,_,records=self.setup_records();fp="9"*64
        groups=observations.group(records,{x["observation_id"]:fp for x in records})
        self.assertEqual(len(groups),1);self.assertEqual(groups[0]["current_severity"],"High")
        self.assertEqual(groups[0]["independent_detector_count"],2)
    def test_history_retains_observations_without_claiming_resolution(self):
        _,_,_,records=self.setup_records();groups=observations.group(records)
        previous=[{k:g[k] for k in ("fingerprint","first_seen","observations")} for g in groups]
        next_groups=observations.group([],previous=previous)
        self.assertTrue(all(x["resolution"]=="not_observed_currently_unresolved" for x in next_groups))
        self.assertTrue(all(x["current_severity"] is None and x["effective_severity"] is not None for x in next_groups))
        self.assertTrue(all(set(x["required_observation_ids"])=={o["observation_id"] for o in x["observations"]} for x in next_groups))
        self.assertEqual(sum(len(g["observations"]) for g in next_groups),2)
    def test_correlation_cannot_silently_waive_a_finding(self):
        _,_,_,records=self.setup_records()
        with self.assertRaises(Refusal):observations.group(records,{"0"*64:"1"*64})
    def test_owned_expiring_exact_observation_exceptions(self):
        snap,pol,target,records=self.setup_records();groups=observations.group(records);group=groups[0]
        value={"schema_version":"1.0","kind":"s04-finding-exception","policy_sha256":pol.sha256,
               "subject_sha256":digest(canonical(target)),"fingerprint":group["fingerprint"],
               "observation_ids":group["current_observation_ids"],"owner":"fixture-owner","reason":"fictional exception only",
               "issued_at":"2026-11-06T00:00:00Z","expires_at":"2026-11-07T00:00:00Z",
               "scope":"exact_finding_observations","waives_controls":False,"authorization_receipt_sha256":"a"*64,
               "evidence_sha256":"b"*64,"state":"exception_approved"}
        def call(doc):
            raw=canonical(doc);ref=TrustedRef('/synthetic-exception',digest(raw))
            with patch('ocr_security_gate.contracts.read_ref',return_value=raw):
                return exceptions.decisions((ref,),None,pol,target,groups,support.NOW)
        self.assertIn(group["fingerprint"],call(value))
        for change in ({"owner":"candidate"},{"waives_controls":True},{"scope":"all_findings"},
                       {"expires_at":"2026-11-06T00:30:00Z"},{"observation_ids":[]},{"policy_sha256":"0"*64}):
            with self.subTest(change=change),self.assertRaises(Refusal):call(dict(value,**change))
