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
    def test_decision_covers_complete_retained_and_current_set(self):
        from pathlib import Path
        import json
        snap,pol,target,records=self.setup_records()
        template=records[0]
        history=[dict(template,observation_id=digest(('old-%d'%i).encode())) for i in range(256)]
        current=[dict(template,observation_id=digest(b'current'))]
        prior=[{'fingerprint':template['fingerprint'],'first_seen':template['observed_at'],'observations':history}]
        actual=observations.group(current,previous=prior)[0]
        self.assertEqual(len(actual['required_observation_ids']),257)
        for count in (257,4096,4097,8192,8193):
            ids=actual['required_observation_ids'] if count==257 else [digest(str(i).encode()) for i in range(count)]
            groups=[dict(actual,required_observation_ids=ids)]
            value={'schema_version':'1.0','kind':'s04-finding-exception','policy_sha256':pol.sha256,
                   'subject_sha256':digest(canonical(target)),'fingerprint':actual['fingerprint'],
                   'observation_ids':ids,'owner':'fixture-owner','reason':'synthetic exact set',
                   'issued_at':'2026-11-06T00:00:00Z','expires_at':'2026-11-07T00:00:00Z',
                   'scope':'exact_finding_observations','waives_controls':False,'authorization_receipt_sha256':'a'*64,
                   'evidence_sha256':'b'*64,'state':'exception_approved'}
            def call(doc):
                raw=canonical(doc);ref=TrustedRef('/synthetic-exception',digest(raw))
                with patch('ocr_security_gate.contracts.read_ref',return_value=raw):
                    return exceptions.decisions((ref,),None,pol,target,groups,support.NOW,
                                                'finding-resolution' if doc['kind']=='s04-finding-resolution' else 'finding-exception')
            if count>exceptions.MAX_DECISION_OBSERVATIONS:
                with self.assertRaises(Refusal):call(value)
            else:
                self.assertIn(actual['fingerprint'],call(value))
                self.assertIn(actual['fingerprint'],call(dict(value,kind='s04-finding-resolution',state='independently_resolved')))
                with self.assertRaises(Refusal):call(dict(value,observation_ids=ids[:-1]))
                with self.assertRaises(Refusal):call(dict(value,observation_ids=ids[:-1]+['f'*64]))
                with self.assertRaises(Refusal):call(dict(value,observation_ids=ids+[ids[0]]))
        schema=json.loads((Path(__file__).parents[1]/'schemas/finding-decision.schema.json').read_text())
        self.assertEqual(schema['properties']['observation_ids']['maxItems'],exceptions.MAX_DECISION_OBSERVATIONS)

    def test_decision_parser_does_not_relax_other_document_limits(self):
        from ocr_security_adapters.data import bounded_json
        from ocr_security_gate.contracts import pinned
        ids=[digest(str(i).encode()) for i in range(4097)]
        raw=canonical({'observation_ids':ids})
        self.assertEqual(exceptions.decision_document(raw)['observation_ids'],ids)
        with self.assertRaises(Refusal):bounded_json(raw)
        ref=TrustedRef('/synthetic-generic',digest(raw))
        with patch('ocr_security_gate.contracts.read_ref',return_value=raw):
            with self.assertRaises(Refusal):pinned(ref,None,'other')
        for extra in ({'other':[0]*4097},{'other':'x'*65537}):
            with self.assertRaises(Refusal):exceptions.decision_document(canonical(dict(extra,observation_ids=ids)))
        with self.assertRaises(Refusal):exceptions.decision_document(raw+b' '*1048576)
        with self.assertRaises(Refusal):exceptions.decision_document(canonical({'observation_ids':['bad']}))

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
