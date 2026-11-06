# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest.mock import patch
import support
from ocr_security.common import canonical,digest
from ocr_security.policy import TrustedRef
from ocr_security_gate import gate,updates,qualification,observations,reports

class GateTests(unittest.TestCase):
    def evaluate(self,items=None,findings=(),current=None,attest=True,mutation=None):
        snap,_=support.snapshot();pol=support.policy();current=current or support.update()
        items=support.all_evidence(snap,findings,current) if items is None else items
        fresh=updates.freshness(current,None,["npm"],support.NOW)
        receipt=support.attestation(snap,pol,items,fresh)
        if mutation:receipt.update(mutation)
        raw=canonical(receipt);ref=TrustedRef('/synthetic-run-attestation',digest(raw)) if attest else None
        with patch('ocr_security_gate.contracts.read_ref',return_value=raw):
            return gate.evaluate(support.target(snap),pol,items,snap,current,None,support.NOW,attestation_ref=ref)
    def test_no_evidence_is_not_run(self):
        self.assertEqual(self.evaluate(items=(),attest=False)["status"],"not-run")
    def test_exit_zero_without_independent_receipt_is_incomplete(self):
        self.assertEqual(self.evaluate(attest=False)["status"],"incomplete")
    def test_complete_fictional_negative_contract_can_evaluate_pass(self):
        result=self.evaluate();self.assertEqual(result["status"],"pass");self.assertFalse(result["execution_enabled"])
    def test_seeded_positive_is_not_a_passing_target(self):
        snap,_=support.snapshot();result=self.evaluate(findings=(support.finding(snap),))
        self.assertEqual(result["status"],"with-findings");self.assertEqual(len(result["blocking_fingerprints"]),1)
    def test_missing_review_partial_and_errors_fail_closed(self):
        snap,_=support.snapshot();complete=support.all_evidence(snap)
        self.assertEqual(self.evaluate(items=complete[1:])["status"],"incomplete")
        for state,expected in (("partial","incomplete"),("error","error"),("timeout","error")):
            items=(support.evidence(snap,"ocr",state=state,complete="incomplete"),)+complete[1:]
            self.assertEqual(self.evaluate(items=items)["status"],expected)
    def test_stale_database_and_attestation_cannot_pass(self):
        expired=support.update("2026-11-06T00:00:00Z")
        self.assertEqual(self.evaluate(current=expired)["status"],"incomplete")
        self.assertEqual(self.evaluate(mutation={"subject_sha256":"0"*64})["status"],"incomplete")
        self.assertEqual(self.evaluate(mutation={"reviewer_actor":"fixture-writer"})["status"],"incomplete")
    def test_fixture_qualification_separate_from_target(self):
        expectation={"case_id":"fictional-positive","fixture_sha256":"a"*64,"polarity":"positive","expected_rule_hashes":["b"*64]}
        observed={"fixture_sha256":"a"*64,"rule_hashes":["b"*64],"process_status":"success","coverage_complete":True,"execution_receipt_sha256":"c"*64}
        self.assertEqual(qualification.fixture_outcome(expectation,observed,{"status":"with-findings"})["qualification"],"passed")
        self.assertEqual(qualification.fixture_outcome(expectation,observed,{"status":"pass"})["qualification"],"failed")
        self.assertFalse(qualification.fixture_outcome(expectation,observed,{"status":"with-findings"})["target_clearance_granted"])
    def test_negative_fixture_and_unreliable_observations(self):
        expectation={'case_id':'fictional-negative','fixture_sha256':'a'*64,'polarity':'negative','expected_rule_hashes':[]}
        observed={'fixture_sha256':'a'*64,'rule_hashes':[],'process_status':'success','coverage_complete':True,
                  'execution_receipt_sha256':'c'*64}
        result=qualification.fixture_outcome(expectation,observed,{'status':'pass'})
        self.assertEqual(result['qualification'],'passed');self.assertFalse(result['target_clearance_granted'])
        for changed in ({'rule_hashes':['b'*64]},{'fixture_sha256':'d'*64},
                        {'process_status':'partial'},{'coverage_complete':False}):
            with self.subTest(changed=changed):
                self.assertEqual(qualification.fixture_outcome(expectation,dict(observed,**changed),
                                 {'status':'incomplete'})['qualification'],'failed')
        positive=dict(expectation,case_id='fictional-positive',polarity='positive',expected_rule_hashes=['b'*64])
        self.assertEqual(qualification.fixture_outcome(positive,observed,{'status':'with-findings'})['qualification'],'failed')

class RetainedHistoryTests(unittest.TestCase):
    def case(self,current_severity=None):
        old,_=support.snapshot(b'print("old fictional vulnerability")\n')
        old_policy=support.policy(source_sha256='f'*64)
        old_items=(support.evidence(old,findings=(support.finding(old),)),)
        old_groups=observations.group(observations.collect(old_items,old,support.NOW))
        history=observations.history_document(old_groups,old_policy,dict(support.target(old),source_sha256='f'*64),support.NOW)
        raw=canonical(history)
        # The new policy pins an already existing prior document, avoiding a
        # policy/history hash cycle and without treating old coverage as current.
        pol=support.policy(prior_history_sha256=digest(raw))
        snap,views=support.snapshot(b'print("current fictional source")\n')
        findings=() if current_severity is None else (support.finding(snap,current_severity),)
        items=support.all_evidence(snap,findings)
        return {'snapshot':snap,'views':views,'policy':pol,'items':items,'history':raw,'old_groups':old_groups}
    def evaluate_case(self,case,decision=None,include_history=True,items=None,history_bytes=None):
        snap,pol=case['snapshot'],case['policy'];items=case['items'] if items is None else items
        current=support.update();fresh=updates.freshness(current,None,['npm'],support.NOW)
        attestation=support.attestation(snap,pol,items,fresh)
        documents={'/fixture-history':case['history'] if history_bytes is None else history_bytes,
                   '/fixture-attestation':canonical(attestation)}
        options={}
        if include_history:options['history_ref']=TrustedRef('/fixture-history',digest(documents['/fixture-history']))
        if decision is not None:
            documents['/fixture-resolution']=canonical(decision)
            options['resolution_refs']=(TrustedRef('/fixture-resolution',digest(documents['/fixture-resolution'])),)
        def read(ref,context):return documents[ref.path]
        with patch('ocr_security_gate.contracts.read_ref',side_effect=read):
            return gate.evaluate(support.target(snap),pol,items,snap,current,None,support.NOW,
                attestation_ref=TrustedRef('/fixture-attestation',digest(documents['/fixture-attestation'])),**options)
    def resolution(self,case,group,ids=None):
        return {'schema_version':'1.0','kind':'s04-finding-resolution','policy_sha256':case['policy'].sha256,
                'subject_sha256':digest(canonical(support.target(case['snapshot']))),'fingerprint':group['fingerprint'],
                'observation_ids':group['required_observation_ids'] if ids is None else ids,
                'owner':'fixture-owner','reason':'fictional independent resolution',
                'issued_at':'2026-11-06T00:00:00Z','expires_at':'2026-11-07T00:00:00Z',
                'scope':'exact_finding_observations','waives_controls':False,'authorization_receipt_sha256':'a'*64,
                'evidence_sha256':'b'*64,'state':'independently_resolved'}
    def test_omitted_high_still_blocks_with_complete_current_negative(self):
        case=self.case();result=self.evaluate_case(case);group=result['groups'][0]
        self.assertEqual(result['status'],'with-findings');self.assertEqual(result['gaps'],[])
        self.assertFalse(group['current']);self.assertEqual(group['resolution'],'not_observed_currently_unresolved')
        self.assertIsNone(group['current_severity']);self.assertEqual(group['effective_severity'],'High')
        self.assertEqual(result['blocking_fingerprints'],[group['fingerprint']])
        report=reports.project(result,case['items'],case['views'],case['snapshot']).value()
        public=report['findings'][0]
        self.assertEqual(public['severity'],'High');self.assertTrue(public['blocking']);self.assertFalse(public['current'])
        self.assertTrue(all(x['locations']==[] and x['location_state']=='historical_withheld' for x in public['confirmations']))
        self.assertEqual(self.evaluate_case(case,self.resolution(case,group))['status'],'pass')
    def test_lower_current_severity_cannot_clear_retained_high(self):
        for severity in ('Low','Info'):
            with self.subTest(severity=severity):
                case=self.case(severity);result=self.evaluate_case(case);group=result['groups'][0]
                self.assertEqual(result['status'],'with-findings');self.assertTrue(group['current'])
                self.assertEqual(group['current_severity'],severity);self.assertEqual(group['effective_severity'],'High')
                self.assertEqual(len(group['current_observation_ids']),1);self.assertEqual(len(group['required_observation_ids']),2)
                current_only=self.resolution(case,group,group['current_observation_ids'])
                self.assertEqual(self.evaluate_case(case,current_only)['status'],'error')
                self.assertEqual(self.evaluate_case(case,self.resolution(case,group))['status'],'pass')
    def test_required_history_cannot_be_omitted_substituted_or_re_scoped(self):
        case=self.case()
        missing=self.evaluate_case(case,include_history=False)
        self.assertEqual(missing['status'],'incomplete');self.assertIn('required_finding_history_missing',missing['gaps'])
        changed=case['history']+b'\n'
        self.assertIn('invalid_history',self.evaluate_case(case,history_bytes=changed)['errors'])
        changed_case=dict(case,policy=support.policy(prior_history_sha256=digest(case['history']),history_scope_sha256='0'*64))
        self.assertIn('invalid_history',self.evaluate_case(changed_case)['errors'])
        initial=dict(case,policy=support.policy())
        self.assertIn('invalid_history',self.evaluate_case(initial)['errors'])
    def test_retained_history_never_fills_missing_current_adapter_coverage(self):
        case=self.case();items=case['items'][:-1]
        result=self.evaluate_case(case,items=items)
        self.assertEqual(result['status'],'incomplete');self.assertIn('missing_osv',result['gaps'])
        self.assertTrue(result['blocking_fingerprints'])
