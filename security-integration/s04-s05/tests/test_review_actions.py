# SPDX-License-Identifier: Apache-2.0
import unittest
import support
from ocr_security.common import Refusal
from ocr_security_gate import review_gate

class ReviewActionTests(unittest.TestCase):
    def event(self,head='a'*40,state='complete',origin='automatic',event_id='review-1'):
        return {'event_id':event_id,'origin':origin,'head':head,'state':state,'receipt_sha256':'b'*64,
                'intent_sha256':'c'*64 if origin=='root_intentional' else None}
    def test_no_lookup_or_request_before_final_freeze(self):
        value=review_gate.reconcile_reviews([],'a'*40,False)
        self.assertEqual(value['decision'],'defer_lookup_until_final_freeze');self.assertFalse(value['request_sent'])
    def test_empty_ledger_only_prepares_root_intent(self):
        value=review_gate.reconcile_reviews([],'a'*40,True)
        intent=review_gate.review_intent(value,1,2,'b'*64)
        self.assertFalse(intent['sent']);self.assertTrue(intent['exactly_one'])
    def test_automatic_and_manual_current_reviews_prevent_duplicate(self):
        for origin in ('automatic','root_intentional'):
            value=review_gate.reconcile_reviews([self.event(origin=origin)],'a'*40,True)
            self.assertTrue(value['current_head_covered'])
            with self.assertRaises(Refusal):review_gate.review_intent(value,1,2,'b'*64)
    def test_inflight_uncertain_and_prior_head_never_request(self):
        for state in ('in_flight','uncertain'):
            self.assertEqual(review_gate.reconcile_reviews([self.event(state=state)],'a'*40,True)['decision'],
                             'reconcile_existing_review_no_request')
        value=review_gate.reconcile_reviews([self.event(head='d'*40)],'a'*40,True)
        self.assertEqual(value['decision'],'hold_review_history_or_current_head_conflict')
    def test_duplicate_intentional_calls_hold(self):
        entries=[self.event(origin='root_intentional'),self.event(origin='root_intentional',event_id='review-2')]
        self.assertEqual(review_gate.reconcile_reviews(entries,'a'*40,True)['decision'],'hold_duplicate_intentional_reviews')
    def test_merge_requires_exact_current_checks_and_qualification(self):
        review=review_gate.reconcile_reviews([self.event()],'a'*40,True)
        checks=[{'name':'unit','head':'a'*40,'status':'passed','receipt_sha256':'b'*64}]
        value=review_gate.merge_handoff('a'*40,review,checks,['unit'],False,'c'*64,[],'qualified')
        self.assertEqual(value['status'],'ready_for_root_reconciliation');self.assertFalse(value['merge_executed'])
        checks[0]['head']='d'*40
        value=review_gate.merge_handoff('a'*40,review,checks,['unit'],True,None,['exact-hold'],'held')
        self.assertEqual(value['status'],'held');self.assertIn('required_check_unsatisfied',value['blockers'])
        self.assertIn('integration_qualification_held',value['blockers']);self.assertFalse(value['extra_review_requested'])
