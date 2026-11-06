# SPDX-License-Identifier: Apache-2.0
import unittest
import support
from ocr_security.common import Refusal
from ocr_security_gate import workflow,batching

class WorkflowTests(unittest.TestCase):
    def handoff(self,review='failed',state='not_attempted'):
        return workflow.preservation_handoff(1,'fixture-branch',2,'a'*40,
            [{'path':'safe.py','sha256':'b'*64,'eligible':True,'hold_code':None},
             {'path':'private.txt','sha256':'c'*64,'eligible':False,'hold_code':'permission_hold'}],
            'd'*64,review,state)
    def test_review_failure_does_not_strand_eligible_source(self):
        for state in ('failed','pending','findings','unavailable','clean'):
            value=self.handoff(state);self.assertEqual(value['next_action'],'root_preserve_eligible_source')
            self.assertEqual([x['path'] for x in value['eligible']],['safe.py'])
            self.assertEqual(len(value['held']),1);self.assertEqual(value['acceptance'],'held')
            self.assertFalse(value['wait_for_batch_size']);self.assertFalse(value['review_lookup_required_for_preservation'])
    def test_uncertain_and_denied_publication_do_not_auto_retry(self):
        self.assertEqual(self.handoff(state='uncertain')['next_action'],'reconcile_exact_outcome')
        self.assertEqual(self.handoff(state='failed')['next_action'],'reconcile_exact_outcome')
        self.assertEqual(self.handoff(state='denied')['next_action'],'retain_exact_hold')
    def test_failed_action_requires_known_nonexecution_and_unused_authorization(self):
        record=workflow.begin_attempt(workflow.ActionRecord('a'*64,'b'*64,'publish'),'c'*64)
        uncertain=workflow.record_outcome(record,'failed','d'*64)
        self.assertEqual(workflow.action_handoff(uncertain,'e'*64)['action'],'reconcile_exact_outcome')
        with self.assertRaises(Refusal):workflow.begin_attempt(uncertain,'e'*64)
        failed=workflow.record_outcome(record,'failed','d'*64,known_not_executed=True)
        for authorization in (None,'c'*64,'d'*64):
            self.assertEqual(workflow.action_handoff(failed,authorization)['action'],'retain_exact_hold')
        self.assertEqual(workflow.action_handoff(failed,'e'*64)['action'],'root_consider_one_supported_retry')
    def test_denial_retry_needs_new_evidence_once(self):
        record=workflow.ActionRecord('a'*64,'b'*64,'publish')
        record=workflow.begin_attempt(record,'c'*64)
        record=workflow.record_outcome(record,'denied','d'*64,known_not_executed=True)
        self.assertEqual(workflow.action_handoff(record)['action'],'retain_exact_hold')
        self.assertEqual(workflow.action_handoff(record,'c'*64)['action'],'retain_exact_hold')
        self.assertEqual(workflow.action_handoff(record,'e'*64)['action'],'root_consider_one_supported_retry')
        record=workflow.begin_attempt(record,'e'*64)
        record=workflow.record_outcome(record,'denied','f'*64,known_not_executed=True)
        self.assertEqual(workflow.action_handoff(record,'e'*64)['action'],'retain_exact_hold')
    def test_uncertain_action_requires_reconciliation_even_with_new_evidence(self):
        record=workflow.ActionRecord('a'*64,'b'*64,'merge',outcome='uncertain',attempts=1)
        self.assertEqual(workflow.action_handoff(record,'c'*64)['action'],'reconcile_exact_outcome')
        with self.assertRaises(Refusal):workflow.begin_attempt(record,'c'*64)
    def test_success_is_not_repeated_and_stage_cannot_self_accept(self):
        record=workflow.ActionRecord('a'*64,'b'*64,'publish',outcome='succeeded',attempts=1)
        self.assertEqual(workflow.action_handoff(record)['action'],'do_not_repeat')
        with self.assertRaises(Refusal):workflow.stage_summary('complete','clean','verified','passed','qualified')
    def test_rollback_and_all_root_actions_remain_data_only(self):
        self.assertEqual(workflow.rollback(),workflow.rollback())
        self.assertFalse(workflow.rollback()['actions_executed'])
        with self.assertRaises(Refusal):workflow.execute('publish',authorized=True)

class BatchingTests(unittest.TestCase):
    def paths(self,n):return ['file-%d.py'%i for i in range(n)]
    def test_below_target_continues_without_waiting_to_preserve(self):
        value=batching.batch_decision(self.paths(100),['next.py'],True)
        self.assertEqual(value['decision'],'preserve_then_continue_coherent_scope');self.assertFalse(value['preservation_delayed'])
    def test_distinct_not_repeated_paths_count(self):
        value=batching.batch_decision(self.paths(200),self.paths(200),True)
        self.assertEqual(value['projected_distinct_paths'],200)
        self.assertEqual(value['decision'],'freeze_current_batch')
    def test_coherent_over_cap_and_existing_over_cap(self):
        self.assertEqual(batching.batch_decision(self.paths(250),['next-%d.py'%i for i in range(60)],True)['decision'],
                         'preserve_current_then_dependent_draft')
        self.assertEqual(batching.batch_decision(self.paths(301),[],False)['decision'],'hold_over_cap_existing_batch')
    def test_final_dependency_boundaries_do_not_add_filler(self):
        for reason in ('final_scope','dependency_hold','no_eligible_work'):
            value=batching.batch_decision(self.paths(94),[],False,reason)
            self.assertEqual(value['decision'],'document_smaller_boundary');self.assertFalse(value['padding_allowed'])
