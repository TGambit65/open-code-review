# SPDX-License-Identifier: Apache-2.0
"""Inert, synthetic state records. No external action or approval is performed."""
import unittest
from pathlib import Path
import sys
ROOT = Path(__file__).absolute().parents[1]
for directory in (ROOT, ROOT.parent / 's01', ROOT.parent / 's02-s03'):
    sys.path.insert(0, str(directory))
from dataclasses import replace
from ocr_security.common import Refusal
from ocr_security_gate import workflow as w


class ActionShapeTests(unittest.TestCase):
    def record(self):
        return w.record_outcome(w.begin_attempt(w.ActionRecord('a'*64, 'b'*64, 'publish'), 'c'*64),
                                'failed', 'd'*64, True, authorization_sha256='c'*64)

    def reject_every_consumer(self, record):
        for call in (lambda: w.action_handoff(record, 'e'*64),
                     lambda: w.begin_attempt(record, 'e'*64),
                     lambda: w.record_outcome(record, 'failed', 'f'*64, True, authorization_sha256='c'*64)):
            with self.assertRaises(Refusal) as caught:
                call()
            self.assertNotIn('private-marker', str(caught.exception))

    def test_wrong_knowledge_types_never_offer_retry(self):
        for value in ('false', 'private-marker', 1, 0, None, [], {}):
            with self.subTest(value=value):
                self.reject_every_consumer(replace(self.record(), known_not_executed=value))

    def test_attempt_shape(self):
        for value in (True, False, -1, 1.0, '1', None, 2**63):
            self.reject_every_consumer(replace(self.record(), attempts=value))

    def test_history_is_bounded_immutable_unique_digests(self):
        for value in (['c'*64], 'c'*64, None, {}, ([],), ('private-marker',),
                      ('c'*64, 'c'*64), tuple(f'{i:064x}' for i in range(4097))):
            self.reject_every_consumer(replace(self.record(), used_authorizations=value))

    def test_optional_receipt_and_record_identity(self):
        for value in ('private-marker', 123, []):
            self.reject_every_consumer(replace(self.record(), last_evidence_sha256=value))
        for record in (None, {}, 'private-marker'):
            self.reject_every_consumer(record)

    def test_contradictory_execution_knowledge(self):
        for outcome in ('in_flight', 'uncertain', 'succeeded'):
            self.reject_every_consumer(replace(self.record(), outcome=outcome))

    def test_legacy_display_records_still_do_not_retry(self):
        for outcome, action in (('uncertain', 'reconcile_exact_outcome'), ('succeeded', 'do_not_repeat')):
            record=w.ActionRecord('a'*64, 'b'*64, 'publish', outcome=outcome, attempts=1)
            self.assertEqual(w.action_handoff(record)['action'], action)
            with self.assertRaises(Refusal): w.begin_attempt(record, 'e'*64)

    def test_actual_sequence_retains_used_digest_and_latest_attempt_fence(self):
        failed=self.record()
        self.assertEqual(w.action_handoff(failed, 'e'*64)['action'], 'root_consider_one_supported_retry')
        second=w.begin_attempt(failed, 'e'*64)
        self.assertEqual(second.attempts, 2)
        self.assertEqual(second.used_authorizations, ('c'*64, 'e'*64))
        with self.assertRaises(Refusal):
            w.record_outcome(second, 'failed', 'f'*64, True, authorization_sha256='c'*64)
        uncertain=w.record_outcome(second, 'uncertain', 'f'*64, authorization_sha256='e'*64)
        self.assertEqual(w.action_handoff(uncertain, '1'*64)['action'], 'reconcile_exact_outcome')
        done=w.record_outcome(uncertain, 'succeeded', '1'*64, authorization_sha256='e'*64)
        handoff=w.action_handoff(done)
        self.assertEqual(handoff['action'], 'do_not_repeat')
        self.assertFalse(handoff['permission_granted'])
        self.assertFalse(handoff['external_action_executed'])
        with self.assertRaises(Refusal): w.execute('publish')

    def test_initial_record_cannot_reuse_known_authorization(self):
        initial=w.ActionRecord('a'*64, 'b'*64, 'publish', used_authorizations=('c'*64,))
        self.assertEqual(w.action_handoff(initial, 'c'*64)['action'], 'retain_exact_hold')
        with self.assertRaisesRegex(Refusal, 'action_not_retryable'):
            w.begin_attempt(initial, 'c'*64)
        self.assertEqual(initial.used_authorizations, ('c'*64,))
        self.assertEqual(w.action_handoff(initial, 'e'*64)['action'], 'root_consider_initial_action')
        started=w.begin_attempt(initial, 'e'*64)
        self.assertEqual(started.used_authorizations, ('c'*64, 'e'*64))
        self.assertEqual(w.action_handoff(started)['action'], 'reconcile_exact_outcome')
        done=w.record_outcome(started, 'succeeded', 'f'*64, authorization_sha256='e'*64)
        self.assertEqual(w.action_handoff(done)['action'], 'do_not_repeat')

    def test_capacity_never_discards_history(self):
        history=tuple(f'{i:064x}' for i in range(4096))
        full=replace(self.record(), attempts=4096, used_authorizations=history)
        with self.assertRaisesRegex(Refusal, 'action_history_capacity'): w.begin_attempt(full, 'e'*64)
        self.assertEqual(full.used_authorizations, history)
        with self.assertRaisesRegex(Refusal, 'action_history_capacity'):
            w.begin_attempt(replace(self.record(), attempts=2**63-1), 'e'*64)


if __name__ == '__main__': unittest.main()
