# SPDX-License-Identifier: Apache-2.0
"""Synthetic aggregate boundaries only; no native process or real authority."""
import copy
import unittest
from unittest.mock import patch
import support
from ocr_security.common import Refusal, canonical, digest
from ocr_security_adapters.data import bounded_json
from ocr_security_gate import evidence, gate, observations, reports


class AggregateCapacityTests(unittest.TestCase):
    def retained_groups(self, count):
        previous=[dict(fingerprint=digest(str(i).encode()),first_seen=support.NOW.isoformat(),observations=[])
                  for i in range(count)]
        # group deliberately preserves evidence even when its composed output is too large.
        if count <= 1024:
            return observations.group([],previous=previous)
        return self.retained_groups(1024)+[dict(self.retained_groups(1)[0],fingerprint=digest(b'extra'))]

    def test_history_1024_round_trip_and_1025_explicit_refusal(self):
        snap,_=support.snapshot();pol=support.policy();target=support.target(snap)
        groups=self.retained_groups(1024);before=canonical(groups)
        self.assertTrue(observations.within_capacity(groups))
        doc=observations.history_document(groups,pol,target,support.NOW)
        raw=canonical(doc);pin=digest(raw)
        # Mock only external custody; both actual budget parser and row validator run.
        adopted=support.policy(prior_history_sha256=pin)
        with patch.object(observations,'pinned',return_value=(bounded_json(raw),pin)):
            loaded,_=observations.load_history(None,None,adopted,target,support.NOW)
        self.assertEqual(loaded,doc['groups']);self.assertEqual(canonical(groups),before)
        too_many=self.retained_groups(1025);before=canonical(too_many)
        self.assertFalse(observations.within_capacity(too_many))
        with self.assertRaisesRegex(Refusal,'aggregate_capacity_exceeded'):
            observations.history_document(too_many,pol,target,support.NOW)
        self.assertEqual(canonical(too_many),before)

    def test_two_valid_scanner_producers_overflow_is_renderable_and_retained(self):
        snap,views=support.snapshot(b'x\n'*513);items=[]
        for adapter in ('gitleaks','opengrep'):
            findings=[]
            for line in range(1,514):
                row=support.finding(snap,identity=adapter+str(line))
                row['evidence_identity']['ranges']=[[line,line]];findings.append(row)
            envelope,pins=support.normalized(snap,views,findings)
            envelope['adapter']=adapter
            item=evidence.scanner(canonical(envelope),adapter,snap,views,pins,support.adapter_policy(snap))
            self.assertEqual(len(item.value()['private_findings']),513);items.append(item)
        items=tuple(items);original=tuple(x.private_document for x in items)
        decision=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        self.assertEqual(len(decision['groups']),1026)
        self.assertEqual(decision['status'],'error')
        self.assertIn(observations.CAPACITY_ERROR,decision['errors'])
        before=canonical(decision)
        report=reports.project(decision,items,views,snap);value=report.value()
        self.assertEqual(value['decision']['status'],'error')
        self.assertIn('Private group count: 1026',value['limitations'])
        self.assertEqual(value['findings'],[])
        self.assertTrue(any('not absence of findings' in x for x in value['limitations']))
        for format in ('json','markdown','html'):self.assertTrue(reports.render(report,format))
        self.assertEqual(canonical(decision),before)
        self.assertEqual(tuple(x.private_document for x in items),original)
        with self.assertRaises(Refusal):
            observations.history_document(decision['groups'],support.policy(),support.target(snap),support.NOW)

    def test_unmarked_overflow_cannot_masquerade_as_pass(self):
        snap,views=support.snapshot();items=support.all_evidence(snap)
        decision=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        decision['groups']=self.retained_groups(1025);decision['status']='pass'
        decision.pop('decision_sha256');decision['decision_sha256']=digest(canonical(decision))
        with self.assertRaisesRegex(Refusal,'unmarked_aggregate_overflow'):
            reports.project(decision,items,views,snap)

    def test_history_only_overflow_is_error_and_renderable(self):
        snap,views=support.snapshot();pol=support.policy();target=support.target(snap)
        seed=observations.collect((support.evidence(snap,findings=(support.finding(snap),)),),snap,support.NOW)[0]
        previous=[]
        for i in range(900):
            row=copy.deepcopy(seed);row['observation_id']=digest(str(i).encode())
            row['fingerprint']=digest(('fp'+str(i)).encode())
            previous.append(dict(fingerprint=row['fingerprint'],first_seen=support.NOW.isoformat(),observations=[row]))
        history=dict(schema_version='1.0',kind='private-finding-history',policy_sha256=pol.sha256,
                     history_scope_sha256=pol.value()['history_scope_sha256'],repository_id=1,
                     source_sha256=target['source_sha256'],at=support.NOW.isoformat(),groups=previous)
        raw=canonical(history);pin=digest(raw);bounded_json(raw)
        pol=support.policy(prior_history_sha256=pin)
        with patch.object(observations,'pinned',return_value=(bounded_json(raw),pin)):
            decision=gate.evaluate(target,pol,(),snap,support.update(),None,support.NOW,history_ref=object())
        self.assertEqual(len(decision['groups']),900)
        self.assertFalse(observations.within_capacity(decision['groups']))
        self.assertEqual(decision['status'],'error')
        self.assertIn(observations.CAPACITY_ERROR,decision['errors'])
        self.assertEqual(decision['external_receipts']['history'],pin)
        before=canonical(decision)
        report=reports.project(decision,(),views,snap)
        self.assertEqual(report.value()['decision']['status'],'error')
        self.assertTrue(reports.render(report,'json'))
        self.assertEqual(canonical(decision),before)
        self.assertEqual(canonical(history),raw)

    def test_final_resolution_label_crosses_exact_byte_boundary(self):
        snap,views=support.snapshot();items=support.all_evidence(snap,findings=(support.finding(snap),))
        groups=observations.group(observations.collect(items,snap,support.NOW))
        fp=groups[0]['fingerprint']
        # Retained history permits opaque provenance. Construct an exact bounded
        # synthetic serialization near the byte ceiling, without huge strings.
        padding=['x'*65000 for _ in range(16)]+['']
        groups[0]['observations'][0]['provenance']['fixture_padding']=padding
        remaining=1048575-len(canonical(groups))
        self.assertGreater(remaining,0);self.assertLess(remaining,65536)
        padding[-1]='x'*remaining
        self.assertEqual(len(canonical(groups)),1048575)
        self.assertTrue(observations.within_capacity(groups))
        def disposition(refs,context,policy,target,actual,now,kind='finding-exception'):
            return {fp:'synthetic-receipt'} if kind=='finding-resolution' else {}
        with patch.object(gate,'group',return_value=groups),patch.object(gate,'decisions',side_effect=disposition):
            decision=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        self.assertEqual(decision['groups'][0]['resolution'],'independently_resolved')
        self.assertGreater(len(canonical(decision['groups'])),1048576)
        self.assertEqual(decision['status'],'error')
        self.assertIn(observations.CAPACITY_ERROR,decision['errors'])
        self.assertEqual(reports.project(decision,items,views,snap).value()['decision']['status'],'error')

    def test_timeline_and_serialized_limits_never_drop_history(self):
        groups=self.retained_groups(1)
        groups[0]['observations']=[{'observation_id':digest(str(i).encode())} for i in range(4097)]
        before=canonical(groups)
        self.assertFalse(observations.within_capacity(groups))
        snap,_=support.snapshot()
        with self.assertRaises(Refusal):
            observations.history_document(groups,support.policy(),support.target(snap),support.NOW)
        self.assertEqual(canonical(groups),before)
        groups=self.retained_groups(1);groups[0]['observations']=[{'large':'x'*65536} for _ in range(17)]
        self.assertFalse(observations.within_capacity(groups))


if __name__=='__main__':unittest.main()
