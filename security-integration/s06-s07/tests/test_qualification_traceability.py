# SPDX-License-Identifier: Apache-2.0
import copy
import json
import unittest
from unittest.mock import patch
import support
from ocr_security.common import Refusal, canonical, digest
from ocr_security.policy import TrustedRef
from ocr_security_integration import qualification, traceability


class QualificationTests(unittest.TestCase):
    def documents(self):
        documents={};pins={}
        dependencies={'implementation':(), 'independent_source_review':('implementation',),
                      'remote_preservation':('implementation',), 'offline_fixtures':('remote_preservation',),
                      'native_baseline':('remote_preservation',), 'sanitized_review':('remote_preservation',),
                      'rendering':('remote_preservation',), 'independent_evidence_review':qualification.STEPS[:-1]}
        for stage in qualification.STEPS:
            row={'schema_version':'1.0','kind':'independent-integration-stage-receipt','source_sha256':'a'*64,
                 'scope_sha256':'b'*64,'stage':stage,'result':'passed','actor':'fictional-reviewer',
                 'independence_receipt_sha256':'c'*64,'artifact_sha256':'d'*64,'artifact_location':'private:FICTIONAL_ONLY',
                 'issued_at':'2026-11-06T00:00:00Z','expires_at':'2026-11-07T00:00:00Z',
                 'authority_receipt_sha256':'e'*64,'actual_action':'fictional contract fixture; no action occurred',
                 'input_receipts':{key:pins[key] for key in dependencies[stage]}}
            raw=canonical(row);documents['/fixture-'+stage]=raw;pins[stage]=digest(raw)
        return documents
    def call(self,documents):
        refs=tuple(TrustedRef(path,digest(raw)) for path,raw in documents.items())
        with patch('ocr_security_gate.contracts.read_ref',side_effect=lambda ref,context:documents[ref.path]):
            return qualification.inventory(refs,None,'a'*64,'b'*64,support.NOW)
    def test_no_receipts_stays_unrun_held(self):
        result=self.call({})
        self.assertTrue(all(row['result']=='unrun' for row in result['stages'].values()))
        self.assertEqual(result['sprint_qualification'],'HELD');self.assertFalse(result['execution_enabled'])
    def test_even_complete_fictional_inventory_cannot_enable_native_entrypoint(self):
        result=self.call(self.documents())
        self.assertEqual(result['blockers'],['qualified_native_entrypoint_not_implemented'])
        self.assertEqual(result['sprint_qualification'],'HELD');self.assertFalse(result['target_clearance_granted'])
        self.assertEqual(result['code_rabbit_gate'],'separate_root_batch_requirement')
        self.assertNotIn(b'private:FICTIONAL_ONLY',canonical(result));self.assertNotIn(b'fictional-reviewer',canonical(result))
    def test_wrong_source_scope_expired_future_and_unknown_stage_refuse(self):
        for change in ({'source_sha256':'0'*64},{'scope_sha256':'0'*64},{'expires_at':'2026-11-06T00:30:00Z'},
                       {'issued_at':'2026-11-07T00:00:00Z'},{'stage':'activation'},{'extra':True}):
            documents=self.documents();path='/fixture-implementation';row=json.loads(documents[path]);row.update(change)
            documents[path]=canonical(row)
            with self.subTest(change=change),self.assertRaises(Refusal):self.call(documents)
    def test_final_review_requires_exact_complete_earlier_receipt_set(self):
        for mode in ('missing','changed','prior_failed'):
            documents=self.documents();path='/fixture-independent_evidence_review';row=json.loads(documents[path])
            if mode=='missing':del row['input_receipts']['rendering']
            elif mode=='changed':row['input_receipts']['rendering']='0'*64
            else:
                render=json.loads(documents['/fixture-rendering']);render['result']='blocked'
                documents['/fixture-rendering']=canonical(render)
            documents[path]=canonical(row)
            with self.subTest(mode=mode),self.assertRaises(Refusal):self.call(documents)
    def test_validation_cannot_precede_preservation(self):
        documents=self.documents();path='/fixture-offline_fixtures';row=json.loads(documents[path])
        row['issued_at']='2026-11-05T23:00:00Z';documents[path]=canonical(row)
        with self.assertRaises(Refusal):self.call(documents)
    def test_real_blocked_receipt_is_retained_without_pretending_success(self):
        documents=self.documents();row=json.loads(documents['/fixture-implementation'])
        row['result']='blocked';row['input_receipts']={}
        result=self.call({'/fixture-implementation':canonical(row)})
        self.assertEqual(result['stages']['implementation']['result'],'blocked')
        self.assertEqual(result['sprint_qualification'],'HELD')


class TraceabilityTests(unittest.TestCase):
    def value(self):return json.loads((support.ROOT/'traceability.json').read_bytes())
    def parse(self,value):
        raw=canonical(value);return traceability.parse_ledger(raw,digest(raw))
    def test_all_170_tasks_and_23_recommendations_are_accounted_not_qualified(self):
        raw=(support.ROOT/'traceability.json').read_bytes();value=traceability.summary(raw,digest(raw))
        self.assertEqual(value['task_count'],170);self.assertEqual(value['recommendation_count'],23)
        self.assertTrue(value['mapping_complete']);self.assertFalse(value['requirements_satisfied'])
        self.assertEqual(value['qualification'],'HELD');self.assertFalse(value['execution_enabled'])
    def test_prior_conditional_deferrals_are_preserved(self):
        value=self.parse(self.value());rows={row['id']:row for row in value['tasks']}
        expected={
            'S03.01A':('s02-s03', ['asset-prerequisites.json','scope.json']),
            'S04.08S':('s04-s05', ['scope.json','ocr_security_gate/reports.py'])}
        for identity,(prefix,artifacts) in expected.items():
            with self.subTest(identity=identity):
                self.assertEqual(rows[identity]['disposition'],'deferred_not_selected')
                self.assertEqual(rows[identity]['source_artifacts'],
                                 ['security-integration/'+prefix+'/'+name for name in artifacts])
                locator='security-integration/'+prefix+'/task-map.json#'+identity
                self.assertIn(locator,rows[identity]['evidence_locations'])
                self.assertEqual(rows[identity]['qualification'],'not_asserted_by_this_ledger')
                for recommendation in value['recommendations']:
                    if identity in recommendation['task_ids']:
                        self.assertIn(locator,recommendation['evidence_locations'])
                        self.assertTrue(set(rows[identity]['source_artifacts']) <=
                                        set(recommendation['source_artifacts']))
        baseline=support.ROOT.parent/'s02-s03'
        deferred=json.loads((baseline/'scope.json').read_bytes())['conditional_dispositions']['S03.01A']
        self.assertEqual(deferred,{'disposition':'deferred',
                         'reason':'No exact acquisition authorization; no binary/rule/database assets may be fetched or installed',
                         'checked':False})
        baseline_map=json.loads((baseline/'task-map.json').read_bytes())['tasks']
        acquisition=next(row for row in baseline_map if row['id']=='S03.01A')
        self.assertEqual(acquisition['state'],'DEFERRED_NO_ACQUISITION_AUTHORITY')
        self.assertEqual(acquisition['artifacts'],['asset-prerequisites.json'])
        self.assertFalse(acquisition['accepted'])
        assets=json.loads((baseline/'asset-prerequisites.json').read_bytes())
        self.assertFalse(assets['acquisition_authorized']);self.assertFalse(assets['execution_enabled'])
        reports=support.ROOT.parent/'s04-s05'
        report_scope=json.loads((reports/'scope.json').read_bytes())
        self.assertEqual(report_scope['conditional_disposition']['S04.08S'],
                         'deferred_not_selected_no_receiving_schema')
        report_map=json.loads((reports/'task-map.json').read_bytes())['tasks']
        sarif=next(row for row in report_map if row['id']=='S04.08S')
        self.assertEqual(sarif['state'],'deferred_not_selected')
        self.assertEqual(sarif['completion_evidence'],[])
    def test_missing_duplicate_or_orphan_tasks_refuse(self):
        for mode in ('missing','duplicate','orphan'):
            value=self.value()
            if mode=='missing':value['tasks'].pop()
            elif mode=='duplicate':value['tasks'][-1]=value['tasks'][0]
            else:value['tasks'][0].update(source_artifacts=[],evidence_locations=[])
            with self.subTest(mode=mode),self.assertRaises(Refusal):self.parse(value)
    def test_dependency_condition_and_contract_identity_cannot_drift(self):
        for mode in ('dependency','condition','pin','manifest','qualified'):
            value=self.value();row=next(row for row in value['tasks'] if row['id']=='S06.04')
            if mode=='dependency':row['original_dependencies']=[]
            elif mode=='condition':row['condition']=None
            elif mode=='pin':row['contract_sha256']='0'*64
            elif mode=='manifest':value['original_contract_manifest_sha256']='0'*64
            else:row['qualification']='QUALIFIED'
            with self.subTest(mode=mode),self.assertRaises(Refusal):self.parse(value)
    def test_original_recommendation_mappings_cannot_drop_tasks(self):
        value=self.value();value['recommendations'][0]['task_ids'].pop()
        with self.assertRaises(Refusal):self.parse(value)
        value=self.value();value['recommendations'].pop()
        with self.assertRaises(Refusal):self.parse(value)
    def test_unknown_fields_stale_digest_and_oversized_input_refuse(self):
        value=self.value();value['extra']=True
        with self.assertRaises(Refusal):self.parse(value)
        raw=canonical(self.value())
        with self.assertRaises(Refusal):traceability.parse_ledger(raw,'0'*64)
        raw=b' '*1048577
        with self.assertRaises(Refusal):traceability.parse_ledger(raw,digest(raw))
