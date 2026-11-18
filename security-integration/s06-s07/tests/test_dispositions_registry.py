# SPDX-License-Identifier: Apache-2.0
import copy
import json
import unittest
import support
from ocr_security.common import Refusal, canonical, digest
from ocr_security_integration import dispositions, registry


class DispositionTests(unittest.TestCase):
    def test_all_ten_candidates_are_explicitly_not_adopted(self):
        catalog = support.catalog(); value = dispositions.summary(catalog)
        self.assertEqual(len(value['tools']),10); self.assertFalse(value['adoption_authority'])
        self.assertFalse(value['baseline_changed']); self.assertFalse(value['deferred_pilots_block_baseline_disposition'])
        self.assertTrue(all(row['qualification']=='NOT_QUALIFIED' and row['registration_enabled'] is False for row in value['tools']))
    def test_candidate_cannot_select_adopt_or_enable_itself(self):
        original = support.catalog().value()
        for changes in ({'decision':'adopt'}, {'implementation_selected':True}, {'registration_enabled':True}, {'qualification':'QUALIFIED'}):
            value=copy.deepcopy(original); value['decisions'][0].update(changes); raw=canonical(value)
            with self.assertRaises(Refusal):dispositions.load_catalog(raw,digest(raw))
    def test_missing_duplicate_unknown_and_stale_catalogs_refuse(self):
        original=support.catalog().value()
        cases=[]
        value=copy.deepcopy(original); value['decisions'].pop(); cases.append(value)
        value=copy.deepcopy(original); value['decisions'][-1]=value['decisions'][0]; cases.append(value)
        value=copy.deepcopy(original); value['extra']=True; cases.append(value)
        value=copy.deepcopy(original); value['decisions'][0]['tool']='unknown'; cases.append(value)
        for value in cases:
            raw=canonical(value)
            with self.assertRaises(Refusal):dispositions.load_catalog(raw,digest(raw))
        with self.assertRaises(Refusal):dispositions.load_catalog(canonical(original),'0'*64)
        raw=b'{"kind":1,"kind":2}'
        with self.assertRaises(Refusal):dispositions.load_catalog(raw,digest(raw))
    def test_tool_specific_controls_are_recorded_without_executing_flags(self):
        records={row['tool']:row for row in support.catalog().value()['decisions']}
        self.assertEqual(records['betterleaks']['research_release'],'v1.9.0')
        self.assertIn('credential_validation',records['betterleaks']['prohibited_modes'])
        self.assertIn('revocation',records['betterleaks']['prohibited_modes'])
        for flag in ('telemetry','version_check','database_download','module_download','vex_download','registry_contact'):
            self.assertIn(flag,records['trivy']['prohibited_modes'])
        for flag in ('opus','injection','deep','sandbox','repair','runtime_hooks','online_lookup','home_discovery','raw_content_model_path'):
            self.assertIn(flag,records['agentshield']['prohibited_modes'])
    def test_seven_conditional_tasks_are_retained_not_selected(self):
        value=json.loads((support.ROOT/'scope.json').read_bytes())
        self.assertEqual(len(value['current_task_ids']),42)
        self.assertEqual(set(value['conditional_dispositions']),{'S06.04','S06.05','S06.06','S06.QA','S06.V02','S06.V03','S06.V04'})
        self.assertTrue(all(state=='deferred_not_selected' for state in value['conditional_dispositions'].values()))


class RegistryTests(unittest.TestCase):
    def test_registry_describes_only_actual_source_interfaces(self):
        value=registry.manifest(); self.assertEqual(len(value['tools']),14)
        for row in value['tools']:
            self.assertFalse(row['registration_enabled']); self.assertFalse(row['execution_supported'])
            if row['tool'] in registry.BASELINE:
                self.assertTrue(row['interfaces']); self.assertEqual(row['native_runtime'],'NOT_QUALIFIED')
            else:
                self.assertEqual(row['interfaces'],[]); self.assertEqual(row['native_runtime'],'NOT_IMPLEMENTED')
        self.assertEqual(len(value['baseline_operations']),5)
    def test_no_boolean_or_receipt_can_enable_execution(self):
        for action in (registry.execute,registry.activate,registry.acquire):
            with self.assertRaises(Refusal):action(enabled=True,qualified=True,authorized=True,receipt='a'*64)
    def test_optional_and_integration_rollback_keep_standard_ocr_visible(self):
        self.assertEqual(registry.disable_optional(),registry.disable_optional())
        self.assertEqual(registry.disable_optional()['baseline'],'unchanged')
        value=registry.disable_integration()
        self.assertEqual(value['standard_ocr'],'unchanged'); self.assertEqual(value['coverage'],'missing')
        self.assertIn('coverage is missing',value['notice']); self.assertFalse(value['actions_executed'])
