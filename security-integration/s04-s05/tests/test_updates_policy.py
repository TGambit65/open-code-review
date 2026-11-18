# SPDX-License-Identifier: Apache-2.0
"""Authored offline regressions; not executed during implementation."""
import unittest
from dataclasses import replace
import support
from ocr_security.common import Refusal,canonical,digest
from ocr_security_gate import contracts,updates,orchestrator
from ocr_security_adapters.boundary import Plan

class UpdatesPolicyTests(unittest.TestCase):
    def test_external_policy_cannot_drop_required_security(self):
        for changes in ({"required_adapters":["ocr"]},{"blocking_severities":["High"]},{"candidate_controls":"effective"},{"required_datasets":[]}):
            with self.subTest(changes=changes),self.assertRaises(Refusal):support.policy(**changes).value()
    def test_policy_source_identity_is_exact(self):
        p=support.policy()
        with self.assertRaises(Refusal):replace(p,sha256="0"*64).value()
    def test_policy_rejects_unknown_keys_and_duplicate_json(self):
        with self.assertRaises(Refusal):support.policy(extra=True).value()
        with self.assertRaises(Refusal):contracts.parse_policy(b'{"x":1,"x":2}')
        for changes in ({'history_scope_sha256':None},{'prior_history_sha256':'missing'}):
            with self.assertRaises(Refusal):support.policy(**changes).value()
    def test_supplied_assets_need_exact_bytes(self):
        item=support.update()
        self.assertTrue(updates.verify_supplied_bytes(item,{"db-npm":b"fictional-database"})["bytes_match"])
        for raw in ({},{"db-npm":b"other"}):
            with self.assertRaises(Refusal):updates.verify_supplied_bytes(item,raw)
    def test_mutable_and_unverified_declarations_refused(self):
        with self.assertRaises(Refusal):support.update(version="latest").value()
        value=support.update().value();value["assets"][0]["verification_receipt_sha256"]="missing"
        with self.assertRaises(Refusal):updates.parse_manifest(canonical(value))
    def test_current_expired_absent_unsupported_truthful(self):
        cases=((support.update(),["npm"],"current"),(support.update("2026-11-06T00:00:00Z"),["npm"],"expired"),
               (None,["npm"],"absent"),(support.update(),["PyPI"],"unsupported"))
        for current,datasets,expected in cases:
            value=updates.freshness(current,None,datasets,support.NOW)
            self.assertEqual(value["datasets"][0]["state"],expected)
            self.assertEqual(value["intelligence_current"],expected=="current")
    def test_failure_and_rollback_never_masquerade_as_current(self):
        old=support.update();new=support.update(previous=old.sha256)
        self.assertFalse(updates.freshness(new,old,["npm"],support.NOW,rollback=True)["intelligence_current"])
        self.assertFalse(updates.freshness(new,old,["npm"],support.NOW,"failed")["intelligence_current"])
        with self.assertRaises(Refusal):updates.freshness(old,new,["npm"],support.NOW,rollback=True)
    def test_all_execution_and_acquisition_remain_refused(self):
        for callback in (updates.acquire,orchestrator.execute):
            with self.assertRaises(Refusal):callback(enabled=True,accepted=True)
        self.assertEqual(orchestrator.rollback(),orchestrator.rollback())
        self.assertFalse(orchestrator.rollback()["execution_enabled"])

class OrchestrationTests(unittest.TestCase):
    def plans(self,gitleaks_operation='files'):
        snap,_=support.snapshot()
        # Pure prior-interface objects, not qualified native plans or executions.
        def plan(adapter,operation):
            pins=(('binary','c'*64),('rules','d'*64))
            if adapter=='ocr':pins+=(('model_projection','e'*64),)
            return Plan(adapter,operation,('/tool/'+adapter,operation),'c'*64,'b'*64,snap.snapshot_id,
                        'model' if adapter=='ocr' else 'scanner',pins,('qualification_held',),
                        'item-0000' if operation=='stdin' else None)
        return snap,(plan('ocr','preview'),plan('ocr','rule'),plan('opengrep','files'),
                     plan('gitleaks',gitleaks_operation),plan('osv','lockfiles'))
    def test_exact_five_operations_remain_disabled(self):
        for operation in ('files','history','stdin'):
            snap,plans=self.plans(operation)
            value=orchestrator.offline_plan(support.target(snap),support.policy(),plans)
            self.assertEqual(len(value['plans']),5);self.assertFalse(value['execution_enabled'])
            self.assertEqual(value['qualification'],'HELD');self.assertEqual(value['status'],'not-run')
            self.assertEqual({(x['adapter'],x['operation']) for x in value['plans']},
                             {('ocr','preview'),('ocr','rule'),('opengrep','files'),('gitleaks',operation),('osv','lockfiles')})
    def test_missing_duplicate_or_mixed_ocr_operations_refuse(self):
        snap,plans=self.plans()
        cases=(plans[1:],(plans[0],plans[0])+plans[2:],(plans[0],replace(plans[1],operation='files'))+plans[2:],
               (plans[0],replace(plans[1],tool_sha256='f'*64))+plans[2:],
               (plans[0],replace(plans[1],policy_sha256='f'*64))+plans[2:],
               (plans[0],replace(plans[1],snapshot_id='f'*64))+plans[2:],
               (plans[0],replace(plans[1],view='scanner'))+plans[2:],
               (plans[0],replace(plans[1],asset_pins=(('binary','c'*64),('rules','d'*64))))+plans[2:],
               (plans[0],replace(plans[1],asset_pins=(('binary','c'*64),('rules','d'*64),('model_projection','f'*64))))+plans[2:],
               (plans[0],replace(plans[1],asset_pins=(('binary','c'*64),('rules','f'*64),('model_projection','e'*64))))+plans[2:],
               plans[:3]+(replace(plans[3],operation='unsupported'),)+plans[4:],
               plans[:4]+(replace(plans[4],adapter='opengrep',operation='files'),))
        for candidate in cases:
            with self.subTest(roles=[(x.adapter,x.operation) for x in candidate]),self.assertRaises(Refusal):
                orchestrator.offline_plan(support.target(snap),support.policy(),candidate)
