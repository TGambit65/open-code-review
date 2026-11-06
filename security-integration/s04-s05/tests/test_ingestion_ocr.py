# SPDX-License-Identifier: Apache-2.0
import unittest
from dataclasses import replace
from unittest.mock import patch
import support
from ocr_security.common import Refusal,canonical,digest
from ocr_security.policy import TrustedRef
from ocr_security_adapters import projection,reviewer
from ocr_security_adapters.assets import Asset,Inventory,SOURCES
from ocr_security_gate import evidence

class IngestionTests(unittest.TestCase):
    def test_normalized_scanner_contract_and_private_paths(self):
        snap,views=support.snapshot();raw,pins=support.normalized(snap,views,(support.finding(snap),))
        result=evidence.scanner(canonical(raw),'gitleaks',snap,views,pins,support.adapter_policy(snap))
        self.assertEqual(result.value()['completeness'],'complete')
        self.assertIn(b'private-path.py',result.private_document)
        self.assertFalse(result.value()['raw_output_forwarded'])
    def test_malformed_oversized_duplicate_unknown_output_refused(self):
        snap,views=support.snapshot();value,pins=support.normalized(snap,views)
        cases=(b'{bad',b' '*1048577,b'{"adapter":"gitleaks","adapter":"osv"}',canonical(dict(value,unknown=True)))
        for raw in cases:
            result=evidence.scanner(raw,'gitleaks',snap,views,pins,support.adapter_policy(snap))
            self.assertEqual(result.value()['process_status'],'parser_error')
            self.assertNotIn(b'{bad',result.private_document)
    def test_wrong_snapshot_and_mixed_state_refused(self):
        snap,views=support.snapshot();value,pins=support.normalized(snap,views)
        value['result']['identity']['snapshot_id']='0'*64
        self.assertEqual(evidence.scanner(canonical(value),'gitleaks',snap,views,pins,support.adapter_policy(snap)).value()['process_status'],'parser_error')
        value,pins=support.normalized(snap,views);value['process_status']='partial'
        self.assertEqual(evidence.scanner(canonical(value),'gitleaks',snap,views,pins,support.adapter_policy(snap)).value()['process_status'],'parser_error')
    def test_failed_payloads_retain_bounded_digest_only_identity_and_scope(self):
        snap,views=support.snapshot();_,pins=support.normalized(snap,views);pol=support.adapter_policy(snap)
        first=evidence.scanner(b'{bad-one','gitleaks',snap,views,pins,pol)
        second=evidence.scanner(b'{bad-two','gitleaks',snap,views,pins,pol)
        self.assertNotEqual(first.sha256,second.sha256)
        self.assertEqual(first.value()['input_identities']['scanner'],
                         {'sha256':digest(b'{bad-one'),'bytes':8,'state':'exact_digest'})
        self.assertEqual(first.value()['snapshot_id'],snap.snapshot_id)
        self.assertEqual(first.value()['snapshot_policy_sha256'],snap.policy_sha256)
        self.assertEqual(first.value()['adapter_policy_sha256'],pol.sha256)
        self.assertEqual(first.value()['expected_pins'],pins)
        self.assertTrue(first.value()['full_input_identity_available'])
        self.assertNotIn(b'{bad-one',first.private_document)
        other,_=support.snapshot(b'print("another fixture")\n')
        changed=evidence.scanner(b'{bad-one','gitleaks',other,views,pins,pol)
        self.assertNotEqual(first.sha256,changed.sha256)
        changed=evidence.scanner(b'{bad-one','gitleaks',snap,views,pins,replace(pol,sha256='0'*64))
        self.assertNotEqual(first.sha256,changed.sha256)
        changed=evidence.scanner(b'{bad-one','gitleaks',snap,views,dict(pins,tool_sha256='0'*64),pol)
        self.assertNotEqual(first.sha256,changed.sha256)
    def test_oversized_failed_identity_is_explicitly_incomplete(self):
        snap,views=support.snapshot();_,pins=support.normalized(snap,views)
        raw=b'x'*16777217
        value=evidence.scanner(raw,'gitleaks',snap,views,pins,support.adapter_policy(snap)).value()
        identity=value['input_identities']['scanner']
        self.assertIsNone(identity['sha256']);self.assertEqual(identity['bytes'],len(raw))
        self.assertEqual(identity['state'],'full_digest_unavailable_oversize')
        self.assertEqual(identity['prefix_sha256'],digest(raw[:65536]))
        self.assertFalse(value['full_input_identity_available']);self.assertEqual(value['process_status'],'parser_error')
    def test_failed_ocr_inputs_remain_separate_without_forwarding_content(self):
        snap,_=support.snapshot();pol=support.adapter_policy(snap)
        item=evidence.failure('ocr',inputs={'preview':b'bad-preview','rule':b'bad-rules'},snapshot=snap,adapter_policy=pol)
        self.assertEqual(item.value()['input_identities']['preview']['sha256'],digest(b'bad-preview'))
        self.assertEqual(item.value()['input_identities']['rule']['sha256'],digest(b'bad-rules'))
        self.assertNotIn(b'bad-preview',item.private_document);self.assertNotIn(b'bad-rules',item.private_document)
        changed=evidence.failure('ocr',inputs={'preview':b'bad-preview','rule':b'other-rules'},snapshot=snap,adapter_policy=pol)
        self.assertNotEqual(item.sha256,changed.sha256)

class OCRCompositionTests(unittest.TestCase):
    def fixture(self,excluded=False,missing_review=False,suffix='py',authority_changes=None,missing_suffixes=False):
        content={'py':b'print("public fixture")\n','txt':b'Fictional plain text.\n','md':b'# Fictional Markdown\n'}[suffix]
        snap,views=support.snapshot(content,path='private-path.'+suffix);pol=support.adapter_policy(snap)
        suffixes={item.opaque_id:suffix for item in views.model.items}
        view=projection.sanitized_projection(views.model,suffixes)
        excluded=excluded or suffix in ('txt','md')
        rule='Review all JSON values and control paths.\n';rule_asset=digest(b'fictional-rules-file')
        inv=Inventory('ocr',SOURCES['ocr'][0],SOURCES['ocr'][1],digest(b'ocr'),
            (Asset('binary','binary','843be0e56fdff0a5ca6f86c5866f942d6a372dff1c0ca19e7893d72495abf45c','synthetic','a'*64,'b'*64,SOURCES['ocr'][1],None,None,None),
             Asset('rules','rules',rule_asset,'synthetic','a'*64,'b'*64,'fixture',None,None,None)),(),(),'c'*64,'d'*64)
        aliases=[x[0] for x in view.alias_items]
        rows=[{'path':path,'status':'added','insertions':1,'deletions':0} for path in aliases]
        if excluded:
            for row in rows:row['exclude_reason']='unsupported_ext' if suffix in ('txt','md') else 'user_exclude'
        native={'schema_version':'1','mode':'range','repository':'/review','from':view.base_commit,'to':view.head_commit,
                'total_files':len(rows),'reviewable_count':0 if excluded else len(rows),'excluded_count':len(rows) if excluded else 0,
                'total_insertions':len(rows),'total_deletions':0,'reviewable_files':[] if excluded else rows,'excluded_files':rows if excluded else []}
        rules={'schema_version':'1','groups':[{'group_id':1,'source':'custom','pattern':'*','files':aliases,'rule':rule}]}
        preview_raw,rules_raw=canonical(native),canonical(rules)
        events={op:{'at':support.NOW.isoformat(),'exit_code':0,'process_status':'success','report_sha256':digest(raw),
                    'native_execution_receipt_sha256':'e'*64} for op,raw in (('preview',preview_raw),('rule',rules_raw))}
        packet=reviewer.handoff(views.model,pol,'fixture-writer','fixture-reviewer')
        records=[{'handoff_id':packet['handoff_id'],'chunk_id':chunk['chunk_id'],'reviewer_context_id':'fixture-reviewer',
                  'depth':'deep','topics':list(reviewer.TOPICS),'findings':[],'uncertainties':[],'truncated':False} for chunk in packet['chunks']]
        authority_value={'schema_version':'1.0','kind':'approved-ocr-rule-body','adapter_policy_sha256':pol.sha256,
                         'rules_asset_sha256':rule_asset,'body_sha256':digest(rule.encode()),'snapshot_id':snap.snapshot_id,
                         'model_bundle_id':views.model.bundle_id,'projection_suffixes':suffixes}
        if authority_changes:authority_value.update(authority_changes)
        if missing_suffixes:del authority_value['projection_suffixes']
        authority=canonical(authority_value)
        with patch('ocr_security_gate.contracts.read_ref',return_value=authority):
            return evidence.independent_review(preview_raw,rules_raw,events,snap,views,pol,inv,rule,[] if missing_review else records,
                        'fixture-writer','fixture-reviewer',TrustedRef('/fictional-rule-authority',digest(authority)))
    def test_native_preview_and_separate_semantic_accounting_combine(self):
        value=self.fixture().value();self.assertEqual(value['completeness'],'complete')
        self.assertFalse(value['independent_identity_attested_externally'])
        self.assertEqual(value['projection_suffixes'],{'item-0000':'py'})
    def test_exclusions_and_missing_review_stay_incomplete(self):
        self.assertEqual(self.fixture(excluded=True).value()['completeness'],'incomplete')
        self.assertEqual(self.fixture(missing_review=True).value()['completeness'],'incomplete')
        for suffix in ('txt','md'):
            value=self.fixture(suffix=suffix).value()
            self.assertEqual(value['completeness'],'incomplete');self.assertGreater(value['gap_count'],0)
            self.assertEqual(value['projection_suffixes'],{'item-0000':suffix})
    def test_projection_map_must_be_explicit_exact_and_authorized(self):
        self.assertEqual(self.fixture(missing_suffixes=True).value()['process_status'],'parser_error')
        for changed in ({'projection_suffixes':{}},{'projection_suffixes':{'item-0000':'js'}},
                        {'projection_suffixes':{'item-0000':'exe'}},{'snapshot_id':'0'*64},{'model_bundle_id':'0'*64}):
            with self.subTest(changed=changed):
                self.assertEqual(self.fixture(authority_changes=changed).value()['process_status'],'parser_error')
        _,views=support.snapshot()
        for suffixes in (None,{}, {'unselected':'py'}):
            with self.assertRaises(Refusal):evidence.review_projection(views.model,suffixes)
