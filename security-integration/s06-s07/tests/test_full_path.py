# SPDX-License-Identifier: Apache-2.0
"""Function-only end-to-end fixtures. No native detector or real authority runs."""
import json
import unittest
from dataclasses import replace
from html.parser import HTMLParser
import support
from ocr_security.common import Refusal
from ocr_security_integration import entrypoint, registry


class Pre(HTMLParser):
    def __init__(self):super().__init__();self.active=False;self.content=[];self.tags=[]
    def handle_starttag(self,tag,attrs):self.tags.append(tag);self.active=self.active or tag=='pre'
    def handle_endtag(self,tag):
        if tag=='pre':self.active=False
    def handle_data(self,data):
        if self.active:self.content.append(data)


class FullPathTests(unittest.TestCase):
    def decision(self,result):return json.loads(result.baseline.private_decision)
    def test_safe_fixture_composes_ingestion_and_sanitized_public_boundary(self):
        result=support.evaluate(support.case())
        self.assertEqual(self.decision(result)['status'],'pass')
        self.assertFalse(self.decision(result)['execution_enabled'])
        artifacts=dict(entrypoint.public_artifacts(result))
        self.assertEqual(set(artifacts),{'security-report.json','security-report.md','security-report.html','security-integration-status.json'})
        status=json.loads(artifacts['security-integration-status.json'])
        self.assertEqual(status['sprint_qualification'],'HELD');self.assertFalse(status['target_clearance_granted'])
        self.assertIn('coverage is missing',status['notice'])
    def test_seeded_high_is_not_a_passing_target(self):
        result=support.evaluate(support.case(positive=True))
        self.assertEqual(self.decision(result)['status'],'with-findings')
        self.assertTrue(self.decision(result)['blocking_fingerprints'])
    def test_exit_zero_without_independent_evidence_is_incomplete(self):
        result=support.evaluate(support.case(),attested=False)
        self.assertEqual(self.decision(result)['status'],'incomplete')
    def test_missing_semantic_review_native_exclusion_and_partial_are_incomplete(self):
        for change in ({'missing_review':True},{'excluded':True},{'partial':True},{'expired_database':True}):
            with self.subTest(change=change):
                result=support.evaluate(support.case(**change))
                self.assertEqual(self.decision(result)['status'],'incomplete')
    def test_malformed_scanner_retains_failure_without_raw_publication(self):
        result=support.evaluate(support.case(malformed=True))
        self.assertEqual(self.decision(result)['status'],'error')
        for name,raw in entrypoint.public_artifacts(result):
            self.assertNotIn(b'{bad-fictional-output',raw)
    def test_redacted_originals_never_reach_reports_or_status(self):
        result=support.evaluate(support.case(redacted=True),excerpt_ranges=(('item-0000','primary',1,1),))
        self.assertEqual(self.decision(result)['status'],'incomplete')
        for name,raw in entrypoint.public_artifacts(result):
            self.assertNotIn(b'FICTIONAL_PRIVATE_BEFORE_DO_NOT_PUBLISH',raw)
            self.assertNotIn(b'private-path.py',raw)
        self.assertIn(b'[REDACTED]',dict(entrypoint.public_artifacts(result))['security-report.json'])
    def test_changed_valid_bundle_cannot_replace_bound_views(self):
        value=support.case();_,other=support.baseline.snapshot(b'print("other source")\n')
        value['views']=other
        with self.assertRaises(Refusal):support.evaluate(value)
    def test_candidate_policy_cannot_drop_a_required_adapter(self):
        value=support.case();value['policy']=support.baseline.policy(required_adapters=['ocr'])
        with self.assertRaises(Refusal):support.evaluate(value)
    def test_public_formats_have_semantic_parity_and_inert_markup(self):
        result=support.evaluate(support.case(positive=True,hostile=True),excerpt_ranges=(('item-0000','primary',1,1),))
        files=dict(entrypoint.public_artifacts(result))
        document=json.loads(files['security-report.json'])
        markdown=files['security-report.md'].decode().splitlines()[2:]
        self.assertEqual(document,json.loads('\n'.join(line[4:] for line in markdown)))
        html=Pre();html.feed(files['security-report.html'].decode())
        self.assertEqual(document,json.loads(''.join(html.content)))
        self.assertTrue(set(html.tags).isdisjoint({'script','a','img','iframe','form'}))
        self.assertFalse(entrypoint.receipts(result)['files_written']);self.assertFalse(entrypoint.receipts(result)['uploaded'])
    def test_no_evidence_and_rollback_do_not_invent_coverage(self):
        value=support.case();value['items']=()
        result=support.evaluate(value,attested=False)
        self.assertEqual(self.decision(result)['status'],'not-run')
        self.assertEqual(registry.disable_integration()['target_acceptance'],'not-run')
