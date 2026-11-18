# SPDX-License-Identifier: Apache-2.0
"""Actual paired fixture bytes, not prose-only scenarios. No native execution."""
import json
from pathlib import Path
import unittest
import support
from ocr_security.common import Refusal,ModelBundle,ModelItem,canonical,digest
from ocr_security.views import Views
from ocr_security_gate import gate,reports
from ocr_security_adapters.data import bounded_json
FIXTURES=Path(__file__).absolute().parents[1]/'fixtures'

class FixtureContractTests(unittest.TestCase):
    def test_policy_value_only_weakening_is_real_data_not_authority(self):
        before=json.loads((FIXTURES/'policy-before.json').read_bytes())
        after=json.loads((FIXTURES/'policy-after.json').read_bytes())
        self.assertEqual(set(before),set(after));self.assertNotEqual(before,after)
        trusted=support.policy();pin=trusted.sha256
        with self.assertRaises(Refusal):support.policy(**after).value()
        self.assertEqual(trusted.sha256,pin);self.assertIn('Medium',trusted.value()['blocking_severities'])
    def test_secret_fixture_only_released_after_bytes_reach_public_report(self):
        original=(FIXTURES/'secret-before.txt').read_bytes();sanitized=(FIXTURES/'secret-after.txt').read_text()
        snap,views=support.snapshot(original);old=views.model.items[0]
        item=ModelItem(old.opaque_id,old.surfaces,sanitized,((1,1,'redacted'),),((1,1,'not_released'),))
        serial=[{'id':item.opaque_id,'surfaces':item.surfaces,'content':item.content,'line_map':item.line_map,'gaps':item.gaps}]
        bundle=ModelBundle(digest(canonical(serial)),(item,))
        released=Views(views.scanner_inputs,bundle,canonical({'snapshot_id':snap.snapshot_id,'model_bundle_id':bundle.bundle_id}))
        items=support.all_evidence(snap,views=released)
        value=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        report=reports.project(value,items,released,snap,((item.opaque_id,'primary',1,1),))
        for format in ('json','markdown','html'):
            raw=reports.render(report,format)
            self.assertNotIn(original.strip(),raw);self.assertIn(b'[REDACTED]',raw)
        self.assertEqual(value['status'],'incomplete')
    def test_hostile_fixture_is_retained_but_never_raw_html(self):
        raw=(FIXTURES/'hostile-report.txt').read_bytes();snap,views=support.snapshot(raw);items=support.all_evidence(snap)
        value=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        report=reports.project(value,items,views,snap,(('item-0000','primary',1,len(raw.splitlines())),))
        rendered=reports.render(report,'html')
        self.assertNotIn(b'<script>',rendered);self.assertNotIn(b'<img ',rendered)
        self.assertEqual(report.value()['excerpts'][0]['content'],raw.decode())
    def test_deep_nonfinite_and_oversized_data_refused(self):
        for raw in (b'['*40+b'0'+b']'*40,b'{"value":NaN}',b' '*1048577):
            with self.assertRaises(Refusal):bounded_json(raw)
