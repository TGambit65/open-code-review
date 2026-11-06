# SPDX-License-Identifier: Apache-2.0
import html
from html.parser import HTMLParser
import json
import unittest
from dataclasses import replace
import support
from ocr_security.common import Refusal,canonical,digest
from ocr_security_gate import gate,reports,entrypoint

class Tags(HTMLParser):
    def __init__(self):super().__init__();self.tags=[];self.attributes=[];self.in_pre=False;self.pre=[]
    def handle_starttag(self,tag,attrs):self.tags.append(tag);self.attributes.extend(attrs);self.in_pre=self.in_pre or tag=='pre'
    def handle_endtag(self,tag):
        if tag=='pre':self.in_pre=False
    def handle_data(self,data):
        if self.in_pre:self.pre.append(data)

class ReportTests(unittest.TestCase):
    def make(self):
        raw=b'<script>alert("fictional")</script>\n![image](https://example.invalid/track)\n[REDACTED]\n'
        snap,views=support.snapshot(raw);items=support.all_evidence(snap,(support.finding(snap),))
        decision=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        report=reports.project(decision,items,views,snap,(('item-0000','primary',1,3),))
        return snap,views,items,report
    def test_three_formats_have_exact_semantic_parity(self):
        _,_,_,report=self.make();json_doc=json.loads(reports.render(report,'json'))
        markdown=reports.render(report,'markdown').decode().splitlines()[2:]
        self.assertEqual(json.loads('\n'.join(line[4:] for line in markdown)),json_doc)
        parser=Tags();parser.feed(reports.render(report,'html').decode())
        self.assertEqual(json.loads(''.join(parser.pre)),json_doc)
    def test_hostile_text_does_not_create_active_markup_or_links(self):
        _,_,_,report=self.make();raw=reports.render(report,'html').decode();parser=Tags();parser.feed(raw)
        self.assertTrue(set(parser.tags).isdisjoint({'script','img','a','iframe','object','embed','form'}))
        self.assertFalse(any(name in ('href','src') or name.startswith('on') for name,_ in parser.attributes))
        self.assertIn("default-src 'none'",raw)
        self.assertIn('overflow-wrap:anywhere',raw);self.assertIn('@media print',raw)
    def test_original_paths_and_raw_metadata_not_published(self):
        _,_,_,report=self.make()
        for format in ('json','markdown','html'):
            raw=reports.render(report,format)
            self.assertNotIn(b'private-path.py',raw);self.assertNotIn(b'private:DO_NOT_PUBLISH',raw)
            self.assertIn(b'[REDACTED]',raw)
    def test_optional_sarif_and_upload_refuse(self):
        for action in (reports.export_sarif,reports.upload):
            with self.assertRaises(Refusal):action()
    def test_entrypoint_returns_only_named_inert_public_files(self):
        snap,views,items,_=self.make()
        result=entrypoint.assess(support.target(snap),support.policy(),items,snap,views,support.update(),None,support.NOW)
        receipt=entrypoint.artifact_receipts(result)
        self.assertEqual([x['name'] for x in receipt['files']],['security-report.json','security-report.md','security-report.html'])
        self.assertFalse(receipt['files_written']);self.assertFalse(receipt['uploaded'])
    def test_other_snapshot_bundle_cannot_supply_current_report_excerpts(self):
        snap,views,items,_=self.make();other_snapshot,other=support.snapshot(b'print("unrelated released content")\n')
        decision=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        self.assertEqual(views.model.items[0].opaque_id,other.model.items[0].opaque_id)
        with self.assertRaises(Refusal):reports.project(decision,items,other,snap,(("item-0000","primary",1,1),))
        with self.assertRaises(Refusal):reports.project(decision,items,other,other_snapshot)
        with self.assertRaises(Refusal):entrypoint.assess(support.target(snap),support.policy(),items,snap,other,support.update(),None,support.NOW)
    def test_bundle_and_transformation_cannot_be_substituted_independently(self):
        snap,views,items,_=self.make();_,other=support.snapshot(b'print("different released content")\n')
        decision=gate.evaluate(support.target(snap),support.policy(),items,snap,support.update(),None,support.NOW)
        with self.assertRaises(Refusal):reports.project(decision,items,replace(views,model=other.model),snap)
        changed=replace(views,model=other.model,private_evidence=canonical({"snapshot_id":snap.snapshot_id,"model_bundle_id":other.model.bundle_id}))
        with self.assertRaises(Refusal):reports.project(decision,items,changed,snap)
        changed=replace(views,private_evidence=canonical({"snapshot_id":snap.snapshot_id,"model_bundle_id":views.model.bundle_id,"extra":"fictional"}))
        with self.assertRaises(Refusal):reports.project(decision,items,changed,snap)
        with self.assertRaises(Refusal):reports.project(decision,items,replace(views,scanner_inputs=other.scanner_inputs),snap)
        with self.assertRaises(Refusal):reports.project(decision,items,views.model,snap)
    def test_no_evidence_report_is_inert_without_unbound_excerpts(self):
        snap,views=support.snapshot()
        decision=gate.evaluate(support.target(snap),support.policy(),(),snap,support.update(),None,support.NOW)
        report=reports.project(decision,(),views,snap)
        self.assertEqual(report.value()["decision"]["status"],"not-run")
        self.assertEqual(report.value()["excerpts"],[]);self.assertIsNone(report.value()['decision']['model_bundle_id'])
        with self.assertRaises(Refusal):reports.project(decision,(),views,snap,(("item-0000","primary",1,1),))
    def test_each_successful_evidence_requires_exact_transformation_binding(self):
        from ocr_security_gate.evidence import Evidence
        snap,views,items,_=self.make()
        for name in ('ocr','gitleaks'):
            source=next(item for item in items if item.adapter==name);record=source.value()
            if name=='ocr':record['transformation_sha256']='0'*64
            else:record['pins']['transformation_sha256']='0'*64
            raw=canonical(record);changed=Evidence(name,digest(raw),raw)
            altered=tuple(changed if item.adapter==name else item for item in items)
            decision=gate.evaluate(support.target(snap),support.policy(),altered,snap,support.update(),None,support.NOW)
            with self.assertRaises(Refusal):reports.project(decision,altered,views,snap)
