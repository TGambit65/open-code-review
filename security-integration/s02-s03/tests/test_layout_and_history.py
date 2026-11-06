# SPDX-License-Identifier: Apache-2.0
"""Authored virtual layout fixtures. No native Git, mount or process operation."""
import unittest
from dataclasses import replace
import support
from ocr_security.common import Refusal, digest, canonical
from ocr_security_adapters import layout, gitleaks, private_history, projection, ocr

class LayoutHistoryTests(unittest.TestCase):
    def adopted_fixture_inventory(self,name):
        original=support.inventory(name)
        values={x.asset_id:("synthetic-"+x.asset_id).encode() for x in original.assets}
        assets=tuple(replace(x,sha256=digest(values[x.asset_id])) for x in original.assets)
        return replace(original,assets=assets),values

    def test_layout_contains_only_declared_read_only_originals(self):
        snap,_=support.sample(); inv,values=self.adopted_fixture_inventory("gitleaks")
        plan=gitleaks.plan(snap,support.policy(),inv)
        mounts=layout.build_layout(plan,snap,inv,values)
        self.assertTrue(all(x.read_only for x in mounts))
        self.assertIn("/input/item-0000.py",[x.destination for x in mounts])
        self.assertNotIn("/input/.gitleaksignore",[x.destination for x in mounts])
        self.assertFalse(layout.requirements(plan)["execution_enabled"])

    def test_layout_rejects_substituted_asset_bytes(self):
        snap,_=support.sample(); inv,values=self.adopted_fixture_inventory("gitleaks")
        plan=gitleaks.plan(snap,support.policy(),inv); values["binary"]=b"different"
        with self.assertRaises(Refusal): layout.build_layout(plan,snap,inv,values)

    def test_bounded_history_uses_synthetic_commits_and_no_host_paths(self):
        snap,_=support.sample(); history=private_history.original_history(snap)
        plan=gitleaks.plan(snap,support.policy(),support.inventory(),"history")
        self.assertNotEqual(history.head_commit,snap.head_commit)
        self.assertIn("--log-opts="+history.base_commit+".."+history.head_commit,plan.argv)
        self.assertEqual(history.commit_items[0][2],"item-0000")
        self.assertNotIn(".gitleaksignore",dict(history.files))
        with self.assertRaises(Refusal): gitleaks.run(plan)

    def test_history_normalization_requires_exact_synthetic_commit(self):
        snap,views=support.sample(); history=private_history.original_history(snap)
        commit,path,item=history.commit_items[0]
        native=[{"RuleID":"fixture-rule","StartLine":1,"EndLine":1,"File":path,"Secret":"REDACTED","Match":"REDACTED","Commit":commit}]
        raw=canonical(native)
        value=gitleaks.normalize(raw,snap,views,support.policy(),support.inventory(),support.evidence(raw,snap,mode="history"),mode="history")
        self.assertNotEqual(value["process_status"],"parser_error")
        native[0]["Commit"]="0"*40; raw=canonical(native)
        value=gitleaks.normalize(raw,snap,views,support.policy(),support.inventory(),support.evidence(raw,snap,mode="history"),mode="history")
        self.assertEqual(value["process_status"],"parser_error")

    def test_scanner_history_and_model_projection_do_not_share_original_bytes(self):
        snap,views=support.sample(b'FICTIONAL_PRIVATE_ORIGINAL\n',redact=True)
        scanner=private_history.original_history(snap); model=projection.sanitized_projection(views.model)
        self.assertIn(b'FICTIONAL_PRIVATE_ORIGINAL\n',dict(scanner.files).values())
        self.assertNotIn(b'FICTIONAL_PRIVATE_ORIGINAL\n',dict(model.files).values())

if __name__=="__main__": unittest.main()
