# SPDX-License-Identifier: Apache-2.0
"""Synthetic detector reports, not actual native detector qualification."""
import copy
import unittest
import support
from ocr_security.common import Refusal, canonical
from ocr_security_adapters import gitleaks, opengrep, osv

class BaselineAdapterTests(unittest.TestCase):
    def test_gitleaks_fixed_flags_and_all_modes_disabled(self):
        snap,_=support.sample()
        for mode,stdin in (("files",None),("stdin","item-0000"),("history",None)):
            plan=gitleaks.plan(snap,support.policy(),support.inventory(),mode,stdin)
            self.assertIn("--redact=100",plan.argv)
            self.assertIn("--exit-code=10",plan.argv)
            self.assertFalse(plan.document()["execution_enabled"])
            with self.assertRaises(Refusal): gitleaks.run(plan)
        with self.assertRaises(Refusal): gitleaks.plan(snap,support.policy(),support.inventory(),"all-history")

    def test_gitleaks_full_metadata_not_forwarded(self):
        snap,views=support.sample(b'fictional_secret=OCR_SYNTHETIC_DO_NOT_USE\n')
        native=[{"RuleID":"fixture-rule","StartLine":1,"EndLine":1,"File":"/input/item-0000.py","Secret":"REDACTED",
                 "Match":"REDACTED","Description":"UNTRUSTED-MARKER","Fragment":"UNTRUSTED-MARKER","Email":"UNTRUSTED-MARKER"}]
        raw=canonical(native)
        value=gitleaks.normalize(raw,snap,views,support.policy(),support.inventory(),support.evidence(raw,snap))
        self.assertNotEqual(value["process_status"],"parser_error")
        self.assertNotIn("UNTRUSTED-MARKER",canonical(value).decode())
        self.assertEqual(value["result"]["findings"][0]["resolution_state"],"open")
        self.assertEqual(value["completeness"],"incomplete")

    def test_gitleaks_unredacted_secret_rejected(self):
        snap,views=support.sample()
        raw=canonical([{"RuleID":"fixture-rule","StartLine":1,"EndLine":1,"File":"/input/item-0000.py","Secret":"not-redacted","Match":"not-redacted"}])
        value=gitleaks.normalize(raw,snap,views,support.policy(),support.inventory(),support.evidence(raw,snap))
        self.assertEqual(value["process_status"],"parser_error")

    def test_gitleaks_safe_negative_and_failure_do_not_clear_target(self):
        snap,views=support.sample(b'const public_value = 1;\n')
        for status,code in (("success",0),("error",1),("timeout",-9)):
            raw=b'[]'; value=gitleaks.normalize(raw,snap,views,support.policy(),support.inventory(),support.evidence(raw,snap,exit_code=code,status=status))
            self.assertEqual(value["completeness"],"incomplete")
            self.assertEqual(value["target_security_acceptance"],"NOT_ASSESSED")

    def test_opengrep_uses_only_local_rules_and_output(self):
        snap,_=support.sample(); plan=opengrep.plan(snap,support.policy(),support.inventory("opengrep"))
        self.assertIn("/policy/opengrep.yaml",plan.argv)
        self.assertIn("--disable-nosem",plan.argv)
        self.assertNotIn("auto",plan.argv)
        self.assertNotIn("--metrics=off",plan.argv)
        with self.assertRaises(Refusal): opengrep.run(plan)

    def test_opengrep_seeded_and_negative_require_independent_coverage(self):
        snap,views=support.sample()
        positive={"check_id":"fixture-rule","path":"/input/item-0000.py","start":{"line":1,"col":1},"end":{"line":1,"col":8},
                  "extra":{"severity":"ERROR","message":"UNTRUSTED-MARKER","lines":"UNTRUSTED-MARKER"}}
        for findings in ([positive],[]):
            raw=canonical({"results":findings,"errors":[],"paths":{"scanned":["/input/item-0000.py"],"skipped":[]},"skipped_rules":[]})
            value=opengrep.normalize(raw,snap,views,support.policy(),support.inventory("opengrep"),support.evidence(raw,snap,"opengrep"))
            self.assertNotEqual(value["process_status"],"parser_error")
            self.assertEqual(value["completeness"],"incomplete")
            self.assertNotIn("UNTRUSTED-MARKER",canonical(value).decode())

    def test_native_parser_failure_does_not_become_empty_clean(self):
        snap,views=support.sample()
        raw=b'{invalid'
        value=opengrep.normalize(raw,snap,views,support.policy(),support.inventory("opengrep"),support.evidence(raw,snap,"opengrep"))
        self.assertEqual(value["process_status"],"parser_error")
        self.assertEqual(value["completeness"],"unknown")

    def test_osv_offline_explicit_parser_and_no_package_analysis(self):
        snap,_=support.sample(b'{"lockfileVersion":3}\n',"json")
        selection=(osv.Lockfile("item-0000","npm"),)
        plan=osv.plan(snap,support.policy(),support.inventory("osv"),selection,support.NOW)
        self.assertIn("--offline",plan.argv)
        self.assertIn("--no-call-analysis=all",plan.argv)
        self.assertIn("--download-offline-databases=false",plan.argv)
        self.assertIn("--lockfile=package-lock.json:/input/item-0000/package-lock.json",plan.argv)
        with self.assertRaises(Refusal): osv.run(plan)

    def test_osv_missing_expired_and_unsupported_db_refused(self):
        from dataclasses import replace
        snap,_=support.sample(); inv=support.inventory("osv"); selection=(osv.Lockfile("item-0000","npm"),)
        for modified in (replace(inv,assets=inv.assets[:1]),support.inventory("osv","2026-11-02T00:00:00Z"),replace(inv,supported_ecosystems=())):
            with self.assertRaises(Refusal): osv.plan(snap,support.policy(),modified,selection,support.NOW)

    def test_osv_positive_no_fabricated_line_or_clearance(self):
        snap,views=support.sample(b'{"lockfileVersion":3}\n',"json")
        native={"results":[{"source":{"path":"/input/item-0000/package-lock.json","type":"lockfile"},"packages":[{
            "package":{"name":"synthetic-only","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"CVE-2026-12345","summary":"UNTRUSTED-MARKER"}]}]}],"experimental_config":{}}
        raw=canonical(native)
        selection=(osv.Lockfile("item-0000","npm"),)
        value=osv.normalize(raw,snap,views,support.policy(),support.inventory("osv"),support.evidence(raw,snap,"osv",1,"error",selection=selection),selection)
        self.assertNotEqual(value["process_status"],"parser_error")
        self.assertEqual(value["result"]["findings"][0]["evidence_identity"]["ranges"],[])
        self.assertNotIn("UNTRUSTED-MARKER",canonical(value).decode())
        self.assertEqual(value["target_security_acceptance"],"NOT_ASSESSED")

    def test_stale_source_receipt_rejected(self):
        snap,views=support.sample(); evidence=support.evidence(b'[]',snap); evidence["snapshot_id"]="0"*64
        value=gitleaks.normalize(b'[]',snap,views,support.policy(),support.inventory(),evidence)
        self.assertEqual(value["process_status"],"parser_error")

if __name__=="__main__": unittest.main()
