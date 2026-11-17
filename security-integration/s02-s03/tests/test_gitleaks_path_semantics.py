# SPDX-License-Identifier: Apache-2.0
"""Synthetic source contracts only; no native scanner or coverage qualification."""
from dataclasses import replace
import re
import unittest
from unittest.mock import patch
import support
from test_adapter_bindings import receipt
from ocr_security.common import Refusal, canonical, digest, parse_json
from ocr_security.policy import TrustedRef
from ocr_security_adapters import gitleaks
from ocr_security_adapters.inputs import scanner_inputs
from ocr_security_adapters.private_history import original_history
from ocr_security_adapters.projection import sanitized_projection


def sample(path, raw=b'fictional-only\n'):
    snap, views = support.sample(raw)
    entry = replace(snap.entries[0], path=path)
    manifest = parse_json(snap.manifest)
    manifest['selection']['entries'][0]['path'] = path
    encoded = canonical(manifest)
    snap = replace(snap, entries=(entry,), manifest=encoded, snapshot_id=digest(encoded))
    private = canonical({'snapshot_id': snap.snapshot_id, 'model_bundle_id': views.model.bundle_id})
    return snap, replace(views, private_evidence=private)


def inv(rule):
    return replace(support.inventory(), allowed_rule_ids=(rule,))


def normalized(snap, views, native, rule, mode='files', covered=False):
    raw = canonical(native)
    stdin = 'item-0000' if mode == 'stdin' else None
    inventory = inv(rule)
    evidence = support.evidence(raw, snap, mode=mode, stdin_item=stdin)
    evidence['plan_sha256'] = gitleaks.plan(snap, support.policy(), inventory, mode, stdin).identity
    coverage = canonical(receipt(evidence, snap, ['item-0000']))
    ref = TrustedRef('/synthetic-receipt', digest(coverage)) if covered else None
    with patch('ocr_security_adapters.normalization.read_ref', return_value=coverage):
        return gitleaks.normalize(raw, snap, views, support.policy(), inventory, evidence,
                                  coverage_ref=ref, mode=mode, stdin_item=stdin)


class GitleaksPathTests(unittest.TestCase):
    def test_scanner_suffixes_do_not_expand_model_projection(self):
        snap, views = sample('private/container.p12')
        for suffix in ('tf', 'hcl', 'p12', 'pfx', 'nuget.config'):
            with self.subTest(suffix=suffix):
                with self.assertRaises(Refusal):
                    sanitized_projection(views.model, {'item-0000': suffix})
        self.assertEqual(sanitized_projection(views.model).alias_items,
                         (('item-0000.txt', 'item-0000'),))

    def test_opaque_suffixes_match_all_five_pinned_path_rules(self):
        cases = [('private/main.tf', 'tf', r'(?i)\.(?:tf|hcl)$'),
                 ('private/main.HCL', 'hcl', r'(?i)\.(?:tf|hcl)$'),
                 ('private/NuGet.Config', 'nuget.config', r'(?i)nuget\.config$'),
                 ('private/prefixNuGet.Config', 'nuget.config', r'(?i)nuget\.config$'),
                 ('private/secrets.p12', 'p12', r'(?i)(?:^|/)[^/]+\.p(?:12|fx)$'),
                 ('private/secrets.PFX', 'pfx', r'(?i)(?:^|/)[^/]+\.p(?:12|fx)$'),
                 ('private/source.php', 'php', r'(?i)\.php$'),
                 ('private/secret.yaml', 'yaml', r'(?i)\.ya?ml$')]
        for path, suffix, pattern in cases:
            with self.subTest(path=path):
                snap, _ = sample(path)
                item = scanner_inputs(snap)[0]
                self.assertEqual(item.mount_path, '/input/item-0000.' + suffix)
                self.assertIsNotNone(re.search(pattern, item.mount_path))
                self.assertEqual(item.content, snap.entries[0].content)
                self.assertEqual(item.original_sha256, snap.entries[0].sha256)
                self.assertEqual(item.identity[0], path)
                history = original_history(snap)
                alias = history.commit_items[0][1]
                self.assertEqual(alias, item.mount_path.rsplit('/', 1)[-1])
                self.assertIsNotNone(re.search(pattern, alias))
                self.assertEqual(dict(history.files)[alias], item.content)

    def test_nuget_marker_matches_suffix_not_arbitrary_config(self):
        for path in ('private/other.config', 'private/nuget.config.txt', 'private/nuget.config/other.config'):
            with self.subTest(path=path):
                snap, _ = sample(path)
                self.assertEqual(scanner_inputs(snap)[0].mount_path, '/input/item-0000.txt')

    def test_path_only_findings_have_no_fabricated_lines_or_raw_text(self):
        for suffix in ('p12', 'pfx'):
            for mode in ('files', 'history'):
                with self.subTest(suffix=suffix, mode=mode):
                    snap, views = sample('private/container.' + suffix, b'')
                    item = scanner_inputs(snap)[0]
                    native = {'RuleID': 'pkcs12-file', 'StartLine': 0, 'EndLine': 0,
                              'File': item.mount_path, 'Secret': '', 'Match': 'PRIVATE-MARKER'}
                    if mode == 'history':
                        native['Commit'], native['File'], _ = original_history(snap).commit_items[0]
                    value = normalized(snap, views, [native], 'pkcs12-file', mode)
                    self.assertNotEqual(value['process_status'], 'parser_error')
                    finding = value['result']['findings'][0]
                    self.assertEqual(finding['evidence_identity']['ranges'], [])
                    self.assertIn('contents and private-key presence are unverified', finding['preconditions'][0])
                    self.assertNotIn('PRIVATE-MARKER', canonical(value).decode())
                    self.assertEqual(value['target_security_acceptance'], 'NOT_ASSESSED')

    def test_path_only_rejects_wrong_shape_and_unbound_type(self):
        for path, override, mode in [('sample.txt', {}, 'files'), ('sample.p12', {'StartLine': True}, 'files'),
                                     ('sample.p12', {'EndLine': 1}, 'files'), ('sample.p12', {'Secret': 'RAW'}, 'files'),
                                     ('sample.p12', {'File': 'stdin'}, 'stdin')]:
            with self.subTest(path=path, override=override, mode=mode):
                snap, views = sample(path)
                native = {'RuleID': 'pkcs12-file', 'StartLine': 0, 'EndLine': 0,
                          'File': scanner_inputs(snap)[0].mount_path, 'Secret': '', 'Match': ''}
                native.update(override)
                self.assertEqual(normalized(snap, views, [native], 'pkcs12-file', mode)['process_status'], 'parser_error')

    def test_content_rule_still_requires_redacted_secret_and_real_lines(self):
        snap, views = sample('secret.tf')
        for secret, start in (('', 1), ('RAW', 1), ('REDACTED', 0)):
            raw = {'RuleID': 'hashicorp-tf-password', 'StartLine': start, 'EndLine': 1,
                   'File': '/input/item-0000.tf', 'Secret': secret, 'Match': ''}
            self.assertEqual(normalized(snap, views, [raw], 'hashicorp-tf-password')['process_status'], 'parser_error')

    def test_path_sensitive_stdin_remains_incomplete_even_with_coverage_claim(self):
        snap, views = sample('private/main.tf')
        for rule in gitleaks.PATH_RULES:
            with self.subTest(rule=rule):
                plan = gitleaks.plan(snap, support.policy(), inv(rule), 'stdin', 'item-0000')
                self.assertIn('stdin_path_sensitive_rules_unqualified', plan.blockers)
                value = normalized(snap, views, [], rule, 'stdin', covered=True)
                self.assertEqual(value['completeness'], 'incomplete')
                self.assertIn('stdin_path_sensitive_rules_unqualified', value['gaps'])
                self.assertEqual(value['result']['coverage'][0]['analyzed_ranges'], [])

    def test_content_only_stdin_retains_existing_receipt_semantics(self):
        snap, views = sample('sample.txt')
        value = normalized(snap, views, [], 'fixture-rule', 'stdin', covered=True)
        self.assertEqual(value['completeness'], 'complete')
        self.assertEqual(value['target_security_acceptance'], 'NOT_ASSESSED')


if __name__ == '__main__':
    unittest.main()
