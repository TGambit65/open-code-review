# SPDX-License-Identifier: Apache-2.0
"""Fictional offline integration inputs. No actual native or authority receipts."""
from pathlib import Path
import importlib.util
import sys
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[1]
for directory in (ROOT, ROOT.parent/'s01', ROOT.parent/'s02-s03', ROOT.parent/'s04-s05'):
    sys.path.insert(0, str(directory))
# Load only the explicit preserved fictional helper, not prior test modules.
spec = importlib.util.spec_from_file_location('s04_fictional_fixture', ROOT.parent/'s04-s05/tests/support.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)

from ocr_security.common import canonical, digest, ModelItem, ModelBundle
from ocr_security.views import Views
from ocr_security.policy import TrustedRef
from ocr_security_adapters import projection, reviewer
from ocr_security_adapters.assets import Asset, Inventory, SOURCES
from ocr_security_gate import evidence as ingest, updates
from ocr_security_integration import dispositions, entrypoint

NOW = baseline.NOW


def catalog():
    raw = (ROOT/'decisions/catalog.json').read_bytes()
    return dispositions.load_catalog(raw, digest(raw))


def ocr_evidence(snapshot, views, missing_review=False, excluded=False):
    policy = baseline.adapter_policy(snapshot)
    suffixes = {item.opaque_id: 'py' for item in views.model.items}
    view = projection.sanitized_projection(views.model, suffixes)
    rule = 'Review all fictional source values and control paths.\n'
    rules_pin = digest(b'fictional-rule-file')
    inventory = Inventory('ocr', SOURCES['ocr'][0], SOURCES['ocr'][1], digest(b'ocr'),
        (Asset('binary', 'binary', '843be0e56fdff0a5ca6f86c5866f942d6a372dff1c0ca19e7893d72495abf45c',
               'synthetic', 'a'*64, 'b'*64, SOURCES['ocr'][1], None, None, None),
         Asset('rules', 'rules', rules_pin, 'synthetic', 'a'*64, 'b'*64, 'fixture', None, None, None)),
        (), (), 'c'*64, 'd'*64)
    aliases = [name for name, _ in view.alias_items]
    rows = [{'path':name, 'status':'added', 'insertions':1, 'deletions':0} for name in aliases]
    if excluded:
        for row in rows:
            row['exclude_reason'] = 'user_exclude'
    preview = {'schema_version':'1', 'mode':'range', 'repository':'/review', 'from':view.base_commit, 'to':view.head_commit,
               'total_files':len(rows), 'reviewable_count':0 if excluded else len(rows), 'excluded_count':len(rows) if excluded else 0,
               'total_insertions':len(rows), 'total_deletions':0, 'reviewable_files':[] if excluded else rows,
               'excluded_files':rows if excluded else []}
    rules = {'schema_version':'1', 'groups':[{'group_id':1, 'source':'custom', 'pattern':'*', 'files':aliases, 'rule':rule}]}
    preview_raw, rule_raw = canonical(preview), canonical(rules)
    events = {op:{'at':NOW.isoformat(), 'exit_code':0, 'process_status':'success', 'report_sha256':digest(raw),
                  'native_execution_receipt_sha256':'e'*64} for op, raw in (('preview',preview_raw), ('rule',rule_raw))}
    handoff = reviewer.handoff(views.model, policy, 'fixture-writer', 'fixture-reviewer')
    records = [{'handoff_id':handoff['handoff_id'], 'chunk_id':chunk['chunk_id'], 'reviewer_context_id':'fixture-reviewer',
                'depth':'deep', 'topics':list(reviewer.TOPICS), 'findings':[], 'uncertainties':[], 'truncated':False}
               for chunk in handoff['chunks']]
    authority = canonical({'schema_version':'1.0', 'kind':'approved-ocr-rule-body', 'adapter_policy_sha256':policy.sha256,
                           'rules_asset_sha256':rules_pin, 'body_sha256':digest(rule.encode()), 'snapshot_id':snapshot.snapshot_id,
                           'model_bundle_id':views.model.bundle_id, 'projection_suffixes':suffixes})
    with patch('ocr_security_gate.contracts.read_ref', return_value=authority):
        return ingest.independent_review(preview_raw, rule_raw, events, snapshot, views, policy, inventory, rule,
                    [] if missing_review else records, 'fixture-writer', 'fixture-reviewer',
                    TrustedRef('/fictional-ocr-body', digest(authority)))


def case(positive=False, malformed=False, missing_review=False, excluded=False, partial=False,
         redacted=False, expired_database=False, hostile=False):
    raw = b'print("fictional source")\n'
    if hostile:
        raw = b'payload = "<script>fictional()</script> ![x](https://example.invalid/track)"\n'
    if redacted:
        raw = b'credential = "FICTIONAL_PRIVATE_BEFORE_DO_NOT_PUBLISH"\n'
    snapshot, views = baseline.snapshot(raw)
    if redacted:
        prior = views.model.items[0]
        item = ModelItem(prior.opaque_id, prior.surfaces, 'credential = "[REDACTED]"\n',
                         ((1,1,'redacted'),), ((1,1,'not_released'),))
        bundle = ModelBundle(digest(canonical([{'id':item.opaque_id, 'surfaces':item.surfaces, 'content':item.content,
                                             'line_map':item.line_map, 'gaps':item.gaps}])), (item,))
        views = Views(views.scanner_inputs, bundle, canonical({'snapshot_id':snapshot.snapshot_id, 'model_bundle_id':bundle.bundle_id}))
    current = baseline.update('2026-11-06T00:00:00Z' if expired_database else '2026-11-07T00:00:00Z')
    findings = (baseline.finding(snapshot),) if positive else ()
    items = [ocr_evidence(snapshot, views, missing_review, excluded)]
    for name in ('opengrep', 'gitleaks', 'osv'):
        document, pins = baseline.normalized(snapshot, views, findings if name == 'gitleaks' else ())
        document['adapter'] = name
        if name == 'osv':
            pins['database_pin'] = baseline.database_pin(current)
            document['result']['identity']['database_pin'] = pins['database_pin']
        if partial and name == 'opengrep':
            document['completeness'] = document['result']['completeness'] = 'incomplete'
            document['gaps'] = ['fictional_coverage_gap']
        raw_output = b'{bad-fictional-output' if malformed and name == 'gitleaks' else canonical(document)
        items.append(ingest.scanner(raw_output, name, snapshot, views, pins, baseline.adapter_policy(snapshot)))
    return {'snapshot':snapshot, 'views':views, 'policy':baseline.policy(), 'items':tuple(items), 'current':current}


def evaluate(value, attested=True, **options):
    snapshot, policy = value['snapshot'], value['policy']
    fresh = updates.freshness(value['current'], None, ['npm'], NOW)
    authority = canonical(baseline.attestation(snapshot, policy, value['items'], fresh))
    with patch('ocr_security_gate.contracts.read_ref', return_value=authority):
        return entrypoint.evaluate_evidence(baseline.target(snapshot), policy, value['items'], snapshot, value['views'],
            value['current'], None, NOW, catalog(),
            attestation_ref=TrustedRef('/fictional-run-attestation', digest(authority)) if attested else None, **options)
