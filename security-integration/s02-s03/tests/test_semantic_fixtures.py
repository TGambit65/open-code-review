# SPDX-License-Identifier: Apache-2.0
"""Authored, unrun data/contract tests; no native or semantic review execution."""
import hashlib
import json
from pathlib import Path
import unittest
import support  # Existing synthetic policy and import-path setup only.
from ocr_security.common import ModelBundle, ModelItem, canonical, digest
from ocr_security.snapshot import Entry, Snapshot
from ocr_security_adapters import effective_policy, projection, reviewer
from ocr_security_adapters.inputs import scanner_inputs

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "semantic"


def fixture(name):
    return (FIXTURES / name).read_bytes()


def blob_id(raw):
    """Actual Git blob identity of fictional bytes, not a target object receipt."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def snapshot_and_bundle():
    before = fixture("authorization-before.json")
    after = fixture("authorization-after.json")
    base_blob, head_blob = blob_id(before), blob_id(after)
    records = [
        ("security-policy.json", "base", before, base_blob, head_blob, "modified"),
        ("security-policy.json", "head", after, base_blob, head_blob, "modified"),
        ("sample.py", "head", b"eval(input())\n", None, None, "added"),
        (".gitignore", "head", fixture("candidate-gitignore.txt"), None, None, "added"),
        (".gitleaksignore", "head", fixture("candidate-gitleaksignore.txt"), None, None, "added"),
        (".gitleaks.toml", "head", fixture("candidate-gitleaks-policy.toml"), None, None, "added"),
    ]
    entries, declarations, model_items = [], [], []
    surfaces = ("primary", "search", "filename")
    for ordinal, (path, side, raw, base, head, change) in enumerate(records):
        head = head if head is not None else blob_id(raw)
        count = len(raw.splitlines())
        ranges = ((1, count),)
        entries.append(Entry(ordinal, path, "synthetic-fixture", change, base, head,
                             side, ranges, surfaces, True, "explicit_fixture_selection",
                             digest(raw), raw, count))
        declarations.append({"path": path, "source": "synthetic-fixture", "change_kind": change,
                             "base_blob": base, "head_blob": head, "side": side,
                             "selected": True, "reason": "explicit_fixture_selection",
                             "sha256": digest(raw), "bytes": len(raw), "surfaces": surfaces,
                             "required_ranges": ranges})
        model_items.append(ModelItem(entries[-1].opaque_id, surfaces, raw.decode("utf-8"),
                                     tuple((i, i, "released") for i in range(1, count + 1)), ()))
    # These source commits and policy identity are explicit synthetic metadata.
    selection = {"repository": {"name": "synthetic/semantic-fixtures", "id": 1},
                 "base_commit": "1" * 40, "head_commit": "2" * 40,
                 "frozen_diff_sha256": digest(canonical(declarations)), "entries": declarations}
    selection_sha = digest(canonical(selection))
    policy_sha = support.policy().snapshot_policy_sha256
    manifest = canonical({"selection_sha256": selection_sha, "policy_sha256": policy_sha,
                          "selection": selection})
    snapshot = Snapshot(digest(manifest), selection_sha, policy_sha,
                        selection["repository"]["name"], 1, "1" * 40, "2" * 40,
                        selection["frozen_diff_sha256"], tuple(entries), manifest)
    serial = [{"id": x.opaque_id, "surfaces": x.surfaces, "content": x.content,
               "line_map": x.line_map, "gaps": x.gaps} for x in model_items]
    return snapshot, ModelBundle(digest(canonical(serial)), tuple(model_items))


class SemanticFixtureContractTests(unittest.TestCase):
    def test_value_only_fixture_has_paired_modified_identity(self):
        before = json.loads(fixture("authorization-before.json"))
        after = json.loads(fixture("authorization-after.json"))
        self.assertEqual(set(before), set(after))
        self.assertEqual(set(before["authorization"]), set(after["authorization"]))
        self.assertEqual(before["authorization"], {"required_role": "administrator", "allow_anonymous": False})
        self.assertEqual(after["authorization"], {"required_role": "anyone", "allow_anonymous": True})
        snapshot, bundle = snapshot_and_bundle()
        old, new = snapshot.entries[:2]
        self.assertEqual(old.identity[:-1], new.identity[:-1])
        self.assertEqual((old.change_kind, old.side, new.side), ("modified", "base", "head"))
        self.assertNotEqual(old.base_blob, old.head_blob)
        self.assertEqual(old.base_blob, blob_id(old.content))
        self.assertEqual(new.head_blob, blob_id(new.content))
        self.assertNotEqual(old.sha256, new.sha256)
        self.assertEqual(bundle.items[0].content.encode(), old.content)
        self.assertEqual(bundle.items[1].content.encode(), new.content)

    def test_selected_control_bytes_retained_under_inert_aliases(self):
        snapshot, bundle = snapshot_and_bundle()
        inputs = scanner_inputs(snapshot)
        self.assertEqual(len(inputs), len(snapshot.selected))
        self.assertEqual({x.opaque_id for x in inputs}, {x.opaque_id for x in snapshot.selected})
        for original, mapped in zip(snapshot.selected, inputs):
            self.assertEqual(mapped.identity, original.identity)
            self.assertEqual(mapped.original_sha256, digest(original.content))
            self.assertEqual(mapped.content, original.content)
            self.assertEqual(mapped.mount_path.rsplit("/", 1)[-1].split(".")[0], original.opaque_id)
        control_names = {".gitignore", ".gitleaksignore", ".gitleaks.toml"}
        self.assertEqual({e.path for e in snapshot.entries[3:]}, control_names)
        self.assertTrue(control_names.isdisjoint(x.mount_path.rsplit("/", 1)[-1] for x in inputs))
        projected = projection.sanitized_projection(bundle)
        files = dict(projected.files)
        aliases = dict(projected.alias_items)
        self.assertTrue(control_names.isdisjoint(files))
        self.assertEqual(set(aliases.values()), {e.opaque_id for e in snapshot.selected})
        for alias, item_id in aliases.items():
            original = next(e for e in snapshot.selected if e.opaque_id == item_id)
            self.assertEqual(files[alias], original.content)

    def test_controls_do_not_mutate_policy_or_remove_required_review(self):
        snapshot, bundle = snapshot_and_bundle()
        policy = support.policy()
        selected = tuple(e.opaque_id for e in snapshot.selected)
        control_ids = tuple(e.opaque_id for e in snapshot.entries[3:])
        requirements = effective_policy.receipt(policy, snapshot.snapshot_id, selected, control_ids)
        self.assertEqual(requirements["selected_ids"], list(selected))
        self.assertEqual(requirements["candidate_control_ids"], list(control_ids))
        self.assertEqual(requirements["policy_sha256"], policy.sha256)
        self.assertEqual(requirements["candidate_controls"], "inert_review_data")
        self.assertFalse(requirements["native_effective_config_observed"])
        packet = reviewer.handoff(bundle, policy, "synthetic-writer", "synthetic-reviewer")
        self.assertEqual({c["id"] for c in packet["chunks"]}, set(selected))
        for chunk in packet["chunks"]:
            self.assertIn("json_values", chunk["required_topics"])
            self.assertIn("policy_content", chunk["required_topics"])
        self.assertFalse(packet["review_performed"])
        # No fabricated semantic finding or successful review record is supplied.
        accounting = reviewer.assess_review(packet, [], "synthetic-reviewer")
        self.assertEqual(accounting["completeness"], "incomplete")
        self.assertEqual(accounting["findings"], [])
        self.assertEqual(accounting["target_security_acceptance"], "NOT_ASSESSED")


if __name__ == "__main__":
    unittest.main()
