# SPDX-License-Identifier: Apache-2.0
"""Authored synthetic fixtures. Run only after reviewed draft preservation."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
from ocr_security.broker import Broker
from ocr_security.common import Refusal, STAGES, canonical, digest
from ocr_security.isolation import PROFILE_SHA256
from ocr_security.policy import (ADOPTION_SHA256, POLICY_SHA256, TrustContext, TrustedRef, resolve_policy)
from ocr_security.snapshot import build_snapshot, materialize_private_snapshot
from ocr_security.views import materialize_views

CONFIG = None


def configure():
    global CONFIG
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--adoption", required=True)
    CONFIG, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0]] + remaining


class Fixture:
    def __init__(self, root=None, policy_path=None, adoption_path=None):
        self.temporary = tempfile.TemporaryDirectory(prefix="ocr-s01-synthetic-") if root is None else None
        self.root = Path(self.temporary.name) if self.temporary else Path(root)
        if not self.temporary:
            self.root.mkdir(mode=0o700)
        self.inputs, self.authority, self.output = (self.root / name for name in ("inputs", "authority", "evidence"))
        for directory in (self.inputs, self.authority, self.output):
            directory.mkdir(mode=0o700)
        self.candidate = str(Path(__file__).absolute().parents[3])
        self.context = TrustContext((self.candidate,), (str(self.inputs),), (str(self.output),))
        self.policy_ref = TrustedRef(policy_path or CONFIG.policy, POLICY_SHA256)
        self.adoption_ref = TrustedRef(adoption_path or CONFIG.adoption, ADOPTION_SHA256)
        self.policy = resolve_policy(self.policy_ref, self.adoption_ref, self.context)
        cases_path = Path(__file__).absolute().parents[1] / "fixtures" / "cases.json"
        self.cases = json.loads(cases_path.read_text())["cases"]
        self.entries = []
        for case in self.cases:
            raw = case["content"].encode()
            (self.inputs / case["storage"]).write_bytes(raw)
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            self.entries.append({"path": case["logical_path"], "source": case["storage"],
                                 "change_kind": case["change_kind"], "base_blob": blob if case["side"] == "base" else None,
                                 "head_blob": blob if case["side"] != "base" else None, "side": case["side"],
                                 "required_ranges": [[1, 3]], "surfaces": [case["surface"], "search", "filename"],
                                 "selected": True, "reason": "synthetic_qualification", "sha256": digest(raw), "bytes": len(raw)})

    def close(self):
        if self.temporary:
            self.temporary.cleanup()

    def write_ref(self, value, prefix="document"):
        raw = canonical(value)
        path = self.authority / (prefix + "-" + digest(raw) + ".json")
        if path.exists():
            if path.read_bytes() != raw:
                raise Refusal("fixture_collision")
        else:
            with path.open("xb") as output:
                output.write(raw)
        return TrustedRef(str(path), digest(raw))

    def selection(self, entries=None, **overrides):
        entries = copy.deepcopy(self.entries if entries is None else entries)
        info = self.inputs.stat()
        document = {"schema_version": "1.0", "kind": "approved-selection", "repository": {"name": "synthetic/fixture", "id": 123},
                    "base_commit": "1" * 40, "head_commit": "2" * 40, "frozen_diff_sha256": digest(canonical(entries)),
                    "root": {"path": str(self.inputs), "device": info.st_dev, "inode": info.st_ino},
                    "entries": entries, "inventory_complete": True}
        document.update(overrides)
        return self.write_ref(document, "selection")

    def snapshot(self, entries=None):
        return build_snapshot(self.selection(entries), self.context, self.policy)

    def views(self, snapshot, release=True):
        ref = None
        if release:
            ref = self.write_ref({"schema_version": "1.0", "kind": "approved-line-release", "snapshot_id": snapshot.snapshot_id,
                                  "entries": [{"opaque_id": entry.opaque_id, "original_sha256": entry.sha256,
                                               "ranges": [[1, 1], [3, 3]]} for entry in snapshot.selected]}, "release")
        return materialize_views(snapshot, self.context, ref)

    def coverage(self, snapshot):
        return [{"snapshot_id": snapshot.snapshot_id, "path": e.path, "change_kind": e.change_kind,
                 "base_blob": e.base_blob, "head_blob": e.head_blob, "side": e.side, "original_sha256": e.sha256,
                 "analyzed_ranges": [[1, e.lines]] if e.lines else [], "truncated": False, "omissions": []}
                for e in snapshot.selected]

    def result(self, snapshot, views):
        pins = {"tool_sha256": "a" * 64, "profile_sha256": PROFILE_SHA256, "rule_pin": "not_applicable",
                "database_pin": "not_applicable", "transformation_sha256": digest(views.private_evidence), "view": "scanner"}
        identity = {"repository": {"name": snapshot.repository_name, "id": snapshot.repository_id},
                    "base_commit": snapshot.base_commit, "head_commit": snapshot.head_commit,
                    "frozen_diff_sha256": snapshot.frozen_diff_sha256, "snapshot_id": snapshot.snapshot_id,
                    "policy_sha256": snapshot.policy_sha256, **pins}
        result = {"schema_version": "1.0", "kind": "analysis-result", "identity": identity,
                  "event": {"at": "2026-11-01T00:00:00Z", "actor": "synthetic-harness", "action_id": "synthetic-case", "artifact_sha256": "b" * 64, "artifact_location": "synthetic:in-memory-result"},
                  "process": {"status": "success", "exit_code": 0, "code": "ok"}, "completeness": "complete",
                  "stages": {stage: "pending" for stage in STAGES}, "coverage": self.coverage(snapshot), "findings": []}
        return result, pins


class SnapshotViewsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.close)

    def test_all_surfaces_receive_only_released_safe_lines(self):
        snapshot = self.fixture.snapshot()
        views = self.fixture.views(snapshot)
        broker = Broker(views.model)
        serialized = canonical([broker.read(case["surface"], entry.opaque_id)
                                for case, entry in zip(self.fixture.cases, snapshot.entries)])
        for case, entry, scanner in zip(self.fixture.cases, snapshot.entries, views.scanner_inputs):
            self.assertEqual(scanner[1], case["content"].encode())
            self.assertIn(case["secret"].encode(), scanner[1])
            self.assertNotIn(case["secret"].encode(), serialized)
            self.assertNotIn(case["logical_path"].encode(), serialized)
            self.assertIn(("safe_" + case["id"]).encode(), serialized)
            self.assertEqual(broker.read("filename", entry.opaque_id)["content"], entry.opaque_id)
        self.assertNotIn(b"SYNTHETIC_SECRET", canonical(broker.search("SYNTHETIC_SECRET")))
        self.assertTrue(broker.search("safe_")["matches"])
        self.assertEqual(broker.read("git", "../../secret")["status"], "unsupported")
        self.assertEqual(broker.read("secondary", "/etc/passwd")["code"], "unknown_item")

    def test_default_release_is_gap_not_clean(self):
        snapshot = self.fixture.snapshot()
        views = self.fixture.views(snapshot, False)
        for item in views.model.items:
            self.assertTrue(item.gaps)
            self.assertNotIn("safe_", item.content)
            self.assertNotIn("SYNTHETIC_SECRET", item.content)

    def test_original_and_transform_hash_mapping(self):
        snapshot = self.fixture.snapshot()
        views = self.fixture.views(snapshot)
        evidence = json.loads(views.private_evidence)
        self.assertEqual(evidence["snapshot_id"], snapshot.snapshot_id)
        for original, transformed, row in zip(snapshot.entries, views.model.items, evidence["entries"]):
            self.assertEqual(row["original_sha256"], digest(original.content))
            self.assertEqual(row["transformed_sha256"], digest(transformed.content.encode()))
            self.assertEqual(row["line_mapping"][1], [2, 2, "redacted"])
            self.assertEqual(row["identity"], list(original.identity))

    def test_path_and_file_type_rejections(self):
        for source in ("../outside", "/etc/passwd", "a/../outside", "a//b"):
            with self.subTest(source=source):
                entries = copy.deepcopy(self.fixture.entries[:1]); entries[0]["source"] = source
                with self.assertRaises(Refusal): self.fixture.snapshot(entries)
        outside = self.fixture.root / "outside"; outside.write_bytes(b"synthetic")
        (self.fixture.inputs / "leaf").symlink_to(outside)
        (self.fixture.inputs / "ancestor").symlink_to(self.fixture.root, target_is_directory=True)
        os.link(self.fixture.inputs / "input-00.txt", self.fixture.inputs / "hardlink")
        os.mkfifo(self.fixture.inputs / "fifo")
        for source in ("leaf", "ancestor/outside", "hardlink", "fifo"):
            with self.subTest(source=source):
                entries = copy.deepcopy(self.fixture.entries[:1]); entries[0]["source"] = source
                with self.assertRaises(Refusal): self.fixture.snapshot(entries)

    def test_changed_bytes_incomplete_inventory_and_duplicate_identity(self):
        entries = copy.deepcopy(self.fixture.entries[:1])
        entries[0]["sha256"] = "0" * 64
        with self.assertRaises(Refusal): self.fixture.snapshot(entries)
        with self.assertRaises(Refusal):
            build_snapshot(self.fixture.selection(inventory_complete=False), self.fixture.context, self.fixture.policy)
        with self.assertRaises(Refusal): self.fixture.snapshot(self.fixture.entries[:1] * 2)

    def test_stale_release_and_unsafe_encoding(self):
        snapshot = self.fixture.snapshot()
        ref = self.fixture.write_ref({"schema_version": "1.0", "kind": "approved-line-release", "snapshot_id": "0" * 64, "entries": []})
        with self.assertRaises(Refusal): materialize_views(snapshot, self.fixture.context, ref)
        raw = b"\xff\x00SYNTHETIC_SECRET_ONLY_BINARY"
        (self.fixture.inputs / "binary").write_bytes(raw)
        entry = copy.deepcopy(self.fixture.entries[0]); entry.update(source="binary", bytes=len(raw), sha256=digest(raw), required_ranges=[[1, 1]])
        binary = self.fixture.snapshot([entry]); views = self.fixture.views(binary, False)
        self.assertEqual(views.scanner_inputs[0][1], raw)
        self.assertEqual(views.model.items[0].content, "")
        self.assertEqual(views.model.items[0].gaps[0][2], "unsafe_encoding_or_content")

    def test_line_expansion_is_bounded_and_originals_preserved(self):
        raw = b"\n" * 5000
        (self.fixture.inputs / "many-lines").write_bytes(raw)
        entry = copy.deepcopy(self.fixture.entries[0])
        entry.update(source="many-lines", bytes=len(raw), sha256=digest(raw), required_ranges=[[1, 5000]])
        snapshot = self.fixture.snapshot([entry])
        views = self.fixture.views(snapshot, False)
        self.assertEqual(views.scanner_inputs[0][1], raw)
        self.assertEqual(views.model.items[0].content, "")
        self.assertEqual(views.model.items[0].gaps, ((1, 5000, "line_limit"),))

    def test_immutable_snapshot_and_private_materialization(self):
        snapshot = self.fixture.snapshot()
        original = snapshot.selected[0].content
        (self.fixture.inputs / "input-00.txt").write_bytes(b"later mutation")
        self.assertEqual(snapshot.selected[0].content, original)
        target = self.fixture.output / "snapshot"
        materialize_private_snapshot(snapshot, str(target))
        self.assertEqual((target / snapshot.selected[0].opaque_id).read_bytes(), original)
        with self.assertRaises(Refusal): materialize_private_snapshot(snapshot, str(target))


if __name__ == "__main__":
    configure()
    unittest.main()
