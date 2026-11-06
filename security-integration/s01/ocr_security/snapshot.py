# SPDX-License-Identifier: Apache-2.0
"""Freeze only explicitly approved files; never discover Git or a worktree."""

import os
import stat
from dataclasses import dataclass

from .common import (CHANGES, SURFACES, Refusal, canonical, digest, fields,
                     git_id, integer, parse_json, ranges, relative_path, sha, text)
from .policy import open_at_regular, open_directory, read_descriptor, resolve_document


@dataclass(frozen=True)
class Entry:
    ordinal: int
    path: str
    source: str | None
    change_kind: str
    base_blob: str | None
    head_blob: str | None
    side: str
    required_ranges: tuple
    surfaces: tuple
    selected: bool
    reason: str
    sha256: str | None
    content: bytes | None
    lines: int

    @property
    def identity(self):
        return (self.path, self.change_kind, self.base_blob, self.head_blob, self.side)

    @property
    def opaque_id(self):
        return "item-%04d" % self.ordinal


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    selection_sha256: str
    policy_sha256: str
    repository_name: str
    repository_id: int
    base_commit: str
    head_commit: str
    frozen_diff_sha256: str
    entries: tuple
    manifest: bytes

    @property
    def selected(self):
        return tuple(entry for entry in self.entries if entry.selected)


def line_count(data):
    return 0 if not data else data.count(b"\n") + (not data.endswith(b"\n"))


def _read_entry(root_fd, path, expected_bytes, expected_sha):
    parts = relative_path(path).split("/")
    directory = os.dup(root_fd)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = open_at_regular(directory, parts[-1], expected_bytes)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != expected_bytes:
            raise Refusal("unsafe_file")
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise Refusal("unsafe_file")
        data = read_descriptor(fd, expected_bytes)
        if digest(data) != expected_sha:
            raise Refusal("source_mismatch")
        return data
    except OSError:
        raise Refusal("input_unreadable") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def build_snapshot(selection_ref, context, policy):
    document = resolve_document(selection_ref, context, "approved-selection")
    fields(document, ("schema_version", "kind", "repository", "base_commit", "head_commit",
                      "frozen_diff_sha256", "root", "entries", "inventory_complete"))
    if document["inventory_complete"] is not True:
        raise Refusal("incomplete_inventory")
    fields(document["repository"], ("name", "id"))
    name = text(document["repository"]["name"])
    repository_id = integer(document["repository"]["id"], 1)
    base = git_id(document["base_commit"])
    head = git_id(document["head_commit"])
    diff = sha(document["frozen_diff_sha256"])
    root = fields(document["root"], ("path", "device", "inode"))
    if root["path"] not in context.input_roots or root["path"] in ("/", "/home", "/root"):
        raise Refusal("unapproved_root")
    integer(root["device"])
    integer(root["inode"], 1)
    inventory = document["entries"]
    if type(inventory) is not list or not 1 <= len(inventory) <= 256:
        raise Refusal("inventory_limit")
    root_fd = open_directory(root["path"])
    entries, seen, total = [], set(), 0
    try:
        info = os.fstat(root_fd)
        if (info.st_dev, info.st_ino) != (root["device"], root["inode"]):
            raise Refusal("root_changed")
        for ordinal, item in enumerate(inventory):
            fields(item, ("path", "source", "change_kind", "base_blob", "head_blob", "side",
                          "required_ranges", "surfaces", "selected", "reason", "sha256", "bytes"))
            path = relative_path(item["path"])
            if item["change_kind"] not in CHANGES or item["side"] not in ("base", "head", "context", "error"):
                raise Refusal("invalid_identity")
            base_blob, head_blob = git_id(item["base_blob"], True), git_id(item["head_blob"], True)
            if type(item["selected"]) is not bool:
                raise Refusal("invalid_selection")
            reason = text(item["reason"], 512)
            surfaces = item["surfaces"]
            if type(surfaces) is not list or not surfaces or len(set(surfaces)) != len(surfaces) or not set(surfaces) <= SURFACES:
                raise Refusal("invalid_surface")
            size = integer(item["bytes"], 0, 1048576)
            expected_sha = sha(item["sha256"]) if item["sha256"] is not None else None
            identity = (path, item["change_kind"], base_blob, head_blob, item["side"])
            if identity in seen:
                raise Refusal("duplicate_identity")
            seen.add(identity)
            data, count, source = None, 0, item["source"]
            if item["selected"]:
                if expected_sha is None:
                    raise Refusal("missing_digest")
                source = relative_path(source)
                total += size
                if total > 16777216:
                    raise Refusal("input_limit")
                data = _read_entry(root_fd, source, size, expected_sha)
                count = line_count(data)
                requested = ranges(item["required_ranges"], count)
                if count and not requested:
                    raise Refusal("missing_ranges")
            else:
                if source is not None:
                    relative_path(source)
                requested = ranges(item["required_ranges"], 1048576)
            entries.append(Entry(ordinal, path, source, item["change_kind"], base_blob, head_blob,
                                 item["side"], requested, tuple(surfaces), item["selected"], reason,
                                 expected_sha, data, count))
    finally:
        os.close(root_fd)
    manifest = canonical({"schema_version": "1.0", "selection_sha256": selection_ref.sha256,
                          "policy_sha256": policy.sha256, "selection": document})
    return Snapshot(digest(manifest), selection_ref.sha256, policy.sha256, name, repository_id,
                    base, head, diff, tuple(entries), manifest)


def materialize_private_snapshot(snapshot, new_directory):
    """Create new private evidence, never a bindable mutable scanner worktree."""
    validate_snapshot(snapshot)
    parent, leaf = os.path.split(new_directory)
    relative_path(leaf)
    directory = open_directory(parent)
    created_fd = None
    try:
        os.mkdir(leaf, 0o700, dir_fd=directory)
        created_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        files = [("manifest.json", snapshot.manifest)] + [(entry.opaque_id, entry.content) for entry in snapshot.selected]
        for name, data in files:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=created_fd)
            try:
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(created_fd)
        os.fsync(directory)
    except OSError:
        raise Refusal("evidence_write_failed") from None
    finally:
        if created_fd is not None:
            os.close(created_fd)
        os.close(directory)


def validate_snapshot(snapshot):
    if not isinstance(snapshot, Snapshot) or digest(snapshot.manifest) != snapshot.snapshot_id:
        raise Refusal("snapshot_mismatch")
    manifest = parse_json(snapshot.manifest, 8388608)
    if manifest.get("selection_sha256") != snapshot.selection_sha256 or manifest.get("policy_sha256") != snapshot.policy_sha256:
        raise Refusal("snapshot_mismatch")
    selection = manifest["selection"]
    if (selection["repository"]["name"], selection["repository"]["id"], selection["base_commit"],
        selection["head_commit"], selection["frozen_diff_sha256"]) != (snapshot.repository_name, snapshot.repository_id,
        snapshot.base_commit, snapshot.head_commit, snapshot.frozen_diff_sha256):
        raise Refusal("snapshot_mismatch")
    if len(selection["entries"]) != len(snapshot.entries):
        raise Refusal("snapshot_mismatch")
    for ordinal, (item, entry) in enumerate(zip(selection["entries"], snapshot.entries)):
        actual = (entry.path, entry.source, entry.change_kind, entry.base_blob, entry.head_blob, entry.side,
                  entry.selected, entry.reason, entry.sha256, entry.surfaces, entry.required_ranges)
        expected = (item["path"], item["source"], item["change_kind"], item["base_blob"], item["head_blob"], item["side"],
                    item["selected"], item["reason"], item["sha256"], tuple(item["surfaces"]),
                    tuple(tuple(pair) for pair in item["required_ranges"]))
        if actual != expected or entry.ordinal != ordinal:
            raise Refusal("snapshot_mismatch")
        if entry.selected:
            if type(entry.content) is not bytes or len(entry.content) != item["bytes"] or digest(entry.content) != entry.sha256 or line_count(entry.content) != entry.lines:
                raise Refusal("snapshot_mismatch")
        elif entry.content is not None or entry.lines != 0:
            raise Refusal("snapshot_mismatch")
    return snapshot
