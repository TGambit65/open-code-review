# SPDX-License-Identifier: Apache-2.0
"""Construct a synthetic Git view from sanitized bytes without invoking Git.

This is a virtual file map for a future qualified runner, not a host filesystem
write. Every selected item is represented as an addition. Native preview on this
projection is selection assistance, never the original change/coverage ledger.
"""

from dataclasses import dataclass
import hashlib
import zlib
from ocr_security.common import Refusal, canonical, digest, git_id, relative_path, sha
from .reviewer import validate_bundle
from .inputs import ALLOWED_SUFFIXES
from .data import token


@dataclass(frozen=True)
class Projection:
    bundle_id: str
    base_commit: str
    head_commit: str
    files: tuple
    alias_items: tuple
    identity: str


def sanitized_projection(bundle, suffixes=None):
    validate_bundle(bundle)
    suffixes = {} if suffixes is None else suffixes
    if type(suffixes) is not dict or not set(suffixes) <= {x.opaque_id for x in bundle.items}:
        raise Refusal("invalid_suffix_map")
    objects, files, aliases, tree = {}, {}, [], []
    def object_bytes(kind, raw):
        payload = kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw
        object_id = hashlib.sha1(payload).hexdigest()
        objects[".git/objects/" + object_id[:2] + "/" + object_id[2:]] = zlib.compress(payload)
        return object_id
    empty = object_bytes("tree", b"")
    author = b"author Security Projection <projection@invalid> 0 +0000\ncommitter Security Projection <projection@invalid> 0 +0000\n"
    base = object_bytes("commit", b"tree " + empty.encode("ascii") + b"\n" + author + b"\nSanitized empty base\n")
    for item in bundle.items:
        suffix = suffixes.get(item.opaque_id, "txt")
        if suffix not in ALLOWED_SUFFIXES:
            raise Refusal("unsupported_suffix")
        alias = item.opaque_id + "." + suffix
        raw = item.content.encode("utf-8")
        blob = object_bytes("blob", raw)
        tree.append((alias, b"100644 " + alias.encode("ascii") + b"\0" + bytes.fromhex(blob)))
        files[alias] = raw
        aliases.append((alias, item.opaque_id))
    tree_id = object_bytes("tree", b"".join(value for _, value in sorted(tree)))
    head = object_bytes("commit", b"tree " + tree_id.encode("ascii") + b"\nparent " + base.encode("ascii") + b"\n" + author + b"\nSanitized inventory only\n")
    files.update(objects)
    files[".git/HEAD"] = b"ref: refs/heads/sanitized\n"
    files[".git/refs/heads/sanitized"] = head.encode("ascii") + b"\n"
    files[".git/config"] = b"[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = false\nhooksPath = /nonexistent\n"
    if sum(len(value) for value in files.values()) > 16777216:
        raise Refusal("projection_limit")
    manifest = {"bundle_id": bundle.bundle_id, "base_commit": base, "head_commit": head,
                "files": [[name, digest(data)] for name, data in sorted(files.items())],
                "alias_items": aliases}
    return Projection(bundle.bundle_id, base, head, tuple(sorted(files.items())), tuple(aliases), digest(canonical(manifest)))


def validate_projection(projection):
    """Recheck immutable projection identity before binding or mounting it."""
    if not isinstance(projection, Projection) or type(projection.files) is not tuple or type(projection.alias_items) is not tuple:
        raise Refusal("invalid_projection")
    if len(projection.files) > 2048 or len(projection.alias_items) > 256:
        raise Refusal("projection_limit")
    sha(projection.bundle_id)
    git_id(projection.base_commit)
    git_id(projection.head_commit)
    names, total, records = set(), 0, []
    for pair in projection.files:
        if type(pair) is not tuple or len(pair) != 2:
            raise Refusal("invalid_projection")
        path, raw = pair
        relative_path(path)
        if path in names or type(raw) is not bytes:
            raise Refusal("invalid_projection")
        names.add(path)
        total += len(raw)
        if total > 16777216:
            raise Refusal("projection_limit")
        records.append([path, digest(raw)])
    aliases, opaque_ids = set(), set()
    for pair in projection.alias_items:
        if type(pair) is not tuple or len(pair) != 2:
            raise Refusal("invalid_projection")
        alias, opaque_id = pair
        if type(alias) is not str or type(opaque_id) is not str or alias not in names or alias in aliases or opaque_id in opaque_ids:
            raise Refusal("invalid_projection")
        if not alias.startswith(opaque_id + ".") or alias[len(opaque_id) + 1:] not in ALLOWED_SUFFIXES:
            raise Refusal("invalid_projection")
        token(opaque_id, 32)
        aliases.add(alias)
        opaque_ids.add(opaque_id)
    manifest = {"bundle_id": projection.bundle_id, "base_commit": projection.base_commit,
                "head_commit": projection.head_commit, "files": sorted(records),
                "alias_items": projection.alias_items}
    if digest(canonical(manifest)) != sha(projection.identity):
        raise Refusal("stale_projection")
    return projection
