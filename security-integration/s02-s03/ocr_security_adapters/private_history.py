# SPDX-License-Identifier: Apache-2.0
"""Scanner-only bounded Git projection of approved original snapshot records.

Never give this object to the model broker. It contains original bytes. Synthetic
commits enumerate selected snapshot records, not undiscovered target history.
"""

from dataclasses import dataclass
import hashlib
import zlib
from ocr_security.common import Refusal, canonical, digest
from .inputs import scanner_inputs


@dataclass(frozen=True)
class OriginalHistory:
    snapshot_id: str
    base_commit: str
    head_commit: str
    files: tuple
    commit_items: tuple
    identity: str


def original_history(snapshot):
    inputs = scanner_inputs(snapshot)
    files, objects, records, tree_entries = {}, {}, [], {}
    def store(kind, data):
        raw = kind.encode("ascii") + b" " + str(len(data)).encode("ascii") + b"\0" + data
        identifier = hashlib.sha1(raw).hexdigest()
        objects[".git/objects/" + identifier[:2] + "/" + identifier[2:]] = zlib.compress(raw)
        return identifier
    author = b"author Synthetic Snapshot <snapshot@invalid> 0 +0000\ncommitter Synthetic Snapshot <snapshot@invalid> 0 +0000\n"
    empty = store("tree", b"")
    base = store("commit", b"tree " + empty.encode() + b"\n" + author + b"\nSelected original snapshots\n")
    head = base
    for item in inputs:
        alias = item.mount_path.rsplit("/", 1)[-1]
        blob = store("blob", item.content)
        files[alias] = item.content
        tree_entries[alias] = b"100644 " + alias.encode("ascii") + b"\0" + bytes.fromhex(blob)
        tree = store("tree", b"".join(value for _,value in sorted(tree_entries.items())))
        head = store("commit", b"tree " + tree.encode() + b"\nparent " + head.encode() + b"\n" + author + b"\nSelected item\n")
        records.append((head, alias, item.opaque_id))
    files.update(objects)
    files[".git/HEAD"] = b"ref: refs/heads/selected\n"
    files[".git/refs/heads/selected"] = head.encode() + b"\n"
    files[".git/config"] = b"[core]\nrepositoryformatversion = 0\nbare = false\nhooksPath = /nonexistent\n"
    if sum(len(data) for data in files.values()) > 67108864:
        raise Refusal("history_projection_limit")
    manifest = {"snapshot_id":snapshot.snapshot_id,"base_commit":base,"head_commit":head,
                "files":[[name,digest(data)] for name,data in sorted(files.items())],"commit_items":records}
    return OriginalHistory(snapshot.snapshot_id,base,head,tuple(sorted(files.items())),tuple(records),digest(canonical(manifest)))
