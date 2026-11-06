# SPDX-License-Identifier: Apache-2.0
"""Private scanner mount inventory; never expose this map to a model.

Content comes only from an already selected S01 snapshot. No path is opened and
no directory is discovered. Candidate filenames are not used as native targets.
"""

from dataclasses import dataclass
import re
from ocr_security.common import Refusal, canonical, digest
from ocr_security.snapshot import validate_snapshot

ALLOWED_SUFFIXES = frozenset(("py", "js", "jsx", "ts", "tsx", "go", "rs", "java", "kt", "c", "h", "cpp", "cs", "rb", "php", "json", "yaml", "yml", "toml", "xml", "sh", "md", "txt", "lock", "sum", "mod"))


@dataclass(frozen=True)
class Input:
    opaque_id: str
    mount_path: str
    content: bytes
    original_sha256: str
    identity: tuple
    required_ranges: tuple
    lines: int


def scanner_inputs(snapshot):
    validate_snapshot(snapshot)
    output = []
    for entry in snapshot.selected:
        suffix = entry.identity[0].rsplit(".", 1)[-1].lower()
        suffix = suffix if suffix in ALLOWED_SUFFIXES else "txt"
        if re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", entry.opaque_id) is None:
            raise Refusal("invalid_opaque_id")
        output.append(Input(entry.opaque_id, "/input/" + entry.opaque_id + "." + suffix,
                            entry.content, entry.sha256, entry.identity, entry.required_ranges, entry.lines))
    if len({item.mount_path for item in output}) != len(output):
        raise Refusal("duplicate_input")
    return tuple(output)


def input_manifest(snapshot):
    inputs = scanner_inputs(snapshot)
    document = {"snapshot_id": snapshot.snapshot_id, "kind": "private-scanner-input-inventory",
                "items": [{"id": x.opaque_id, "mount": x.mount_path, "original_sha256": x.original_sha256,
                           "identity": list(x.identity), "required_ranges": [list(r) for r in x.required_ranges]}
                          for x in inputs]}
    return document, digest(canonical(document))


def coverage_record(snapshot, item, complete, omissions=()):
    if type(complete) is not bool or type(omissions) is not tuple:
        raise Refusal("invalid_coverage")
    path, change, base_blob, head_blob, side = item.identity
    return {"snapshot_id": snapshot.snapshot_id, "path": path, "change_kind": change,
            "base_blob": base_blob, "head_blob": head_blob, "side": side,
            "original_sha256": item.original_sha256,
            "analyzed_ranges": [list(x) for x in item.required_ranges] if complete else [],
            "truncated": False, "omissions": list(omissions)}
