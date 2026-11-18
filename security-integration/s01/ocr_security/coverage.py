# SPDX-License-Identifier: Apache-2.0
"""Coverage is keyed by content/change identity, not a path-level green flag."""

from dataclasses import dataclass

from .common import CHANGES, Refusal, fields, git_id, ranges, relative_path, sha, text
from .snapshot import validate_snapshot


@dataclass(frozen=True)
class Coverage:
    complete: bool
    gaps: tuple


def identity(record):
    return (relative_path(record["path"]), record["change_kind"], git_id(record["base_blob"], True),
            git_id(record["head_blob"], True), record["side"])


def _covers(actual, required):
    for start, end in required:
        cursor = start
        for first, last in actual:
            if first > cursor:
                break
            if last >= cursor:
                cursor = last + 1
            if cursor > end:
                break
        if cursor <= end:
            return False
    return True


def assess_coverage(snapshot, records):
    validate_snapshot(snapshot)
    if type(records) is not list or len(records) > 256:
        raise Refusal("invalid_coverage")
    expected = {entry.identity: entry for entry in snapshot.entries}
    seen, gaps = set(), []
    required_fields = ("snapshot_id", "path", "change_kind", "base_blob", "head_blob", "side",
                       "original_sha256", "analyzed_ranges", "truncated", "omissions")
    for record in records:
        fields(record, required_fields)
        if type(record["change_kind"]) is not str or record["change_kind"] not in CHANGES:
            raise Refusal("invalid_coverage")
        if type(record["side"]) is not str or record["side"] not in ("base", "head", "context", "error"):
            raise Refusal("invalid_coverage")
        sha(record["snapshot_id"])
        sha(record["original_sha256"])
        ranges(record["analyzed_ranges"], 1048576)
        if type(record["truncated"]) is not bool or type(record["omissions"]) is not list or len(record["omissions"]) > 4096:
            raise Refusal("invalid_coverage")
        for omission in record["omissions"]:
            text(omission, 128)
        key = identity(record)
        if key in seen:
            raise Refusal("duplicate_coverage")
        seen.add(key)
        if sha(record["snapshot_id"]) != snapshot.snapshot_id:
            gaps.append((key, "stale_snapshot"))
        if key not in expected:
            gaps.append((key, "unexpected_identity"))
            continue
        entry = expected[key]
        if not entry.selected:
            gaps.append((key, "excluded"))
            continue
        if record["original_sha256"] != entry.sha256:
            gaps.append((key, "stale_content"))
        actual = ranges(record["analyzed_ranges"], entry.lines)
        if not _covers(actual, entry.required_ranges):
            gaps.append((key, "partial_ranges"))
        if record["truncated"]:
            gaps.append((key, "truncated"))
        if record["omissions"]:
            gaps.append((key, "omitted"))
    for key, entry in expected.items():
        if not entry.selected:
            if (key, "excluded") not in gaps:
                gaps.append((key, "excluded"))
        elif key not in seen:
            gaps.append((key, "missing_identity"))
    return Coverage(not gaps, tuple(gaps))
