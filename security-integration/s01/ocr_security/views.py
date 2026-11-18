# SPDX-License-Identifier: Apache-2.0
"""Materialize model bytes before any model-facing request can be served."""

from dataclasses import dataclass

from .common import ModelBundle, ModelItem, Refusal, canonical, digest, fields, ranges, sha
from .policy import resolve_document
from .snapshot import validate_snapshot


@dataclass(frozen=True)
class Views:
    scanner_inputs: tuple
    model: ModelBundle
    private_evidence: bytes


def materialize_views(snapshot, context, release_ref=None):
    validate_snapshot(snapshot)
    releases = {}
    release_digest = None
    if release_ref is not None:
        document = resolve_document(release_ref, context, "approved-line-release")
        fields(document, ("schema_version", "kind", "snapshot_id", "entries"))
        if document["snapshot_id"] != snapshot.snapshot_id:
            raise Refusal("stale_release")
        if type(document["entries"]) is not list or len(document["entries"]) > len(snapshot.entries):
            raise Refusal("invalid_release")
        by_id = {entry.opaque_id: entry for entry in snapshot.selected}
        for item in document["entries"]:
            fields(item, ("opaque_id", "original_sha256", "ranges"))
            opaque_id = item["opaque_id"]
            if opaque_id not in by_id or opaque_id in releases:
                raise Refusal("invalid_release")
            entry = by_id[opaque_id]
            if sha(item["original_sha256"]) != entry.sha256:
                raise Refusal("stale_release")
            releases[opaque_id] = ranges(item["ranges"], entry.lines)
        release_digest = release_ref.sha256
    items, evidence, scanner_inputs = [], [], []
    mapped_lines, model_bytes = 0, 0
    for entry in snapshot.entries:
        original = entry.content
        transformed, line_map, gaps = [], [], []
        if not entry.selected:
            gaps.append((0, 0, "excluded"))
        else:
            scanner_inputs.append((entry.opaque_id, original))
            try:
                if entry.lines > 4096 or mapped_lines + entry.lines > 16384:
                    raise OverflowError()
                decoded = original.decode("utf-8")
                if any(ch not in "\n\t" and not ch.isprintable() for ch in decoded):
                    raise UnicodeError()
                lines = decoded.splitlines(keepends=True)
                if len(lines) != entry.lines:
                    raise UnicodeError()
            except OverflowError:
                lines = None
                gaps.append((1 if entry.lines else 0, entry.lines, "line_limit"))
            except UnicodeError:
                lines = None
                gaps.append((1 if entry.lines else 0, entry.lines, "unsafe_encoding_or_content"))
            if lines is not None:
                approved = releases.get(entry.opaque_id, ())
                release_index = 0
                for number, line in enumerate(lines, 1):
                    while release_index < len(approved) and approved[release_index][1] < number:
                        release_index += 1
                    if release_index < len(approved) and approved[release_index][0] <= number <= approved[release_index][1]:
                        transformed.append(line)
                        line_map.append((number, number, "released"))
                    else:
                        transformed.append("[REDACTED]\n" if line.endswith("\n") else "[REDACTED]")
                        line_map.append((number, number, "redacted"))
                        gaps.append((number, number, "not_released"))
        content = "".join(transformed)
        content_bytes = len(content.encode("utf-8"))
        if model_bytes + content_bytes > 1048576:
            content, line_map = "", []
            gaps = [(1 if entry.lines else 0, entry.lines, "model_output_limit")]
        else:
            model_bytes += content_bytes
            mapped_lines += len(line_map)
        items.append(ModelItem(entry.opaque_id, entry.surfaces, content, tuple(line_map), tuple(gaps)))
        evidence.append({"opaque_id": entry.opaque_id, "identity": list(entry.identity),
                         "original_sha256": entry.sha256, "transformed_sha256": digest(content.encode("utf-8")),
                         "line_mapping": line_map, "omissions": gaps, "selected": entry.selected})
    safe_serialized = canonical([{"id": x.opaque_id, "surfaces": x.surfaces, "content": x.content,
                                 "line_map": x.line_map, "gaps": x.gaps} for x in items])
    model = ModelBundle(digest(safe_serialized), tuple(items))
    private = canonical({"schema_version": "1.0", "snapshot_id": snapshot.snapshot_id,
                         "release_policy_sha256": release_digest, "model_bundle_id": model.bundle_id,
                         "entries": evidence})
    return Views(tuple(scanner_inputs), model, private)
