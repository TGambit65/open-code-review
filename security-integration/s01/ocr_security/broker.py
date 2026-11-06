# SPDX-License-Identifier: Apache-2.0
"""The model-facing surface has sanitized data only, no source/Git capability."""

from .common import SURFACES, ModelBundle


class Broker:
    def __init__(self, bundle):
        if not isinstance(bundle, ModelBundle):
            raise TypeError("sanitized_bundle_required")
        self._items = {item.opaque_id: item for item in bundle.items}

    def read(self, surface, opaque_id, start=1, end=None):
        if type(surface) is not str or surface not in SURFACES:
            return {"status": "unsupported", "code": "unsupported_surface"}
        if type(opaque_id) is not str or len(opaque_id) > 32:
            return {"status": "unsupported", "code": "unknown_item"}
        item = self._items.get(opaque_id)
        if item is None or surface not in item.surfaces:
            return {"status": "unsupported", "code": "unknown_item"}
        if surface == "filename":
            return {"status": "partial", "id": item.opaque_id, "content": item.opaque_id,
                    "gaps": ((0, 0, "original_filename_withheld"),)}
        lines = item.content.splitlines(keepends=True)
        if end is None:
            end = len(lines)
        if type(start) is not int or type(end) is not int or start < 1 or end < 0 or end > len(lines) or start > end + 1:
            return {"status": "unsupported", "code": "invalid_range"}
        return {"status": "partial" if item.gaps else "success", "id": item.opaque_id,
                "content": "".join(lines[start - 1:end]), "line_map": item.line_map[start - 1:end],
                "gaps": item.gaps}

    def search(self, query, maximum=64):
        if type(query) is not str or not 1 <= len(query) <= 256 or type(maximum) is not int or not 1 <= maximum <= 64:
            return {"status": "unsupported", "code": "invalid_query"}
        matches = []
        for item in self._items.values():
            if "search" not in item.surfaces:
                continue
            for number, line in enumerate(item.content.splitlines(), 1):
                if number <= len(item.line_map) and item.line_map[number - 1][2] == "released" and query in line:
                    if len(matches) == maximum:
                        return {"status": "partial", "matches": matches, "code": "result_limit"}
                    matches.append({"id": item.opaque_id, "line": number, "content": line})
        return {"status": "partial" if any(x.gaps for x in self._items.values()) else "success", "matches": matches}
