# SPDX-License-Identifier: Apache-2.0
"""Bounded data primitives; no filesystem, process or provider capabilities."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

VERSION = "1.0"
SURFACES = frozenset(("primary", "secondary", "base", "deleted", "history",
                      "search", "filename", "rules", "background", "tool_error"))
STAGES = ("implementation", "independent_review", "remote_preservation",
          "applicable_validation", "acceptance")
STATUSES = frozenset(("success", "unknown", "timeout", "partial", "skipped",
                      "stale", "parser_error", "error", "unsupported"))
CHANGES = frozenset(("added", "modified", "deleted", "renamed", "copied",
                     "untracked", "staged_deleted", "context"))


class Refusal(Exception):
    """Errors are stable codes, never source paths, input text or OS messages."""

    def __init__(self, code="invalid_input"):
        self.code = code if re.fullmatch(r"[a-z_]{1,64}", code) else "invalid_input"
        super().__init__(self.code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise Refusal("invalid_document") from None


def parse_json(raw, limit=1048576):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise Refusal("document_limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refusal("duplicate_key")
            result[key] = value
        return result

    def invalid(_):
        raise Refusal("invalid_document")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=invalid)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise Refusal("invalid_document") from None


def fields(value, required, optional=()):
    if type(value) is not dict or set(value) != set(required) | (set(value) & set(optional)):
        raise Refusal("invalid_fields")
    return value


def integer(value, low=0, high=2**63 - 1):
    if type(value) is not int or not low <= value <= high:
        raise Refusal("invalid_integer")
    return value


def text(value, maximum=256):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise Refusal("invalid_text")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise Refusal("invalid_text")
    return value


def sha(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise Refusal("invalid_digest")
    return value


def git_id(value, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
        raise Refusal("invalid_blob")
    return value


def relative_path(value):
    text(value, 4096)
    if value.startswith("/") or "\\" in value or any(x in ("", ".", "..") for x in value.split("/")):
        raise Refusal("unsafe_path")
    return value


def ranges(value, maximum):
    if type(value) is not list or len(value) > 4096:
        raise Refusal("invalid_ranges")
    result = []
    last = 0
    for pair in value:
        if type(pair) is not list or len(pair) != 2:
            raise Refusal("invalid_ranges")
        start, end = integer(pair[0], 1, maximum), integer(pair[1], 1, maximum)
        if start > end or start <= last:
            raise Refusal("invalid_ranges")
        result.append((start, end))
        last = end
    return tuple(result)


def utc(value):
    text(value, 64)
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise Refusal("invalid_time") from None


def now_utc():
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ModelItem:
    opaque_id: str
    surfaces: tuple
    content: str
    line_map: tuple
    gaps: tuple


@dataclass(frozen=True)
class ModelBundle:
    bundle_id: str
    items: tuple
