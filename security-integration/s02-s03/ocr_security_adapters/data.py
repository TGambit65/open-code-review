# SPDX-License-Identifier: Apache-2.0
"""Bounded inert data parsing shared by native output and external inventories."""

import math
from ocr_security.common import Refusal, parse_json, text, integer, sha, fields


def bounded_json(raw, maximum=1048576):
    value = parse_json(raw, maximum)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 32768:
            raise Refusal("document_structure_limit")
        if type(item) is dict:
            if len(item) > 4096:
                raise Refusal("document_structure_limit")
            for key, child in item.items():
                if type(key) is not str or len(key) > 256:
                    raise Refusal("invalid_key")
                pending.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > 4096:
                raise Refusal("document_structure_limit")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > 65536:
                raise Refusal("document_string_limit")
        elif type(item) is float and not math.isfinite(item):
            raise Refusal("invalid_document")
        elif item is not None and type(item) not in (bool, int, float):
            raise Refusal("invalid_document")
    return value


def sequence(value, maximum=4096):
    if type(value) is not list or len(value) > maximum:
        raise Refusal("invalid_array")
    return value


def choice(value, allowed, code="unsupported_value"):
    if type(value) is not str or value not in allowed:
        raise Refusal(code)
    return value


def token(value, maximum=128):
    text(value, maximum)
    if any(not (ch.isascii() and (ch.isalnum() or ch in "_-.")) for ch in value):
        raise Refusal("invalid_token")
    return value
