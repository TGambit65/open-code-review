# SPDX-License-Identifier: Apache-2.0
"""Fixed Linux x86_64 classic-BPF profile, independently pinned outside source."""

import struct

from .common import Refusal, digest
from .policy import FILTER_SHA256

ALLOW_NUMBERS = (0, 1, 3, 5, 8, 11, 12, 13, 14, 15, 17, 19, 20, 21, 24, 25,
                 28, 39, 59, 60, 63, 74, 75, 77, 79, 80, 102, 104, 107, 108,
                 110, 158, 186, 202, 217, 218, 228, 231, 262, 267, 273, 318, 334)
CONDITIONAL = ((2, 24, 4194368), (257, 32, 4194368), (9, 32, 4), (10, 32, 4))


def filter_bytes():
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
                    (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0),
                    (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for number in ALLOW_NUMBERS:
        instructions.extend(((0x15, 0, 1, number), (0x06, 0, 0, 0x7FFF0000)))
    for number, offset, forbidden in CONDITIONAL:
        instructions.extend(((0x15, 0, 4, number), (0x20, 0, 0, offset),
                             (0x45, 0, 1, forbidden), (0x06, 0, 0, 0x50001),
                             (0x06, 0, 0, 0x7FFF0000)))
    instructions.append((0x06, 0, 0, 0x50001))
    raw = b"".join(struct.pack("<HBBI", *instruction) for instruction in instructions)
    if digest(raw) != FILTER_SHA256:
        raise Refusal("filter_mismatch")
    return raw
