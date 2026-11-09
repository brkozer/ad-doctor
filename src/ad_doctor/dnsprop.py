"""Bounded parser for the dnsProperty attribute of Active Directory-integrated DNS zones.

[MS-DNSP] 2.3.2.1: DataLength, NameLength, Flag, Version and Id, four bytes each, then Data
and one byte of Name. Every value holds one property. Anything that does not fit that layout
gives "unknown" (None), never a default: a value read wrongly must not become a finding, and
one that cannot be read must not pass as clean.
"""

from __future__ import annotations

import struct
from collections.abc import Collection, Sequence
from dataclasses import dataclass

HEADER = struct.Struct("<5I")
# a zone holds about a dozen values of a few bytes each; these are far above that
MAX_VALUES = 64
MAX_VALUE_BYTES = 4096

PROPERTY_ZONE_TYPE = 0x01
PROPERTY_ALLOW_UPDATE = 0x02

# DNS_ZONE_TYPE, [MS-DNSP] 2.2.5.1.1
ZONE_TYPE_PRIMARY = 1
ZONE_TYPES = frozenset(range(6))
# fAllowUpdate, [MS-DNSP] 2.2.5.2.4.1
UPDATE_OFF = 0
UPDATE_NONSECURE = 1
UPDATE_SECURE = 2
UPDATE_VALUES = frozenset((UPDATE_OFF, UPDATE_NONSECURE, UPDATE_SECURE))


@dataclass(frozen=True)
class ZoneProperties:
    zone_type: int | None = None
    allow_update: int | None = None


def _split(raw: bytes) -> tuple[int, bytes] | None:
    """(Id, Data) of one value, None when it does not follow the layout."""
    if not HEADER.size <= len(raw) <= MAX_VALUE_BYTES:
        return None
    length, _name_length, flag, version, prop = HEADER.unpack_from(raw)
    if flag != 0 or version != 1 or length > len(raw) - HEADER.size:
        return None
    return prop, raw[HEADER.size : HEADER.size + length]


def _number(data: bytes, allowed: Collection[int], default: int | None) -> int | None:
    """A little-endian integer of 1 or 4 bytes. A DataLength of 0 takes the default the
    specification gives for the property."""
    if not data:
        return default
    if len(data) not in (1, 4):
        return None
    value = int.from_bytes(data, "little")
    return value if value in allowed else None


def parse(values: Sequence[bytes]) -> ZoneProperties:
    """The zone type and the dynamic update setting, each None when absent, malformed, or
    stored twice with different values. [MS-DNSP] gives a default for an empty zone type
    (primary) and none for an empty dynamic update setting."""
    if len(values) > MAX_VALUES:
        return ZoneProperties()
    seen: dict[int, list[bytes]] = {}
    for raw in values:
        parsed = _split(raw)
        if parsed is not None:
            seen.setdefault(parsed[0], []).append(parsed[1])
    return ZoneProperties(
        _single(seen.get(PROPERTY_ZONE_TYPE), ZONE_TYPES, ZONE_TYPE_PRIMARY),
        _single(seen.get(PROPERTY_ALLOW_UPDATE), UPDATE_VALUES, None),
    )


def _single(found: list[bytes] | None, allowed: Collection[int], default: int | None) -> int | None:
    if not found:
        return None
    numbers = {_number(data, allowed, default) for data in found}
    return numbers.pop() if len(numbers) == 1 else None
