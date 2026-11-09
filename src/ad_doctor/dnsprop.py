"""Bounded parsers for the dnsProperty and dnsRecord attributes of Active Directory DNS.

Any domain user can create a record, so everything here reads attacker-controlled bytes.

[MS-DNSP] 2.3.2.1: DataLength, NameLength, Flag, Version and Id, four bytes each, then Data
and one byte of Name. Every value holds one property. Anything that does not fit that layout
gives "unknown" (None), never a default: a value read wrongly must not become a finding, and
one that cannot be read must not pass as clean.
"""

from __future__ import annotations

import re
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

# dnsRecord, [MS-DNSP] 2.3.2.2: DataLength, Type, Version, Rank, Flags, Serial, TtlSeconds,
# Reserved, TimeStamp, then Data. Only the type is read: the data is never needed.
RECORD_HEADER = struct.Struct("<HHBBHIIII")
RECORD_VERSION = 5
MAX_RECORD_VALUES = 1024
MAX_RECORD_BYTES = RECORD_HEADER.size + 0xFFFF
# DNS_RECORD_TYPE, [MS-DNSP] 2.2.2.1.1; 0 marks a record the server has tombstoned
TYPE_TOMBSTONE = 0
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28
ADDRESS_TYPES = frozenset((TYPE_A, TYPE_AAAA, TYPE_CNAME))

# why a name is kept in the snapshot; decided when collected, redaction replaces the name
KIND_MARSHALED = "marshaled"
KIND_WILDCARD = "wildcard"
KIND_WELL_KNOWN = "well-known"
NODE_KINDS = (KIND_MARSHALED, KIND_WILDCARD, KIND_WELL_KNOWN)
MAX_NAME_LENGTH = 255
# a marshaled CREDENTIAL_TARGET_INFORMATION in a host name: the structure has a fixed part, so
# what lies between the two constant ends is never short. DNS ignores case, so this does too.
MARSHALED = re.compile(r"uwhrc[a-z0-9#-]{20,}baaaa", re.IGNORECASE)
# wpad and isatap are the default DNS global query block list; autodiscover is what mail
# clients ask for by themselves
WELL_KNOWN_NAMES = frozenset(("wpad", "isatap", "autodiscover"))


def record_type(raw: bytes) -> int | None:
    """The type of one dnsRecord value, None when it does not follow the layout."""
    if not RECORD_HEADER.size <= len(raw) <= MAX_RECORD_BYTES:
        return None
    length, kind, version, *_ = RECORD_HEADER.unpack_from(raw)
    if version != RECORD_VERSION or length > len(raw) - RECORD_HEADER.size:
        return None
    return int(kind)


def record_types(values: Sequence[bytes]) -> list[int] | None:
    """The types of the readable values, or None when none is readable or there are more
    values than are read. A malformed value beside a valid one cannot hide the valid one, and
    neither can a long run of values ahead of it."""
    if len(values) > MAX_RECORD_VALUES:
        return None
    found = {record_type(raw) for raw in values}
    found.discard(None)
    return sorted(t for t in found if t is not None) or None


def node_kind(name: str) -> str | None:
    """Why the checks need this name, or None for an ordinary name."""
    if len(name) > MAX_NAME_LENGTH:
        return None
    if MARSHALED.search(name):
        return KIND_MARSHALED
    first = name.split(".", 1)[0].lower()
    if first == "*":
        return KIND_WILDCARD
    return KIND_WELL_KNOWN if first in WELL_KNOWN_NAMES else None


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
