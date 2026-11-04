"""Minimal parser for self-relative security descriptors (nTSecurityDescriptor).

Only the DACL is read, and only allow ACEs matter for the checks: deny ACEs are rare on
the objects audited here and ignoring them can only over-report, never hide a finding.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

ACCESS_ALLOWED = 0x00
ACCESS_ALLOWED_OBJECT = 0x05
INHERIT_ONLY = 0x08
ACE_OBJECT_TYPE_PRESENT = 0x1

# Access mask bits as Active Directory uses them.
CREATE_CHILD = 0x00000001
SELF = 0x00000008
WRITE_PROPERTY = 0x00000020
CONTROL_ACCESS = 0x00000100
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
FULL_CONTROL = 0x000F01FF

# Extended rights and property sets.
DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
CERT_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERT_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
ALL_EXTENDED_RIGHTS = None  # an object ACE without an object type


@dataclass(frozen=True)
class Ace:
    sid: str
    mask: int
    object_type: str | None = None

    def grants(self, bits: int) -> bool:
        return bool(self.mask & bits)

    @property
    def takeover(self) -> bool:
        """Rights that let the trustee rewrite the object or its permissions."""
        if self.mask & (GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER):
            return True
        if (self.mask & FULL_CONTROL) == FULL_CONTROL:
            return True
        # WriteProperty on every attribute, not on one attribute or property set
        return bool(self.mask & WRITE_PROPERTY) and self.object_type is None

    def extended_right(self, right: str) -> bool:
        """True if the ACE grants this control-access right (or all of them)."""
        if self.mask & GENERIC_ALL:
            return True
        if not self.mask & CONTROL_ACCESS:
            return False
        return self.object_type is None or self.object_type == right


def sid_from_bytes(raw: bytes, offset: int = 0) -> tuple[str, int]:
    """Parse a binary SID; returns the string form and its length in bytes."""
    revision, count = raw[offset], raw[offset + 1]
    authority = int.from_bytes(raw[offset + 2 : offset + 8], "big")
    subs = struct.unpack_from(f"<{count}I", raw, offset + 8)
    return f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs), 8 + 4 * count


def parse_dacl(raw: bytes) -> list[Ace]:
    """Allow ACEs that apply to the object itself (inherit-only ACEs are skipped)."""
    if len(raw) < 20:
        return []
    dacl_offset = struct.unpack_from("<I", raw, 16)[0]
    if dacl_offset == 0:
        return []
    _rev, _sbz, _size, count, _sbz2 = struct.unpack_from("<BBHHH", raw, dacl_offset)
    pos = dacl_offset + 8
    aces = []
    for _ in range(count):
        ace_type, flags, size = struct.unpack_from("<BBH", raw, pos)
        body = pos + 4
        if ace_type in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT) and not flags & INHERIT_ONLY:
            mask = struct.unpack_from("<I", raw, body)[0]
            cursor = body + 4
            object_type = None
            if ace_type == ACCESS_ALLOWED_OBJECT:
                obj_flags = struct.unpack_from("<I", raw, cursor)[0]
                cursor += 4
                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    object_type = str(uuid.UUID(bytes_le=raw[cursor : cursor + 16]))
                    cursor += 16
                if obj_flags & 0x2:  # inherited object type present
                    cursor += 16
            sid, _ = sid_from_bytes(raw, cursor)
            aces.append(Ace(sid, mask, object_type))
        pos += size
    return aces
