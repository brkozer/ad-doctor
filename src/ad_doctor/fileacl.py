"""NTFS security descriptors of SYSVOL files, and who can change what a path runs.

The rules follow the Windows access model: writing a file takes write rights on it, and
replacing it takes the right to delete it (DELETE on the file or FILE_DELETE_CHILD on its
folder) with the right to create it again. A folder is also lost to whoever can rewrite its
DACL or take ownership. An owner can always rewrite the DACL, unless an OWNER RIGHTS ACE
says otherwise.

Deny ACEs and conditional ACEs depend on the groups of each user, which a descriptor does
not show, so a descriptor that has one for a right that matters is not judged at all.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import sd
from .model import SysvolAcl

FILE_ADD_FILE = 0x00000002  # FILE_WRITE_DATA on a file
FILE_ADD_SUBDIRECTORY = 0x00000004  # FILE_APPEND_DATA on a file
FILE_DELETE_CHILD = 0x00000040
DELETE = 0x00010000
TAKEOVER = sd.WRITE_DAC | sd.WRITE_OWNER | sd.GENERIC_ALL
CHANGES_FILE = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | TAKEOVER | sd.GENERIC_WRITE
MATTERS = CHANGES_FILE | DELETE | FILE_DELETE_CHILD

ACCESS_ALLOWED = 0x00
ACCESS_DENIED = 0x01
SE_DACL_PRESENT = 0x0004
EVERYONE = "S-1-1-0"
CREATOR_OWNER = "S-1-3-0"
OWNER_RIGHTS = "S-1-3-4"
NOT_TRUSTEES = {CREATOR_OWNER, OWNER_RIGHTS}  # placeholders, not principals


def parse(raw: bytes, path: str, directory: bool) -> SysvolAcl:
    """What a self-relative descriptor says about writers. Only rights that matter are kept;
    a descriptor that cannot be parsed comes back with `error` set."""
    try:
        return _parse(raw, path, directory)
    except (IndexError, struct.error, ValueError):
        return SysvolAcl(path, directory, error="security descriptor not parseable")


def _parse(raw: bytes, path: str, directory: bool) -> SysvolAcl:
    _, _, control, owner_at, _, _, dacl_at = struct.unpack_from("<BBHIIII", raw)
    owner = sd.sid_from_bytes(raw, owner_at)[0] if owner_at else None
    if not control & SE_DACL_PRESENT or not dacl_at:  # a NULL DACL: everyone may do anything
        return SysvolAcl(path, directory, owner, [sd.Ace(EVERYONE, sd.GENERIC_ALL)])
    _, _, _, count, _ = struct.unpack_from("<BBHHH", raw, dacl_at)
    offset = dacl_at + 8
    aces: list[sd.Ace] = []
    judged = True
    for _ in range(count):
        kind, flags, size, mask = struct.unpack_from("<BBHI", raw, offset)
        if size < 8:
            raise ValueError("ACE too short")
        sid = sd.sid_from_bytes(raw, offset + 8)[0] if kind <= ACCESS_DENIED else ""
        offset += size
        if flags & sd.INHERIT_ONLY:
            continue  # applies to children only
        if sid == OWNER_RIGHTS:
            judged = False
        if not mask & MATTERS:
            continue
        if kind == ACCESS_ALLOWED:
            aces.append(sd.Ace(sid, mask & MATTERS, inherited=bool(flags & sd.INHERITED_ACE)))
        else:
            judged = False  # a deny or a conditional ACE: it depends on each user's groups
    return SysvolAcl(path, directory, owner, aces, judged)


def chain(target: str) -> list[str]:
    """A SYSVOL-relative path and the folders above it, up to the GPO's folder, or the
    top folder outside Policies (scripts: NETLOGON). The writable tree stops there: the
    folders above a GPO are shared by every GPO and are not read."""
    parts = target.split("\\")
    top = 2 if parts[0].lower() == "policies" and len(parts) > 1 else 1
    return ["\\".join(parts[:n]) for n in range(len(parts), max(top - 1, 0), -1)]


@dataclass
class Writers:
    """Who can change what `target` runs: (SID, path of the ACL that gives it) -> the right
    as text. `judged` is False when a descriptor on the way could not be read or judged:
    the writers found are then only the ones that could be seen."""

    found: dict[tuple[str, str], str] = field(default_factory=dict)
    judged: bool = True
    unknown: str = ""  # the first path that could not be judged


def _replaces_child(mask: int, add: int) -> bool:
    return bool(mask & TAKEOVER) or bool(mask & FILE_DELETE_CHILD and mask & add)


def writers(acls: dict[str, SysvolAcl], target: str) -> Writers:
    """`acls` is keyed by lower-cased path."""
    out = Writers()
    deleters: set[str] = set()
    for depth, path in enumerate(chain(target)):
        acl = acls.get(path.lower())
        if acl is None or acl.error or not acl.judged:
            out.judged = False
            out.unknown = out.unknown or path
            continue
        if acl.owner and acl.owner not in NOT_TRUSTEES:
            out.found.setdefault((acl.owner, acl.path), "owner")
        for ace in acl.aces:
            if ace.sid in NOT_TRUSTEES:
                continue
            if depth == 0:
                if ace.mask & CHANGES_FILE:
                    out.found.setdefault((ace.sid, acl.path), "write")
                elif ace.mask & DELETE:
                    deleters.add(ace.sid)
                continue
            add = FILE_ADD_FILE if depth == 1 else FILE_ADD_SUBDIRECTORY
            if _replaces_child(ace.mask, add):
                out.found.setdefault((ace.sid, acl.path), "replace files in the folder")
            elif depth == 1 and ace.mask & add and ace.sid in deleters:
                out.found.setdefault((ace.sid, target), "delete and recreate")
    return out
