"""Minimal parser for self-relative security descriptors (nTSecurityDescriptor).

The owner, the DACL-protected flag and the allow ACEs are read: deny ACEs are rare on the
objects audited here and ignoring them can only over-report, never hide a finding. The
CA's own descriptor is the exception (parse_ca): denying a CA right to a group that a
broad allow covers is a documented way to restrict CA roles.
"""

from __future__ import annotations

import re
import struct
import uuid
from dataclasses import dataclass, field

ACCESS_ALLOWED = 0x00
ACCESS_ALLOWED_OBJECT = 0x05
INHERIT_ONLY = 0x08
ACE_OBJECT_TYPE_PRESENT = 0x1

# Access mask bits as Active Directory uses them.
CREATE_CHILD = 0x00000001
SELF = 0x00000008
READ_PROPERTY = 0x00000010
WRITE_PROPERTY = 0x00000020
CONTROL_ACCESS = 0x00000100
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FULL_CONTROL = 0x000F01FF

# Extended rights and property sets.
DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
CERT_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERT_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
# Attributes whose write access alone is a takeover path
KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"  # shadow credentials
ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"  # RBCD
MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
SERVICE_PRINCIPAL_NAME = "f3a64788-5306-11d1-a9c5-0000f80367c1"  # targeted Kerberoasting
ALT_SECURITY_IDENTITIES = "00fbf30c-91fe-11d1-aebc-0000f80367c1"  # ESC14
GP_LINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
APPLY_GROUP_POLICY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
# Classes
DMSA_CLASS = "0feb936f-47b3-49f2-9386-1dedc2c23765"  # msDS-DelegatedManagedServiceAccount

SE_DACL_PROTECTED = 0x1000

# Certification authority rights (the CA's own security descriptor, not an AD object)
CA_MANAGE = 0x1  # ManageCA (CA administrator)
CA_OFFICER = 0x2  # ManageCertificates (certificate manager)
# CA registry settings
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000  # policy\EditFlags: SAN from request attributes
IF_ENFORCEENCRYPTICERTREQUEST = 0x200  # CA\InterfaceFlags: ICPR requires packet privacy
REQDISP_PENDING = 0x100  # policy\RequestDisposition: every request waits for a manager
SZOID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"  # the SID extension (KB5014754)


CONTAINER_INHERIT = 0x02
INHERITED_OBJECT_TYPE_PRESENT = 0x2

# Property sets that contain attributes the checks track; a WriteProperty on the set
# writes every attribute in it.
MEMBERSHIP_SET = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"  # member
PUBLIC_INFORMATION_SET = "e48d0154-bcf8-11d1-8702-00c04fb96050"  # altSecurityIdentities
# User-Account-Restrictions (BloodHound: WriteAccountRestrictions)
ACCOUNT_RESTRICTIONS_SET = "4c164200-20c0-11d0-a768-00aa006e0529"  # RBCD attribute
PROPERTY_SET = {
    MEMBER: MEMBERSHIP_SET,
    ALT_SECURITY_IDENTITIES: PUBLIC_INFORMATION_SET,
    ALLOWED_TO_ACT: ACCOUNT_RESTRICTIONS_SET,
}

# Object classes, for ACEs that only children of one class inherit
USER_CLASS = "bf967aba-0de6-11d0-a285-00aa003049e2"
COMPUTER_CLASS = "bf967a86-0de6-11d0-a285-00aa003049e2"
GROUP_CLASS = "bf967a9c-0de6-11d0-a285-00aa003049e2"
OU_CLASS = "bf967aa5-0de6-11d0-a285-00aa003049e2"


@dataclass(frozen=True, slots=True)
class Ace:
    sid: str
    mask: int
    object_type: str | None = None
    # for inheritable ACEs: the only child class that inherits it (None = every class)
    inherited_object_type: str | None = None

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

    @property
    def rewrites_dacl(self) -> bool:
        """Rights that let the trustee change who the object applies to, not only its values."""
        if self.mask & (GENERIC_ALL | WRITE_DAC | WRITE_OWNER):
            return True
        return (self.mask & FULL_CONTROL) == FULL_CONTROL

    def writes(self, attribute: str) -> bool:
        """True if the ACE lets the trustee write this attribute (or all attributes)."""
        if self.mask & (GENERIC_ALL | GENERIC_WRITE):
            return True
        allowed = (None, attribute, PROPERTY_SET.get(attribute))
        return bool(self.mask & WRITE_PROPERTY) and self.object_type in allowed

    def adds_self(self) -> bool:
        """The validated write 'Add/remove self as member' (or all validated writes)."""
        return bool(self.mask & SELF) and self.object_type in (None, MEMBER)

    def creates(self, object_class: str) -> bool:
        """True if the ACE lets the trustee create children of this class."""
        if self.mask & GENERIC_ALL:
            return True
        return bool(self.mask & CREATE_CHILD) and self.object_type in (None, object_class)

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


@dataclass(frozen=True)
class Descriptor:
    owner: str | None
    dacl_protected: bool
    aces: list[Ace]
    # ACEs that children inherit (CONTAINER_INHERIT), including inherit-only ones
    inheritable: list[Ace] = field(default_factory=list)


def parse(raw: bytes) -> Descriptor:
    """Owner (when it was requested), DACL protection, effective and inheritable ACEs."""
    if len(raw) < 20:
        return Descriptor(None, False, [])
    control, owner_offset = struct.unpack_from("<HI", raw, 2)
    owner = sid_from_bytes(raw, owner_offset)[0] if owner_offset else None
    return Descriptor(
        owner, bool(control & SE_DACL_PROTECTED), parse_dacl(raw), parse_dacl(raw, True)
    )


ACCESS_DENIED = 0x01
# a deny for these applies to every principal that can hold a CA right
_DENY_ALL = ("S-1-1-0", "S-1-5-11")


def parse_ca(raw: bytes) -> tuple[str | None, list[Ace]]:
    """Owner and effective allow ACEs of a CA security descriptor (the registry value
    CertSvc\\Configuration\\<CA>\\Security).

    Deny ACEs are applied the way Windows evaluates a canonical DACL: a right denied to a
    SID (or to Everyone or Authenticated Users) by an earlier ACE is removed from later
    allows. A deny through some other group membership is not seen, which can only
    over-report. Malformed input raises IndexError or struct.error.
    """
    if len(raw) < 20:
        return None, []
    owner_offset, _group, _sacl, dacl_offset = struct.unpack_from("<IIII", raw, 4)
    owner = sid_from_bytes(raw, owner_offset)[0] if owner_offset else None
    if dacl_offset == 0:
        return owner, []
    count = struct.unpack_from("<H", raw, dacl_offset + 4)[0]
    pos = dacl_offset + 8
    denied: dict[str, int] = {}
    aces = []
    for _ in range(count):
        ace_type, flags, size = struct.unpack_from("<BBH", raw, pos)
        if size < 8:
            raise ValueError("ACE shorter than its header")
        if not flags & INHERIT_ONLY and ace_type in (ACCESS_ALLOWED, ACCESS_DENIED):
            mask = struct.unpack_from("<I", raw, pos + 4)[0]
            sid, _ = sid_from_bytes(raw, pos + 8)
            if ace_type == ACCESS_DENIED:
                denied[sid] = denied.get(sid, 0) | mask
            else:
                for s in (sid, *_DENY_ALL):
                    mask &= ~denied.get(s, 0)
                if mask:
                    aces.append(Ace(sid, mask))
        pos += size
    return owner, aces


def parse_dacl(raw: bytes, inheritable: bool = False) -> list[Ace]:
    """Allow ACEs that apply to the object itself (default) or that children inherit."""
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
        wanted = bool(flags & CONTAINER_INHERIT) if inheritable else not flags & INHERIT_ONLY
        if ace_type in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT) and wanted:
            mask = struct.unpack_from("<I", raw, body)[0]
            cursor = body + 4
            object_type = inherited_type = None
            if ace_type == ACCESS_ALLOWED_OBJECT:
                obj_flags = struct.unpack_from("<I", raw, cursor)[0]
                cursor += 4
                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    object_type = str(uuid.UUID(bytes_le=raw[cursor : cursor + 16]))
                    cursor += 16
                if obj_flags & INHERITED_OBJECT_TYPE_PRESENT:
                    inherited_type = str(uuid.UUID(bytes_le=raw[cursor : cursor + 16]))
                    cursor += 16
            sid, _ = sid_from_bytes(raw, cursor)
            aces.append(Ace(sid, mask, object_type, inherited_type if inheritable else None))
        pos += size
    return aces


# SDDL SID strings. Domain-relative ones take the domain's SID, forest-wide ones the root's.
SDDL_SIDS = {
    "WD": "S-1-1-0", "CO": "S-1-3-0", "CG": "S-1-3-1", "NU": "S-1-5-2", "IU": "S-1-5-4",
    "SU": "S-1-5-6", "AN": "S-1-5-7", "ED": "S-1-5-9", "PS": "S-1-5-10", "AU": "S-1-5-11",
    "RC": "S-1-5-12", "SY": "S-1-5-18", "LS": "S-1-5-19", "NS": "S-1-5-20",
    "BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "PU": "S-1-5-32-547",
    "AO": "S-1-5-32-548", "SO": "S-1-5-32-549", "PO": "S-1-5-32-550", "BO": "S-1-5-32-551",
    "RE": "S-1-5-32-552", "RU": "S-1-5-32-554", "RD": "S-1-5-32-555", "NO": "S-1-5-32-556",
    "MU": "S-1-5-32-558", "LU": "S-1-5-32-559", "IS": "S-1-5-32-568", "CY": "S-1-5-32-569",
    "ER": "S-1-5-32-573", "CD": "S-1-5-32-574", "RA": "S-1-5-32-575", "ES": "S-1-5-32-576",
    "MS": "S-1-5-32-577", "HA": "S-1-5-32-578", "AA": "S-1-5-32-579", "RM": "S-1-5-32-580",
    "HO": "S-1-5-32-584", "SH": "S-1-5-32-585", "OW": "S-1-3-4", "WR": "S-1-5-33",
    "UD": "S-1-5-84-0-0-0-0-0", "AC": "S-1-15-2-1", "LW": "S-1-16-4096", "ME": "S-1-16-8192",
    "MP": "S-1-16-8448", "HI": "S-1-16-12288", "SI": "S-1-16-16384", "AS": "S-1-18-1",
    "SS": "S-1-18-2",
}  # fmt: skip
SDDL_DOMAIN_RIDS = {
    "LA": 500, "LG": 501, "DA": 512, "DU": 513, "DG": 514, "DC": 515, "DD": 516, "CA": 517,
    "PA": 520, "CN": 522, "AP": 525, "KA": 526, "RS": 553,
}  # fmt: skip
SDDL_ROOT_RIDS = {"RO": 498, "SA": 518, "EA": 519, "EK": 527}
SDDL_DACL = re.compile(r"D:[A-Z_]*((?:\([^()]*\))*)\s*$")
SDDL_ACE = re.compile(r"\(([^;()]*);[^;()]*;[^;()]*;[^;()]*;[^;()]*;([^;()]*)(?:;[^()]*)?\)")


def _sddl_sid(token: str, domain_sid: str, root_sid: str) -> str:
    token = token.strip().upper()
    if token.startswith("S-1-"):
        return token
    if token in SDDL_SIDS:
        return SDDL_SIDS[token]
    if token in SDDL_DOMAIN_RIDS:
        return f"{domain_sid}-{SDDL_DOMAIN_RIDS[token]}"
    if token in SDDL_ROOT_RIDS:
        return f"{root_sid or domain_sid}-{SDDL_ROOT_RIDS[token]}"
    raise ValueError(f"unknown SDDL trustee {token}")


def sddl_trustees(text: str, domain_sid: str, root_sid: str = "") -> tuple[list[str], list[str]]:
    """(allowed SIDs, denied SIDs) of the DACL in an SDDL string; ValueError when the text
    holds anything but plain allow and deny ACEs."""
    dacl = SDDL_DACL.search(text.split("S:(", 1)[0].strip())
    if dacl is None:
        raise ValueError("no DACL in the SDDL string")
    body = dacl.group(1)
    aces = list(SDDL_ACE.finditer(body))
    if "".join(m.group(0) for m in aces) != body:
        raise ValueError("ACE not understood")
    allow: list[str] = []
    deny: list[str] = []
    for ace in aces:
        kind = ace.group(1).strip().upper()
        if kind not in ("A", "D"):
            raise ValueError(f"ACE type {kind} not understood")
        sid = _sddl_sid(ace.group(2), domain_sid, root_sid)
        (allow if kind == "A" else deny).append(sid)
    return allow, deny
