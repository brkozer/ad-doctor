"""Registry.pol: the registry settings a GPO writes, in the format of [MS-GPREG].

A file is the header 'PReg' with version 1, then instructions [key;value;type;size;data] in
UTF-16LE, where the order of the instructions matters. The value name can be a marker
instead: **del.NAME and **DeleteValues remove values, **delvals. removes every value of the
key, **DeleteKeys removes subkeys, and **soft.NAME sets a value only where none exists.

The bytes come from SYSVOL and anybody who can edit a GPO can write them, so everything is
bounded and a file that does not parse raises `MalformedPol` as a whole: half a file says
nothing about what the other half sets. Only the values the checks read are kept. A value
named like a password leaves here as its location alone; its data is never returned.

An instruction may stop after its key, value, type or size. Such an instruction, or one whose
value, type or data is empty, only creates the key: it sets no value.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from .model import RegistryEntry

SIGNATURE = b"PReg"
VERSION = 1
MAX_KEPT = 4096  # entries kept from one file
MAX_TEXT = 1024  # characters kept of one string
MAX_STRINGS = 64  # strings kept of one REG_MULTI_SZ
# characters of a registry path or value name, far past any real one: an instruction can list
# thousands of names, so a padded name must not reach the checks
MAX_NAME = 1024
_HEADER = 8

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_MULTI_SZ = 7
REG_QWORD = 11
_TEXT_TYPES = (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ)

LLMNR_KEY = r"Software\Policies\Microsoft\Windows NT\DNSClient"
LLMNR_VALUE = "EnableMulticast"
WSUS_KEY = r"Software\Policies\Microsoft\Windows\WindowsUpdate"
WSUS_SERVER = "WUServer"
WSUS_AU_KEY = rf"{WSUS_KEY}\AU"
WSUS_USE = "UseWUServer"
SCRIPT_BLOCK_KEY = r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
SCRIPT_BLOCK_VALUE = "EnableScriptBlockLogging"
MODULE_KEY = r"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
MODULE_VALUE = "EnableModuleLogging"
MODULE_NAMES_KEY = rf"{MODULE_KEY}\ModuleNames"
HARDENED_KEY = r"Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
SCHANNEL_KEY = r"System\CurrentControlSet\Control\SecurityProviders\Schannel"
CERT_MAPPING = "CertificateMappingMethods"
KDC_KEY = r"System\CurrentControlSet\Services\Kdc"
STRONG_MAPPING = "StrongCertificateBindingEnforcement"
DEFAULT_ENCTYPES = "DefaultDomainSupportedEncTypes"
MSV1_0_KEY = r"System\CurrentControlSet\Control\Lsa\MSV1_0"
BLOCK_NTLMV1_SSO = "BlockNtlmv1SSO"
WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
AUTO_LOGON = "AutoAdminLogon"
DEFAULT_PASSWORD = "DefaultPassword"
LOOPBACK_KEY = r"Software\Policies\Microsoft\Windows\System"
LOOPBACK_VALUE = "UserPolicyMode"  # 1 merge, 2 replace

# a hardened path for one of the two shares Group Policy itself is read from
_HARDENED_SHARE = re.compile(r"^\\\\[^\\]+\\(?:sysvol|netlogon)\\?$", re.IGNORECASE)
_SECRET_NAME = re.compile(r"password|passwd|pwd", re.IGNORECASE)
SECRET_NAME = _SECRET_NAME
_VARIABLE = re.compile(r"\s*%[^%]+%\s*")  # not a password: expanded on the client
_URL_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# what the notes say about such a value, and where redaction finds its location
SECRET_NOTE = ": holds a value named like a password: "


def norm(key: str) -> str:
    """A registry path for comparing: not case-sensitive, outer backslashes do not count."""
    return key.strip().strip("\\").casefold()


_VALUES = {
    norm(LLMNR_KEY): {LLMNR_VALUE.casefold()},
    norm(WSUS_KEY): {WSUS_SERVER.casefold()},
    norm(WSUS_AU_KEY): {WSUS_USE.casefold()},
    norm(SCRIPT_BLOCK_KEY): {SCRIPT_BLOCK_VALUE.casefold()},
    norm(MODULE_KEY): {MODULE_VALUE.casefold()},
    norm(SCHANNEL_KEY): {CERT_MAPPING.casefold()},
    norm(KDC_KEY): {STRONG_MAPPING.casefold(), DEFAULT_ENCTYPES.casefold()},
    norm(MSV1_0_KEY): {BLOCK_NTLMV1_SSO.casefold()},
    norm(LOOPBACK_KEY): {LOOPBACK_VALUE.casefold()},
}
_MODULE_NAMES = norm(MODULE_NAMES_KEY)
_HARDENED = norm(HARDENED_KEY)
_WINLOGON = norm(WINLOGON_KEY)
# every key the checks read values from, for a **DeleteKeys above one of them
_WATCHED_KEYS = (*_VALUES, _MODULE_NAMES, _HARDENED)


class MalformedPol(ValueError):
    pass


@dataclass
class Autologon:
    """What one file says about Winlogon: the facts only, never the password."""

    auto_on: bool = False  # AutoAdminLogon written as 1
    password: bool = False  # a literal DefaultPassword is in the file


@dataclass
class Parsed:
    entries: list[RegistryEntry] = field(default_factory=list)
    # (key, value name) of values named like a password that hold data
    secrets: list[tuple[str, str]] = field(default_factory=list)
    autologon: Autologon = field(default_factory=Autologon)


def note_winlogon(found: Autologon, key: str, name: str, data: object, applied: bool) -> None:
    """Records an AutoAdminLogon or DefaultPassword write; `data` itself is not kept. A
    password counts even when the write is switched off: it is still in the file."""
    if norm(key) != _WINLOGON:
        return
    if name.casefold() == AUTO_LOGON.casefold() and applied:
        found.auto_on = found.auto_on or str(data).strip() == "1"
    elif name.casefold() == DEFAULT_PASSWORD.casefold() and isinstance(data, str):
        found.password = found.password or bool(data.strip() and not _VARIABLE.fullmatch(data))


def watched(key: str, name: str) -> bool:
    k = norm(key)
    if k == _MODULE_NAMES:
        return True
    if k == _HARDENED:
        return bool(_HARDENED_SHARE.match(name.strip()))
    return name.casefold() in _VALUES.get(k, ())


def is_default_password(location: str) -> bool:
    """Whether 'key\\name' is Winlogon's own DefaultPassword, the same words in every domain."""
    key, _, name = location.rpartition("\\")
    return norm(key) == _WINLOGON and name.casefold() == DEFAULT_PASSWORD.casefold()


def _watched_key(key: str) -> bool:
    k = norm(key)
    return k in _VALUES or k in (_MODULE_NAMES, _HARDENED)


def deletes_watched(key: str) -> bool:
    """Whether deleting this key also deletes a key the checks read."""
    k = norm(key)
    return any(w == k or w.startswith(k + "\\") for w in _WATCHED_KEYS)


def bound(name: str) -> str:
    """A registry path or value name, which the bytes of a GPO can make any length."""
    if len(name) > MAX_NAME:
        raise MalformedPol(f"a registry name of {len(name)} characters")
    return name


def scrub_url(value: str) -> str:
    """A server URL without credentials: everything before the last @ goes, since a password
    can hold '/' or '@' itself, and losing part of a server name costs less than a password."""
    text = value.strip()
    scheme = _URL_SCHEME.match(text)
    head = scheme.group(0) if scheme else ""
    return head + text[len(head) :].rpartition("@")[2]


def kept_data(
    key: str, name: str, data: int | str | list[str] | None
) -> int | str | list[str] | None:
    """What the data of a watched value may leave the parser as, from either file format."""
    if norm(key) == _MODULE_NAMES:
        return ""  # the value name is the module; the data repeats it
    if name.casefold() == WSUS_SERVER.casefold():
        if isinstance(data, str):
            return scrub_url(data)
        if isinstance(data, list):
            return [scrub_url(item) for item in data]
    return data


def _string(data: bytes, pos: int) -> tuple[str, int]:
    """A null-terminated UTF-16LE string at pos, and the offset after its terminator."""
    end = pos
    while True:
        end = data.find(b"\0\0", end)
        if end < 0:
            raise MalformedPol(f"unterminated string at offset {pos}")
        if (end - pos) % 2 == 0:
            return data[pos:end].decode("utf-16-le", errors="replace"), end + 2
        end += 1


def _expect(data: bytes, pos: int, char: bytes) -> int:
    if data[pos : pos + 2] != char:
        raise MalformedPol(f"expected {char[:1].decode()} at offset {pos}")
    return pos + 2


def _text(payload: bytes) -> str:
    return payload.decode("utf-16-le", errors="replace").split("\0", 1)[0]


def _value_data(reg_type: int, payload: bytes) -> int | str | list[str] | None:
    """The data of a value in Python terms; None when it is binary or the wrong length."""
    if reg_type == REG_DWORD and len(payload) == 4:
        return int(struct.unpack("<I", payload)[0])
    if reg_type == REG_DWORD_BIG_ENDIAN and len(payload) == 4:
        return int(struct.unpack(">I", payload)[0])
    if reg_type == REG_QWORD and len(payload) == 8:
        return int(struct.unpack("<Q", payload)[0])
    if reg_type in (REG_SZ, REG_EXPAND_SZ):
        return _text(payload)[:MAX_TEXT]
    if reg_type == REG_MULTI_SZ:
        strings = payload.decode("utf-16-le", errors="replace").split("\0")
        return [s[:MAX_TEXT] for s in strings if s][:MAX_STRINGS]
    return None


def keep(out: Parsed, entry: RegistryEntry) -> None:
    if len(out.entries) >= MAX_KEPT:
        raise MalformedPol(f"more than {MAX_KEPT} entries for the settings read")
    out.entries.append(entry)


def _set_value(out: Parsed, key: str, name: str, action: str, kind: int, payload: bytes) -> None:
    if not (name and kind and payload):
        return  # only the key is created: a value an earlier GPO set stays as it is
    note_winlogon(out.autologon, key, name, _value_data(kind, payload), True)
    if not watched(key, name):
        if kind in _TEXT_TYPES and _SECRET_NAME.search(name) and _text(payload).strip():
            out.secrets.append((key[:256], name[:128]))
        return
    data = kept_data(key, name, _value_data(kind, payload))
    keep(out, RegistryEntry(key, name, action, kind, data))


def _targets(payload: bytes) -> list[str]:
    """The names a **DeleteValues or **DeleteKeys instruction lists."""
    return [bound(t) for t in (t.strip() for t in _text(payload).split(";")) if t]


def _instruction(out: Parsed, key: str, name: str, kind: int, payload: bytes) -> None:
    marker = name.strip().casefold()
    if not marker.startswith("**"):
        _set_value(out, key, name, "set", kind, payload)
    elif marker.startswith("**soft."):
        _set_value(out, key, name.strip()[len("**soft.") :], "soft", kind, payload)
    elif marker.startswith("**del."):
        target = name.strip()[len("**del.") :]
        if watched(key, target):
            keep(out, RegistryEntry(key, target, "delete"))
    elif marker.startswith("**delvals"):
        if _watched_key(key):
            keep(out, RegistryEntry(key, "", "delete_all"))
    elif marker == "**deletevalues":
        for target in _targets(payload):
            if watched(key, target):
                keep(out, RegistryEntry(key, target, "delete"))
    elif marker == "**deletekeys":
        # compared form, once each: a kept path is then no longer than the watched key it
        # is above, however the file spells it and however often it lists it
        base = key.rstrip("\\")
        for full in dict.fromkeys(norm(f"{base}\\{t}") for t in _targets(payload)):
            if deletes_watched(full):
                keep(out, RegistryEntry(full, "", "delete_key"))
    # **SecureKey changes a key's ACL and sets no value; other markers set nothing either


def _closes(data: bytes, pos: int) -> bool:
    return data[pos : pos + 2] == b"]\0"


def _number(data: bytes, pos: int, what: str) -> tuple[int, int]:
    if pos + 4 > len(data):
        raise MalformedPol(f"truncated {what}")
    return int(struct.unpack("<I", data[pos : pos + 4])[0]), pos + 4


def _record(data: bytes, pos: int) -> tuple[tuple[str, str, int, bytes] | None, int]:
    """The fields of the instruction after an opening bracket, and the offset after it. None
    for an instruction that stops before its data."""
    key, pos = _string(data, pos)
    bound(key)
    if _closes(data, pos):
        return None, pos + 2
    pos = _expect(data, pos, b";\0")
    name, pos = _string(data, pos)
    bound(name)
    if _closes(data, pos):
        return None, pos + 2
    pos = _expect(data, pos, b";\0")
    kind, pos = _number(data, pos, "type")
    if _closes(data, pos):
        return None, pos + 2
    pos = _expect(data, pos, b";\0")
    size, pos = _number(data, pos, "size")
    if _closes(data, pos):
        return None, pos + 2
    pos = _expect(data, pos, b";\0")
    if pos + size > len(data):
        raise MalformedPol("size runs past the end of the file")
    return (key, name, kind, data[pos : pos + size]), _expect(data, pos + size, b"]\0")


def parse(data: bytes) -> Parsed:
    """The instructions of one Registry.pol that the checks read, in file order."""
    if len(data) < _HEADER or data[:4] != SIGNATURE:
        raise MalformedPol("no PReg signature")
    if struct.unpack("<I", data[4:8])[0] != VERSION:
        raise MalformedPol("unknown version")
    out = Parsed()
    pos = _HEADER
    while pos < len(data):
        fields, pos = _record(data, _expect(data, pos, b"[\0"))
        if fields is not None:
            _instruction(out, *fields)
    return out
