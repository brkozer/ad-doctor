"""Advanced audit policy in a GPO: Machine\\Microsoft\\Windows NT\\Audit\\audit.csv ([MS-GPAC]).

A file is a CSV with a fixed header. The GUID of a row names the subcategory (its name is for
people and differs by language), and Setting Value says what to audit. A later GPO overrides
an earlier one per subcategory.

Windows ignores a file that does not conform as a whole, so a bad file raises `MalformedAudit`
and stays unknown. Only the subcategories the checks read are kept.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass

from .model import RegistryEntry

KEY = "audit"  # the `key` of every entry, so the registry precedence code can play them
SUCCESS = 1
FAILURE = 2
BOTH = SUCCESS | FAILURE
NOT_CHANGED = 0  # [MS-GPAC] "unchanged"; its own example pairs this value with "No Auditing"
NONE = 4
_MAX_SETTING = NONE
_HEADER = (
    "machine name",
    "policy target",
    "subcategory",
    "subcategory guid",
    "inclusion setting",
    "exclusion setting",
    "setting value",
)
_GUID = re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", re.I)


class MalformedAudit(ValueError):
    pass


@dataclass(frozen=True)
class Subcategory:
    guid: str  # lower case with braces
    name: str
    legacy: str  # the [Event Audit] category of GptTmpl.inf it belongs to
    wanted: int  # SUCCESS, FAILURE or BOTH


def _sub(suffix: str, name: str, legacy: str, wanted: int) -> Subcategory:
    return Subcategory(f"{{0cce92{suffix}-69ae-11d9-bed3-505054503030}}", name, legacy, wanted)


# The Baseline column for domain controllers of "System Audit Policy recommendations"
# (Microsoft Learn, Windows Server tab); GUIDs from [MS-GPAC] Subcategory and SubcategoryGUID
RECOMMENDED = (
    _sub("3f", "Credential Validation", "AuditAccountLogon", BOTH),
    _sub("36", "Computer Account Management", "AuditAccountManage", BOTH),
    _sub("3a", "Other Account Management Events", "AuditAccountManage", BOTH),
    _sub("37", "Security Group Management", "AuditAccountManage", BOTH),
    _sub("35", "User Account Management", "AuditAccountManage", BOTH),
    _sub("2b", "Process Creation", "AuditProcessTracking", SUCCESS),
    _sub("3b", "Directory Service Access", "AuditDSAccess", BOTH),
    _sub("3c", "Directory Service Changes", "AuditDSAccess", BOTH),
    _sub("16", "Logoff", "AuditLogonEvents", SUCCESS),
    _sub("15", "Logon", "AuditLogonEvents", BOTH),
    _sub("1b", "Special Logon", "AuditLogonEvents", SUCCESS),
    _sub("2f", "Audit Policy Change", "AuditPolicyChange", BOTH),
    _sub("30", "Authentication Policy Change", "AuditPolicyChange", SUCCESS),
    _sub("13", "IPsec Driver", "AuditSystemEvents", BOTH),
    _sub("10", "Security State Change", "AuditSystemEvents", BOTH),
    _sub("11", "Security System Extension", "AuditSystemEvents", BOTH),
    _sub("12", "System Integrity", "AuditSystemEvents", BOTH),
)
_WATCHED = {s.guid for s in RECOMMENDED}
LEGACY_CATEGORIES = {
    "auditaccountlogon": "AuditAccountLogon",
    "auditaccountmanage": "AuditAccountManage",
    "auditdsaccess": "AuditDSAccess",
    "auditlogonevents": "AuditLogonEvents",
    "auditobjectaccess": "AuditObjectAccess",
    "auditpolicychange": "AuditPolicyChange",
    "auditprivilegeuse": "AuditPrivilegeUse",
    "auditprocesstracking": "AuditProcessTracking",
    "auditsystemevents": "AuditSystemEvents",
}


def parse(text: str) -> list[RegistryEntry]:
    """The system audit settings of one audit.csv, for the subcategories the checks read."""
    if not text.strip():
        return []
    kept: dict[str, RegistryEntry] = {}
    try:
        reader = csv.reader(io.StringIO(text, newline=""))
        header = next(reader, [])
        if tuple(c.strip().lstrip("﻿").casefold() for c in header) != _HEADER:
            raise MalformedAudit("not the audit.csv header")
        for row in reader:
            if not row:
                continue
            if len(row) < len(_HEADER):
                raise MalformedAudit("a row has too few columns")
            guid = row[3].strip()
            if guid:  # option and global SACL rows have none
                _setting(kept, guid, row)
    except csv.Error as exc:
        raise MalformedAudit(str(exc)) from exc
    return list(kept.values())


def _setting(kept: dict[str, RegistryEntry], guid: str, row: list[str]) -> None:
    if not _GUID.fullmatch(guid):
        raise MalformedAudit("a subcategory GUID is malformed")
    target = row[1].strip().casefold()
    if (target and target != "system") or row[5].strip():
        return  # a per-user setting
    setting = row[6].strip()
    if not (setting.isascii() and setting.isdigit() and len(setting) <= 3):
        raise MalformedAudit("a setting value is not a number")
    value = int(setting)
    if value > _MAX_SETTING:
        raise MalformedAudit("a setting value is out of range")
    if guid.lower() in _WATCHED:
        kept[guid.lower()] = RegistryEntry(KEY, guid.lower(), "set", 4, value)
