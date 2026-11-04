"""Directory snapshot and finding types shared by the collector and the checks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any

from .sd import Ace


class UAC(IntEnum):
    """userAccountControl bits the checks care about."""

    ACCOUNTDISABLE = 0x2
    PASSWD_NOTREQD = 0x20
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def filetime_to_datetime(value: int) -> datetime | None:
    """AD stores times as 100 ns ticks since 1601; 0 and the max value mean 'never'."""
    if value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=value // 10)


@dataclass
class Account:
    dn: str
    sam: str
    uac: int
    is_computer: bool = False
    spns: list[str] = field(default_factory=list)
    pwd_last_set: datetime | None = None
    last_logon: datetime | None = None
    admin_count: bool = False
    rbcd: bool = False
    allowed_to_delegate_to: list[str] = field(default_factory=list)
    laps: bool = False

    def has(self, flag: UAC) -> bool:
        return bool(self.uac & flag)

    @property
    def enabled(self) -> bool:
        return not self.has(UAC.ACCOUNTDISABLE)

    @property
    def is_dc(self) -> bool:
        return self.has(UAC.SERVER_TRUST_ACCOUNT)


@dataclass
class DomainPolicy:
    min_pwd_length: int
    pwd_complexity: bool
    lockout_threshold: int
    max_pwd_age_days: int | None
    machine_account_quota: int
    functional_level: int


@dataclass
class CertTemplate:
    name: str
    published: bool
    enrollee_supplies_subject: bool
    manager_approval: bool
    authorized_signatures: int
    # application policies (EKUs); empty means "any purpose"
    ekus: list[str]
    aces: list[Ace]


@dataclass
class GppPassword:
    path: str
    user: str


@dataclass
class Snapshot:
    domain: str
    domain_dn: str
    domain_sid: str
    collected_at: datetime
    policy: DomainPolicy
    accounts: list[Account]
    # privileged group name -> DNs of transitive members
    privileged: dict[str, list[str]]
    protected_users: list[str]
    templates: list[CertTemplate] = field(default_factory=list)
    # DACLs of security-critical objects ("domain", "AdminSDHolder")
    acls: dict[str, list[Ace]] = field(default_factory=dict)
    # SID -> account or group name, for the trustees that appear in acls/templates
    principals: dict[str, str] = field(default_factory=dict)
    gpp_passwords: list[GppPassword] = field(default_factory=list)
    # parts of the collection that could not run (no AD CS, SYSVOL unreachable, ...)
    notes: list[str] = field(default_factory=list)

    def by_dn(self) -> dict[str, Account]:
        return {a.dn.lower(): a for a in self.accounts}

    def privileged_dns(self) -> set[str]:
        return {dn.lower() for members in self.privileged.values() for dn in members}

    def name_of(self, sid: str) -> str:
        if sid in self.principals:
            return self.principals[sid]
        rid = sid.removeprefix(self.domain_sid + "-")
        return WELL_KNOWN_RIDS.get(rid, WELL_KNOWN_SIDS.get(sid, sid))

    def broad_sids(self) -> set[str]:
        """Groups every (or nearly every) account belongs to."""
        return BROAD_SIDS | {f"{self.domain_sid}-{rid}" for rid in BROAD_RIDS}

    def tier0_sids(self) -> set[str]:
        """Principals that are expected to hold control over the domain."""
        return TIER0_SIDS | {f"{self.domain_sid}-{rid}" for rid in TIER0_RIDS}

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        return _encode(data)  # type: ignore[no-any-return]

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Snapshot:
        accounts = [
            Account(
                **{
                    **a,
                    "pwd_last_set": _dt(a["pwd_last_set"]),
                    "last_logon": _dt(a["last_logon"]),
                }
            )
            for a in data["accounts"]
        ]
        collected = _dt(data["collected_at"])
        assert collected is not None
        return cls(
            domain=data["domain"],
            domain_dn=data["domain_dn"],
            domain_sid=data["domain_sid"],
            collected_at=collected,
            policy=DomainPolicy(**data["policy"]),
            accounts=accounts,
            privileged=data["privileged"],
            protected_users=data["protected_users"],
            templates=[
                CertTemplate(**{**t, "aces": [Ace(**a) for a in t["aces"]]})
                for t in data.get("templates", [])
            ],
            acls={k: [Ace(**a) for a in v] for k, v in data.get("acls", {}).items()},
            principals=data.get("principals", {}),
            gpp_passwords=[GppPassword(**g) for g in data.get("gpp_passwords", [])],
            notes=data.get("notes", []),
        )


WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
}
WELL_KNOWN_RIDS = {
    "498": "Enterprise Read-only Domain Controllers",
    "500": "Administrator",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "521": "Read-only Domain Controllers",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
}
BROAD_SIDS = {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"}
BROAD_RIDS = {"513", "514", "515"}
TIER0_SIDS = {"S-1-5-9", "S-1-5-18", "S-1-5-32-544"}
TIER0_RIDS = {"498", "500", "512", "516", "518", "519", "521"}


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    return value


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    detail: str
    remediation: str
    objects: list[str] = field(default_factory=list)
