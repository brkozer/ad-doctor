"""Directory snapshot and finding types shared by the collector and the checks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any


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

    def by_dn(self) -> dict[str, Account]:
        return {a.dn.lower(): a for a in self.accounts}

    def privileged_dns(self) -> set[str]:
        return {dn.lower() for members in self.privileged.values() for dn in members}

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
        )


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
