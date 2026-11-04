"""Read-only LDAP collector: one pass over the domain into a Snapshot."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPException

from .model import Account, DomainPolicy, Snapshot, filetime_to_datetime

IN_CHAIN = "1.2.840.113556.1.4.1941"
PAGE_SIZE = 500

# Well-known tier-0 groups: domain-relative RIDs and builtin SIDs.
PRIVILEGED_RIDS = {"Domain Admins": 512, "Schema Admins": 518, "Enterprise Admins": 519}
PRIVILEGED_BUILTIN = {
    "Administrators": "S-1-5-32-544",
    "Account Operators": "S-1-5-32-548",
    "Server Operators": "S-1-5-32-549",
    "Print Operators": "S-1-5-32-550",
    "Backup Operators": "S-1-5-32-551",
}
PROTECTED_USERS_RID = 525

ACCOUNT_ATTRS = [
    "distinguishedName",
    "sAMAccountName",
    "objectClass",
    "userAccountControl",
    "servicePrincipalName",
    "pwdLastSet",
    "lastLogonTimestamp",
    "adminCount",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-AllowedToDelegateTo",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
]


class CollectError(Exception):
    pass


@dataclass
class Target:
    host: str
    port: int = 389
    user: str | None = None
    password: str | None = None
    use_ssl: bool = False


def sid_to_str(raw: bytes) -> str:
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack(f"<{count}I", raw[8 : 8 + 4 * count])
    return f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs)


def _str(values: list[Any]) -> list[str]:
    return [v.decode() if isinstance(v, bytes) else str(v) for v in values]


def _int(entry: dict[str, list[Any]], attr: str, default: int = 0) -> int:
    values = entry.get(attr.lower())
    return int(_str(values)[0]) if values else default


class Collector:
    def __init__(self, conn: ldap3.Connection) -> None:
        self.conn = conn

    def search(
        self, base: str, flt: str, attrs: list[str], scope: str = ldap3.SUBTREE
    ) -> list[dict[str, list[Any]]]:
        """Paged search returning raw attribute values with lower-cased names."""
        entries = self.conn.extend.standard.paged_search(
            base, flt, search_scope=scope, attributes=attrs, paged_size=PAGE_SIZE, generator=True
        )
        out = []
        for e in entries:
            if e.get("type") != "searchResEntry":
                continue
            raw = {k.lower(): list(v) for k, v in e["raw_attributes"].items()}
            raw["distinguishedname"] = [e["dn"]]
            out.append(raw)
        return out

    def snapshot(self) -> Snapshot:
        root = self.conn.server.info
        if root is None or not root.other.get("defaultNamingContext"):
            raise CollectError("rootDSE did not return defaultNamingContext")
        domain_dn = root.other["defaultNamingContext"][0]
        domain = ".".join(p.split("=", 1)[1] for p in domain_dn.split(","))

        head = self.search(
            domain_dn,
            "(objectClass=domain)",
            [
                "objectSid",
                "minPwdLength",
                "pwdProperties",
                "lockoutThreshold",
                "maxPwdAge",
                "ms-DS-MachineAccountQuota",
                "msDS-Behavior-Version",
            ],
            scope=ldap3.BASE,
        )
        if not head:
            raise CollectError(f"cannot read domain object {domain_dn}")
        h = head[0]
        domain_sid = sid_to_str(h["objectsid"][0])
        max_age = _int(h, "maxPwdAge")
        policy = DomainPolicy(
            min_pwd_length=_int(h, "minPwdLength"),
            pwd_complexity=bool(_int(h, "pwdProperties") & 1),
            lockout_threshold=_int(h, "lockoutThreshold"),
            # stored as a negative interval; the minimum int64 means "never"
            max_pwd_age_days=None if max_age in (0, -(2**63)) else abs(max_age) // (10**7 * 86400),
            machine_account_quota=_int(h, "ms-DS-MachineAccountQuota", 10),
            functional_level=_int(h, "msDS-Behavior-Version"),
        )

        accounts = [
            self._account(e)
            for e in self.search(
                domain_dn, "(&(objectCategory=person)(objectClass=user))", ACCOUNT_ATTRS
            )
            + self.search(domain_dn, "(objectClass=computer)", ACCOUNT_ATTRS)
        ]

        privileged = {}
        for name, rid in PRIVILEGED_RIDS.items():
            privileged[name] = self._members(domain_dn, f"{domain_sid}-{rid}")
        for name, sid in PRIVILEGED_BUILTIN.items():
            privileged[name] = self._members(domain_dn, sid)
        protected = self._members(domain_dn, f"{domain_sid}-{PROTECTED_USERS_RID}")

        return Snapshot(
            domain=domain,
            domain_dn=domain_dn,
            domain_sid=domain_sid,
            collected_at=datetime.now(UTC),
            policy=policy,
            accounts=accounts,
            privileged={k: v for k, v in privileged.items() if v is not None},
            protected_users=protected or [],
        )

    def _members(self, domain_dn: str, sid: str) -> list[str] | None:
        group = self.search(domain_dn, f"(objectSid={sid})", ["distinguishedName"])
        if not group:
            return None  # e.g. Enterprise Admins only exists in the forest root
        group_dn = ldap3.utils.conv.escape_filter_chars(group[0]["distinguishedname"][0])
        members = self.search(
            domain_dn, f"(&(objectClass=user)(memberOf:{IN_CHAIN}:={group_dn}))", ["sAMAccountName"]
        )
        return sorted(m["distinguishedname"][0] for m in members)

    @staticmethod
    def _account(e: dict[str, list[Any]]) -> Account:
        classes = {c.lower() for c in _str(e.get("objectclass", []))}
        return Account(
            dn=e["distinguishedname"][0],
            sam=_str(e.get("samaccountname", [""]))[0],
            uac=_int(e, "userAccountControl"),
            is_computer="computer" in classes,
            spns=_str(e.get("serviceprincipalname", [])),
            pwd_last_set=filetime_to_datetime(_int(e, "pwdLastSet")),
            last_logon=filetime_to_datetime(_int(e, "lastLogonTimestamp")),
            admin_count=_int(e, "adminCount") == 1,
            rbcd=bool(e.get("msds-allowedtoactonbehalfofotheridentity")),
            allowed_to_delegate_to=_str(e.get("msds-allowedtodelegateto", [])),
            laps=bool(
                e.get("ms-mcs-admpwdexpirationtime") or e.get("mslaps-passwordexpirationtime")
            ),
        )


def connect(target: Target) -> ldap3.Connection:
    server = ldap3.Server(
        target.host,
        port=target.port,
        use_ssl=target.use_ssl,
        get_info=ldap3.DSA,
        connect_timeout=10,
    )
    try:
        if target.user:
            conn = ldap3.Connection(
                server,
                user=target.user,
                password=target.password,
                authentication=ldap3.NTLM if "\\" in target.user else ldap3.SIMPLE,
                read_only=True,
                auto_bind=True,
                raise_exceptions=True,
            )
        else:
            conn = ldap3.Connection(server, read_only=True, auto_bind=True, raise_exceptions=True)
    except LDAPException as exc:
        raise CollectError(f"bind to {target.host}:{target.port} failed: {exc}") from exc
    return conn


def collect(target: Target) -> Snapshot:
    conn = connect(target)
    try:
        return Collector(conn).snapshot()
    finally:
        conn.unbind()
