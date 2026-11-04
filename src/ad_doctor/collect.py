"""Read-only LDAP collector: one pass over the domain into a Snapshot."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPException, LDAPNoSuchObjectResult
from ldap3.protocol.microsoft import security_descriptor_control

from . import sd, sysvol
from .model import (
    Account,
    CertTemplate,
    DomainPolicy,
    Gpo,
    Snapshot,
    Trust,
    filetime_to_datetime,
)

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
PRE2K_SID = "S-1-5-32-554"
DACL_ONLY = security_descriptor_control(sdflags=0x04)  # readable without admin rights

# msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag bits
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
CT_FLAG_PEND_ALL_REQUESTS = 0x2
CT_FLAG_NO_SECURITY_EXTENSION = 0x80000

GPLINK = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.IGNORECASE)
GPLINK_DISABLED = 0x1

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
    "operatingSystem",
    "sIDHistory",
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
    sysvol: bool = True
    smb_port: int = 445
    # plain-LDAP port for the signing probe; 0 disables the probe
    plain_port: int = 389


def sid_to_str(raw: bytes) -> str:
    return sd.sid_from_bytes(raw)[0]


def _str(values: list[Any]) -> list[str]:
    return [v.decode() if isinstance(v, bytes) else str(v) for v in values]


def _int(entry: dict[str, list[Any]], attr: str, default: int = 0) -> int:
    values = entry.get(attr.lower())
    return int(_str(values)[0]) if values else default


def _first(entry: dict[str, list[Any]], attr: str, default: str = "") -> str:
    values = entry.get(attr.lower())
    return _str(values)[0] if values else default


class Collector:
    def __init__(self, conn: ldap3.Connection, target: Target | None = None) -> None:
        self.conn = conn
        self.target = target
        self.notes: list[str] = []
        self.ca_hosts: list[str] = []

    def search(
        self,
        base: str,
        flt: str,
        attrs: list[str],
        scope: str = ldap3.SUBTREE,
        controls: list[Any] | None = None,
    ) -> list[dict[str, list[Any]]]:
        """Paged search returning raw attribute values with lower-cased names."""
        entries = self.conn.extend.standard.paged_search(
            base,
            flt,
            search_scope=scope,
            attributes=attrs,
            controls=controls,
            paged_size=PAGE_SIZE,
            generator=True,
        )
        out = []
        for e in entries:
            if e.get("type") != "searchResEntry":
                continue
            raw = {k.lower(): list(v) for k, v in e["raw_attributes"].items()}
            raw["distinguishedname"] = [e["dn"]]
            out.append(raw)
        return out

    def optional(self, base: str, flt: str, attrs: list[str], **kw: Any) -> list[dict[str, Any]]:
        """A search whose base may not exist (no AD CS, no trusts container, ...)."""
        try:
            return self.search(base, flt, attrs, **kw)
        except LDAPNoSuchObjectResult:
            return []

    def snapshot(self) -> Snapshot:
        root = self.conn.server.info
        if root is None or not root.other.get("defaultNamingContext"):
            raise CollectError("rootDSE did not return defaultNamingContext")
        domain_dn = root.other["defaultNamingContext"][0]
        config_dn = root.other["configurationNamingContext"][0]
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
                "gPLink",
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
            privileged[name] = self._members(domain_dn, f"(objectSid={domain_sid}-{rid})")
        for name, sid in PRIVILEGED_BUILTIN.items():
            privileged[name] = self._members(domain_dn, f"(objectSid={sid})")
        protected = self._members(domain_dn, f"(objectSid={domain_sid}-{PROTECTED_USERS_RID})")
        dns_admins = self._members(domain_dn, "(&(objectClass=group)(sAMAccountName=DnsAdmins))")
        pre2k = self.search(domain_dn, f"(objectSid={PRE2K_SID})", ["member"])

        pks = f"CN=Public Key Services,CN=Services,{config_dn}"
        acls = {
            "domain": self._dacl(domain_dn),
            "AdminSDHolder": self._dacl(f"CN=AdminSDHolder,CN=System,{domain_dn}"),
        }
        templates, ca_dns = self._templates(pks)
        for key, dn in [
            ("PKI:NTAuthCertificates", f"CN=NTAuthCertificates,{pks}"),
            ("PKI:Certificate Templates", f"CN=Certificate Templates,{pks}"),
            ("PKI:Enrollment Services", f"CN=Enrollment Services,{pks}"),
            *((f"PKI:CA {name}", dn) for name, dn in ca_dns.items()),
        ]:
            aces = self._dacl(dn)
            if aces:
                acls[key] = aces
        gpos = self._gpos(domain_dn, _first(h, "gPLink"))

        trustees = {a.sid for aces in acls.values() for a in aces}
        trustees |= {a.sid for t in templates for a in t.aces}
        trustees |= {a.sid for g in gpos for a in g.aces}

        return Snapshot(
            domain=domain,
            domain_dn=domain_dn,
            domain_sid=domain_sid,
            collected_at=datetime.now(UTC),
            policy=policy,
            accounts=accounts,
            privileged={k: v for k, v in privileged.items() if v is not None},
            protected_users=protected or [],
            templates=templates,
            acls=acls,
            principals=self._resolve(domain_dn, trustees),
            gpp_passwords=self._sysvol(domain),
            trusts=self._trusts(domain_dn),
            gpos=gpos,
            oid_group_links=self._oid_links(pks),
            ca_hosts=self.ca_hosts,
            dns_admins=dns_admins or [],
            pre2k_members=_str(pre2k[0].get("member", [])) if pre2k else [],
            ds_heuristics=self._ds_heuristics(config_dn),
            recycle_bin=self._recycle_bin(config_dn),
            ldap_signing_required=self._probe_signing(),
            notes=self.notes,
        )

    def _dacl(self, dn: str) -> list[sd.Ace]:
        entry = self.optional(
            dn, "(objectClass=*)", ["nTSecurityDescriptor"], scope=ldap3.BASE, controls=DACL_ONLY
        )
        raw = entry[0].get("ntsecuritydescriptor") if entry else None
        return sd.parse_dacl(raw[0]) if raw else []

    def _templates(self, pks: str) -> tuple[list[CertTemplate], dict[str, str]]:
        services = self.optional(
            f"CN=Enrollment Services,{pks}",
            "(objectClass=pKIEnrollmentService)",
            ["name", "certificateTemplates", "dNSHostName"],
        )
        entries = self.optional(
            f"CN=Certificate Templates,{pks}",
            "(objectClass=pKICertificateTemplate)",
            [
                "name",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-RA-Signature",
                "msPKI-Template-Schema-Version",
                "msPKI-Certificate-Policy",
                "pKIExtendedKeyUsage",
                "msPKI-Certificate-Application-Policy",
                "nTSecurityDescriptor",
            ],
            controls=DACL_ONLY,
        )
        if not entries:
            self.notes.append("AD CS not installed")
            return [], {}
        if not services:
            self.notes.append("no enterprise CA found, so no template is published")
        ca_dns = {_first(s, "name"): s["distinguishedname"][0] for s in services}
        # the CA server's own computer account manages its enrollment service object
        self.ca_hosts = sorted(
            _first(s, "dNSHostName").split(".")[0].upper() + "$"
            for s in services
            if _first(s, "dNSHostName")
        )
        published = {n for svc in services for n in _str(svc.get("certificatetemplates", []))}
        templates = []
        for e in entries:
            name = _first(e, "name")
            # schema v2+ templates carry the authoritative list in the application policy
            ekus = _str(e.get("mspki-certificate-application-policy", []))
            ekus = ekus or _str(e.get("pkiextendedkeyusage", []))
            raw_sd = e.get("ntsecuritydescriptor")
            name_flag = _int(e, "msPKI-Certificate-Name-Flag")
            enroll_flag = _int(e, "msPKI-Enrollment-Flag")
            templates.append(
                CertTemplate(
                    name=name,
                    published=name in published,
                    enrollee_supplies_subject=bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
                    manager_approval=bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS),
                    authorized_signatures=_int(e, "msPKI-RA-Signature"),
                    ekus=ekus,
                    aces=sd.parse_dacl(raw_sd[0]) if raw_sd else [],
                    schema_version=_int(e, "msPKI-Template-Schema-Version", 1),
                    no_security_extension=bool(enroll_flag & CT_FLAG_NO_SECURITY_EXTENSION),
                    issuance_policies=_str(e.get("mspki-certificate-policy", [])),
                )
            )
        return sorted(templates, key=lambda t: t.name), ca_dns

    def _oid_links(self, pks: str) -> dict[str, str]:
        entries = self.optional(
            f"CN=OID,{pks}",
            "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
            ["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
        )
        return {
            _first(e, "msPKI-Cert-Template-OID"): _first(e, "msDS-OIDToGroupLink") for e in entries
        }

    def _gpos(self, domain_dn: str, domain_gplink: str) -> list[Gpo]:
        dc_ou = self.optional(
            f"OU=Domain Controllers,{domain_dn}", "(objectClass=*)", ["gPLink"], scope=ldap3.BASE
        )
        # lower-cased DN -> (DN as written, places it is linked)
        links: dict[str, tuple[str, list[str]]] = {}
        for where, gplink in [
            ("domain", domain_gplink),
            ("Domain Controllers OU", _first(dc_ou[0], "gPLink") if dc_ou else ""),
        ]:
            for dn, options in GPLINK.findall(gplink):
                if not int(options) & GPLINK_DISABLED:
                    links.setdefault(dn.lower(), (dn, []))[1].append(where)
        gpos = []
        for dn, places in sorted(links.values()):
            entry = self.optional(
                dn,
                "(objectClass=groupPolicyContainer)",
                ["displayName", "name", "nTSecurityDescriptor"],
                scope=ldap3.BASE,
                controls=DACL_ONLY,
            )
            if not entry:
                continue
            e = entry[0]
            raw_sd = e.get("ntsecuritydescriptor")
            gpos.append(
                Gpo(
                    name=_first(e, "displayName", dn),
                    guid=_first(e, "name"),
                    linked_to=places,
                    aces=sd.parse_dacl(raw_sd[0]) if raw_sd else [],
                )
            )
        return gpos

    def _trusts(self, domain_dn: str) -> list[Trust]:
        return [
            Trust(
                name=_first(e, "trustPartner"),
                direction=_int(e, "trustDirection"),
                trust_type=_int(e, "trustType"),
                attributes=_int(e, "trustAttributes"),
            )
            for e in self.optional(
                f"CN=System,{domain_dn}",
                "(objectClass=trustedDomain)",
                ["trustPartner", "trustDirection", "trustType", "trustAttributes"],
            )
        ]

    def _ds_heuristics(self, config_dn: str) -> str:
        entry = self.optional(
            f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}",
            "(objectClass=*)",
            ["dSHeuristics"],
            scope=ldap3.BASE,
        )
        return _first(entry[0], "dSHeuristics") if entry else ""

    def _recycle_bin(self, config_dn: str) -> bool | None:
        entry = self.optional(
            f"CN=Partitions,{config_dn}",
            "(objectClass=*)",
            ["msDS-EnabledFeature"],
            scope=ldap3.BASE,
        )
        if not entry:
            return None
        features = _str(entry[0].get("msds-enabledfeature", []))
        return any(f.lower().startswith("cn=recycle bin feature,") for f in features)

    def _resolve(self, domain_dn: str, sids: set[str]) -> dict[str, str]:
        names = {}
        for sid in sorted(sids):
            if not sid.startswith("S-1-5-21-"):
                continue  # well-known SIDs are named in model.py
            hit = self.search(domain_dn, f"(objectSid={sid})", ["sAMAccountName"])
            if hit:
                names[sid] = _first(hit[0], "sAMAccountName")
        return names

    def _members(self, domain_dn: str, group_filter: str) -> list[str] | None:
        group = self.search(domain_dn, group_filter, ["distinguishedName"])
        if not group:
            return None  # e.g. Enterprise Admins only exists in the forest root
        group_dn = ldap3.utils.conv.escape_filter_chars(group[0]["distinguishedname"][0])
        members = self.search(
            domain_dn, f"(&(objectClass=user)(memberOf:{IN_CHAIN}:={group_dn}))", ["sAMAccountName"]
        )
        return sorted(m["distinguishedname"][0] for m in members)

    def _sysvol(self, domain: str) -> list[Any]:
        t = self.target
        if t is None or not t.sysvol:
            return []
        if not t.user:
            self.notes.append("SYSVOL not checked: needs credentials")
            return []
        try:
            return sysvol.find_gpp_passwords(t.host, domain, t.user, t.password or "", t.smb_port)
        except sysvol.SysvolError as exc:
            self.notes.append(f"SYSVOL not checked: {exc}")
            return []

    def _probe_signing(self) -> bool | None:
        """Try an unsigned NTLM bind on plain LDAP; a DC that requires signing refuses it."""
        t = self.target
        if t is None or not t.plain_port or not t.user or "\\" not in t.user:
            return None
        server = ldap3.Server(t.host, port=t.plain_port, connect_timeout=10)
        conn = ldap3.Connection(server, user=t.user, password=t.password, authentication=ldap3.NTLM)
        try:
            if conn.bind():
                return False
            if conn.result.get("result") == 8:  # strongerAuthRequired
                return True
            self.notes.append(f"LDAP signing probe inconclusive: {conn.result.get('description')}")
            return None
        except LDAPException as exc:
            self.notes.append(f"LDAP signing probe failed: {exc}")
            return None
        finally:
            conn.unbind()

    @staticmethod
    def _account(e: dict[str, list[Any]]) -> Account:
        classes = {c.lower() for c in _str(e.get("objectclass", []))}
        return Account(
            dn=e["distinguishedname"][0],
            sam=_first(e, "sAMAccountName"),
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
            os=_first(e, "operatingSystem") or None,
            sid_history=[sid_to_str(s) for s in e.get("sidhistory", [])],
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
        return Collector(conn, target).snapshot()
    finally:
        conn.unbind()
