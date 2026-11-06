"""Read-only LDAP collector: one pass over the domain into a Snapshot."""

from __future__ import annotations

import dataclasses
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import ldap3
from ldap3.core.exceptions import (
    LDAPException,
    LDAPInsufficientAccessRightsResult,
    LDAPNoSuchObjectResult,
    LDAPOperationResult,
)
from ldap3.protocol.microsoft import security_descriptor_control

from . import gpo_scope, probes, sd, sysvol
from .model import (
    TIER0_RIDS,
    UAC,
    Account,
    CaConfig,
    CertTemplate,
    DcProbe,
    DirObject,
    DomainPolicy,
    Gmsa,
    GpLink,
    Gpo,
    GpoLocalGroup,
    GpoSettings,
    Probes,
    Rodc,
    Snapshot,
    Trust,
    UnreadableMember,
    exchange_members,
    filetime_to_datetime,
    well_known_sid,
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
RODC_GROUP_RID = 521
REPL_METADATA = "msDS-ReplAttributeMetaData"
# direct reads of member values that no search returned; each one is a BASE search
MAX_MEMBER_READS = 500
NOT_RETURNED = "not returned: hidden, or this account has no right to see it"
NO_ATTRIBUTES = "returned without attributes: this account cannot read it"
SEARCH_MISSED = "readable by its DN but missing from the searches"
PRE2K_SID = "S-1-5-32-554"
DACL_ONLY = security_descriptor_control(sdflags=0x04)  # readable without admin rights
OWNER_AND_DACL = security_descriptor_control(sdflags=0x05)

# msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag bits
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
CT_FLAG_PEND_ALL_REQUESTS = 0x2
CT_FLAG_NO_SECURITY_EXTENSION = 0x80000

GPLINK = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.IGNORECASE)
GPLINK_DISABLED = 0x1
GPLINK_ENFORCED = 0x2
GPOPTIONS_BLOCK = 0x1
GPO_GUID = re.compile(r"\{[0-9A-Fa-f-]{36}\}")
# gPCMachineExtensionNames: [{CSE}{tool}...][{CSE}{tool}...]
CSE_GROUP = re.compile(r"\[(\{[0-9A-Fa-f-]{36}\})")
SECRET_TEXT = re.compile(
    r"\b(?:pass(?:word)?|passwd|pwd|parola|şifre|sifre|kennwort|contrase[ñn]a|mot de passe)"
    r"\s*[:=]\s*\S{3,}",
    re.IGNORECASE,
)
# Entra Connect (Azure AD Connect) names its sync account MSOL_<hex> and writes the server
# into the description; older DirSync/express installs use Sync_<server>_<hex>
SYNC_DESCRIPTION = re.compile(r"running on computer ([A-Za-z0-9._-]+)", re.IGNORECASE)
SYNC_SAM = re.compile(r"^(?:MSOL_[0-9a-f]{12}|Sync_(?P<host>.+)_[0-9a-f]{12})$", re.IGNORECASE)
PASSWORD_ATTRIBUTES = ("userPassword", "unixUserPassword", "msSFU30Password", "orclCommonAttribute")
LAPS_PASSWORD_ATTRIBUTES = ("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword")
DMSA_CLASS = "msds-delegatedmanagedserviceaccount"
# Microsoft Entra Kerberos writes this fixed object: a logical RODC with its own krbtgt
ENTRA_KERBEROS_DN = re.compile(r"^cn=azureadkerberos,ou=domain controllers,", re.IGNORECASE)
MANAGED_CLASSES = {
    "msds-groupmanagedserviceaccount",
    "msds-managedserviceaccount",
    DMSA_CLASS,
}

ACCOUNT_ATTRS = [
    "distinguishedName",
    "sAMAccountName",
    "objectClass",
    "objectSid",
    "userAccountControl",
    "primaryGroupID",
    "servicePrincipalName",
    "pwdLastSet",
    "lastLogonTimestamp",
    "logonCount",
    "whenCreated",
    "adminCount",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-AllowedToDelegateTo",
    "msDS-SupportedEncryptionTypes",
    "altSecurityIdentities",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
    "operatingSystem",
    "dNSHostName",
    "sIDHistory",
    "description",
    "info",
    "msDS-ManagedAccountPrecededByLink",
    "msDS-KrbTgtLink",
    "msDS-RevealOnDemandGroup",
    "msDS-NeverRevealGroup",
    *PASSWORD_ATTRIBUTES,
    *LAPS_PASSWORD_ATTRIBUTES,
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
    # web enrollment port for the ESC8 probe; 0 disables it
    http_port: int = 80
    # SMB posture and channel binding probes
    probes: bool = True
    kerberos: bool = False
    # probe every DC found in the directory, not only the one being scanned
    all_dcs: bool = True
    # read each CA's configuration over the winreg pipe (part of the probes)
    ca_registry: bool = True


def sid_to_str(raw: bytes) -> str:
    return sd.sid_from_bytes(raw)[0]


def _str(values: list[Any]) -> list[str]:
    return [v.decode(errors="replace") if isinstance(v, bytes) else str(v) for v in values]


def _int(entry: dict[str, list[Any]], attr: str, default: int = 0) -> int:
    values = entry.get(attr.lower())
    return int(_str(values)[0]) if values else default


def _first(entry: dict[str, list[Any]], attr: str, default: str = "") -> str:
    values = entry.get(attr.lower())
    return _str(values)[0] if values else default


def _generalized_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


class Collector:
    def __init__(self, conn: ldap3.Connection, target: Target | None = None) -> None:
        self.conn = conn
        self.target = target
        self.notes: list[str] = []
        self.ca_hosts: list[str] = []
        self.ca_dns_hosts: list[str] = []
        # CA host (lower-cased dNSHostName) -> enrollment service name
        self.ca_names: dict[str, str] = {}
        self.rodc_policies: list[tuple[Account, list[str], list[str]]] = []
        self.domain_dn = ""
        self.scanned_ldap_signing: bool | None = None
        self.dmsa_seen = False
        self.pwd_unread: list[str] = []

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
            raw: dict[str, list[Any]] = {}
            for k, v in e["raw_attributes"].items():
                key = k.lower()
                if ";range=" in key:  # ranged retrieval of a large multi-valued attribute
                    key = key.split(";", 1)[0]
                    self.notes.append(f"{e['dn']}: {key} has more values than one LDAP page")
                raw[key] = list(v)
            raw["distinguishedname"] = [e["dn"]]
            out.append(raw)
        return out

    def optional(self, base: str, flt: str, attrs: list[str], **kw: Any) -> list[dict[str, Any]]:
        """A search that may fail without failing the scan.

        A missing base (no AD CS, no trusts) is normal; any other refusal (time or size
        limit, access denied) is reported as a note and the part is skipped.
        """
        try:
            return self.search(base, flt, attrs, **kw)
        except LDAPNoSuchObjectResult:
            return []
        except LDAPOperationResult as exc:
            self.notes.append(f"search {flt} under {base} failed: {exc.description}")
            return []

    def snapshot(self) -> Snapshot:
        root = self.conn.server.info
        if root is None or not root.other.get("defaultNamingContext"):
            raise CollectError("rootDSE did not return defaultNamingContext")
        domain_dn = root.other["defaultNamingContext"][0]
        self.domain_dn = domain_dn
        config_dn = root.other["configurationNamingContext"][0]
        dc_dns_host = (root.other.get("dnsHostName") or [""])[0]
        root_dn = (root.other.get("rootDomainNamingContext") or [""])[0]
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
                "gPOptions",
                "msDS-ReplAttributeMetaData",
            ],
            scope=ldap3.BASE,
        )
        if not head:
            raise CollectError(f"cannot read domain object {domain_dn}")
        h = head[0]
        domain_sid = sid_to_str(h["objectsid"][0])
        root_sid = domain_sid
        if root_dn and root_dn.lower() != domain_dn.lower():
            forest_root = self.optional(root_dn, "(objectClass=*)", ["objectSid"], scope=ldap3.BASE)
            if forest_root and forest_root[0].get("objectsid"):
                root_sid = sid_to_str(forest_root[0]["objectsid"][0])
            else:
                self.notes.append("forest root SID not readable; root admins may be reported")
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

        registered = self._registered_dcs(config_dn)
        if registered is not None:
            mark_rogue_dcs(accounts, registered)

        privileged = {}
        for name, rid in PRIVILEGED_RIDS.items():
            privileged[name] = self._members(domain_dn, f"(objectSid={domain_sid}-{rid})")
        for name, sid in PRIVILEGED_BUILTIN.items():
            privileged[name] = self._members(domain_dn, f"(objectSid={sid})")
        # primaryGroupID membership never shows in member/memberOf; add it back so a
        # hidden admin is treated as an admin everywhere (AD-PRIV-007 still reports it)
        for name, rid in PRIVILEGED_RIDS.items():
            hidden = {a.dn for a in accounts if not a.is_computer and a.primary_group == rid}
            for group in (name, "Administrators"):  # these groups nest into Administrators
                if hidden and privileged.get(group) is not None:
                    privileged[group] = sorted(set(privileged[group] or []) | hidden)
        # a user whose primary group is a DC group is a DC as far as rights go
        fake_dcs = sorted(
            a.dn for a in accounts if not a.is_computer and a.primary_group in (498, 516, 521)
        )
        if fake_dcs:
            privileged["Domain Controllers"] = fake_dcs
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

        priv_dns = {dn.lower() for members in privileged.values() if members for dn in members}
        # accounts that hold DCSync are tier 0 in practice (Entra Connect, backup tools)
        domain_aces = acls["domain"]
        get = {a.sid for a in domain_aces if a.extended_right(sd.DS_REPL_GET_CHANGES)}
        get_all = {a.sid for a in domain_aces if a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)}
        priv_dns |= {a.dn.lower() for a in accounts if a.sid and a.sid in get & get_all}
        objects = self._objects(domain_dn, accounts, priv_dns)
        unreadable = self._unreadable_members(domain_dn, config_dn, domain_sid, accounts, objects)
        gpos = self._gpos(domain_dn, config_dn, h, objects)
        dc_sites, site_count = self._dc_sites(config_dn)
        ca_configs = self._ca_configs(dc_dns_host)

        trustees = {a.sid for aces in acls.values() for a in aces}
        trustees |= {a.sid for t in templates for a in t.aces}
        trustees |= {a.sid for g in gpos for a in g.aces}
        trustees |= {a.sid for o in objects for a in o.aces} | {o.owner for o in objects if o.owner}
        gmsas = self._gmsas(domain_dn)
        trustees |= {s for g in gmsas for s in g.readers}
        trustees |= {a.sid for c in ca_configs for a in c.aces}
        trustees |= {c.owner for c in ca_configs if c.owner}

        sysvol_result = self._sysvol(domain, [g.guid for g in gpos])
        local_groups, gpo_settings = self._resolve_local_groups(
            sysvol_result.local_groups, sysvol_result.gpo_settings, domain_dn, config_dn, domain
        )
        trustees |= {x.member_sid for x in local_groups if x.member_sid.startswith("S-1-5-21-")}
        trustees |= {x.group_sid for x in local_groups if x.group_sid.startswith("S-1-5-21-")}
        trustees |= _channel_trustees(gpo_settings, domain_sid, root_sid)
        # one value per attribute; dSASignature changes on every backup
        metadata = "".join(_str(h.get("msds-replattributemetadata", [])))
        snap = Snapshot(
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
            principals=self._resolve(domain_dn, trustees, objects),
            gpp_passwords=sysvol_result.gpp_passwords,
            trusts=self._trusts(domain_dn),
            gpos=gpos,
            oid_group_links=self._oid_links(pks),
            ca_hosts=self.ca_hosts,
            root_sid=root_sid,
            dns_admins=dns_admins or [],
            pre2k_members=_str(pre2k[0].get("member", [])) if pre2k else [],
            ds_heuristics=self._ds_heuristics(config_dn),
            recycle_bin=self._recycle_bin(config_dn),
            ldap_signing_required=None,  # set from the scanned DC's probe below
            probes=self._probes(dc_dns_host, accounts),
            objects=objects,
            gpo_settings=gpo_settings,
            script_secrets=sysvol_result.script_secrets,
            gmsas=gmsas,
            rodcs=[Rodc(a.sam, a_reveal, a_never) for a, a_reveal, a_never in self.rodc_policies],
            last_backup=_last_backup(metadata),
            backup_checked="dSASignature" in metadata,
            psos_visible=self._psos_visible(domain_dn),
            dmsa_visible=self.dmsa_seen,
            gpo_local_groups=local_groups,
            local_groups_collected=sysvol_result.scanned,
            ntlm_policy_collected=sysvol_result.scanned,
            dc_registration_checked=registered is not None,
            channel_policy_collected=sysvol_result.scanned,
            aes_cutover=self._aes_cutover(domain_dn, domain_sid),
            pwd_metadata_checked=True,
            unreadable_members=unreadable or [],
            tier0_members_checked=unreadable is not None,
            dc_sites=dc_sites,
            site_count=site_count,
            notes=self.notes,
        )
        snap.ldap_signing_required = self.scanned_ldap_signing
        snap.probes.ca_configs = ca_configs
        snap.notes += gpo_scope.resolve(snap).notes
        snap.notes += _channel_notes(snap)
        if self.pwd_unread:
            shown = ", ".join(sorted(self.pwd_unread)[:5])
            more = len(self.pwd_unread) - 5
            snap.notes.append(
                f"replication metadata of unicodePwd not readable for {shown}"
                + (f" (+{more} more)" if more > 0 else "")
                + ": AD-ACC-012 not judged for them, and their age checks trust pwdLastSet"
            )
        if snap.has_2025 and not snap.dmsa_visible:
            snap.notes.append(
                "no dMSA visible (none exist, or this account cannot read them; by default "
                "ordinary users cannot): AD-INF-007 did not check existing dMSA links"
            )
        return snap

    # --- DACLs and objects -----------------------------------------------------------

    def _dacl(self, dn: str) -> list[sd.Ace]:
        entry = self.optional(
            dn, "(objectClass=*)", ["nTSecurityDescriptor"], scope=ldap3.BASE, controls=DACL_ONLY
        )
        raw = entry[0].get("ntsecuritydescriptor") if entry else None
        return sd.parse_dacl(raw[0]) if raw else []

    def _object(self, e: dict[str, Any], kind: str) -> DirObject:
        raw_sd = e.get("ntsecuritydescriptor")
        desc = sd.parse(raw_sd[0]) if raw_sd else sd.Descriptor(None, False, [])
        sid = sid_to_str(e["objectsid"][0]) if e.get("objectsid") else ""
        return DirObject(
            dn=e["distinguishedname"][0],
            name=_first(e, "sAMAccountName") or _first(e, "name") or e["distinguishedname"][0],
            kind=kind,
            sid=sid,
            owner=desc.owner,
            aces=desc.aces,
            dacl_protected=desc.dacl_protected,
            members=_str(e.get("member", [])),
            inheritable=desc.inheritable if kind in ("ou", "container", "domain") else [],
        )

    def _objects(
        self, domain_dn: str, accounts: list[Account], priv_dns: set[str]
    ) -> list[DirObject]:
        """Groups, OUs, the domain head and every tier-0 account, with owner and DACL."""
        attrs = ["sAMAccountName", "name", "objectSid", "member", "nTSecurityDescriptor"]
        objects = [
            self._object(e, "group")
            for e in self.search(domain_dn, "(objectClass=group)", attrs, controls=OWNER_AND_DACL)
        ]
        objects += [
            self._object(e, "ou")
            for e in self.search(
                domain_dn, "(objectClass=organizationalUnit)", attrs, controls=OWNER_AND_DACL
            )
        ]
        # top-level containers (CN=Users, CN=Computers, Managed Service Accounts, ...)
        objects += [
            self._object(e, "container")
            for e in self.optional(
                domain_dn, "(objectClass=container)", attrs, scope=ldap3.LEVEL,
                controls=OWNER_AND_DACL,
            )
        ]  # fmt: skip
        holder = f"CN=AdminSDHolder,CN=System,{domain_dn}"
        for dn, kind in [(domain_dn, "domain"), (holder, "container")]:
            objects += [self._object(e, kind) for e in self._base(dn, attrs)]
        # Entra Connect sync accounts and their servers, and Exchange servers: whoever
        # controls them controls what they hold over the domain
        sync_hosts = {a.sync_host.lower() for a in accounts if a.sync_host}
        exchange = exchange_members(objects)
        sensitive = [
            a
            for a in accounts
            if a.dn.lower() in priv_dns
            or a.is_dc
            or a.sam.lower() == "krbtgt"
            or a.rid == 500
            or a.sync_host
            or (a.is_computer and a.sam.lower().rstrip("$") in sync_hosts)
            or a.dn.lower() in exchange
        ]
        for a in sensitive:
            kind = "computer" if a.is_computer else "user"
            # the attribute is constructed, so it only comes back from a BASE read: this
            # read happens anyway, which keeps the cost to tier 0 and to no extra search
            tier0 = a.dn.lower() in priv_dns or a.is_dc or a.sam.lower() == "krbtgt" or a.rid == 500
            entries = self._base(a.dn, [*attrs, REPL_METADATA] if tier0 else attrs)
            objects += [self._object(e, kind) for e in entries]
            if tier0:
                a.pwd_changed = _pwd_changed(entries)
                if a.pwd_changed is None:
                    self.pwd_unread.append(a.sam)
        return objects

    def _unreadable_members(
        self,
        domain_dn: str,
        config_dn: str,
        domain_sid: str,
        accounts: list[Account],
        objects: list[DirObject],
    ) -> list[UnreadableMember] | None:
        """Member values of tier-0 groups, nesting included, that no search returned.

        Skipped, because a search of this domain cannot return them: foreign security
        principals, and DNs in other naming contexts. Values that turn out to be readable
        objects of another class (a contact) are not reported. None when it cannot be told.
        """
        groups = {o.dn.lower(): o for o in objects if o.kind == "group"}
        seeds = {f"{domain_sid}-{rid}" for rid in PRIVILEGED_RIDS.values()}
        seeds |= {f"{domain_sid}-{rid}" for rid in TIER0_RIDS} | set(PRIVILEGED_BUILTIN.values())
        todo = [g for g in groups.values() if g.sid in seeds]
        if not {g.sid for g in todo} >= {f"{domain_sid}-512", "S-1-5-32-544"}:
            self.notes.append(
                "Domain Admins or Administrators not readable: AD-PRIV-012 not judged"
            )
            return None
        for g in todo:
            if g.sid in (f"{domain_sid}-512", "S-1-5-32-544") and not g.members:
                self.notes.append(
                    f"{g.name}: member attribute empty or unreadable, so AD-PRIV-012 cannot "
                    "see hidden members there"
                )
        seen = {g.dn.lower() for g in todo}
        known = {a.dn.lower() for a in accounts} | {o.dn.lower() for o in objects}
        missing: dict[str, tuple[str, str]] = {}
        while todo:
            group = todo.pop()
            for member in group.members:
                key = member.lower()
                if key in groups and key not in seen:
                    seen.add(key)
                    todo.append(groups[key])
                elif key not in known:
                    missing.setdefault(key, (member, group.name))
        fsp = f",cn=foreignsecurityprincipals,{domain_dn.lower()}"
        head = "," + domain_dn.lower()
        missing = {k: v for k, v in missing.items() if k.endswith(head) and not k.endswith(fsp)}
        if not missing:
            return []
        contexts = self._other_contexts(domain_dn, config_dn)
        if contexts is None:
            return None
        missing = {
            k: v for k, v in missing.items() if not any(k.endswith("," + c) for c in contexts)
        }
        if len(missing) > MAX_MEMBER_READS:
            self.notes.append(
                f"{len(missing)} members of tier-0 groups did not come back from the searches; "
                f"AD-PRIV-012 read only the first {MAX_MEMBER_READS}"
            )
        sids = {a.sid for a in accounts} | {o.sid for o in objects}
        out = []
        failed: Counter[tuple[str, str]] = Counter()
        for key in sorted(missing)[:MAX_MEMBER_READS]:
            dn, group_name = missing[key]
            try:
                reason = self._member_problem(dn, sids)
            except LDAPOperationResult as exc:
                failed[group_name, str(exc.description)] += 1
                continue
            if reason:
                out.append(UnreadableMember(dn, group_name, reason))
        # counts only: a DN here would survive redaction, unlike one in unreadable_members
        for (group_name, why), count in sorted(failed.items()):
            self.notes.append(
                f"{count} member value(s) of {group_name} not judged by AD-PRIV-012: {why}"
            )
        return out

    def _other_contexts(self, domain_dn: str, config_dn: str) -> list[str] | None:
        """Lower-cased naming contexts below this domain (child domains, DNS partitions);
        a DN in them is out of this scan's reach. None when the crossRefs were not readable,
        because reading such a DN here could follow a referral to another host."""
        entries = self.optional(
            f"CN=Partitions,{config_dn}", "(objectClass=crossRef)", ["nCName"], scope=ldap3.LEVEL
        )
        names = [_first(e, "nCName").lower() for e in entries]
        if domain_dn.lower() not in names:
            self.notes.append("naming contexts not readable: AD-PRIV-012 not judged")
            return None
        return [n for n in names if n != domain_dn.lower()]

    def _member_problem(self, dn: str, sids: set[str]) -> str | None:
        """Why a member value is a blind spot; None when it is a readable object that the
        searches had no reason to return."""
        try:
            hit = self.search(dn, "(objectClass=*)", ["objectClass", "objectSid"], ldap3.BASE)
        except (LDAPNoSuchObjectResult, LDAPInsufficientAccessRightsResult):
            return NOT_RETURNED
        if not hit:
            return NOT_RETURNED
        classes = {c.lower() for c in _str(hit[0].get("objectclass", []))}
        if not classes:
            return NO_ATTRIBUTES
        raw_sid = hit[0].get("objectsid")
        if raw_sid and sid_to_str(raw_sid[0]) in sids:
            return None  # same object under another spelling of its DN
        return SEARCH_MISSED if classes & {"user", "computer", "group"} else None

    def _aes_cutover(self, domain_dn: str, domain_sid: str) -> datetime | None:
        """The first Server 2008 DC created Read-only Domain Controllers; passwords from
        before it were never turned into AES keys. A proxy, used by PingCastle as well."""
        hit = self.optional(
            domain_dn, f"(objectSid={domain_sid}-{RODC_GROUP_RID})", ["whenCreated"]
        )
        created = _generalized_time(_first(hit[0], "whenCreated")) if hit else None
        if created is None:
            self.notes.append(
                "Read-only Domain Controllers group not readable: AD-KRB-005 did not look for "
                "passwords older than AES support"
            )
        return created

    def _base(self, dn: str, attrs: list[str]) -> list[dict[str, Any]]:
        """One object with its owner and DACL."""
        return self.optional(
            dn, "(objectClass=*)", attrs, scope=ldap3.BASE, controls=OWNER_AND_DACL
        )

    def _gpos(
        self, domain_dn: str, config_dn: str, head: dict[str, Any], objects: list[DirObject]
    ) -> list[Gpo]:
        dc_ou_dn = f"OU=Domain Controllers,{domain_dn}"
        dc_ou = self.optional(dc_ou_dn, "(objectClass=*)", ["gPLink"], scope=ldap3.BASE)
        # (container DN, kind, gPLink, gPOptions); the domain head and the DC OU first, as
        # read before, then every other OU and the sites
        containers: dict[str, tuple[str, str, str, int]] = {
            domain_dn.lower(): (
                domain_dn,
                "domain",
                _first(head, "gPLink"),
                _int(head, "gPOptions"),
            )
        }
        if dc_ou:
            containers[dc_ou_dn.lower()] = (dc_ou_dn, "ou", _first(dc_ou[0], "gPLink"), 0)
        for e in self.optional(
            domain_dn, "(|(gPLink=*)(gPOptions=*))", ["gPLink", "gPOptions", "objectClass"]
        ):
            dn = e["distinguishedname"][0]
            classes = {c.lower() for c in _str(e.get("objectclass", []))}
            kind = "domain" if "domaindns" in classes else "ou"
            containers[dn.lower()] = (dn, kind, _first(e, "gPLink"), _int(e, "gPOptions"))
        for e in self.optional(f"CN=Sites,{config_dn}", "(objectClass=site)", ["gPLink"]):
            dn = e["distinguishedname"][0]
            containers[dn.lower()] = (dn, "site", _first(e, "gPLink"), 0)

        by_dn = {o.dn.lower(): o for o in objects}
        links: dict[str, list[GpLink]] = {}
        policies = f"cn=policies,cn=system,{domain_dn}".lower()
        for key, (dn, kind, gplink, options) in containers.items():
            if options & GPOPTIONS_BLOCK and key in by_dn:
                by_dn[key].gp_blocked = True
            for gpo_dn, link in parse_gplink(dn, kind, gplink):
                if not gpo_dn.lower().endswith("," + policies):
                    self.notes.append(f"GPO from another domain linked at {dn}: not evaluated")
                    continue
                links.setdefault(gpo_dn.lower(), []).append(link)

        gpos = []
        for e in self.optional(
            f"CN=Policies,CN=System,{domain_dn}",
            "(objectClass=groupPolicyContainer)",
            [
                "displayName",
                "name",
                "nTSecurityDescriptor",
                "flags",
                "versionNumber",
                "gPCMachineExtensionNames",
                "gPCWQLFilter",
            ],
            scope=ldap3.LEVEL,
            controls=OWNER_AND_DACL,
        ):
            dn = e["distinguishedname"][0]
            raw_sd = e.get("ntsecuritydescriptor")
            desc = sd.parse(raw_sd[0]) if raw_sd else sd.Descriptor(None, False, [])
            gpo_links = links.pop(dn.lower(), [])
            readable = bool(e.get("versionnumber"))
            # where the GPO reaches DCs: enabled links on the domain head and the DC OU
            linked_to = [
                where
                for container, where in ((domain_dn, "domain"), (dc_ou_dn, "Domain Controllers OU"))
                for link in gpo_links
                if link.enabled and link.container.lower() == container.lower()
            ]
            gpo = Gpo(
                name=_first(e, "displayName", dn),
                guid=_first(e, "name"),
                linked_to=linked_to,
                aces=desc.aces,
                links=gpo_links,
                flags=_int(e, "flags"),
                # without versionNumber the GPC attributes were not readable: unknown
                machine_version=_int(e, "versionNumber") & 0xFFFF if readable else None,
                machine_extensions=(
                    machine_extensions(_first(e, "gPCMachineExtensionNames")) if readable else None
                ),
                wmi_filter=self._wmi_filter(domain_dn, _first(e, "gPCWQLFilter")),
            )
            gpos.append(gpo)
            objects.append(DirObject(dn, gpo.name, "gpo", owner=desc.owner, aces=desc.aces))
        for gpo_dn, dangling in sorted(links.items()):
            where = ", ".join(sorted({link.container for link in dangling}))
            self.notes.append(f"dangling gPLink at {where}: {gpo_dn} does not exist")
        return sorted(gpos, key=lambda g: g.name.lower())

    def _wmi_filter(self, domain_dn: str, value: str) -> str | None:
        """Name of the WMI filter in gPCWQLFilter ('[domain;{GUID};0]'), else its GUID."""
        m = GPO_GUID.search(value)
        if not m:
            return None
        hit = self.optional(
            f"CN={m.group(0)},CN=SOM,CN=WMIPolicy,CN=System,{domain_dn}",
            "(objectClass=*)",
            ["msWMI-Name"],
            scope=ldap3.BASE,
        )
        return (_first(hit[0], "msWMI-Name") if hit else "") or m.group(0)

    def _dc_sites(self, config_dn: str) -> tuple[dict[str, str], int]:
        """DC computer DN (lower case) -> its site's DN, and the number of sites."""
        sites = f"CN=Sites,{config_dn}"
        dc_sites = {}
        for e in self.optional(sites, "(objectClass=server)", ["serverReference"]):
            ref = _first(e, "serverReference")
            if ref:
                # CN=<server>,CN=Servers,CN=<site>,CN=Sites,...
                dc_sites[ref.lower()] = _parent(e["distinguishedname"][0], 2)
        count = len(self.optional(sites, "(objectClass=site)", ["name"], scope=ldap3.LEVEL))
        return dc_sites, count

    def _registered_dcs(self, config_dn: str) -> set[str] | None:
        """Lower-cased DNs of the computers that have a server object with an nTDSDSA
        child (read-only DCs included); None when the set cannot be trusted. A server whose
        nTDSDSA did not come back counts as registered: it may only be hidden."""
        entries = self.optional(
            f"CN=Sites,{config_dn}",
            "(|(objectClass=server)(objectClass=nTDSDSA))",
            ["objectClass", "serverReference"],
        )
        servers = {
            e["distinguishedname"][0].lower(): _first(e, "serverReference").lower() for e in entries
        }
        dsas = [
            servers.get(_parent(e["distinguishedname"][0]).lower(), "")
            for e in entries
            if "ntdsdsa" in {c.lower() for c in _str(e.get("objectclass", []))}
        ]
        registered = set(dsas) - {""}
        if not registered:
            self.notes.append("no nTDSDSA object readable: AD-INF-014 (rogue DCs) not judged")
            return None
        if "" in dsas:
            self.notes.append(
                f"{dsas.count('')} nTDSDSA object(s) without a readable serverReference: "
                "AD-INF-014 (rogue DCs) not judged"
            )
            return None
        hidden = set(servers.values()) - registered - {""}
        if hidden:
            self.notes.append(
                f"{len(hidden)} server object(s) without a visible nTDSDSA: AD-INF-014 (rogue "
                "DCs) not judged for those computers"
            )
        return registered | hidden

    def _resolve_local_groups(
        self,
        entries: list[GpoLocalGroup],
        settings: dict[str, GpoSettings],
        domain_dn: str,
        config_dn: str,
        domain: str,
    ) -> tuple[list[GpoLocalGroup], dict[str, GpoSettings]]:
        """Fill in the SIDs of principals the files name instead of giving a SID: in local
        group entries, and among the holders of the remote logon right, which decides
        whether Remote Desktop Users membership counts."""

        def named(holder: str) -> bool:
            return not holder.upper().startswith("S-1-") and not well_known_sid(holder)

        right = gpo_scope.REMOTE_LOGON_RIGHT
        if not any(
            (x.member_name and not x.member_sid) or (x.group_name and not x.group_sid)
            for x in entries
        ) and not any(named(h) for s in settings.values() for h in s.privileges.get(right, [])):
            return entries, settings
        crossref = self.optional(
            f"CN=Partitions,{config_dn}",
            f"(&(objectClass=crossRef)(nCName={ldap3.utils.conv.escape_filter_chars(domain_dn)}))",
            ["nETBIOSName"],
        )
        netbios = (_first(crossref[0], "nETBIOSName") if crossref else "") or domain.split(".")[0]
        cache: dict[str, str] = {}
        unresolved: list[str] = []

        def resolve(name: str) -> str:
            if name not in cache:
                cache[name] = self._principal_sid(name, domain_dn, domain, netbios)
                if not cache[name]:
                    unresolved.append(name)
            return cache[name]

        out = []
        for x in entries:
            group_sid = x.group_sid or (resolve(x.group_name) if x.group_name else "")
            member_sid = x.member_sid or (resolve(x.member_name) if x.member_name else "")
            out.append(dataclasses.replace(x, group_sid=group_sid, member_sid=member_sid))
        resolved_settings = {}
        for guid, s in settings.items():
            holders = s.privileges.get(right)
            if holders and any(named(h) for h in holders):
                # an unresolved name stays as written; gpo_scope then gives it the benefit
                # of the doubt rather than dropping the grant
                holders = [(resolve(h) or h) if named(h) else h for h in holders]
                s = dataclasses.replace(s, privileges={**s.privileges, right: holders})
            resolved_settings[guid] = s
        if unresolved:
            self.notes.append(
                "GPO group-membership or remote logon settings name principals that could "
                f"not be resolved: {', '.join(unresolved[:5])}"
                + (f" (+{len(unresolved) - 5} more)" if len(unresolved) > 5 else "")
            )
        return out, resolved_settings

    def _principal_sid(self, name: str, domain_dn: str, domain: str, netbios: str) -> str:
        """SID of a principal named in a local group setting; "" if unknown or foreign."""
        name = name.strip()
        if name.lower().startswith("%domainname%\\"):
            name = netbios + name[len("%domainname%") :]
        if "%" in name:
            return ""  # other GPP variables (%ComputerName%, %LogonUser%...) vary per host
        sid = well_known_sid(name)
        if sid:
            return sid
        prefix, sep, sam = name.rpartition("\\")
        if sep and prefix.lower() not in (netbios.lower(), domain.lower()):
            return ""  # another domain: its principals are not in this snapshot
        for candidate in (sam, f"{sam}$"):
            hit = self.optional(
                domain_dn,
                f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(candidate)})",
                ["objectSid"],
            )
            if hit and hit[0].get("objectsid"):
                return sid_to_str(hit[0]["objectsid"][0])
        return ""

    def _gmsas(self, domain_dn: str) -> list[Gmsa]:
        out = []
        for e in self.search(
            domain_dn,
            "(objectClass=msDS-GroupManagedServiceAccount)",
            ["sAMAccountName", "msDS-GroupMSAMembership"],
        ):
            raw = e.get("msds-groupmsamembership")
            readers = sorted({a.sid for a in sd.parse_dacl(raw[0])}) if raw else []
            out.append(Gmsa(_first(e, "sAMAccountName"), e["distinguishedname"][0], readers))
        return out

    # --- AD CS -----------------------------------------------------------------------

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
                "msPKI-Minimal-Key-Size",
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
        self.ca_dns_hosts = sorted({_first(s, "dNSHostName") for s in services} - {""})
        self.ca_names = {
            _first(s, "dNSHostName").lower(): _first(s, "name")
            for s in services
            if _first(s, "dNSHostName")
        }
        # the CA server's own computer account manages its enrollment service object
        self.ca_hosts = sorted(self._computer_name(h) for h in self.ca_dns_hosts)
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
                    min_key_size=_int(e, "msPKI-Minimal-Key-Size"),
                )
            )
        return sorted(templates, key=lambda t: t.name), ca_dns

    def _computer_name(self, dns_host: str) -> str:
        """sAMAccountName of a host (NetBIOS names are cut at 15 characters)."""
        hit = self.optional(
            self.domain_dn,
            f"(&(objectClass=computer)(dNSHostName={ldap3.utils.conv.escape_filter_chars(dns_host)}))",
            ["sAMAccountName"],
        )
        found = _first(hit[0], "sAMAccountName") if hit else ""
        return (found or dns_host.split(".")[0][:15] + "$").upper()

    def _oid_links(self, pks: str) -> dict[str, str]:
        entries = self.optional(
            f"CN=OID,{pks}",
            "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
            ["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
        )
        return {
            _first(e, "msPKI-Cert-Template-OID"): _first(e, "msDS-OIDToGroupLink") for e in entries
        }

    # --- domain-wide settings --------------------------------------------------------

    def _trusts(self, domain_dn: str) -> list[Trust]:
        return [
            Trust(
                name=_first(e, "trustPartner"),
                direction=_int(e, "trustDirection"),
                trust_type=_int(e, "trustType"),
                attributes=_int(e, "trustAttributes"),
                sid=sid_to_str(e["securityidentifier"][0]) if e.get("securityidentifier") else "",
            )
            for e in self.optional(
                f"CN=System,{domain_dn}",
                "(objectClass=trustedDomain)",
                [
                    "trustPartner",
                    "trustDirection",
                    "trustType",
                    "trustAttributes",
                    "securityIdentifier",
                ],
            )
        ]

    def _ds_heuristics(self, config_dn: str) -> str:
        entry = self.optional(
            f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}",
            "(objectClass=*)",
            ["dSHeuristics"],
            scope=ldap3.BASE,
        )
        if not entry:
            self.notes.append("dSHeuristics not readable: AD-INF-004 not judged")
            return ""
        return _first(entry[0], "dSHeuristics")

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

    def _psos_visible(self, domain_dn: str) -> bool:
        psos = self.optional(
            f"CN=Password Settings Container,CN=System,{domain_dn}",
            "(objectClass=msDS-PasswordSettings)",
            ["name"],
        )
        if not psos:
            self.notes.append(
                "no fine-grained password policy visible (none exist, or this account cannot "
                "read them); AD-POL-001 judges the default domain policy only"
            )
        return bool(psos)

    def _resolve(self, domain_dn: str, sids: set[str], objects: list[DirObject]) -> dict[str, str]:
        known = {o.sid: o.name for o in objects if o.sid}
        names = {}
        for sid in sorted(sids):
            if not sid.startswith("S-1-5-21-"):
                continue  # well-known SIDs are named in model.py
            if sid in known:
                names[sid] = known[sid]
                continue
            hit = self.search(domain_dn, f"(objectSid={sid})", ["sAMAccountName"])
            if hit:
                names[sid] = _first(hit[0], "sAMAccountName")
        return names

    def _members(self, domain_dn: str, group_filter: str) -> list[str] | None:
        group = self.optional(domain_dn, group_filter, ["distinguishedName"])
        if not group:
            return None  # e.g. Enterprise Admins only exists in the forest root
        group_dn = ldap3.utils.conv.escape_filter_chars(group[0]["distinguishedname"][0])
        members = self.optional(
            domain_dn, f"(&(objectClass=user)(memberOf:{IN_CHAIN}:={group_dn}))", ["sAMAccountName"]
        )
        return sorted(m["distinguishedname"][0] for m in members)

    # --- SMB, probes -----------------------------------------------------------------

    def _sysvol(self, domain: str, gpo_guids: list[str]) -> sysvol.SysvolResult:
        t = self.target
        if t is None or not t.sysvol:
            return sysvol.SysvolResult()
        if not t.user and not t.kerberos:
            self.notes.append("SYSVOL not checked: needs credentials")
            return sysvol.SysvolResult()
        try:
            result = sysvol.scan(
                t.host, domain, t.user, t.password, gpo_guids, t.smb_port, t.kerberos
            )
            if result.unreadable:
                shown = ", ".join(result.unreadable[:5])
                more = len(result.unreadable) - 5
                self.notes.append(
                    f"SYSVOL files not readable by this account: {shown}"
                    + (f" (+{more} more)" if more > 0 else "")
                )
            self.notes += result.notes
            return result
        except sysvol.SysvolError as exc:
            self.notes.append(f"SYSVOL not checked: {exc}")
            return sysvol.SysvolResult()

    def _probe_signing(self, host: str, port: int) -> tuple[bool | None, str | None]:
        """Try an unsigned NTLM bind on plain LDAP; a DC that requires signing refuses it.

        Returns the result and, when there is none, why.
        """
        t = self.target
        assert t is not None
        server = ldap3.Server(host, port=port, connect_timeout=10)
        conn = ldap3.Connection(server, user=t.user, password=t.password, authentication=ldap3.NTLM)
        try:
            if conn.bind():
                return False, None
            if conn.result.get("result") == 8:  # strongerAuthRequired
                return True, None
            return None, f"LDAP signing probe inconclusive: {conn.result.get('description')}"
        except LDAPException as exc:
            return None, f"LDAP signing probe failed: {exc}"
        finally:
            conn.unbind()

    def _dc_targets(self, dc_dns_host: str, accounts: list[Account]) -> list[tuple[str, bool]]:
        """(DC host name, is the scanned DC) for every DC to probe, the scanned one first."""
        t = self.target
        assert t is not None
        scanned = dc_dns_host or t.host
        out = [(scanned, True)]
        if not t.all_dcs:
            return out
        others = {
            a.dns_host.lower(): a.dns_host
            for a in accounts
            # credentials never go to an unregistered "DC", and Entra Kerberos has no host
            if a.is_registered_dc
            and not a.entra_kerberos
            and a.enabled
            and a.dns_host
            and a.dns_host.lower() != scanned.lower()
        }
        return out + [(others[k], False) for k in sorted(others)]

    def _probe_dc(self, name: str, scanned: bool) -> DcProbe:
        """Every probe against one DC; the scanned DC is reached through the given ports."""
        t = self.target
        assert t is not None
        host = t.host if scanned else name
        result = DcProbe(name)
        ntlm = bool(t.user and "\\" in t.user and not t.kerberos)
        plain_port = t.plain_port if scanned else (389 if t.plain_port else 0)
        if plain_port and ntlm:
            result.ldap_signing_required, note = self._probe_signing(host, plain_port)
            if note:
                self.notes.append(f"{name}: {note}")
        if not t.probes:
            return result
        if t.kerberos or (t.user and t.password is not None):
            smb_port = t.smb_port if scanned else 445
            result.smb_signing_required, result.spooler = probes.smb_posture(
                host, smb_port, t.user, t.password, t.kerberos
            )
            if result.smb_signing_required is None:
                result.error = "no SMB connection"
        if t.use_ssl and ntlm:
            result.ldaps_channel_binding_required = probes.ldaps_channel_binding_required(
                host, t.port if scanned else 636, t.user or "", t.password or ""
            )
        return result

    def _probes(self, dc_dns_host: str, accounts: list[Account]) -> Probes:
        t = self.target
        result = Probes()
        if t is None:
            return result
        if t.plain_port and not (t.user and "\\" in t.user and not t.kerberos):
            self.notes.append(
                "LDAP signing and channel binding not probed: they need a DOMAIN\\user account "
                "with a password (NTLM)"
            )
        if not t.probes and not t.plain_port:
            return result
        for name, scanned in self._dc_targets(dc_dns_host, accounts):
            if not scanned and not t.probes:
                break
            dc = self._probe_dc(name, scanned)
            result.dcs.append(dc)
            if scanned:
                self.scanned_ldap_signing = dc.ldap_signing_required
                result.smb_signing_required = dc.smb_signing_required
                result.spooler_on_dc = dc.spooler
                result.ldaps_channel_binding_required = dc.ldaps_channel_binding_required
                if dc.error and t.probes:
                    self.notes.append("SMB probes did not run: no SMB connection to the DC")
            elif dc.error:
                self.notes.append(f"{name}: not probed ({dc.error})")
        if t.probes and t.http_port:
            for ca_host in self.ca_dns_hosts:
                # a CA on the DC being scanned is reached through the address given for it
                same = ca_host.lower() == dc_dns_host.lower()
                url, error = probes.web_enrollment_ntlm(
                    t.host if same else ca_host, ca_host, t.http_port
                )
                if error:
                    self.notes.append(f"web enrollment on {ca_host} not probed: {error}")
                if url:
                    result.web_enrollment_ntlm.append(url)
        return result

    def _ca_configs(self, dc_dns_host: str) -> list[CaConfig]:
        """Each enterprise CA's configuration, read from its registry over the winreg pipe."""
        t = self.target
        if t is None or not t.probes or not self.ca_dns_hosts:
            return []
        skipped = "CA configuration (ESC6, ESC7, ESC11, ESC16, audit filter) not read"
        if not t.ca_registry:
            self.notes.append(f"{skipped}: --no-ca-registry")
            return []
        if not (t.kerberos or (t.user and t.password is not None)):
            self.notes.append(f"{skipped}: needs credentials")
            return []
        out = []
        for ca_host in self.ca_dns_hosts:
            # a CA on the DC being scanned is reached through the address given for it
            same = ca_host.lower() == dc_dns_host.lower()
            cfg = probes.ca_registry(
                t.host if same else ca_host,
                t.smb_port if same else 445,
                ca_host,
                self.ca_names.get(ca_host.lower(), ca_host),
                t.user,
                t.password,
                t.kerberos,
            )
            if cfg.error:
                self.notes.append(f"CA configuration on {ca_host} not read: {cfg.error}")
            elif cfg.third_party_policy:
                self.notes.append(
                    f"{cfg.name} on {ca_host} uses the policy module {cfg.policy_module}: "
                    "ESC6 and ESC16 not judged"
                )
            out.append(cfg)
        return out

    # --- accounts --------------------------------------------------------------------

    def _account(self, e: dict[str, list[Any]]) -> Account:
        classes = {c.lower() for c in _str(e.get("objectclass", []))}
        text = " ".join(_str(e.get("description", [])) + _str(e.get("info", [])))
        uac = _int(e, "userAccountControl")
        self.dmsa_seen = self.dmsa_seen or DMSA_CLASS in classes
        account = Account(
            dn=e["distinguishedname"][0],
            sam=_first(e, "sAMAccountName"),
            uac=uac,
            is_computer="computer" in classes and not classes & MANAGED_CLASSES,
            spns=_str(e.get("serviceprincipalname", [])),
            pwd_last_set=filetime_to_datetime(_int(e, "pwdLastSet")),
            pwd_must_change=_int(e, "pwdLastSet", -1) == 0,
            last_logon=filetime_to_datetime(_int(e, "lastLogonTimestamp")),
            admin_count=_int(e, "adminCount") == 1,
            rbcd=bool(e.get("msds-allowedtoactonbehalfofotheridentity")),
            allowed_to_delegate_to=_str(e.get("msds-allowedtodelegateto", [])),
            laps=bool(
                e.get("ms-mcs-admpwdexpirationtime") or e.get("mslaps-passwordexpirationtime")
            ),
            os=_first(e, "operatingSystem") or None,
            sid_history=[sid_to_str(s) for s in e.get("sidhistory", [])],
            sid=sid_to_str(e["objectsid"][0]) if e.get("objectsid") else "",
            primary_group=_int(e, "primaryGroupID"),
            dns_host=_first(e, "dNSHostName") or None,
            enc_types=(
                _int(e, "msDS-SupportedEncryptionTypes")
                if e.get("msds-supportedencryptiontypes")
                else None
            ),
            alt_security_identities=_str(e.get("altsecurityidentities", [])),
            logon_count=_int(e, "logonCount") if e.get("logoncount") else None,
            when_created=_generalized_time(_first(e, "whenCreated")),
            password_attributes=[a for a in PASSWORD_ATTRIBUTES if e.get(a.lower())],
            secret_in_description=bool(SECRET_TEXT.search(text)),
            laps_password_readable=any(e.get(a.lower()) for a in LAPS_PASSWORD_ATTRIBUTES),
            preceded_by=_first(e, "msDS-ManagedAccountPrecededByLink") or None,
            managed=bool(classes & MANAGED_CLASSES),
            sync_host=_sync_host(_first(e, "sAMAccountName"), text),
            entra_kerberos=is_entra_kerberos(
                e["distinguishedname"][0], uac, _first(e, "msDS-KrbTgtLink")
            ),
        )
        if account.is_rodc:
            self.rodc_policies.append(
                (
                    account,
                    _str(e.get("msds-revealondemandgroup", [])),
                    _str(e.get("msds-neverrevealgroup", [])),
                )
            )
        return account


def is_entra_kerberos(dn: str, uac: int, krbtgt_link: str) -> bool:
    """The Entra Kerberos object by structure: its fixed place, RODC flags without the
    writable-DC bit, and a link to its own krbtgt account. The name alone proves nothing."""
    rodc_style = bool(uac & UAC.PARTIAL_SECRETS_ACCOUNT) and not uac & UAC.SERVER_TRUST_ACCOUNT
    return rodc_style and bool(krbtgt_link) and bool(ENTRA_KERBEROS_DN.match(dn))


def mark_rogue_dcs(accounts: list[Account], registered: set[str]) -> None:
    """Flag computers with a DC bit in userAccountControl that have no nTDSDSA object."""
    for a in accounts:
        a.rogue_dc = (
            a.is_computer and a.is_dc and not a.entra_kerberos and a.dn.lower() not in registered
        )


def parse_gplink(container: str, kind: str, value: str) -> list[tuple[str, GpLink]]:
    """(GPO DN, link) for each entry of a gPLink value, disabled links included."""
    out = []
    for index, (gpo_dn, options) in enumerate(GPLINK.findall(value)):
        flags = int(options)
        link = GpLink(
            container, kind, not flags & GPLINK_DISABLED, bool(flags & GPLINK_ENFORCED), index
        )
        out.append((gpo_dn, link))
    return out


def machine_extensions(value: str) -> list[str]:
    """CSE GUIDs (upper case) listed in gPCMachineExtensionNames."""
    return [g.upper() for g in CSE_GROUP.findall(value)]


def _parent(dn: str, levels: int = 1) -> str:
    parts = gpo_scope.RDN_SEPARATOR.split(dn, maxsplit=levels)
    return parts[-1] if len(parts) > levels else ""


def _sync_host(sam: str, description: str) -> str | None:
    """Server an Entra Connect sync account belongs to; None for any other account."""
    m = SYNC_SAM.match(sam)
    if not m:
        return None
    if m.group("host"):
        return m.group("host").upper()
    found = SYNC_DESCRIPTION.search(description)
    return found.group(1).split(".")[0].upper() if found else "unknown server"


META_BLOCK = re.compile(r"<DS_REPL_ATTR_META_DATA>(.*?)</DS_REPL_ATTR_META_DATA>", re.S)
LAST_CHANGE = re.compile(r"<ftimeLastOriginatingChange>([^<]+)</ftimeLastOriginatingChange>")


def _meta_time(metadata_xml: str, attribute: str) -> datetime | None:
    """Last originating change of one attribute in msDS-ReplAttributeMetaData."""
    for block in META_BLOCK.findall(metadata_xml):
        if f"<pszAttributeName>{attribute}</pszAttributeName>" in block:
            m = LAST_CHANGE.search(block)
            if m and not m.group(1).startswith("1601"):
                try:
                    return datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
                except ValueError:
                    return None  # the caller's "not readable" case
    return None


def _last_backup(metadata_xml: str) -> datetime | None:
    """dSASignature's last originating change = last backup."""
    return _meta_time(metadata_xml, "dSASignature")


def _pwd_changed(entries: list[dict[str, Any]]) -> datetime | None:
    """When unicodePwd was really written, from one account's BASE read."""
    if not entries:
        return None
    return _meta_time("".join(_str(entries[0].get(REPL_METADATA.lower(), []))), "unicodePwd")


def _channel_trustees(settings: dict[str, GpoSettings], domain_sid: str, root_sid: str) -> set[str]:
    """SIDs named by the Netlogon allow lists, so they can be given names."""
    sids: set[str] = set()
    for s in settings.values():
        if s.vulnerable_channel_allow:
            try:
                allow, deny = sd.sddl_trustees(s.vulnerable_channel_allow, domain_sid, root_sid)
            except ValueError:
                continue  # AD-GPO-008 shows the raw text
            sids |= set(allow) | set(deny)
    return sids


def _channel_notes(snap: Snapshot) -> list[str]:
    if not snap.channel_policy_collected:
        return ["AD-GPO-008 (Netlogon allow list) not judged: SYSVOL was not read"]
    hits, unread = gpo_scope.dc_channel_allow(snap)
    if unread:
        return [f"AD-GPO-008 did not read the security template of: {', '.join(unread)}"]
    if hits:
        return []
    return [
        "no GPO reaching a DC sets VulnerableChannelAllowList; a value set in a DC's own "
        "registry cannot be seen by this scan (AD-GPO-008)"
    ]


def connect(target: Target) -> ldap3.Connection:
    server = ldap3.Server(
        target.host,
        port=target.port,
        use_ssl=target.use_ssl,
        get_info=ldap3.DSA,
        connect_timeout=10,
    )
    try:
        if target.kerberos:
            conn = ldap3.Connection(
                server,
                authentication=ldap3.SASL,
                sasl_mechanism=ldap3.KERBEROS,
                read_only=True,
                raise_exceptions=True,
            )
            conn.bind()
        elif target.user and "\\" in target.user:
            conn = ldap3.Connection(
                server,
                user=target.user,
                password=target.password,
                authentication=ldap3.NTLM,
                read_only=True,
                raise_exceptions=True,
            )
            conn.open()
            # LDAPS binds carry a channel binding token so DCs that enforce it accept them
            if not probes.ntlm_bind(conn, channel_binding=target.use_ssl):
                raise CollectError(f"bind failed: {conn.result.get('message') or conn.result}")
        elif target.user:
            conn = ldap3.Connection(
                server,
                user=target.user,
                password=target.password,
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
    except LDAPException as exc:
        raise CollectError(f"collection failed: {exc}") from exc
    finally:
        conn.unbind()
