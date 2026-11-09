"""Read-only LDAP collector: one pass over the domain into a Snapshot."""

from __future__ import annotations

import dataclasses
import re
import struct
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import ldap3
from ldap3.core.exceptions import (
    LDAPException,
    LDAPInsufficientAccessRightsResult,
    LDAPNoSuchObjectResult,
    LDAPOperationResult,
)
from ldap3.protocol.microsoft import security_descriptor_control

from . import gpo_scope, keycred, probes, sd, sysvol
from .checks import san_note
from .model import (
    TIER0_RIDS,
    UAC,
    Account,
    CaConfig,
    CertTemplate,
    ConflictObject,
    DcProbe,
    DirObject,
    Dmsa,
    DomainPolicy,
    Gmsa,
    GpLink,
    Gpo,
    GpoLocalGroup,
    GpoSettings,
    Probes,
    Pso,
    Rodc,
    Site,
    Snapshot,
    Subnet,
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
VALUE_METADATA = "msDS-ReplValueMetaData"
# direct reads of member values that no search returned; each one is a BASE search
MAX_MEMBER_READS = 500
NOT_RETURNED = "not returned: hidden, or this account has no right to see it"
NO_ATTRIBUTES = "returned without attributes: this account cannot read it"
SEARCH_MISSED = "readable by its DN but missing from the searches"
PRE2K_SID = "S-1-5-32-554"
# BASE reads of the groups fine-grained password policies are linked to
MAX_PSO_LINK_READS = 500
# all mandatory on the class, so one that does not come back could not be read
PSO_SETTINGS = (
    "msDS-MinimumPasswordLength",
    "msDS-PasswordComplexityEnabled",
    "msDS-LockoutThreshold",
    "msDS-PasswordReversibleEncryptionEnabled",
)
GROUP_TYPE_GLOBAL = 0x2
GROUP_TYPE_SECURITY = 0x80000000
# the fixed RDNs Windows gives the SYSVOL subscriptions under a DC's computer object
FRS_SYSVOL = re.compile(r"^cn=domain system volume \(sysvol share\),", re.IGNORECASE)
DFSR_SYSVOL = re.compile(
    r"^cn=sysvol subscription,cn=domain system volume,cn=dfsr-localsettings,", re.IGNORECASE
)
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

# asked for in the BASE read of tier-0 accounts only
TIER0_ATTRS = [REPL_METADATA, VALUE_METADATA, keycred.ATTRIBUTE]

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
    "msDS-ManagedAccountPrecededByLinkBL",
    "msDS-SupersededManagedAccountLink",
    "msDS-KrbTgtLink",
    "userPrincipalName",
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
    # HTTPS port for web enrollment and CES URLs without a port; 0 disables those probes
    https_port: int = 443
    # SMB posture and channel binding probes
    probes: bool = True
    kerberos: bool = False
    # probe every DC found in the directory, not only the one being scanned
    all_dcs: bool = True
    # read each CA's configuration over the winreg pipe (part of the probes)
    ca_registry: bool = True


def _ces_urls(values: list[str]) -> list[str]:
    """HTTP and HTTPS URLs of msPKI-Enrollment-Servers values (priority, auth, renewal, URL)."""
    lines = (line.strip() for value in values for line in value.splitlines())
    return [line for line in lines if line.lower().startswith(("http://", "https://"))]


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


def _optional_int(entry: dict[str, list[Any]], attr: str) -> int | None:
    return _int(entry, attr) if entry.get(attr.lower()) else None


def _optional_bool(entry: dict[str, list[Any]], attr: str) -> bool | None:
    """An LDAP Boolean, which comes back as the text TRUE or FALSE; None when absent."""
    value = _first(entry, attr).upper()
    return value == "TRUE" if value else None


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
        self.ces_urls: list[str] = []
        # CA host (lower-cased dNSHostName) -> enrollment service name
        self.ca_names: dict[str, str] = {}
        self.rodc_policies: list[tuple[Account, list[str], list[str]]] = []
        self.domain_dn = ""
        self.scanned_ldap_signing: bool | None = None
        self.dmsa_seen = False
        self.pwd_unread: list[str] = []
        self.keys_unread: list[str] = []
        # (lower-cased DN, attribute) that came back in ranges: only part of it was read
        self.ranged: set[tuple[str, str]] = set()

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
                    self.ranged.add((e["dn"].lower(), key))
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

    def attempt(
        self, base: str, flt: str, attrs: list[str], must_exist: bool = False, **kw: Any
    ) -> list[dict[str, Any]] | None:
        """optional(), but None when the search was refused: "nothing there" and "could
        not ask" differ for a check that must not report an unread part as clean. With
        must_exist the base is in every forest, so "no such object" can only mean hidden."""
        try:
            return self.search(base, flt, attrs, **kw)
        except LDAPNoSuchObjectResult:
            if must_exist:
                self.notes.append(f"{base} is not visible to this account")
                return None
            return []
        except LDAPOperationResult as exc:
            self.notes.append(f"search {flt} under {base} failed: {exc.description}")
            return None

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
        sites, subnets, topology_checked = self._site_topology(config_dn)
        conflicts, conflicts_checked = self._conflicts(domain_dn, config_dn)
        dfsr_flags, frs_dcs, dfsr_dcs, replication_checked = self._sysvol_replication(domain_dn)
        ca_configs = self._ca_configs(dc_dns_host)

        trustees = {a.sid for aces in acls.values() for a in aces}
        trustees |= {a.sid for t in templates for a in t.aces}
        trustees |= {a.sid for g in gpos for a in g.aces}
        trustees |= {a.sid for o in objects for a in o.aces} | {o.owner for o in objects if o.owner}
        gmsas = self._gmsas(domain_dn)
        trustees |= {s for g in gmsas for s in g.readers}
        dmsas, dmsas_checked = self._dmsas(domain_dn)
        trustees |= {s for d in dmsas for s in d.readers}
        trustees |= {a.sid for d in dmsas for a in d.aces} | {d.owner for d in dmsas if d.owner}
        trustees |= {a.sid for c in ca_configs for a in c.aces}
        trustees |= {s for a in accounts for s in a.rbcd_principals or ()}
        trustees |= {s for a in accounts for s in a.sid_history if s.startswith("S-1-5-21-")}
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
        psos, psos_unreadable, psos_visible = self._psos(domain_dn)
        upn_checked = any(a.upn for a in accounts)
        if not upn_checked:
            self.notes.append(
                "no userPrincipalName came back (none set, or this account cannot read them): "
                "the UPN part of AD-ACC-016 not judged"
            )
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
            trust_details_checked=True,
            spn_mappings=self._spn_mappings(config_dn),
            gpos=gpos,
            oid_group_links=self._oid_links(pks),
            ca_hosts=self.ca_hosts,
            enrollment_urls=self.ces_urls,
            root_sid=root_sid,
            dns_admins=dns_admins or [],
            pre2k_members=_str(pre2k[0].get("member", [])) if pre2k else [],
            ds_heuristics=self._ds_heuristics(config_dn),
            recycle_bin=self._recycle_bin(config_dn),
            ldap_signing_required=None,  # set from the scanned DC's probe below
            probes=self._probes(dc_dns_host, accounts),
            objects=objects,
            gpo_settings=gpo_settings,
            gpo_registry=sysvol_result.registry,
            registry_policy_collected=sysvol_result.scanned,
            script_secrets=sysvol_result.script_secrets,
            gmsas=gmsas,
            rodcs=[Rodc(a.sam, a_reveal, a_never) for a, a_reveal, a_never in self.rodc_policies],
            last_backup=_last_backup(metadata),
            backup_checked="dSASignature" in metadata,
            psos_visible=psos_visible,
            psos=psos,
            psos_unreadable=psos_unreadable,
            psos_checked=True,
            dmsas=dmsas,
            dmsas_checked=dmsas_checked,
            upn_checked=upn_checked,
            krbtgt_links_checked=True,
            dmsa_visible=self.dmsa_seen,
            gpo_local_groups=local_groups,
            local_groups_collected=sysvol_result.scanned,
            ntlm_policy_collected=sysvol_result.scanned,
            dc_registration_checked=registered is not None,
            channel_policy_collected=sysvol_result.scanned,
            aes_cutover=self._aes_cutover(domain_dn, domain_sid),
            pwd_metadata_checked=True,
            key_credentials_checked=True,
            unreadable_members=unreadable or [],
            tier0_members_checked=unreadable is not None,
            dc_sites=dc_sites,
            site_count=site_count,
            sites=sites,
            subnets=subnets,
            site_topology_checked=topology_checked,
            sysvol_dfsr_flags=dfsr_flags,
            sysvol_frs_dcs=frs_dcs,
            sysvol_dfsr_dcs=dfsr_dcs,
            sysvol_replication_checked=replication_checked,
            conflicts=conflicts,
            conflicts_checked=conflicts_checked,
            notes=self.notes,
            ace_inheritance_checked=True,
        )
        snap.ldap_signing_required = self.scanned_ldap_signing
        snap.probes.ca_configs = ca_configs
        snap.notes += gpo_scope.resolve(snap).notes
        snap.notes += gpo_scope.site_note(snap)
        snap.notes += gpo_scope.filter_note(snap)
        snap.notes += _channel_notes(snap)
        snap.notes += _registry_notes(snap, sysvol_result.registry_unread)
        if self.pwd_unread:
            shown = ", ".join(sorted(self.pwd_unread)[:5])
            more = len(self.pwd_unread) - 5
            snap.notes.append(
                f"replication metadata of unicodePwd not readable for {shown}"
                + (f" (+{more} more)" if more > 0 else "")
                + ": AD-ACC-012 not judged for them, and their age checks trust pwdLastSet"
            )
        snap.notes += self._keys_note()
        snap.notes += _machine_age_notes(accounts)
        snap.notes += _blank_name_notes(accounts)
        snap.notes += _sysvol_unseen_notes(snap)
        snap.notes += _entra_kerberos_notes(accounts)
        snap.notes += san_note(snap)
        if snap.has_2025 and not snap.dmsa_visible:
            snap.notes.append(
                "no dMSA visible (none exist, or this account cannot read them; by default "
                "ordinary users cannot): AD-INF-007 did not check existing dMSA links and "
                "AD-ACL-009 did not check who controls them"
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
        ca_hosts = {h.upper() for h in self.ca_hosts}
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
            or a.sam.upper() in ca_hosts
        ]
        for a in sensitive:
            kind = "computer" if a.is_computer else "user"
            # the attribute is constructed, so it only comes back from a BASE read: this
            # read happens anyway, which keeps the cost to tier 0 and to no extra search
            tier0 = a.dn.lower() in priv_dns or a.is_dc or a.sam.lower() == "krbtgt" or a.rid == 500
            # the graph treats CA and sync servers as tier 0, so a key on one is a way in too
            keys = tier0 or (
                bool(a.sync_host)
                or a.sam.upper() in ca_hosts
                or (a.is_computer and a.sam.lower().rstrip("$") in sync_hosts)
            )
            entries = self._base(a.dn, [*attrs, *TIER0_ATTRS] if keys else attrs)
            objects += [self._object(e, kind) for e in entries]
            if tier0:
                a.pwd_changed = _pwd_changed(entries)
                if a.pwd_changed is None:
                    self.pwd_unread.append(a.sam)
            if keys:
                self._read_keys(a, entries)
        return objects

    def _read_keys(self, a: Account, entries: list[dict[str, Any]]) -> None:
        """Key credentials of one tier-0 account, from its BASE read."""
        e = entries[0] if entries else {}
        a.key_credentials = keycred.read(
            _str(e.get(keycred.ATTRIBUTE.lower(), [])),
            "".join(_str(e.get(VALUE_METADATA.lower(), []))),
        )
        # no value and no row proves nothing unless this account may read the metadata
        partial = (a.dn.lower(), VALUE_METADATA.lower()) in self.ranged
        if partial or not e.get(REPL_METADATA.lower()):
            self.keys_unread.append(a.sam)

    def _keys_note(self) -> list[str]:
        if not self.keys_unread:
            return []
        shown = ", ".join(sorted(self.keys_unread)[:5])
        more = len(self.keys_unread) - 5
        return [
            f"replication metadata not fully readable for {shown}"
            + (f" (+{more} more)" if more > 0 else "")
            + ": key credentials there are unknown, AD-ACC-013 did not judge them"
        ]

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

    def _site_topology(self, config_dn: str) -> tuple[list[Site], list[Subnet], bool]:
        """The sites, their server objects and site links, and the subnets. A subnet that
        comes back without attributes is unknown, not unmapped, and then nothing is judged:
        a site is called empty only when every subnet and server has been seen."""
        base = f"CN=Sites,{config_dn}"
        not_judged = "AD-INF-020 (sites and subnets) not judged"
        found = self.attempt(base, "(objectClass=site)", ["objectClass"], scope=ldap3.LEVEL)
        servers = self.attempt(base, "(objectClass=server)", ["objectClass"])
        subnets = self.attempt(
            f"CN=Subnets,{base}",
            "(objectClass=subnet)",
            ["objectClass", "siteObject"],
            must_exist=True,
            scope=ldap3.LEVEL,
        )
        links = self.attempt(
            f"CN=Inter-Site Transports,{base}",
            "(objectClass=siteLink)",
            ["objectClass", "siteList"],
            must_exist=True,
        )
        if not found or servers is None or subnets is None:
            self.notes.append(f"sites, servers or subnets not readable: {not_judged}")
            return [], [], False
        hidden = [e for e in [*found, *servers, *subnets] if not e.get("objectclass")]
        if hidden:
            self.notes.append(f"{len(hidden)} site topology object(s) unreadable: {not_judged}")
            return [], [], False
        in_site = Counter(_parent(e["distinguishedname"][0], 2).lower() for e in servers)
        # a link without attributes may list any site: "in no link" cannot be said then
        linked: set[str] | None = None
        if links is not None and all(e.get("objectclass") for e in links):
            linked = {v.lower() for e in links for v in _str(e.get("sitelist", []))}
        elif len(found) > 1:
            self.notes.append("site links not readable: AD-INF-020 did not judge site links")
        result = []
        for e in found:
            dn = e["distinguishedname"][0]
            result.append(
                Site(dn, in_site[dn.lower()], None if linked is None else dn.lower() in linked)
            )
        nets = [
            Subnet(_rdn_value(e["distinguishedname"][0]), _first(e, "siteObject")) for e in subnets
        ]
        return result, nets, True

    def _conflicts(self, domain_dn: str, config_dn: str) -> tuple[list[ConflictObject], bool]:
        """Objects replication renamed: a mangled RDN (<name>\\0ACNF:<guid>) or a
        sAMAccountName rewritten to $DUPLICATE-<rid>. The filter finds the literal text; the
        line feed in the value tells a conflict from a name that merely says "CNF:"."""
        out: list[ConflictObject] = []
        ok = True
        for base in (domain_dn, config_dn):
            hits = self.attempt(base, "(name=*CNF:*)", ["name"])
            if hits is None:
                ok = False
                continue
            for e in hits:
                if "\ncnf:" in _first(e, "name").lower():
                    out.append(ConflictObject(e["distinguishedname"][0], "cnf"))
        hits = self.attempt(domain_dn, "(sAMAccountName=$DUPLICATE-*)", ["sAMAccountName"])
        if hits is None:
            ok = False
        else:
            out += [ConflictObject(e["distinguishedname"][0], "duplicate-sam") for e in hits]
        if not ok:
            self.notes.append("conflict object searches refused: AD-INF-021 did not judge them")
        return out, ok

    def _sysvol_replication(self, domain_dn: str) -> tuple[int | None, list[str], list[str], bool]:
        """The domain's migration state, and which DCs hold an FRS or DFSR SYSVOL
        subscription. Flags of 0 or none with no subscription seen proves nothing, since a
        hidden object looks the same as a missing one."""
        settings = self.attempt(
            f"CN=DFSR-GlobalSettings,CN=System,{domain_dn}",
            "(objectClass=*)",
            ["msDFSR-Flags"],
            scope=ldap3.BASE,
        )
        flags = (
            _int(settings[0], "msDFSR-Flags")
            if settings and settings[0].get("msdfsr-flags")
            else None
        )
        subscribers = self.attempt(
            domain_dn,
            "(|(objectClass=nTFRSSubscriber)(objectClass=msDFSR-Subscription))",
            ["objectClass"],
        )
        frs: list[str] = []
        dfsr: list[str] = []
        for e in subscribers or []:
            dn = e["distinguishedname"][0]
            if FRS_SYSVOL.match(dn):
                frs.append(_parent(dn, 2))
            elif DFSR_SYSVOL.match(dn):
                dfsr.append(_parent(dn, 3))
        checked = flags in (16, 32, 48) or bool(frs or dfsr)
        if not checked:
            self.notes.append(
                "SYSVOL replication state not readable (no migration state and no "
                "subscription visible): AD-INF-019 not judged"
            )
        return flags, sorted(frs), sorted(dfsr), checked

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
            ["sAMAccountName", "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval"],
        ):
            raw = e.get("msds-groupmsamembership")
            readers = sorted({a.sid for a in sd.parse_dacl(raw[0])}) if raw else []
            interval = _int(e, "msDS-ManagedPasswordInterval") or None
            out.append(
                Gmsa(_first(e, "sAMAccountName"), e["distinguishedname"][0], readers, interval)
            )
        unread = sum(g.interval_days is None for g in out)
        if unread:
            self.notes.append(
                f"password interval not readable for {unread} gMSA(s): AD-ACC-015 not judged "
                "for them"
            )
        return out

    # --- AD CS -----------------------------------------------------------------------

    def _templates(self, pks: str) -> tuple[list[CertTemplate], dict[str, str]]:
        services = self.optional(
            f"CN=Enrollment Services,{pks}",
            "(objectClass=pKIEnrollmentService)",
            ["name", "certificateTemplates", "dNSHostName", "msPKI-Enrollment-Servers"],
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
        self.ces_urls = sorted(
            {u for s in services for u in _ces_urls(_str(s.get("mspki-enrollment-servers", [])))}
        )
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
        trusts = [
            Trust(
                name=_first(e, "trustPartner"),
                direction=_int(e, "trustDirection"),
                trust_type=_int(e, "trustType"),
                attributes=_int(e, "trustAttributes"),
                sid=sid_to_str(e["securityidentifier"][0]) if e.get("securityidentifier") else "",
                enc_types=(
                    _int(e, "msDS-SupportedEncryptionTypes")
                    if e.get("msds-supportedencryptiontypes")
                    else None
                ),
                when_changed=_generalized_time(_first(e, "whenChanged")),
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
                    "msDS-SupportedEncryptionTypes",
                    "whenChanged",
                ],
            )
        ]
        for t in trusts:
            if t.when_changed is None:
                self.notes.append(
                    f"whenChanged of trust {t.name} not readable: AD-INF-016 not judged"
                )
        return trusts

    def _spn_mappings(self, config_dn: str) -> list[str]:
        entry = self.optional(
            f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}",
            "(objectClass=*)",
            ["sPNMappings"],
            scope=ldap3.BASE,
        )
        values = _str(entry[0].get("spnmappings", [])) if entry else []
        if not values:
            self.notes.append(
                "sPNMappings not readable: AD-DEL-005 not judged for targets on hosts that exist"
            )
        return values

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

    def _psos(self, domain_dn: str) -> tuple[list[Pso], int, bool]:
        """The fine-grained password policies whose settings came back, how many came back
        without them, and whether any was visible at all."""
        found = self.optional(
            f"CN=Password Settings Container,CN=System,{domain_dn}",
            "(objectClass=msDS-PasswordSettings)",
            [
                "name",
                "msDS-PasswordSettingsPrecedence",
                *PSO_SETTINGS,
                "msDS-PSOAppliesTo",
            ],
        )
        if not found:
            self.notes.append(
                "no fine-grained password policy visible (none exist, or this account cannot "
                "read them); AD-POL-001 judges the default domain policy only and AD-POL-003 "
                "not judged"
            )
            return [], 0, False
        readable = [e for e in found if e.get("msds-passwordsettingsprecedence")]
        unread = len(found) - len(readable)
        if unread:
            self.notes.append(
                f"{unread} fine-grained password policy object(s) came back without their "
                "settings: AD-POL-003 not judged for them"
            )
        # kept in the list: a weak setting that was read is still a weak setting
        partial = sum(not all(e.get(a.lower()) for a in PSO_SETTINGS) for e in readable)
        if partial:
            self.notes.append(
                f"{partial} fine-grained password policy object(s) came back with only part of "
                "their settings: AD-POL-003 did not judge the missing ones"
            )
        links = sorted({dn for e in readable for dn in _str(e.get("msds-psoappliesto", []))})
        not_global = self._non_global_groups(links)
        psos = []
        for e in readable:
            applies = _str(e.get("msds-psoappliesto", []))
            psos.append(
                Pso(
                    name=_first(e, "name") or _rdn_value(e["distinguishedname"][0]),
                    dn=e["distinguishedname"][0],
                    precedence=_int(e, "msDS-PasswordSettingsPrecedence"),
                    min_length=_optional_int(e, "msDS-MinimumPasswordLength"),
                    complexity=_optional_bool(e, "msDS-PasswordComplexityEnabled"),
                    lockout_threshold=_optional_int(e, "msDS-LockoutThreshold"),
                    reversible=_optional_bool(e, "msDS-PasswordReversibleEncryptionEnabled"),
                    applies_to=applies,
                    not_global=[dn for dn in applies if dn.lower() in not_global],
                )
            )
        return psos, unread, True

    def _non_global_groups(self, links: list[str]) -> set[str]:
        """Lower-cased DNs of the linked groups that are not global security groups. A
        group whose type cannot be read is left out: its link then counts as working."""
        out: set[str] = set()
        if len(links) > MAX_PSO_LINK_READS:
            self.notes.append(
                f"{len(links)} fine-grained password policy links: only the first "
                f"{MAX_PSO_LINK_READS} checked for their group type"
            )
        for dn in links[:MAX_PSO_LINK_READS]:
            entry = self.optional(dn, "(objectClass=group)", ["groupType"], scope=ldap3.BASE)
            if entry and entry[0].get("grouptype"):
                kind = _int(entry[0], "groupType")
                if not (kind & GROUP_TYPE_GLOBAL and kind & GROUP_TYPE_SECURITY):
                    out.add(dn.lower())
        return out

    def _dmsas(self, domain_dn: str) -> tuple[list[Dmsa], bool]:
        """Every dMSA this account can see, with owner, DACL and migration state. None
        visible is not "none exist": the note in snapshot() says so."""
        if not self.dmsa_seen:
            return [], True
        found = self.attempt(
            domain_dn,
            "(objectClass=msDS-DelegatedManagedServiceAccount)",
            [
                "sAMAccountName",
                "msDS-ManagedAccountPrecededByLink",
                "msDS-DelegatedMSAState",
                "msDS-GroupMSAMembership",
                "nTSecurityDescriptor",
            ],
            controls=OWNER_AND_DACL,
        )
        if found is None:
            self.notes.append("dMSA search refused: AD-ACL-009 not judged")
            return [], False
        out = []
        for e in found:
            raw_sd = e.get("ntsecuritydescriptor")
            desc = sd.parse(raw_sd[0]) if raw_sd else sd.Descriptor(None, False, [])
            membership = e.get("msds-groupmsamembership")
            out.append(
                Dmsa(
                    name=_first(e, "sAMAccountName") or e["distinguishedname"][0],
                    dn=e["distinguishedname"][0],
                    preceded_by=_first(e, "msDS-ManagedAccountPrecededByLink") or None,
                    state=_optional_int(e, "msDS-DelegatedMSAState"),
                    readers=sorted({a.sid for a in sd.parse_dacl(membership[0])})
                    if membership
                    else [],
                    owner=desc.owner,
                    aces=desc.aces,
                    acl_read=bool(raw_sd),
                )
            )
        unread = sum(not d.acl_read for d in out)
        if unread:
            self.notes.append(
                f"security descriptor not readable for {unread} dMSA(s): AD-ACL-009 not judged "
                "for them"
            )
        return out, True

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
        if not t.plain_port:
            self.notes.append("LDAP signing not probed by choice: AD-INF-005 did not judge it")
        if (self.ca_dns_hosts or self.ces_urls) and not (t.probes and t.https_port):
            self.notes.append(
                "HTTPS enrollment endpoints not probed by choice: AD-ADCS-019 did not judge them"
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
        if t.probes:
            self._probe_enrollment(dc_dns_host, result)
        return result

    def _enrollment_targets(self) -> list[tuple[str, str, str, str, int, bool]]:
        """(scheme, host, Host header, path, port, published): each CA's web enrollment, which
        is only a guess, then the CES URLs the directory lists."""
        t = self.target
        assert t is not None
        ports = {"http": t.http_port, "https": t.https_port}
        out = [
            (scheme, host, host, "/certsrv/", port, False)
            for host in self.ca_dns_hosts
            for scheme, port in ports.items()
        ]
        for url in self.ces_urls:
            try:
                parts = urlsplit(url)
                scheme, host, port = parts.scheme.lower(), parts.hostname, parts.port
            except ValueError:
                host = None
            if not host:
                self.notes.append(f"enrollment URL {url} not probed: not a valid URL")
                continue
            # a URL that names no port follows the port options, as web enrollment does;
            # a user and password in it stay out of the request
            header = parts.netloc.rpartition("@")[2]
            out.append((scheme, host, header, parts.path or "/", port or ports[scheme], True))
        return [target for target in out if ports[target[0]]]

    def _probe_enrollment(self, dc_dns_host: str, result: Probes) -> None:
        t = self.target
        assert t is not None
        for scheme, host, header, path, port, published in self._enrollment_targets():
            # an endpoint on the DC being scanned is reached through the address given for it
            connect = t.host if host.lower() == dc_dns_host.lower() else host
            probe = probes.web_enrollment_ntlm if scheme == "http" else probes.enrollment_https
            url, error = probe(connect, header, port, path, published)
            if error:
                self.notes.append(f"{scheme}://{header}{path} not probed: {error}")
            found = result.web_enrollment_ntlm if scheme == "http" else result.enrollment_https
            if url and url not in found:
                found.append(url)

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

    def _rbcd_principals(self, e: dict[str, list[Any]]) -> list[str] | None:
        """The SIDs the security descriptor in msDS-AllowedToActOnBehalfOfOtherIdentity
        allows, deny ACEs applied; None when there is none or it cannot be parsed."""
        raw = e.get("msds-allowedtoactonbehalfofotheridentity")
        if not raw:
            return None
        try:
            return sorted({a.sid for a in sd.parse_ca(raw[0])[1]})
        except (IndexError, ValueError, TypeError, struct.error):
            self.notes.append(
                f"{_first(e, 'sAMAccountName')}: msDS-AllowedToActOnBehalfOfOtherIdentity "
                "could not be parsed: its resource-based delegation edges are not in the "
                "control graph"
            )
            return None

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
            rbcd_principals=self._rbcd_principals(e),
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
            upn=_first(e, "userPrincipalName") or None,
            krbtgt_link=_first(e, "msDS-KrbTgtLink") or None,
            superseded_by=(
                _first(e, "msDS-SupersededManagedAccountLink")
                or _first(e, "msDS-ManagedAccountPrecededByLinkBL")
                or None
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


def _entra_kerberos_notes(accounts: list[Account]) -> list[str]:
    """An Entra Kerberos object whose key account cannot be read: unknown is not clean."""
    by_dn = {a.dn.lower(): a for a in accounts}
    notes = []
    for a in accounts:
        if not a.entra_kerberos:
            continue
        key = by_dn.get((a.krbtgt_link or "").lower())
        if key is None or key.password_changed is None:
            notes.append(f"key age of the Entra Kerberos object {a.sam} not readable: AD-KRB-007")
    return notes


def _blank_name_notes(accounts: list[Account]) -> list[str]:
    """Accounts with no readable sAMAccountName: an unknown name is not a shared name."""
    blank = sum(not a.sam for a in accounts)
    if not blank:
        return []
    return [
        f"{blank} account(s) came back without a sAMAccountName: AD-INF-021 did not compare "
        "their names and AD-ACC-016 did not judge their host names"
    ]


def _sysvol_unseen_notes(snap: Snapshot) -> list[str]:
    """Registered DCs with neither subscription visible, when the migration state does not
    already answer for the domain: a hidden subscription looks the same as none."""
    if not snap.sysvol_replication_checked or snap.sysvol_dfsr_flags in (16, 32, 48):
        return []
    seen = {dn.lower() for dn in [*snap.sysvol_frs_dcs, *snap.sysvol_dfsr_dcs]}
    unseen = sum(
        a.is_computer and a.is_registered_dc and not a.entra_kerberos and a.dn.lower() not in seen
        for a in snap.accounts
    )
    if not unseen:
        return []
    return [
        f"{unseen} registered DC(s) show neither an FRS nor a DFS Replication SYSVOL "
        "subscription: AD-INF-019 not judged for them"
    ]


def _machine_age_notes(accounts: list[Account]) -> list[str]:
    """Computers whose age the two machine checks could not read: unknown is not clean."""
    notes = []
    dcs = [a for a in accounts if a.is_computer and a.enabled and a.is_registered_dc]
    unread = [a.sam for a in dcs if not a.entra_kerberos and a.password_changed is None]
    if unread:
        notes.append(f"password age not readable for {len(unread)} DC(s): AD-INF-018 not judged")
    blank = [
        a
        for a in accounts
        if a.is_computer
        and a.enabled
        and not a.managed
        and not a.is_registered_dc
        and not (a.last_logon or a.pwd_last_set or a.when_created)
    ]
    if blank:
        notes.append(
            f"no activity date readable for {len(blank)} computer(s): AD-ACC-014 not judged"
        )
    return notes


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


def _rdn_value(dn: str) -> str:
    return gpo_scope.RDN_SEPARATOR.split(dn, maxsplit=1)[0].split("=", 1)[1]


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


REGISTRY_CHECKS = "AD-GPO-009, AD-GPO-010, AD-GPO-011 and AD-GPO-012"


def _registry_notes(snap: Snapshot, unread: list[str]) -> list[str]:
    if not snap.registry_policy_collected:
        return [f"{REGISTRY_CHECKS} (registry policy) not judged: SYSVOL was not read"]
    notes = []
    missing = sorted(g.name for g in gpo_scope.unread_registry_gpos(snap))
    if missing:
        notes.append(f"{REGISTRY_CHECKS} did not read the Registry.pol of: {', '.join(missing)}")
    if unread:
        notes.append(f"Registry.pol files not readable by this account: {', '.join(unread[:5])}")
    return notes


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
