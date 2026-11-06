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
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SMARTCARD_REQUIRED = 0x40000
    PARTIAL_SECRETS_ACCOUNT = 0x4000000  # read-only DC


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def filetime_to_datetime(value: int) -> datetime | None:
    """AD stores times as 100 ns ticks since 1601; 0 and the max value mean 'never'."""
    if value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=value // 10)


@dataclass
class KeyCredential:
    """One msDS-KeyCredentialLink value, without the key itself."""

    # False: only replication metadata shows it, the value could not be read
    readable: bool = True
    # False: unreadable, or the blob is malformed
    parsed: bool = False
    device_id: str = ""
    # the time in the blob, which is whatever the writer put there
    created: datetime | None = None
    # when the directory added the value, from msDS-ReplValueMetaData
    added: datetime | None = None
    usage: int | None = None
    source: int | None = None
    # the only shape a computer may write to itself
    self_written: bool = False


@dataclass
class Account:
    dn: str
    sam: str
    uac: int
    is_computer: bool = False
    spns: list[str] = field(default_factory=list)
    pwd_last_set: datetime | None = None
    # last write of unicodePwd from replication metadata; only read for tier-0 accounts
    pwd_changed: datetime | None = None
    last_logon: datetime | None = None
    admin_count: bool = False
    rbcd: bool = False
    allowed_to_delegate_to: list[str] = field(default_factory=list)
    laps: bool = False
    os: str | None = None
    sid_history: list[str] = field(default_factory=list)
    sid: str = ""
    primary_group: int = 0
    dns_host: str | None = None
    # msDS-SupportedEncryptionTypes; None when the attribute is not set
    enc_types: int | None = None
    alt_security_identities: list[str] = field(default_factory=list)
    # msDS-KeyCredentialLink; only read for tier-0 accounts
    key_credentials: list[KeyCredential] = field(default_factory=list)
    logon_count: int | None = None
    when_created: datetime | None = None
    # names of password-bearing attributes that came back (values are never kept)
    password_attributes: list[str] = field(default_factory=list)
    # description/info looks like it holds a password (the text itself is not kept)
    secret_in_description: bool = False
    # a LAPS password attribute was readable by the scanning account
    laps_password_readable: bool = False
    # msDS-ManagedAccountPrecededByLink of a dMSA
    preceded_by: str | None = None
    # gMSA, sMSA or dMSA (computer-like, but not a computer)
    managed: bool = False
    # for an Entra Connect sync account: the server it runs on, from its description/name
    sync_host: str | None = None
    # DC flag in userAccountControl, but no nTDSDSA object in the Configuration partition
    rogue_dc: bool = False
    # pwdLastSet was read as 0: the password age is unknown, not "as old as the account"
    pwd_must_change: bool = False
    # the logical RODC object of Microsoft Entra Kerberos: no server behind it, by design
    entra_kerberos: bool = False

    def has(self, flag: UAC) -> bool:
        return bool(self.uac & flag)

    @property
    def enabled(self) -> bool:
        return not self.has(UAC.ACCOUNTDISABLE)

    @property
    def is_dc(self) -> bool:
        return self.has(UAC.SERVER_TRUST_ACCOUNT) or self.has(UAC.PARTIAL_SECRETS_ACCOUNT)

    @property
    def is_registered_dc(self) -> bool:
        """A DC that may be exempted from checks: the flag alone can be set on any
        computer. is_dc stays true for a rogue object, so it remains a tier-0 target."""
        return self.is_dc and not self.rogue_dc

    @property
    def password_changed(self) -> datetime | None:
        """When the password was last really set, as far as known: pwdLastSet can be moved
        forward without a password change, so the older of the two times counts."""
        times = [t for t in (self.pwd_last_set, self.pwd_changed) if t is not None]
        return min(times) if times else None

    @property
    def is_rodc(self) -> bool:
        return self.has(UAC.PARTIAL_SECRETS_ACCOUNT)

    @property
    def rid(self) -> int:
        return int(self.sid.rsplit("-", 1)[1]) if self.sid else 0


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
    schema_version: int = 2
    no_security_extension: bool = False
    issuance_policies: list[str] = field(default_factory=list)
    min_key_size: int = 0


@dataclass
class GppPassword:
    path: str
    user: str


@dataclass
class Trust:
    name: str
    direction: int  # 1 inbound, 2 outbound, 3 both
    trust_type: int  # 1 downlevel, 2 uplevel (AD), 3 MIT
    attributes: int
    sid: str = ""  # the partner domain's SID (securityIdentifier); "" when not read

    @property
    def within_forest(self) -> bool:
        return bool(self.attributes & TRUST_WITHIN_FOREST)


TRUST_WITHIN_FOREST = 0x20


@dataclass
class GpLink:
    """One entry of a gPLink attribute."""

    container: str  # DN of the domain head, an OU or a site
    kind: str  # "domain", "ou" or "site"
    enabled: bool
    enforced: bool
    index: int  # position in the gPLink value


@dataclass
class Gpo:
    name: str
    guid: str
    # where the GPO is linked among the places that reach domain controllers
    linked_to: list[str]
    aces: list[Ace]
    # every link, disabled ones included (empty in older snapshots)
    links: list[GpLink] = field(default_factory=list)
    flags: int = 0  # 1 user side disabled, 2 computer side disabled
    # low 16 bits of versionNumber; None when not collected
    machine_version: int | None = None
    # client-side extension GUIDs from gPCMachineExtensionNames; None when not collected
    machine_extensions: list[str] | None = None
    # name (or GUID, when unreadable) of the WMI filter
    wmi_filter: str | None = None


@dataclass
class GpoLocalGroup:
    """One membership entry of Restricted Groups (GptTmpl.inf) or GPP Local Groups."""

    gpo: str  # GPO GUID, upper case with braces
    source: str  # "restricted" or "gpp"
    path: str  # SYSVOL-relative file
    group_sid: str  # "" when not resolved
    group_name: str  # as written in the file
    member_sid: str  # "" when not resolved, and for a clear
    member_name: str  # as written ("" for a clear)
    action: str  # "add", "remove" or "set" (Restricted Groups X__Members)
    # the group's other members are removed: X__Members, GPP action R, deleteAll*
    replaces: bool = False
    disabled: bool = False  # GPP item (or its collection) disabled
    filtered: bool = False  # GPP item-level targeting present


@dataclass
class DirObject:
    """Any directory object whose permissions or members matter for control paths."""

    dn: str
    name: str
    kind: str  # user, computer, group, gpo, ou, domain, container, gmsa
    sid: str = ""
    owner: str | None = None
    aces: list[Ace] = field(default_factory=list)
    dacl_protected: bool = False
    # direct members (DNs) for groups
    members: list[str] = field(default_factory=list)
    # ACEs that child objects inherit (OUs, containers, the domain head)
    inheritable: list[Ace] = field(default_factory=list)
    # OU or domain head with Block Inheritance (gPOptions & 1)
    gp_blocked: bool = False

    def rid_is(self, snap: Snapshot, rid: int) -> bool:
        return self.sid == f"{snap.domain_sid}-{rid}"


@dataclass
class GpoSettings:
    """Security settings from a GPO's GptTmpl.inf that matter for the checks."""

    lm_compatibility: int | None = None
    no_lm_hash: int | None = None
    clear_text_password: int | None = None
    # MSV1_0\RestrictSendingNTLMTraffic: 0 allow, 1 audit, 2 deny
    restrict_sending_ntlm: int | None = None
    # MSV1_0\ClientAllowedNTLMServers: servers the deny does not cover
    ntlm_exceptions: list[str] = field(default_factory=list)
    # Netlogon\\Parameters\\VulnerableChannelAllowList: an SDDL string
    vulnerable_channel_allow: str | None = None
    # privilege constant -> SIDs (or names) granted
    privileges: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ScriptSecret:
    path: str
    line: int
    kind: str


@dataclass
class Gmsa:
    name: str
    dn: str
    # SIDs allowed to retrieve the password (msDS-GroupMSAMembership)
    readers: list[str]


@dataclass
class Rodc:
    name: str
    reveal: list[str]  # msDS-RevealOnDemandGroup DNs
    never_reveal: list[str]  # msDS-NeverRevealGroup DNs


@dataclass
class DcProbe:
    """Probe results for one domain controller; None means not run or inconclusive."""

    name: str
    ldap_signing_required: bool | None = None
    smb_signing_required: bool | None = None
    spooler: bool | None = None
    ldaps_channel_binding_required: bool | None = None
    # why the DC could not be probed (unreachable, no credentials, ...)
    error: str | None = None


DEFAULT_POLICY_MODULE = "CertificateAuthority_MicrosoftDefault.Policy"


@dataclass
class CaConfig:
    """An enterprise CA's own configuration, read from its registry over MS-RRP.

    None means unknown (not readable, value absent, or owned by a third-party policy
    module), never "off".
    """

    name: str  # CA name as the registry knows it (Configuration\Active)
    host: str  # dNSHostName of the enrollment service
    policy_module: str | None = None
    edit_flags: int | None = None
    interface_flags: int | None = None
    request_disposition: int | None = None
    disabled_extensions: list[str] | None = None
    # CA\\AuditFilter; None when absent (audit_absent) or unreadable
    audit_filter: int | None = None
    # the read of AuditFilter was attempted (False in older snapshots)
    audit_checked: bool = False
    # the read worked and the value does not exist; an error leaves this False
    audit_absent: bool = False
    # allow ACEs of the CA security descriptor, with CA rights masks (sd.CA_*)
    aces: list[Ace] = field(default_factory=list)
    owner: str | None = None
    # why the configuration could not be read
    error: str | None = None

    @property
    def third_party_policy(self) -> bool:
        return self.policy_module is not None and (
            self.policy_module.lower() != DEFAULT_POLICY_MODULE.lower()
        )


@dataclass
class UnreadableMember:
    """A DN in the member attribute of a tier-0 group that the scan could not read."""

    dn: str
    group: str
    reason: str


@dataclass
class Probes:
    """Results of the active network checks; None means not run or inconclusive."""

    spooler_on_dc: bool | None = None
    smb_signing_required: bool | None = None
    ldaps_channel_binding_required: bool | None = None
    # web enrollment URLs that answered with NTLM over plain HTTP (ESC8)
    web_enrollment_ntlm: list[str] = field(default_factory=list)
    # every DC that was probed, the scanned one included (empty in older snapshots)
    dcs: list[DcProbe] = field(default_factory=list)
    # configuration of each enterprise CA (empty when not read, and in older snapshots)
    ca_configs: list[CaConfig] = field(default_factory=list)

    def per_dc(self, attr: str, fallback: bool | None, scanned: str) -> dict[str, bool | None]:
        """DC name -> result of one probe; older snapshots only hold the scanned DC."""
        if self.dcs:
            return {d.name: getattr(d, attr) for d in self.dcs}
        return {scanned: fallback}

    def overall(self, attr: str, fallback: bool | None) -> bool | None:
        """False if any probed DC failed, True if every probed DC passed, else None."""
        values = [getattr(d, attr) for d in self.dcs] if self.dcs else [fallback]
        if False in values:
            return False
        known = [v for v in values if v is not None]
        return True if known and len(known) == len(values) else None


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
    # DACLs of security-critical objects ("domain", "AdminSDHolder", PKI objects)
    acls: dict[str, list[Ace]] = field(default_factory=dict)
    # SID -> account or group name, for the trustees that appear in acls/templates
    principals: dict[str, str] = field(default_factory=dict)
    gpp_passwords: list[GppPassword] = field(default_factory=list)
    trusts: list[Trust] = field(default_factory=list)
    gpos: list[Gpo] = field(default_factory=list)
    # issuance policy OID -> group DN (msDS-OIDToGroupLink)
    oid_group_links: dict[str, str] = field(default_factory=dict)
    # computer accounts (sAMAccountName) of the enterprise CA servers
    ca_hosts: list[str] = field(default_factory=list)
    # SID of the forest root domain (differs from domain_sid in child domains)
    root_sid: str = ""
    dns_admins: list[str] = field(default_factory=list)
    # direct members of Pre-Windows 2000 Compatible Access
    pre2k_members: list[str] = field(default_factory=list)
    ds_heuristics: str = ""
    recycle_bin: bool | None = None
    # None when the probe did not run
    ldap_signing_required: bool | None = None
    probes: Probes = field(default_factory=Probes)
    # groups, OUs, tier-0 objects, GPOs, the domain head: DACLs, owners, members
    objects: list[DirObject] = field(default_factory=list)
    gpo_settings: dict[str, GpoSettings] = field(default_factory=dict)
    script_secrets: list[ScriptSecret] = field(default_factory=list)
    gmsas: list[Gmsa] = field(default_factory=list)
    rodcs: list[Rodc] = field(default_factory=list)
    # when the domain partition was last backed up (dSASignature); None if never
    last_backup: datetime | None = None
    # whether the replication metadata holding the backup time could be read
    backup_checked: bool = False
    # whether any fine-grained password policy was readable
    psos_visible: bool = False
    # whether any dMSA came back; a plain user normally sees none, even when they exist.
    # None in older snapshots, which did not record it.
    dmsa_visible: bool | None = False
    # local group membership set by Restricted Groups and GPP Local Groups
    gpo_local_groups: list[GpoLocalGroup] = field(default_factory=list)
    # False in older snapshots and when SYSVOL was not read: "not collected", not "clean"
    local_groups_collected: bool = False
    # False in older snapshots and when SYSVOL was not read: NTLM policy is unknown
    ntlm_policy_collected: bool = False
    # False in older snapshots and when no nTDSDSA object could be read
    dc_registration_checked: bool = False
    # False in older snapshots and when SYSVOL was not read: the Netlogon allow list is unknown
    channel_policy_collected: bool = False
    # whenCreated of Read-only Domain Controllers: the domain's first Server 2008 DC
    aes_cutover: datetime | None = None
    # False in older snapshots: Account.pwd_changed was not read
    pwd_metadata_checked: bool = False
    key_credentials_checked: bool = False
    # members of tier-0 groups that did not come back from the searches
    unreadable_members: list[UnreadableMember] = field(default_factory=list)
    # False in older snapshots and when the comparison could not be made
    tier0_members_checked: bool = False
    # DC computer DN (lower case) -> DN of its site
    dc_sites: dict[str, str] = field(default_factory=dict)
    site_count: int = 0
    # parts of the collection that could not run (no AD CS, SYSVOL unreachable, ...)
    notes: list[str] = field(default_factory=list)

    @property
    def has_2025(self) -> bool:
        """The domain looks like it has a Windows Server 2025 DC."""
        return self.policy.functional_level >= 10 or any(
            a.is_dc and a.os and "2025" in a.os for a in self.accounts
        )

    def by_dn(self) -> dict[str, Account]:
        return {a.dn.lower(): a for a in self.accounts}

    def privileged_dns(self) -> set[str]:
        return {dn.lower() for members in self.privileged.values() for dn in members}

    def object_by_dn(self) -> dict[str, DirObject]:
        return {o.dn.lower(): o for o in self.objects}

    def tier0_dns(self) -> set[str]:
        """Lower-cased DNs of tier-0 accounts, groups and domain controllers."""
        tier0 = self.tier0_sids()
        dns = self.privileged_dns()
        dns |= {a.dn.lower() for a in self.accounts if a.is_dc or a.sam.lower() == "krbtgt"}
        dns |= {o.dn.lower() for o in self.objects if o.sid in tier0}
        return dns

    def name_of(self, sid: str) -> str:
        if sid in self.principals:
            return self.principals[sid]
        rid = sid.removeprefix(self.domain_sid + "-")
        return WELL_KNOWN_RIDS.get(rid, WELL_KNOWN_SIDS.get(sid, sid))

    def broad_sids(self) -> set[str]:
        """Groups every (or nearly every) account belongs to."""
        return BROAD_SIDS | {f"{self.domain_sid}-{rid}" for rid in BROAD_RIDS}

    def tier0_sids(self) -> set[str]:
        """Principals that are expected to hold control over the domain.

        In a child domain the forest-wide groups (Enterprise/Schema Admins, Enterprise
        RODCs) and the root domain's admins live under the forest root's SID.
        """
        sids = TIER0_SIDS | {f"{self.domain_sid}-{rid}" for rid in TIER0_RIDS}
        if self.root_sid and self.root_sid != self.domain_sid:
            sids |= {f"{self.root_sid}-{rid}" for rid in FOREST_ROOT_RIDS}
        return sids

    def to_json(self) -> dict[str, Any]:
        return _encode(asdict(self))  # type: ignore[no-any-return]

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Snapshot:
        collected = _dt(data["collected_at"])
        assert collected is not None
        return cls(
            domain=data["domain"],
            domain_dn=data["domain_dn"],
            domain_sid=data["domain_sid"],
            collected_at=collected,
            policy=DomainPolicy(**data["policy"]),
            accounts=[
                Account(
                    **{
                        **a,
                        "pwd_last_set": _dt(a["pwd_last_set"]),
                        "pwd_changed": _dt(a.get("pwd_changed")),
                        "last_logon": _dt(a["last_logon"]),
                        "when_created": _dt(a.get("when_created")),
                        "key_credentials": [
                            _key_credential(k) for k in a.get("key_credentials", [])
                        ],
                    }
                )
                for a in data["accounts"]
            ],
            privileged=data["privileged"],
            protected_users=data["protected_users"],
            templates=[
                CertTemplate(**{**t, "aces": _aces(t["aces"])}) for t in data.get("templates", [])
            ],
            acls={k: _aces(v) for k, v in data.get("acls", {}).items()},
            principals=data.get("principals", {}),
            gpp_passwords=[GppPassword(**g) for g in data.get("gpp_passwords", [])],
            trusts=[Trust(**t) for t in data.get("trusts", [])],
            gpos=[
                Gpo(
                    **{
                        **g,
                        "aces": _aces(g["aces"]),
                        "links": [GpLink(**x) for x in g.get("links", [])],
                    }
                )
                for g in data.get("gpos", [])
            ],
            oid_group_links=data.get("oid_group_links", {}),
            ca_hosts=data.get("ca_hosts", []),
            root_sid=data.get("root_sid", ""),
            probes=_probes(data.get("probes", {})),
            objects=[
                DirObject(
                    **{
                        **o,
                        "aces": _aces(o["aces"]),
                        "inheritable": _aces(o.get("inheritable", [])),
                    }
                )
                for o in data.get("objects", [])
            ],
            gpo_settings={k: GpoSettings(**v) for k, v in data.get("gpo_settings", {}).items()},
            script_secrets=[ScriptSecret(**x) for x in data.get("script_secrets", [])],
            gmsas=[Gmsa(**x) for x in data.get("gmsas", [])],
            rodcs=[Rodc(**x) for x in data.get("rodcs", [])],
            last_backup=_dt(data.get("last_backup")),
            backup_checked=data.get("backup_checked", False),
            psos_visible=data.get("psos_visible", False),
            dmsa_visible=data.get("dmsa_visible"),
            gpo_local_groups=[GpoLocalGroup(**x) for x in data.get("gpo_local_groups", [])],
            local_groups_collected=data.get("local_groups_collected", False),
            ntlm_policy_collected=data.get("ntlm_policy_collected", False),
            dc_registration_checked=data.get("dc_registration_checked", False),
            channel_policy_collected=data.get("channel_policy_collected", False),
            aes_cutover=_dt(data.get("aes_cutover")),
            pwd_metadata_checked=data.get("pwd_metadata_checked", False),
            key_credentials_checked=data.get("key_credentials_checked", False),
            unreadable_members=[UnreadableMember(**x) for x in data.get("unreadable_members", [])],
            tier0_members_checked=data.get("tier0_members_checked", False),
            dc_sites=data.get("dc_sites", {}),
            site_count=data.get("site_count", 0),
            dns_admins=data.get("dns_admins", []),
            pre2k_members=data.get("pre2k_members", []),
            ds_heuristics=data.get("ds_heuristics", ""),
            recycle_bin=data.get("recycle_bin"),
            ldap_signing_required=data.get("ldap_signing_required"),
            notes=[*data.get("notes", []), *_older_snapshot_notes(data)],
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
    "S-1-5-4": "Interactive",
    "S-1-5-15": "This Organization",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-578": "Hyper-V Administrators",
    "S-1-5-32-580": "Remote Management Users",
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
# English names of the built-in and well-known principals local group settings name.
# Localized names are left unresolved and reported rather than guessed.
WELL_KNOWN_NAMES = {
    "administrators": "S-1-5-32-544",
    "users": "S-1-5-32-545",
    "guests": "S-1-5-32-546",
    "backup operators": "S-1-5-32-551",
    "remote desktop users": "S-1-5-32-555",
    "distributed com users": "S-1-5-32-562",
    "hyper-v administrators": "S-1-5-32-578",
    "remote management users": "S-1-5-32-580",
    "everyone": "S-1-1-0",
    "authenticated users": "S-1-5-11",
    "interactive": "S-1-5-4",
}


def well_known_sid(name: str) -> str:
    """SID of a built-in or well-known name such as 'BUILTIN\\Administrators' or
    'Administrators (built-in)'; "" for anything else."""
    key = name.strip().lower().removesuffix("(built-in)").strip()
    for prefix in ("builtin\\", "nt authority\\"):
        key = key.removeprefix(prefix)
    return WELL_KNOWN_NAMES.get(key, "")


# Pre-Windows 2000 Compatible Access holds Authenticated Users on a default domain
BROAD_SIDS = {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-554"}
BROAD_RIDS = {"513", "514", "515"}
# groups Exchange setup creates; their rights over the domain are the PrivExchange problem
EXCHANGE_GROUPS = {
    "exchange windows permissions",
    "exchange trusted subsystem",
    "organization management",
}
TIER0_SIDS = {"S-1-5-9", "S-1-5-18", "S-1-5-32-544"}
TIER0_RIDS = {"498", "500", "512", "516", "518", "519", "521"}
FOREST_ROOT_RIDS = {"498", "500", "512", "518", "519"}


def exchange_members(objects: list[DirObject]) -> set[str]:
    """Lower-cased DNs of every transitive member of the Exchange groups."""
    groups = {o.dn.lower(): o for o in objects if o.kind == "group"}
    todo = [o.dn.lower() for o in groups.values() if o.name.lower() in EXCHANGE_GROUPS]
    seen: set[str] = set()
    while todo:
        dn = todo.pop()
        for m in groups[dn].members if dn in groups else []:
            key = m.lower()
            if key not in seen:
                seen.add(key)
                todo.append(key)
    return seen - {dn for dn in groups if groups[dn].name.lower() in EXCHANGE_GROUPS}


def _older_snapshot_notes(data: dict[str, Any]) -> list[str]:
    missing = [
        text
        for key, text in (
            ("dc_registration_checked", "AD-INF-014 (rogue DC objects)"),
            ("aes_cutover", "the password part of AD-KRB-005 (suspected no AES keys)"),
            ("pwd_metadata_checked", "AD-ACC-012 (pwdLastSet against replication metadata)"),
            ("key_credentials_checked", "the key credential part of AD-ACC-013"),
            ("channel_policy_collected", "AD-GPO-008 (Netlogon allow list)"),
            ("tier0_members_checked", "AD-PRIV-012 (unreadable tier-0 members)"),
        )
        if key not in data
    ]
    cas = data.get("probes", {}).get("ca_configs", [])
    if any("audit_checked" not in c for c in cas):
        missing.append("AD-ADCS-018 (CA audit filter)")
    notes = [f"snapshot from an older version: {text} not evaluated" for text in missing]
    if "dmsa_visible" not in data:
        notes.append(
            "snapshot from an older version: whether a dMSA was visible is not recorded, so "
            "AD-INF-007 may not have seen existing dMSA links"
        )
    return notes


def _key_credential(data: dict[str, Any]) -> KeyCredential:
    return KeyCredential(**{**data, "created": _dt(data["created"]), "added": _dt(data["added"])})


def _aces(items: list[dict[str, Any]]) -> list[Ace]:
    return [Ace(**a) for a in items]


def _probes(data: dict[str, Any]) -> Probes:
    return Probes(
        **{
            **data,
            "dcs": [DcProbe(**d) for d in data.get("dcs", [])],
            "ca_configs": [
                CaConfig(**{**c, "aces": _aces(c.get("aces", []))})
                for c in data.get("ca_configs", [])
            ],
        }
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
    mitre: list[str] = field(default_factory=list)
    # object -> stable identity, for objects whose text carries context that changes
    # between runs (AD-PATH-001 shows a whole path; its identity is the start principal).
    # Fingerprints, baselines and diffs use the identity; objects without one use the text.
    keys: dict[str, str] = field(default_factory=dict)
    # structured data for viewers, e.g. AD-PATH-001's paths step by step (JSON types only)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def category(self) -> str:
        return CATEGORIES[self.check_id.split("-")[1]]

    def key(self, obj: str) -> str:
        return self.keys.get(obj, obj)


CATEGORIES = {
    "ACC": "Accounts",
    "KRB": "Kerberos",
    "DEL": "Delegation",
    "PRIV": "Privileged access",
    "POL": "Policy",
    "SEC": "Hardening",
    "INF": "Infrastructure",
    "ADCS": "Certificate services",
    "ACL": "Permissions",
    "GPP": "Group Policy",
    "GPO": "Group Policy",
    "PATH": "Attack paths",
    "CHAIN": "Attack paths",
    "INV": "Invariants",
}
