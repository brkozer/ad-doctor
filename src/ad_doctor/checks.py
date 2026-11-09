"""Checks: pure functions from a Snapshot to findings.

Each check returns at most one Finding that lists every affected object, so the report
stays one line per problem rather than one line per account.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

from . import auditpol, catalog, gpo_scope, regpol, sd
from .gpo_scope import LOCAL_GROUPS, Grant
from .model import (
    EXCHANGE_GROUPS,
    SILO_LEVEL,
    UAC,
    Account,
    AuthPolicy,
    AuthSilo,
    CaConfig,
    CertTemplate,
    Dmsa,
    Finding,
    KeyCredential,
    Pso,
    Severity,
    Snapshot,
    Trust,
    dns_host_matches,
    exchange_members,
    invisible_chars,
)

CheckFn = Callable[[Snapshot], Finding | None]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    fn: CheckFn


REGISTRY: list[Check] = []


def check(check_id: str, title: str) -> Callable[[CheckFn], CheckFn]:
    def register(fn: CheckFn) -> CheckFn:
        REGISTRY.append(Check(check_id, title, fn))
        return fn

    return register


def run_all(snap: Snapshot, only: Iterable[str] | None = None) -> list[Finding]:
    wanted = {c.upper() for c in only} if only else None
    findings = []
    for c in REGISTRY:
        if wanted is not None and c.id not in wanted:
            continue
        f = c.fn(snap)
        if f is not None:
            findings.append(f)
    return sorted(findings, key=lambda f: (-f.severity, f.check_id))


def _enabled_users(snap: Snapshot) -> list[Account]:
    # gMSA/sMSA/dMSA have 240-byte random passwords: not users for these checks
    return [a for a in snap.accounts if a.enabled and not a.is_computer and not a.managed]


def _names(accounts: Iterable[Account]) -> list[str]:
    return sorted(a.sam for a in accounts)


def _finding(
    check_id: str,
    severity: Severity,
    detail: str,
    remediation: str,
    objects: list[str],
) -> Finding:
    title = next(c.title for c in REGISTRY if c.id == check_id)
    return Finding(
        check_id, title, severity, detail, remediation, objects, list(MITRE.get(check_id, ()))
    )


class _Mitre(Mapping[str, tuple[str, ...]]):
    """Check ID -> MITRE ATT&CK techniques, from the catalog entries; checks without a
    technique (hygiene, invariants) are absent. Read on first use, so importing this
    module does not parse the catalog."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, ...]] | None = None

    def _load(self) -> dict[str, tuple[str, ...]]:
        if self._data is None:
            self._data = {cid: e.mitre for cid, e in catalog.load().items() if e.mitre}
        return self._data

    def __getitem__(self, check_id: str) -> tuple[str, ...]:
        return self._load()[check_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._load())

    def __len__(self) -> int:
        return len(self._load())


MITRE: Mapping[str, tuple[str, ...]] = _Mitre()


KRBTGT_MAX_AGE = timedelta(days=180)
STALE_AFTER = timedelta(days=90)
# a DC changes its machine password every 30 days by default
DC_PASSWORD_REVIEW = timedelta(days=45)
DC_PASSWORD_OLD = timedelta(days=180)
GMSA_INTERVAL_REVIEW_DAYS = 90
SYSVOL_START = 0
SYSVOL_PREPARED = 16
SYSVOL_REDIRECTED = 32
SYSVOL_ELIMINATED = 48
# the same bar as AD-POL-001
PSO_MIN_LENGTH = 12
# Microsoft sets no interval and says to rotate it on the schedule of the other krbtgt keys
ENTRA_KEY_REVIEW = KRBTGT_MAX_AGE
DMSA_MIGRATING = 1
DMSA_MIGRATED = 2
DMSA_USE_RIGHT = "allowed to use it"
# the names Microsoft gives the Entra Kerberos objects; a name alone proves nothing
ENTRA_KERBEROS_COMPUTER = "azureadkerberos$"
ENTRA_KERBEROS_USERS = ("krbtgt_azuread", "krbtgt-azuread")


@check("AD-KRB-001", "krbtgt password not rotated recently")
def krbtgt_age(snap: Snapshot) -> Finding | None:
    krbtgt = next((a for a in snap.accounts if a.sam.lower() == "krbtgt"), None)
    changed = krbtgt.password_changed if krbtgt else None
    if changed is None:
        return None
    age = snap.collected_at - changed
    if age <= KRBTGT_MAX_AGE:
        return None
    return _finding(
        "AD-KRB-001",
        Severity.HIGH,
        f"krbtgt password is {age.days} days old; forged tickets stay valid until it changes.",
        "Rotate the krbtgt password twice, waiting for replication between the two resets.",
        ["krbtgt"],
    )


@check("AD-KRB-002", "Accounts without Kerberos pre-authentication (AS-REP roasting)")
def asrep_roastable(snap: Snapshot) -> Finding | None:
    hits = [a for a in _enabled_users(snap) if a.has(UAC.DONT_REQ_PREAUTH)]
    if not hits:
        return None
    return _finding(
        "AD-KRB-002",
        Severity.HIGH,
        "Anyone can request an AS-REP for these accounts and crack the password offline.",
        "Clear 'Do not require Kerberos preauthentication' on each account.",
        _names(hits),
    )


@check("AD-KRB-003", "User accounts with SPNs (Kerberoasting)")
def kerberoastable(snap: Snapshot) -> Finding | None:
    hits = [a for a in _enabled_users(snap) if a.spns and a.sam.lower() != "krbtgt"]
    if not hits:
        return None
    privileged = snap.privileged_dns()
    priv_hits = [a for a in hits if a.dn.lower() in privileged or a.admin_count]
    severity = Severity.HIGH if priv_hits else Severity.MEDIUM
    detail = "Any domain user can request a service ticket for these accounts and crack it offline."
    if priv_hits:
        detail += f" Privileged: {', '.join(_names(priv_hits))}."
    return _finding(
        "AD-KRB-003",
        severity,
        detail,
        "Use gMSAs for services; otherwise set 25+ character passwords and AES-only encryption.",
        _names(hits),
    )


@check("AD-KRB-004", "Accounts limited to DES encryption")
def des_only(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.enabled and a.has(UAC.USE_DES_KEY_ONLY)]
    if not hits:
        return None
    return _finding(
        "AD-KRB-004",
        Severity.MEDIUM,
        "DES is broken and disabled by default since Windows 7 / Server 2008 R2.",
        "Clear 'Use only Kerberos DES encryption types' and reset the password.",
        _names(hits),
    )


@check("AD-DEL-001", "Unconstrained delegation outside domain controllers")
def unconstrained_delegation(snap: Snapshot) -> Finding | None:
    hits = [
        a
        for a in snap.accounts
        if a.enabled and a.has(UAC.TRUSTED_FOR_DELEGATION) and not a.is_registered_dc
    ]
    if not hits:
        return None
    return _finding(
        "AD-DEL-001",
        Severity.HIGH,
        "These hosts keep the TGT of every user who authenticates to them; "
        "coercing a DC to connect yields domain compromise.",
        "Switch to constrained or resource-based delegation, or remove delegation.",
        _names(hits),
    )


@check("AD-DEL-002", "Constrained delegation with protocol transition")
def protocol_transition(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.enabled and a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)]
    if not hits:
        return None
    return _finding(
        "AD-DEL-002",
        Severity.MEDIUM,
        "These accounts can impersonate any user to their delegation targets "
        "without that user's credentials (S4U2Self).",
        "Use Kerberos-only constrained delegation where possible; review the target SPNs.",
        [f"{a.sam} -> {', '.join(a.allowed_to_delegate_to) or '?'}" for a in hits],
    )


@check("AD-DEL-003", "Resource-based constrained delegation configured")
def rbcd(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.rbcd]
    if not hits:
        return None
    return _finding(
        "AD-DEL-003",
        Severity.LOW,
        "msDS-AllowedToActOnBehalfOfOtherIdentity is set; verify each entry is intended.",
        "Remove entries that are not needed.",
        _names(hits),
    )


@check("AD-ACC-001", "Enabled accounts allowed an empty password")
def passwd_notreqd(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.enabled and a.has(UAC.PASSWD_NOTREQD)]
    if not hits:
        return None
    return _finding(
        "AD-ACC-001",
        Severity.MEDIUM,
        "PASSWD_NOTREQD lets the password be set to empty regardless of policy.",
        "Clear the flag: Set-ADUser <name> -PasswordNotRequired $false.",
        _names(hits),
    )


@check("AD-ACC-002", "Reversible password encryption")
def reversible(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.enabled and a.has(UAC.ENCRYPTED_TEXT_PWD_ALLOWED)]
    if not hits:
        return None
    return _finding(
        "AD-ACC-002",
        Severity.HIGH,
        "Passwords for these accounts are stored in a form equivalent to plain text.",
        "Clear 'Store password using reversible encryption' and reset the passwords.",
        _names(hits),
    )


@check("AD-ACC-003", "Privileged accounts whose password never expires")
def privileged_no_expiry(snap: Snapshot) -> Finding | None:
    privileged = snap.privileged_dns()
    hits = [
        a
        for a in _enabled_users(snap)
        if a.dn.lower() in privileged and a.has(UAC.DONT_EXPIRE_PASSWORD)
    ]
    if not hits:
        return None
    return _finding(
        "AD-ACC-003",
        Severity.MEDIUM,
        "Tier-0 credentials that never rotate stay useful to an attacker indefinitely.",
        "Remove 'Password never expires' and rotate on a schedule, or use a PAM solution.",
        _names(hits),
    )


@check("AD-ACC-004", "Guest account enabled")
def guest_enabled(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.sam.lower() == "guest" and a.enabled]
    if not hits:
        return None
    return _finding(
        "AD-ACC-004",
        Severity.HIGH,
        "The built-in Guest account allows unauthenticated-style access to the domain.",
        "Disable the Guest account.",
        _names(hits),
    )


@check("AD-ACC-005", "Stale enabled user accounts")
def stale_users(snap: Snapshot) -> Finding | None:
    cutoff = snap.collected_at - STALE_AFTER
    hits = [
        a
        for a in _enabled_users(snap)
        if a.sam.lower() not in {"krbtgt", "guest"}
        and (a.last_logon or a.pwd_last_set or cutoff) < cutoff
    ]
    if not hits:
        return None
    return _finding(
        "AD-ACC-005",
        Severity.LOW,
        f"{len(hits)} enabled users have not logged on in {STALE_AFTER.days}+ days.",
        "Disable, then delete after a grace period.",
        _names(hits),
    )


@check("AD-ACC-014", "Stale enabled computer accounts")
def stale_computers(snap: Snapshot) -> Finding | None:
    cutoff = snap.collected_at - STALE_AFTER
    hits = []
    for a in snap.accounts:
        if not a.is_computer or not a.enabled or a.managed or a.is_registered_dc:
            continue
        if a.sam.upper() == "AZUREADSSOACC$":  # never logs on; AD-KRB-006 watches its key
            continue
        # a machine that is online changes its password, so the newest date counts
        seen = [t for t in (a.last_logon, a.pwd_last_set, a.when_created) if t is not None]
        if seen and max(seen) < cutoff:
            hits.append(a)
    if not hits:
        return None
    return _finding(
        "AD-ACC-014",
        Severity.LOW,
        f"{len(hits)} enabled computers show no logon, password change or creation in the last "
        f"{STALE_AFTER.days} days. Review them: appliances and cluster objects can look like this.",
        "Confirm the machine is gone, disable the account, then delete it after a grace period.",
        _names(hits),
    )


@check("AD-ACC-015", "gMSA passwords with a long rotation interval")
def gmsa_long_interval(snap: Snapshot) -> Finding | None:
    hits = sorted(
        (g.name, g.interval_days)
        for g in snap.gmsas
        if g.interval_days is not None and g.interval_days > GMSA_INTERVAL_REVIEW_DAYS
    )
    if not hits:
        return None
    return _finding(
        "AD-ACC-015",
        Severity.LOW,
        f"These gMSAs change their password less often than every {GMSA_INTERVAL_REVIEW_DAYS} "
        "days (the default is 30), so a password that was read stays valid for that long. "
        "Review whether the interval is intended.",
        "The interval is set at creation only: create a new gMSA with a shorter one and move "
        "the services to it.",
        [f"{name} ({days} days)" for name, days in hits],
    )


@check("AD-PRIV-001", "Large tier-0 groups")
def large_admin_groups(snap: Snapshot) -> Finding | None:
    limit = 5
    big = {g: m for g, m in snap.privileged.items() if len(m) > limit}
    if not big:
        return None
    return _finding(
        "AD-PRIV-001",
        Severity.LOW,
        f"Groups with more than {limit} transitive members: "
        + ", ".join(f"{g} ({len(m)})" for g, m in sorted(big.items())),
        "Keep tier-0 membership to a handful of named admin accounts.",
        sorted(big),
    )


@check("AD-PRIV-002", "Privileged accounts that can be delegated")
def privileged_delegable(snap: Snapshot) -> Finding | None:
    privileged = snap.privileged_dns()
    protected = {dn.lower() for dn in snap.protected_users}
    hits = [
        a
        for a in _enabled_users(snap)
        if a.dn.lower() in privileged
        and not a.has(UAC.NOT_DELEGATED)
        and a.dn.lower() not in protected
    ]
    if not hits:
        return None
    return _finding(
        "AD-PRIV-002",
        Severity.MEDIUM,
        "Their credentials can be forwarded by any service trusted for delegation.",
        "Add admins to Protected Users or set 'Account is sensitive and cannot be delegated'.",
        _names(hits),
    )


@check("AD-POL-001", "Weak default password policy")
def password_policy(snap: Snapshot) -> Finding | None:
    p = snap.policy
    issues = []
    if p.min_pwd_length < 12:
        issues.append(f"minimum length {p.min_pwd_length} (< 12)")
    if not p.pwd_complexity:
        issues.append("complexity disabled")
    if p.lockout_threshold == 0:
        issues.append("no account lockout")
    if not issues:
        return None
    return _finding(
        "AD-POL-001",
        Severity.MEDIUM,
        "Default Domain Policy: " + "; ".join(issues) + ".",
        "Raise the minimum length, enable complexity and set a lockout threshold "
        "(or use fine-grained policies for the accounts that need them).",
        [snap.domain],
    )


@check("AD-POL-002", "Any user can join computers to the domain")
def machine_account_quota(snap: Snapshot) -> Finding | None:
    quota = snap.policy.machine_account_quota
    if quota <= 0:
        return None
    return _finding(
        "AD-POL-002",
        Severity.MEDIUM,
        f"ms-DS-MachineAccountQuota is {quota}; any user can create computer accounts, "
        "a common step in RBCD and relay attacks.",
        "Set ms-DS-MachineAccountQuota to 0 and delegate domain join to a dedicated group.",
        [snap.domain],
    )


@check("AD-SEC-001", "Computers without LAPS")
def laps_missing(snap: Snapshot) -> Finding | None:
    hits = [
        a
        for a in snap.accounts
        if a.is_computer
        and a.enabled
        and not a.is_registered_dc
        and not a.laps
        # cluster names, NAS and Linux joins have no local admin for LAPS to manage
        and (a.os is None or "windows" in a.os.lower())
    ]
    if not hits:
        return None
    return _finding(
        "AD-SEC-001",
        Severity.MEDIUM,
        f"{len(hits)} computers have no LAPS-managed local admin password; "
        "shared local admin passwords allow lateral movement.",
        "Deploy Windows LAPS and confirm the policy applies to these computers.",
        _names(hits),
    )


# --- AD CS ---------------------------------------------------------------------------

EKU_CLIENT_AUTH = {
    "1.3.6.1.5.5.7.3.2",  # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
}
EKU_ANY = "2.5.29.37.0"
EKU_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


def _broad_enroll(snap: Snapshot, t: CertTemplate) -> list[str]:
    broad = snap.broad_sids()
    return sorted(
        {
            snap.name_of(a.sid)
            for a in t.aces
            if a.sid in broad
            and (a.extended_right(sd.CERT_ENROLL) or a.extended_right(sd.CERT_AUTOENROLL))
        }
    )


def _issuable(t: CertTemplate) -> bool:
    """Published and issued without a human or an enrollment agent in the loop."""
    return t.published and not t.manager_approval and t.authorized_signatures == 0


def _template_finding(
    snap: Snapshot,
    check_id: str,
    detail: str,
    remediation: str,
    match: Callable[[CertTemplate], bool],
    severity: Severity = Severity.HIGH,
) -> Finding | None:
    hits = []
    for t in snap.templates:
        who = _broad_enroll(snap, t)
        if who and _issuable(t) and match(t):
            hits.append(f"{t.name} (enroll: {', '.join(who)})")
    if not hits:
        return None
    return _finding(check_id, severity, detail, remediation, sorted(hits))


@check("AD-ADCS-001", "ESC1: enrollee-supplied subject on an authentication template")
def esc1(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-001",
        "Any member of the enrolling group can request a certificate for any user, "
        "including a domain admin, and authenticate as them.",
        "Clear 'Supply in the request', require manager approval, or restrict enrollment.",
        lambda t: (
            t.enrollee_supplies_subject
            and (not t.ekus or EKU_ANY in t.ekus or bool(EKU_CLIENT_AUTH & set(t.ekus)))
        ),
    )


@check("AD-ADCS-002", "ESC2: any-purpose or no-EKU template")
def esc2(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-002",
        "Certificates from these templates are valid for any purpose, including "
        "acting as an enrollment agent or a subordinate CA.",
        "Set explicit EKUs, require manager approval, or restrict enrollment.",
        lambda t: not t.ekus or EKU_ANY in t.ekus,
    )


@check("AD-ADCS-003", "ESC3: enrollment agent template open to broad groups")
def esc3(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-003",
        "An enrollment agent certificate lets its holder request certificates on behalf "
        "of other users.",
        "Restrict enrollment to the agents that need it and configure enrollment agent "
        "restrictions on the CA.",
        lambda t: EKU_REQUEST_AGENT in t.ekus,
    )


@check("AD-ADCS-004", "ESC4: broad groups can modify a certificate template")
def esc4(snap: Snapshot) -> Finding | None:
    broad = snap.broad_sids()
    hits = []
    for t in snap.templates:
        who = sorted({snap.name_of(a.sid) for a in t.aces if a.sid in broad and a.takeover})
        if who:
            hits.append(f"{t.name} ({', '.join(who)})")
    if not hits:
        return None
    return _finding(
        "AD-ADCS-004",
        Severity.HIGH,
        "Write access to a template lets an attacker reconfigure it into an ESC1 template.",
        "Remove write, WriteDacl and WriteOwner rights from these groups on the template.",
        sorted(hits),
    )


# --- ACLs ----------------------------------------------------------------------------


@check("AD-ACL-001", "Non-default principals with DCSync rights")
def dcsync(snap: Snapshot) -> Finding | None:
    aces = snap.acls.get("domain", [])
    tier0 = snap.tier0_sids()
    get = {a.sid for a in aces if a.extended_right(sd.DS_REPL_GET_CHANGES)}
    get_all = {a.sid for a in aces if a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)}
    hits = sorted(snap.name_of(s) for s in (get & get_all) - tier0)
    if not hits:
        return None
    return _finding(
        "AD-ACL-001",
        Severity.HIGH,
        "These principals can replicate password hashes from a DC, including krbtgt's.",
        "Remove the 'Replicating Directory Changes (All)' rights unless the account is a "
        "sanctioned sync service (e.g. Entra Connect), and then protect it as tier 0.",
        hits,
    )


def _takeover_finding(snap: Snapshot, key: str, check_id: str, detail: str) -> Finding | None:
    tier0 = snap.tier0_sids()
    hits = sorted(
        {snap.name_of(a.sid) for a in snap.acls.get(key, []) if a.takeover and a.sid not in tier0},
        key=str.lower,
    )
    if not hits:
        return None
    return _finding(
        check_id,
        Severity.HIGH,
        detail,
        "Remove GenericAll, GenericWrite, WriteDacl and WriteOwner grants for these principals.",
        hits,
    )


@check("AD-ACL-002", "Non-default control over AdminSDHolder")
def adminsdholder(snap: Snapshot) -> Finding | None:
    return _takeover_finding(
        snap,
        "AdminSDHolder",
        "AD-ACL-002",
        "SDProp copies the AdminSDHolder ACL onto every protected admin account and group "
        "every hour, so these principals end up controlling all of them.",
    )


@check("AD-ACL-003", "Non-default control over the domain object")
def domain_object_acl(snap: Snapshot) -> Finding | None:
    return _takeover_finding(
        snap,
        "domain",
        "AD-ACL-003",
        "Write access to the domain head lets these principals grant themselves DCSync "
        "or change domain-wide settings.",
    )


# --- SYSVOL --------------------------------------------------------------------------


@check("AD-GPP-001", "Passwords in Group Policy Preferences")
def gpp_passwords(snap: Snapshot) -> Finding | None:
    if not snap.gpp_passwords:
        return None
    return _finding(
        "AD-GPP-001",
        Severity.HIGH,
        "cpassword values in SYSVOL are encrypted with a key Microsoft published (MS14-025); "
        "every domain user can read and decrypt them.",
        "Delete the preference items, remove the XML files and change the passwords.",
        sorted(f"{g.path} ({g.user})" for g in snap.gpp_passwords),
    )


@check("AD-ADCS-005", "ESC5: non-tier-0 control over PKI objects")
def esc5(snap: Snapshot) -> Finding | None:
    # Cert Publishers (the CA servers' group) is expected to manage some PKI objects
    expected = snap.tier0_sids() | {f"{snap.domain_sid}-517"}
    hits = []
    for key, aces in sorted(snap.acls.items()):
        if not key.startswith("PKI:"):
            continue
        who = {snap.name_of(a.sid) for a in aces if a.takeover and a.sid not in expected}
        if key.startswith("PKI:CA "):
            ca_hosts = {h.upper() for h in snap.ca_hosts}
            who = {w for w in who if w.upper() not in ca_hosts}
        if who:
            hits.append(f"{key.removeprefix('PKI:')} ({', '.join(sorted(who))})")
    if not hits:
        return None
    return _finding(
        "AD-ADCS-005",
        Severity.HIGH,
        "Control over the CA objects, the template container or NTAuthCertificates lets "
        "these principals add rogue CAs or vulnerable templates.",
        "Remove write, WriteDacl and WriteOwner rights for these principals.",
        hits,
    )


@check("AD-ADCS-006", "ESC9: authentication template without the security extension")
def esc9(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-006",
        "Certificates from these templates carry no SID. On DCs without full certificate "
        "binding enforcement (the default only since the 2025 updates), anyone who can change "
        "a victim's UPN can then authenticate as that victim.",
        "Clear CT_FLAG_NO_SECURITY_EXTENSION and keep every domain controller on current "
        "updates (full enforcement, the only mode after the September 2025 updates).",
        lambda t: t.no_security_extension and _authenticates(t),
        Severity.MEDIUM,
    )


@check("AD-ADCS-007", "ESC13: issuance policy linked to a group")
def esc13(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-007",
        "Logging on with a certificate from these templates adds the linked group to the "
        "token, so every enrollee gets that group's rights.",
        "Remove the msDS-OIDToGroupLink or restrict enrollment to the group's members.",
        lambda t: _authenticates(t) and bool(linked_policies(snap, t)),
    )


@check("AD-ADCS-008", "ESC15: schema v1 template with enrollee-supplied subject")
def esc15(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-008",
        "Unpatched CAs let the requester add any application policy to a v1 template "
        "(CVE-2024-49019), turning it into a client authentication template.",
        "Install the November 2024 updates on the CA, then duplicate the template as v2+ "
        "or clear 'Supply in the request'.",
        lambda t: t.schema_version == 1 and t.enrollee_supplies_subject,
    )


def _authenticates(t: CertTemplate) -> bool:
    return not t.ekus or EKU_ANY in t.ekus or bool(EKU_CLIENT_AUTH & set(t.ekus))


def linked_policies(snap: Snapshot, t: CertTemplate) -> list[str]:
    """The template's issuance policies that msDS-OIDToGroupLink ties to a group: a logon
    with its certificate adds that group to the ticket (ESC13)."""
    return [p for p in t.issuance_policies if p in snap.oid_group_links]


# --- Group Policy --------------------------------------------------------------------


@check("AD-GPO-001", "GPOs reaching domain controllers editable outside tier 0")
def gpo_edit(snap: Snapshot) -> Finding | None:
    tier0 = snap.tier0_sids()
    hits = []
    for g in snap.gpos:
        who = sorted({snap.name_of(a.sid) for a in g.aces if a.takeover and a.sid not in tier0})
        if who and g.linked_to:
            hits.append(f"{g.name} -> {', '.join(g.linked_to)} ({', '.join(who)})")
    if not hits:
        return None
    return _finding(
        "AD-GPO-001",
        Severity.HIGH,
        "These GPOs apply to domain controllers; whoever can edit them can run code there.",
        "Restrict edit rights on GPOs linked to the domain or the Domain Controllers OU to "
        "tier-0 administrators.",
        sorted(hits),
    )


# --- Accounts and groups (continued) -------------------------------------------------


@check("AD-ACC-006", "adminCount set on accounts that are no longer privileged")
def admincount_orphans(snap: Snapshot) -> Finding | None:
    privileged = snap.privileged_dns()
    hits = [
        a
        for a in _enabled_users(snap)
        # krbtgt and the RODC krbtgt_NNNNN accounts are protected by design
        if a.admin_count
        and a.dn.lower() not in privileged
        and not a.sam.lower().startswith("krbtgt")
    ]
    if not hits:
        return None
    return _finding(
        "AD-ACC-006",
        Severity.LOW,
        "These accounts were once protected admins: inheritance is still disabled on them, "
        "and they are often forgotten former admins.",
        "Review each account, clear adminCount and re-enable inheritance.",
        _names(hits),
    )


PRIVILEGED_RID_SUFFIXES = ("-500", "-512", "-518", "-519")


@check("AD-ACC-007", "Accounts with SID history")
def sid_history(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.enabled and a.sid_history]
    if not hits:
        return None
    risky = [
        a
        for a in hits
        if any(
            s.endswith(PRIVILEGED_RID_SUFFIXES)
            or s == "S-1-5-32-544"
            or s.startswith(snap.domain_sid + "-")
            for s in a.sid_history
        )
    ]
    detail = "SID history grants the rights of the old SIDs at every logon."
    if risky:
        detail += (
            " Privileged or same-domain SIDs (a persistence technique): "
            f"{', '.join(_names(risky))}."
        )
    return _finding(
        "AD-ACC-007",
        Severity.HIGH if risky else Severity.MEDIUM,
        detail,
        "Clear sIDHistory once migrations are finished.",
        _names(hits),
    )


@check("AD-PRIV-003", "Schema Admins or Enterprise Admins not empty")
def standing_forest_admins(snap: Snapshot) -> Finding | None:
    groups = {g: snap.privileged.get(g, []) for g in ("Schema Admins", "Enterprise Admins")}
    by_dn = snap.by_dn()
    hits = sorted(
        f"{g}: {by_dn[dn.lower()].sam if dn.lower() in by_dn else dn}"
        for g, members in groups.items()
        for dn in members
    )
    if not hits:
        return None
    return _finding(
        "AD-PRIV-003",
        Severity.LOW,
        "Forest-wide admin groups should be empty except while a change is being made.",
        "Remove permanent members and add them only for the duration of a change.",
        hits,
    )


@check("AD-PRIV-004", "Members of DnsAdmins")
def dns_admins(snap: Snapshot) -> Finding | None:
    if not snap.dns_admins:
        return None
    by_dn = snap.by_dn()
    return _finding(
        "AD-PRIV-004",
        Severity.MEDIUM,
        "DnsAdmins can make the DNS service on a DC load an arbitrary DLL as SYSTEM.",
        "Treat DnsAdmins as tier 0 or empty it and delegate DNS record management instead.",
        sorted(by_dn[d.lower()].sam if d.lower() in by_dn else d for d in snap.dns_admins),
    )


@check("AD-PRIV-005", "Anonymous or Everyone in Pre-Windows 2000 Compatible Access")
def pre2k(snap: Snapshot) -> Finding | None:
    hits = sorted(
        name
        for sid, name in (("S-1-5-7", "Anonymous Logon"), ("S-1-1-0", "Everyone"))
        if any(m.upper().startswith(f"CN={sid},") for m in snap.pre2k_members)
    )
    if not hits:
        return None
    return _finding(
        "AD-PRIV-005",
        Severity.MEDIUM,
        "Unauthenticated users can enumerate users, groups and policy over legacy interfaces.",
        "Remove Anonymous Logon and Everyone from Pre-Windows 2000 Compatible Access.",
        hits,
    )


# --- Infrastructure ------------------------------------------------------------------

# (name pattern, end of extended support); the first match wins
OS_END_OF_SUPPORT = [
    (r"Windows 2000", date(2010, 7, 13)),
    (r"Windows XP", date(2014, 4, 8)),
    (r"Windows Vista", date(2017, 4, 11)),
    (r"Windows 7\b", date(2020, 1, 14)),
    (r"Windows 8\.1", date(2023, 1, 10)),
    (r"Windows 8\b", date(2016, 1, 12)),
    (r"Windows 10\b", date(2025, 10, 14)),
    (r"Windows Server 2003", date(2015, 7, 14)),
    (r"Windows Server 2008", date(2020, 1, 14)),
    (r"Windows Server 2012", date(2023, 10, 10)),
    (r"Windows Server 2016", date(2027, 1, 12)),
    (r"Windows Server 2019", date(2029, 1, 9)),
]


def end_of_support(os_name: str) -> date | None:
    for pattern, eol in OS_END_OF_SUPPORT:
        if re.search(pattern, os_name):
            return eol
    return None


@check("AD-INF-001", "Computers running unsupported Windows versions")
def obsolete_os(snap: Snapshot) -> Finding | None:
    today = snap.collected_at.date()
    hits = []
    for a in snap.accounts:
        if not (a.is_computer and a.enabled and a.os):
            continue
        eol = end_of_support(a.os)
        if eol and eol <= today:
            hits.append(a)
    if not hits:
        return None
    dcs = [a for a in hits if a.is_dc]
    detail = (
        f"{len(hits)} enabled computers run Windows versions past end of support "
        "(Windows 10 only if not enrolled in Extended Security Updates)."
    )
    if dcs:
        detail += f" Domain controllers: {', '.join(_names(dcs))}."
    return _finding(
        "AD-INF-001",
        Severity.HIGH if dcs else Severity.MEDIUM,
        detail,
        "Upgrade or retire them; isolate the ones that cannot be upgraded.",
        sorted(f"{a.sam} ({a.os})" for a in hits),
    )


@check("AD-INF-002", "AD Recycle Bin disabled")
def recycle_bin(snap: Snapshot) -> Finding | None:
    if snap.recycle_bin is not False:
        return None
    return _finding(
        "AD-INF-002",
        Severity.LOW,
        "Deleted objects cannot be restored with their attributes and group memberships, "
        "which turns a mass deletion by an attacker or an admin into an outage.",
        "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet.",
        [snap.domain],
    )


FUNCTIONAL_LEVELS = {
    0: "2000",
    1: "2003 interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
    10: "2025",
}


@check("AD-INF-003", "Domain functional level below Windows Server 2016")
def functional_level(snap: Snapshot) -> Finding | None:
    level = snap.policy.functional_level
    if level >= 7:
        return None
    return _finding(
        "AD-INF-003",
        Severity.LOW,
        f"The domain runs at the {FUNCTIONAL_LEVELS.get(level, str(level))} functional "
        "level, which leaves out protections such as the DC-side Protected Users "
        "restrictions and rolling of NTLM secrets for smart-card accounts.",
        "Retire old domain controllers and raise the domain and forest functional level.",
        [snap.domain],
    )


def _heuristic(h: str, position: int) -> str:
    """Character at a 1-based position as MS-ADTS numbers them; "" past the end."""
    return h[position - 1] if len(h) >= position else ""


def _bits(h: str, position: int, names: tuple[str, ...]) -> tuple[Severity, str] | None:
    """A character MS-ADTS reads as a bitwise OR, with bit 0 first in `names`."""
    value = _heuristic(h, position)
    if value in ("", "0"):
        return None
    if not value.isdecimal():
        return Severity.LOW, f"character {position} is {value!r}, not a number: not judged"
    on = [name for bit, name in enumerate(names) if int(value) >> bit & 1]
    if not on:
        return Severity.LOW, f"character {position} is {value}, no known bit: not judged"
    return Severity.MEDIUM, f"{' and '.join(on)} (character {position} = {value})"


def _kb5008383(h: str, position: int, what: str) -> tuple[Severity, str] | None:
    """Characters 28 and 29: 0 or unset audit, 1 enforce, 2 disabled. 3 is new, and MS-ADTS
    gives it no meaning we can judge; any other value counts as 1."""
    value = _heuristic(h, position)
    if value == "2":
        return Severity.MEDIUM, f"{what} disabled ({position}th character = 2)"
    if value == "3":
        return Severity.LOW, f"{what}: {position}th character is 3, not judged"
    return None


def ds_heuristic_issues(h: str) -> list[tuple[Severity, str]]:
    """(severity, text) per risky character. Positions are 1-based, as in MS-ADTS
    6.1.1.2.4.1.2; an unset character takes its default, which is never reported."""
    issues: list[tuple[Severity, str] | None] = []
    if _heuristic(h, 3) == "1":
        issues.append(
            (
                Severity.LOW,
                "List Object mode on, so ACLs can hide objects from this scan and its results "
                "may be incomplete (3rd character = 1)",
            )
        )
    if _heuristic(h, 7) == "2":
        issues.append((Severity.HIGH, "anonymous LDAP operations allowed (7th character = 2)"))
    if _heuristic(h, 8) not in ("", "0"):
        issues.append(
            (
                Severity.HIGH,
                f"anonymous NSPI binds allowed (8th character = {_heuristic(h, 8)})",
            )
        )
    if _heuristic(h, 16) not in ("", "0"):
        issues.append(
            (Severity.MEDIUM, "operator groups excluded from AdminSDHolder (16th character)")
        )
    issues.append(
        _bits(
            h, 21, ("UPN uniqueness check off", "SPN uniqueness check off", "SPN alias check off")
        )
    )
    issues.append(_kb5008383(h, 28, "CVE-2021-42291 checks on LDAP add"))
    issues.append(_kb5008383(h, 29, "CVE-2021-42291 owner rights checks"))
    issues.append(
        _bits(
            h,
            31,
            (
                "confidential attributes readable without encryption",
                "confidential attributes writable without encryption on modify",
                "confidential attributes writable without encryption on add",
            ),
        )
    )
    return [i for i in issues if i is not None]


@check("AD-INF-004", "Unsafe dsHeuristics settings")
def ds_heuristics(snap: Snapshot) -> Finding | None:
    h = snap.ds_heuristics
    issues = ds_heuristic_issues(h)
    if not issues:
        return None
    return _finding(
        "AD-INF-004",
        max(severity for severity, _ in issues),
        "dsHeuristics: " + "; ".join(text for _, text in issues) + ".",
        "Reset the affected characters of dsHeuristics to 0; set characters 28 and 29 to 1 "
        "(enforce, KB5008383). Keep the check characters: 10th 1, 20th 2, 30th 3.",
        [h],
    )


def _weak_dcs(snap: Snapshot, attr: str, fallback: bool | None, bad: bool) -> list[str]:
    """DCs whose probe for `attr` returned `bad`."""
    results = snap.probes.per_dc(attr, fallback, snap.domain)
    return sorted(name for name, value in results.items() if value is bad)


def _of_probed(snap: Snapshot, weak: list[str], attr: str) -> str:
    probed = [d for d in snap.probes.dcs if getattr(d, attr) is not None]
    return f" ({len(weak)} of {len(probed)} probed DCs)" if len(probed) > 1 else ""


@check("AD-INF-005", "LDAP signing not required")
def ldap_signing(snap: Snapshot) -> Finding | None:
    weak = _weak_dcs(snap, "ldap_signing_required", snap.ldap_signing_required, False)
    if not weak:
        return None
    return _finding(
        "AD-INF-005",
        Severity.MEDIUM,
        "These DCs accepted an unsigned NTLM bind on plain LDAP"
        + _of_probed(snap, weak, "ldap_signing_required")
        + ", so relayed authentication (for example from coerced machine accounts) can be "
        "used to modify the directory. One weak DC is enough for an attacker.",
        "Set 'Domain controller: LDAP server signing requirements' to Require signing on every "
        "DC (through the Default Domain Controllers Policy) and enable LDAP channel binding.",
        weak,
    )


TRUST_QUARANTINED = 0x4
TRUST_FOREST = 0x8
TRUST_WITHIN_FOREST = 0x20
TRUST_TREAT_AS_EXTERNAL = 0x40
TRUST_CROSS_ORGANIZATION = 0x10  # Selective Authentication
TRUST_USES_AES_KEYS = 0x100
TRUST_ENABLE_TGT_DELEGATION = 0x800
TRUST_INBOUND = 0x1
TRUST_OUTBOUND = 0x2
TRUST_TYPE_DOWNLEVEL = 1
TRUST_TYPE_UPLEVEL = 2
TRUST_TYPE_MIT = 3
TRUST_TYPE_AAD = 5
ENTRA_KERBEROS_REALM = "kerberos.microsoftonline.com"
ENC_AES = 0x18
# Trust passwords change every 30 days; PingCastle's T-Inactive allows 40
TRUST_STALE_AFTER = timedelta(days=40)


@check("AD-INF-006", "Trusts that let SIDs or TGTs through")
def trusts(snap: Snapshot) -> Finding | None:
    hits = []
    for t in snap.trusts:
        if t.attributes & TRUST_WITHIN_FOREST:
            continue
        forest = bool(t.attributes & TRUST_FOREST)
        # SID filtering protects the trusting side: outbound trusts
        if t.direction & TRUST_OUTBOUND:
            if not forest and not t.attributes & TRUST_QUARANTINED:
                hits.append(f"{t.name} (external, SID filtering disabled)")
            if forest and t.attributes & TRUST_TREAT_AS_EXTERNAL:
                hits.append(f"{t.name} (forest, SID history enabled)")
        # TGT delegation exposes this domain's users to the other forest: inbound trusts
        if forest and t.direction & TRUST_INBOUND and t.attributes & TRUST_ENABLE_TGT_DELEGATION:
            hits.append(f"{t.name} (forest, TGT delegation enabled)")
    if not hits:
        return None
    return _finding(
        "AD-INF-006",
        Severity.HIGH,
        "A compromise of the trusted domain can be escalated into this one with forged "
        "SID history or captured TGTs.",
        "Enable SID filtering (netdom trust /quarantine:yes or /enablesidhistory:no) and "
        "disable TGT delegation across the trust.",
        sorted(hits),
    )


def _entra_trust(t: Trust) -> bool:
    return t.trust_type == TRUST_TYPE_AAD or t.name.lower() == ENTRA_KERBEROS_REALM


@check("AD-INF-015", "Trusts limited to old protocols")
def trust_protocols(snap: Snapshot) -> Finding | None:
    severity = Severity.LOW
    hits = []
    for t in snap.trusts:
        if _entra_trust(t):
            continue
        if t.trust_type == TRUST_TYPE_DOWNLEVEL:
            severity = Severity.MEDIUM
            hits.append(f"{t.name} (downlevel, NT4 style)")
        # this domain's KDC encrypts referrals only over trusts its users can cross
        elif not snap.trust_details_checked or not t.direction & TRUST_INBOUND:
            continue
        elif t.enc_types:
            if not t.enc_types & ENC_AES:
                severity = Severity.MEDIUM
                hits.append(f"{t.name} (no AES, encryption types {t.enc_types:#x})")
        elif not t.attributes & TRUST_USES_AES_KEYS:
            hits.append(f"{t.name} (AES not set on the trust)")
    if not hits:
        return None
    return _finding(
        "AD-INF-015",
        severity,
        "These trusts rest on old cryptography: a downlevel trust is the form made for NT4 "
        "domains, and a trust without AES can have its referral tickets encrypted with RC4.",
        "Recreate downlevel trusts as forest or external trusts, or remove them. Enable AES "
        "with ksetup /setenctypeattr once both sides support it.",
        sorted(hits),
    )


@check("AD-INF-016", "Trusts unchanged for over 40 days")
def trust_stale(snap: Snapshot) -> Finding | None:
    severity = Severity.LOW
    hits = []
    for t in snap.trusts:
        if _entra_trust(t) or t.when_changed is None:
            continue
        if snap.collected_at - t.when_changed <= TRUST_STALE_AFTER:
            continue
        changed = t.when_changed.date().isoformat()
        if t.trust_type == TRUST_TYPE_MIT:
            hits.append(f"{t.name} (realm trust, last changed {changed}, review)")
        else:
            severity = Severity.MEDIUM
            hits.append(f"{t.name} (last changed {changed})")
    if not hits:
        return None
    return _finding(
        "AD-INF-016",
        severity,
        "A working trust between Windows domains changes its password about every 30 days, so "
        "these partners are probably gone or unreachable. The secret of a dead trust stays "
        "valid here and can be used to forge tickets.",
        "Check that each partner still exists and can be reached. Remove the trust if not.",
        sorted(hits),
    )


@check("AD-INF-017", "Forest trusts without Selective Authentication")
def trust_selective_auth(snap: Snapshot) -> Finding | None:
    hits = [
        t.name
        for t in snap.trusts
        if t.trust_type == TRUST_TYPE_UPLEVEL
        and t.attributes & TRUST_FOREST
        and t.direction & TRUST_OUTBOUND
        and not t.attributes & (TRUST_CROSS_ORGANIZATION | TRUST_WITHIN_FOREST)
    ]
    if not hits:
        return None
    return _finding(
        "AD-INF-017",
        Severity.MEDIUM,
        "Every account of the trusted forest can authenticate to every computer here, which "
        "gives an attacker in that forest a foothold for enumeration and lateral movement.",
        "Set the trust to Selective Authentication and grant Allowed to Authenticate on the "
        "computers that need it, after checking who uses the trust.",
        sorted(hits),
    )


# --- Round 3: parity with PingCastle / Purple Knight / Locksmith ----------------------

# Principals expected to hold specific rights on tier-0 objects by default
PRINCIPAL_SELF = "S-1-5-10"
CREATOR_OWNER = "S-1-3-0"
OPERATOR_SIDS = {"S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"}


def _tier0_group_sids(snap: Snapshot) -> set[str]:
    return snap.tier0_sids() | OPERATOR_SIDS


def _account_names(snap: Snapshot, dns: Iterable[str]) -> list[str]:
    by_dn = snap.by_dn()
    objs = snap.object_by_dn()
    out = []
    for dn in dns:
        key = dn.lower()
        if key in by_dn:
            out.append(by_dn[key].sam)
        elif key in objs:
            out.append(objs[key].name)
        else:
            out.append(dn.split(",", 1)[0].removeprefix("CN="))
    return sorted(out)


WEAK_MAPPING = re.compile(r"^X509:(?!.*<(?:SR|SKI|SHA1-PUKEY)>).*<(?:S|RFC822)>", re.IGNORECASE)
MAPPING_TAG = re.compile(r"<[A-Za-z0-9-]+>")
MAPPING_SCHEMES = ("X509", "KERBEROS")


@check("AD-ADCS-009", "ESC14: weak explicit certificate mappings")
def esc14(snap: Snapshot) -> Finding | None:
    privileged = snap.privileged_dns()
    hits = [
        a
        for a in snap.accounts
        if a.enabled and any(WEAK_MAPPING.match(m) for m in a.alt_security_identities)
    ]
    if not hits:
        return None
    priv = [a for a in hits if a.dn.lower() in privileged or a.is_dc]
    detail = (
        "altSecurityIdentities maps these accounts by subject, issuer+subject or e-mail, which "
        "anyone able to obtain a certificate with that name can satisfy."
    )
    if priv:
        detail += f" Privileged: {', '.join(_names(priv))}."
    return _finding(
        "AD-ADCS-009",
        Severity.HIGH if priv else Severity.MEDIUM,
        detail,
        "Use strong mappings (X509:<I>…<SR>…, <SKI> or <SHA1-PUKEY>) or remove the mapping.",
        _names(hits),
    )


@check("AD-ADCS-010", "ESC8: web enrollment accepts NTLM over HTTP")
def esc8(snap: Snapshot) -> Finding | None:
    if not snap.probes.web_enrollment_ntlm:
        return None
    return _finding(
        "AD-ADCS-010",
        Severity.HIGH,
        "Coerced NTLM authentication from a DC can be relayed to these endpoints to obtain a "
        "certificate for the DC and then DCSync.",
        "Disable HTTP on the web enrollment site, require HTTPS with Extended Protection for "
        "Authentication, or remove web enrollment if it is unused.",
        sorted(snap.probes.web_enrollment_ntlm),
    )


@check("AD-ADCS-019", "HTTPS enrollment endpoints where EPA is not verified")
def enrollment_epa_unknown(snap: Snapshot) -> Finding | None:
    if not snap.probes.enrollment_https:
        return None
    return _finding(
        "AD-ADCS-019",
        Severity.LOW,
        "These endpoints offer Windows authentication over HTTPS. Without Extended Protection "
        "for Authentication they are as relayable as HTTP (ESC8). The scan sends them no "
        "credentials and cannot see EPA from outside, so the state is unknown, not clean.",
        "On each server check that tokenChecking is Require for the application (IIS, Windows "
        "Authentication, Extended Protection), and remove endpoints nobody uses.",
        sorted(snap.probes.enrollment_https),
    )


ECC_KEY_SIZES = {256, 384, 521}


@check("AD-ADCS-011", "Published templates allowing keys shorter than 2048 bits")
def weak_template_keys(snap: Snapshot) -> Finding | None:
    hits = [
        f"{t.name} ({t.min_key_size} bits)"
        for t in snap.templates
        if t.published and 0 < t.min_key_size < 2048 and t.min_key_size not in ECC_KEY_SIZES
    ]
    if not hits:
        return None
    return _finding(
        "AD-ADCS-011",
        Severity.MEDIUM,
        "RSA keys below 2048 bits are below current guidance and factorable for 1024 bits.",
        "Raise msPKI-Minimal-Key-Size to 2048 or more and re-enroll.",
        sorted(hits),
    )


AES_TYPES = 0x18


# Accounts the domain creates around the same moment can be a little older than the group
AES_CUTOVER_MARGIN = timedelta(hours=1)
OLD_KEYS = "suspected no AES keys (password older than the domain's move to Server 2008)"
NO_VALUE = "no value set, the domain default applies"
COMPUTERS_NO_VALUE = "computer(s) with an SPN"


def _old_password(snap: Snapshot, a: Account) -> bool:
    """The password predates AES support, so no AES key was ever derived from it."""
    changed = a.password_changed
    if changed is None and not a.pwd_must_change:
        changed = a.when_created
    if snap.aes_cutover is None or changed is None:
        return False
    return changed + AES_CUTOVER_MARGIN < snap.aes_cutover


def _rc4_row(snap: Snapshot, a: Account) -> tuple[Severity, str] | None:
    """Grade and text for one account; msDS-SupportedEncryptionTypes 0 counts as not set."""
    if a.sam.lower() == "krbtgt":
        return (Severity.MEDIUM, OLD_KEYS) if _old_password(snap, a) else None
    if not a.enabled or a.managed or not a.spns or a.sam.lower().startswith("krbtgt"):
        return None
    dc = "DC, " if a.is_registered_dc else ""
    if a.enc_types and not a.enc_types & AES_TYPES:
        grade = Severity.MEDIUM
        text = f"{dc}no AES in msDS-SupportedEncryptionTypes (0x{a.enc_types:X})"
    elif not a.enc_types:
        grade = Severity.LOW
        text = f"{dc}{NO_VALUE}"
    else:
        grade, text = Severity.LOW, ""
    if _old_password(snap, a):
        return Severity.MEDIUM, f"{text}; {OLD_KEYS}" if text else OLD_KEYS
    return (grade, text) if text else None


@check("AD-KRB-005", "RC4 readiness: Kerberos encryption settings of service accounts")
def rc4_readiness(snap: Snapshot) -> Finding | None:
    rows = [(a, row) for a in snap.accounts if (row := _rc4_row(snap, a))]
    if not rows:
        return None
    # normal on non-Windows hosts: a line each would bury the accounts that matter
    quiet = sorted(a.sam for a, (_, text) in rows if a.is_computer and text == NO_VALUE)
    objects = {f"{a.sam}: {text}": a.sam for a, (_, text) in rows if a.sam not in quiet}
    if quiet:
        shown = ", ".join(quiet[:SHOWN_HOSTS]) + (", ..." if len(quiet) > SHOWN_HOSTS else "")
        objects[f"{len(quiet)} {COMPUTERS_NO_VALUE}: {NO_VALUE} ({shown})"] = COMPUTERS_NO_VALUE
    texts = " ".join(objects)
    detail = "This reads configuration, not keys: stored keys cannot be seen over LDAP."
    if "no AES in" in texts:
        detail += (
            " An explicit value without AES is honoured after the 2026 RC4 changes, so these "
            "accounts keep getting RC4 tickets, the fastest kind to crack offline."
        )
    if NO_VALUE in texts:
        detail += (
            " With no value set the KDC default applies, which is AES only on DCs with the "
            "2026 updates: services or clients that need RC4 fail there. An attribute this "
            "account cannot read looks the same as no value."
        )
    if OLD_KEYS in texts:
        detail += (
            " A password older than the Read-only Domain Controllers group was probably never "
            "turned into AES keys, so the KDC cannot issue AES tickets for the account."
        )
    finding = _finding(
        "AD-KRB-005",
        max(grade for _, (grade, _) in rows),
        detail + " DefaultDomainSupportedEncTypes and the DCs' update level are not visible here.",
        "Check KDCSVC events 201 to 209 on the DCs. Reset the password of accounts suspected of "
        "having no AES keys, then set AES128/AES256 (0x18) on service accounts and test them.",
        sorted(objects),
    )
    finding.keys = objects
    return finding


SSO_ROLLOVER = timedelta(days=30)


@check("AD-KRB-006", "Seamless SSO key not rolled over")
def seamless_sso(snap: Snapshot) -> Finding | None:
    hits = [
        a
        for a in snap.accounts
        if a.sam.upper() == "AZUREADSSOACC$"
        and a.pwd_last_set is not None
        and snap.collected_at - a.pwd_last_set > SSO_ROLLOVER
    ]
    if not hits:
        return None
    days = (snap.collected_at - hits[0].pwd_last_set).days  # type: ignore[operator]
    return _finding(
        "AD-KRB-006",
        Severity.MEDIUM,
        f"The AZUREADSSOACC$ Kerberos key is {days} days old; whoever has it can forge "
        "tickets to Entra ID for any synced user (silver ticket).",
        "Roll the key over (Update-AzureADSSOForest) and schedule it every 30 days.",
        _names(hits),
    )


DC_SERVICES = ("ldap", "cifs", "host", "http", "gc", "rpcss", "wsman", "dns")
IP_LIKE = re.compile(r"[\d.]+")


def _spn_parts(spn: str) -> tuple[str, str]:
    """Service class and host of an SPN (service/host[:port][/name]), in lower case."""
    service, _, rest = spn.lower().partition("/")
    return service, rest.split(":", 1)[0].split("/", 1)[0].rstrip(".")


@check("AD-DEL-004", "Delegation that reaches domain controllers or krbtgt")
def delegation_to_dcs(snap: Snapshot) -> Finding | None:
    dcs = [a for a in snap.accounts if a.is_dc]
    dc_names = {a.sam.rstrip("$").lower() for a in dcs} | {
        (a.dns_host or "").lower() for a in dcs if a.dns_host
    }
    hits = []
    for a in snap.accounts:
        if not a.enabled:
            continue
        for spn in a.allowed_to_delegate_to:
            service, host = _spn_parts(spn)
            if (service in DC_SERVICES and host in dc_names) or service == "krbtgt":
                hits.append(f"{a.sam} -> {spn}")
        if a.rbcd and (a.is_dc or a.sam.lower() == "krbtgt"):
            hits.append(f"{a.sam} (resource-based delegation configured on it)")
    if not hits:
        return None
    return _finding(
        "AD-DEL-004",
        Severity.HIGH,
        "Whoever controls these accounts can impersonate any user, including domain admins, to "
        "a domain controller service.",
        "Remove the delegation; DCs and krbtgt must never be delegation targets.",
        sorted(set(hits)),
    )


def _spn_aliases(snap: Snapshot) -> dict[str, str]:
    """Service class -> the class that answers for it, from sPNMappings."""
    aliases: dict[str, str] = {}
    for mapping in snap.spn_mappings:
        target, _, names = mapping.lower().partition("=")
        aliases.update({n.strip(): target.strip() for n in names.split(",") if n.strip()})
    return aliases


@check("AD-DEL-005", "Constrained delegation to SPNs no account holds")
def ghost_spn_delegation(snap: Snapshot) -> Finding | None:
    held = {spn.lower() for a in snap.accounts for spn in a.spns}
    hosts = {_spn_parts(spn)[1] for spn in held}
    for a in snap.accounts:
        if a.is_computer or a.managed:
            hosts |= {a.sam.rstrip("$").lower(), (a.dns_host or "").lower()}
    aliases = _spn_aliases(snap)
    suffix = "." + snap.domain.lower()
    severity = Severity.LOW
    hits = []
    for a in snap.accounts:
        if not a.enabled:
            continue
        for spn in a.allowed_to_delegate_to:
            service, host = _spn_parts(spn)
            rest = spn.lower().partition("/")[2]
            mapped = aliases.get(service)
            # krbtgt is AD-DEL-004's; the KDC finds it by name, not by an SPN
            if spn.lower() in held or service == "krbtgt":
                continue
            # MapSPN changes the service class and nothing else: a port or instance stays
            if mapped and f"{mapped}/{rest.rstrip('.')}" in held:
                continue
            short = host.removesuffix(suffix)
            if not host:
                hits.append(f"{a.sam} -> {spn} (cannot be parsed, review)")
                continue
            if host in hosts or short in hosts:
                if not aliases:
                    continue  # a mapping could explain it
                why = "no account holds it, the host exists"
            elif "." in short and (host.endswith(suffix) or IP_LIKE.fullmatch(host)):
                hits.append(f"{a.sam} -> {spn} (not in this domain's snapshot, review)")
                continue
            elif "." in short:
                why = "another domain, this delegation cannot reach it"
            else:
                why = "no computer object"
            # the host decides nothing: the attack is a write on an account the attacker holds
            if a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION):
                severity = Severity.HIGH
                why += ", protocol transition"
            else:
                severity = max(severity, Severity.MEDIUM)
            hits.append(f"{a.sam} -> {spn} ({why})")
    if not hits:
        return None
    return _finding(
        "AD-DEL-005",
        severity,
        "No account the scan can see holds these delegation targets. Whoever controls the "
        "delegating account and can write servicePrincipalName on any account can register a "
        "target there and impersonate users to that account (SPN-jacking). Targets marked "
        "review need a check by hand.",
        "Remove dead entries from msDS-AllowedToDelegateTo (Delegation tab of the account). "
        "An entry for another domain cannot work with this kind of delegation, so remove it "
        "too.",
        sorted(set(hits)),
    )


def _risky_rights(ace: sd.Ace, kind: str) -> list[str]:
    rights = []
    if ace.takeover:
        rights.append("full control" if ace.mask & sd.GENERIC_ALL else "write/WriteDacl/WriteOwner")
    else:
        if ace.writes(sd.KEY_CREDENTIAL_LINK) and kind in ("user", "computer"):
            rights.append("write msDS-KeyCredentialLink")
        if ace.writes(sd.ALLOWED_TO_ACT) and kind == "computer":
            rights.append("write RBCD")
        if ace.writes(sd.MEMBER) and kind == "group":
            rights.append("write members")
        elif ace.adds_self() and kind == "group":
            rights.append("add self")
        if ace.writes(sd.ALT_SECURITY_IDENTITIES) and kind in ("user", "computer"):
            rights.append("write altSecurityIdentities (ESC14)")
        if ace.writes(sd.SERVICE_PRINCIPAL_NAME) and kind == "user":
            rights.append("write SPN")
        resets = ace.mask & sd.CONTROL_ACCESS and ace.extended_right(sd.RESET_PASSWORD)
        if kind == "user" and resets:
            rights.append("reset password")
    return rights


def _control_rights(snap: Snapshot, ace: sd.Ace, kind: str) -> list[str]:
    """_risky_rights minus the KeyCredentialLink write Key Admins hold by default."""
    rights = _risky_rights(ace, kind)
    key_admins = {f"{snap.domain_sid}-526", f"{snap.domain_sid}-527"}
    if snap.root_sid:
        key_admins.add(f"{snap.root_sid}-527")
    if ace.sid in key_admins:
        rights = [r for r in rights if r != "write msDS-KeyCredentialLink"]
    return rights


@check("AD-ACL-004", "Non-tier-0 control over tier-0 accounts, groups or DCs")
def tier0_object_control(snap: Snapshot) -> Finding | None:
    tier0 = _tier0_group_sids(snap)
    targets = snap.tier0_dns() | {o.dn.lower() for o in snap.objects if o.sid in tier0}
    hits = set()
    for o in snap.objects:
        if o.dn.lower() not in targets or o.kind not in ("user", "computer", "group"):
            continue
        if o.owner and o.owner not in tier0:
            hits.add(f"{o.name}: owned by {snap.name_of(o.owner)}")
        for ace in o.aces:
            if ace.sid in tier0 or ace.sid in (PRINCIPAL_SELF, CREATOR_OWNER):
                continue
            rights = _control_rights(snap, ace, o.kind)
            if rights:
                hits.add(f"{o.name}: {snap.name_of(ace.sid)} ({', '.join(rights)})")
    if not hits:
        return None
    return _finding(
        "AD-ACL-004",
        Severity.HIGH,
        "These principals can take over a tier-0 object directly (shadow credentials, RBCD, "
        "group membership, password reset, ownership), which makes them tier 0 in practice.",
        "Remove the rights and ownership, then let SDProp restore protected objects.",
        sorted(hits),
    )


@check("AD-ACL-005", "AdminSDHolder inherits permissions")
def adminsdholder_inheritance(snap: Snapshot) -> Finding | None:
    holder = next((o for o in snap.objects if o.dn.lower().startswith("cn=adminsdholder,")), None)
    if holder is None or holder.dacl_protected or not holder.aces:
        return None
    return _finding(
        "AD-ACL-005",
        Severity.HIGH,
        "With inheritance enabled, permissions granted on the System container or the domain "
        "flow into AdminSDHolder and from there onto every protected admin.",
        "Disable inheritance on CN=AdminSDHolder,CN=System and remove the inherited ACEs.",
        [holder.dn],
    )


@check("AD-ACL-006", "gMSA passwords readable outside tier 0")
def gmsa_readers(snap: Snapshot) -> Finding | None:
    tier0 = _tier0_group_sids(snap)
    broad = snap.broad_sids()
    privileged = snap.privileged_dns()
    hits = []
    for g in snap.gmsas:
        is_priv = g.dn.lower() in privileged
        # a broad reader, or any non-tier-0 reader of a privileged gMSA: both are HIGH
        risky = [s for s in g.readers if s in broad or (is_priv and s not in tier0)]
        if risky:
            who = ", ".join(sorted(snap.name_of(s) for s in risky))
            hits.append(f"{g.name} (readable by {who})")
    if not hits:
        return None
    return _finding(
        "AD-ACL-006",
        Severity.HIGH,
        "Anyone in these groups can retrieve the managed password and act as the service account.",
        "Limit PrincipalsAllowedToRetrieveManagedPassword to the hosts that run the service.",
        sorted(hits),
    )


@check("AD-ACC-008", "Passwords in description or info attributes")
def secret_in_description(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.enabled and a.secret_in_description]
    if not hits:
        return None
    return _finding(
        "AD-ACC-008",
        Severity.MEDIUM,
        "description and info are readable by every domain user; these look like they "
        "contain a password (the text is not reproduced here).",
        "Remove the text and change the passwords.",
        _names(hits),
    )


@check("AD-ACC-009", "Readable password attributes")
def password_attributes(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.password_attributes]
    if not hits:
        return None
    return _finding(
        "AD-ACC-009",
        Severity.HIGH,
        "userPassword, unixUserPassword or msSFU30Password came back to an ordinary user; "
        "they usually hold a reversible or clear-text password.",
        "Clear the attributes and change the passwords.",
        sorted(f"{a.sam} ({', '.join(a.password_attributes)})" for a in hits),
    )


@check("AD-ACC-010", "Pre-created computer accounts with predictable passwords")
def precreated_computers(snap: Snapshot) -> Finding | None:
    hits = [
        a
        for a in snap.accounts
        if a.is_computer
        and a.enabled
        and not a.is_registered_dc
        and a.has(UAC.PASSWD_NOTREQD)
        and a.logon_count == 0
    ]
    if not hits:
        return None
    return _finding(
        "AD-ACC-010",
        Severity.HIGH,
        "Computers created as 'pre-Windows 2000' and never used have the lower-cased computer "
        "name as their password, so anyone can log on as them.",
        "Reset the passwords (or delete the accounts) and clear PASSWD_NOTREQD.",
        _names(hits),
    )


OLD_PRIVILEGED_PASSWORD = timedelta(days=365)


@check("AD-ACC-011", "Privileged accounts with passwords older than a year")
def privileged_old_password(snap: Snapshot) -> Finding | None:
    privileged = snap.privileged_dns()
    cutoff = snap.collected_at - OLD_PRIVILEGED_PASSWORD
    hits = [
        a
        for a in _enabled_users(snap)
        if (a.dn.lower() in privileged or a.rid == 500)
        and (changed := a.password_changed) is not None
        and changed < cutoff
    ]
    if not hits:
        return None
    return _finding(
        "AD-ACC-011",
        Severity.MEDIUM,
        "Old admin passwords have had years to leak into backups, scripts and memory dumps.",
        "Rotate the passwords; consider a PAM tool for tier-0 credentials.",
        _names(hits),
    )


# FILETIME rounding, the tolerance PingCastle uses for the same comparison
FAKE_PWD_TOLERANCE = timedelta(seconds=5)


@check("AD-ACC-012", "pwdLastSet newer than the real password change on tier-0 accounts")
def fake_password_change(snap: Snapshot) -> Finding | None:
    hits = [
        a
        for a in snap.accounts
        if a.pwd_changed is not None
        and a.pwd_last_set is not None
        and a.pwd_last_set - a.pwd_changed > FAKE_PWD_TOLERANCE
        and (a.enabled or a.sam.lower() == "krbtgt")
    ]
    if not hits:
        return None
    objects = {
        f"{a.sam} (pwdLastSet {a.pwd_last_set:%Y-%m-%d}, written {a.pwd_changed:%Y-%m-%d})": a.sam
        for a in hits
    }
    finding = _finding(
        "AD-ACC-012",
        Severity.HIGH if any(a.sam.lower() == "krbtgt" for a in hits) else Severity.MEDIUM,
        "pwdLastSet was moved forward without a password change: replication metadata shows "
        "unicodePwd was written earlier. Password age checks use the older time. Ticking and "
        "clearing 'User must change password' does this, and so does hiding an old password.",
        "Find who wrote pwdLastSet (the metadata names the originating DC and time), then "
        "really change the password; for krbtgt rotate it twice.",
        sorted(objects),
    )
    finding.keys = objects
    return finding


KEY_USAGES = {0x01: "NGC", 0x07: "FIDO", 0x08: "FEK"}
KEY_ID_SHOWN = 8
USER_KEY_USAGES = (0x01, 0x07)


def _key_line(a: Account, key: KeyCredential, count: int) -> tuple[str, str, Severity]:
    """Object text, stable identity and grade of one of an account's `count` key credentials."""
    added = f", added {key.added:%Y-%m-%d}" if key.added else ""
    created = f", created {key.created:%Y-%m-%d}" if key.created else ""
    short = f" {key.key_id[:KEY_ID_SHOWN]}" if key.key_id else ""
    name = key.key_id or key.device_id or key.added or key.created or "without ID"
    identity = f"{a.sam}: key {name}"
    # no normal flow leaves a key on a DC, whatever its shape
    unusual = Severity.HIGH if a.is_dc else Severity.MEDIUM
    if not key.readable:
        return f"{a.sam}: key credential, contents not readable{added}", identity, unusual
    if not key.parsed:
        return f"{a.sam}: key credential that does not parse{added}", identity, Severity.HIGH
    usage = KEY_USAGES.get(key.usage or 0, f"usage {key.usage}")
    device = f", device {key.device_id}" if key.device_id else ", no device ID"
    text = f"{a.sam}: key credential{short} ({usage}){device}{created}{added}"
    # a computer may write one key to itself, and only with no value there already
    if a.is_computer and not a.managed and not a.is_dc and count == 1:
        if key.self_written:
            return f"{a.sam}: computer key{short}{created}{added}", identity, Severity.LOW
        if key.custom_info:
            label = "computer key with custom key information"
            return f"{a.sam}: {label}{short}{created}{added}", identity, Severity.MEDIUM
    person = not a.is_computer and not a.managed and a.sam.lower() != "krbtgt"
    if person and key.device_id and key.usage in USER_KEY_USAGES:
        return text, identity, Severity.MEDIUM
    return text, identity, Severity.HIGH


def _mapping_line(snap: Snapshot, a: Account, mapping: str) -> str:
    """Object text of one mapping. The value stays out of reports; a salted hash tells two
    of one shape apart, so a backdoor beside a known mapping does not pass as the known one."""
    salted = f"{snap.domain_sid}:{a.sam}:{mapping}".encode()
    mark = hashlib.sha256(salted).hexdigest()[:KEY_ID_SHOWN]
    scheme = mapping.split(":", 1)[0]
    if scheme.upper() == "KERBEROS":
        return f"{a.sam}: Kerberos name mapping {mark}"
    scheme = scheme if scheme.upper() in MAPPING_SCHEMES else "other"
    return f"{a.sam}: certificate mapping {scheme}:{''.join(MAPPING_TAG.findall(mapping))} {mark}"


@check("AD-ACC-013", "Key credentials or certificate mappings on tier-0 accounts")
def tier0_key_credentials(snap: Snapshot) -> Finding | None:
    privileged = snap.privileged_dns()
    ca_hosts = {h.upper() for h in snap.ca_hosts}
    sync_servers = {s.dn.lower() for a in _sync_accounts(snap) for s in _sync_servers(snap, a)}
    objects: dict[str, str] = {}
    grades = []

    def report(text: str, identity: str, grade: Severity) -> None:
        # keys the snapshot cannot tell apart still count as two
        number = sum(1 for o in objects if o == text or o.startswith(f"{text} ("))
        suffix = f" ({number + 1})" if number else ""
        objects[text + suffix] = identity + suffix
        grades.append(grade)

    for a in snap.accounts:
        krbtgt = a.sam.lower() == "krbtgt"
        tier0 = a.dn.lower() in privileged or a.is_dc or krbtgt or a.rid == 500
        tier0 = tier0 or bool(a.sync_host) or a.dn.lower() in sync_servers
        if not (tier0 or a.sam.upper() in ca_hosts) or not (a.enabled or krbtgt):
            continue
        for key in a.key_credentials:
            report(*_key_line(a, key, len(a.key_credentials)))
        for mapping in a.alt_security_identities:
            if not WEAK_MAPPING.match(mapping):  # AD-ADCS-009 has the weak ones
                text = _mapping_line(snap, a, mapping)
                report(text, text, Severity.MEDIUM)
    if not objects:
        return None
    finding = _finding(
        "AD-ACC-013",
        max(grades),
        "Whoever holds the private key behind one of these can log on as the account without "
        "its password, and a password reset does not stop it. A Kerberos name mapping does the "
        "same for whoever controls that principal in the other realm. Windows Hello for "
        "Business, a computer's own key and smart cards leave the same values as a backdoor "
        "does, so this needs a person to confirm each one.",
        "Match each device ID to a device the owner enrolled and each mapping to a certificate "
        "you issued or a principal you know. Remove what nobody can explain and treat it as an "
        "incident.",
        sorted(objects),
    )
    finding.keys = objects
    return finding


@check("AD-PRIV-012", "Tier-0 group members this account cannot read")
def unreadable_members(snap: Snapshot) -> Finding | None:
    objects = {
        f"{m.group}: {m.dn} ({m.reason})": f"{m.group}: {m.dn}" for m in snap.unreadable_members
    }
    if not objects:
        return None
    finding = _finding(
        "AD-PRIV-012",
        Severity.HIGH,
        "These DNs are in the member attribute of a tier-0 group, but the object did not come "
        "back: every check is blind to it, and a member that is a group hides its own members. "
        "It is either a hidden admin or a deliberate read restriction.",
        "Look at the object as a Domain Admin and find who denied read or list rights. If the "
        "restriction is deliberate, give the scanning account read access or accept the risk.",
        sorted(objects),
    )
    finding.keys = objects
    return finding


@check("AD-PRIV-006", "Disabled, computer or foreign accounts in tier-0 groups")
def odd_privileged_members(snap: Snapshot) -> Finding | None:
    by_dn = snap.by_dn()
    hits = set()
    for group, members in snap.privileged.items():
        for dn in members:
            a = by_dn.get(dn.lower())
            if a is None:
                continue
            if not a.enabled:
                hits.add(f"{group}: {a.sam} (disabled)")
            elif a.is_computer and not a.is_registered_dc:
                hits.add(f"{group}: {a.sam} (computer)")
    tier0 = _tier0_group_sids(snap)
    for o in snap.objects:
        if o.kind == "group" and o.sid in tier0:
            for m in o.members:
                if ",cn=foreignsecurityprincipals," in m.lower():
                    hits.add(f"{o.name}: {m.split(',', 1)[0].removeprefix('CN=')} (foreign)")
    if not hits:
        return None
    return _finding(
        "AD-PRIV-006",
        Severity.MEDIUM,
        "Disabled accounts can be re-enabled by anyone who controls them, computer accounts "
        "are compromised with their host, and foreign principals extend tier 0 into another "
        "forest.",
        "Remove these members from tier-0 groups.",
        sorted(hits),
    )


PRIVILEGED_PRIMARY_GROUPS = {512: "Domain Admins", 518: "Schema Admins", 519: "Enterprise Admins"}
DC_PRIMARY_GROUPS = {
    516: "Domain Controllers",
    521: "Read-only Domain Controllers",
    498: "Enterprise Read-only Domain Controllers",
}


@check("AD-PRIV-007", "Membership hidden through primaryGroupID")
def hidden_primary_group(snap: Snapshot) -> Finding | None:
    hits = []
    for a in snap.accounts:
        if not a.enabled:
            continue
        if not a.is_computer and a.primary_group in PRIVILEGED_PRIMARY_GROUPS:
            hits.append(f"{a.sam} (primary group {PRIVILEGED_PRIMARY_GROUPS[a.primary_group]})")
        elif not a.is_registered_dc and a.primary_group in DC_PRIMARY_GROUPS:
            hits.append(
                f"{a.sam} (primary group {DC_PRIMARY_GROUPS[a.primary_group]}, but not a DC)"
            )
    if not hits:
        return None
    return _finding(
        "AD-PRIV-007",
        Severity.HIGH,
        "primaryGroupID membership does not appear in the group's member attribute, so it "
        "hides from most membership reviews.",
        "Set primaryGroupID back to 513 (users) or 515 (computers).",
        sorted(hits),
    )


@check("AD-PRIV-008", "Operator groups not empty")
def operators_not_empty(snap: Snapshot) -> Finding | None:
    groups = ("Account Operators", "Server Operators", "Print Operators", "Backup Operators")
    by_dn = snap.by_dn()
    hits = sorted(
        f"{g}: {by_dn[dn.lower()].sam if dn.lower() in by_dn else dn}"
        for g in groups
        for dn in snap.privileged.get(g, [])
    )
    if not hits:
        return None
    return _finding(
        "AD-PRIV-008",
        Severity.MEDIUM,
        "Operator groups can log on to DCs and have rights (backup, driver loading, account "
        "management) that lead to domain admin; Microsoft recommends leaving them empty.",
        "Remove the members and delegate the specific tasks instead.",
        hits,
    )


@check("AD-PRIV-009", "Unexpected members of Cert Publishers")
def cert_publishers(snap: Snapshot) -> Finding | None:
    group = next((o for o in snap.objects if o.sid == f"{snap.domain_sid}-517"), None)
    if group is None:
        return None
    ca_hosts = {h.upper() for h in snap.ca_hosts}
    hits = [n for n in _account_names(snap, group.members) if n.upper() not in ca_hosts]
    if not hits:
        return None
    return _finding(
        "AD-PRIV-009",
        Severity.MEDIUM,
        "Cert Publishers can publish certificates to users and to NTAuth-related containers; "
        "only enterprise CA servers belong in it.",
        "Remove every member that is not an enterprise CA computer account.",
        hits,
    )


@check("AD-PRIV-010", "Protected Users not used for administrators")
def protected_users_unused(snap: Snapshot) -> Finding | None:
    domain_admins = {d.lower() for d in snap.privileged.get("Domain Admins", [])}
    admins = [a for a in _enabled_users(snap) if a.dn.lower() in domain_admins]
    if not admins or snap.protected_users:
        return None
    return _finding(
        "AD-PRIV-010",
        Severity.INFO,
        "Protected Users is empty: admin credentials can still be cached, delegated and used "
        "with NTLM, DES or RC4.",
        "Add administrators (not service accounts) to Protected Users after testing.",
        _names(admins),
    )


@check("AD-SEC-002", "LAPS passwords readable by the scanning account")
def laps_readable(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.laps_password_readable]
    if not hits:
        return None
    return _finding(
        "AD-SEC-002",
        Severity.HIGH,
        f"An ordinary account read the local administrator password of {len(hits)} computers.",
        "Restrict LAPS read permissions (Find-LapsADExtendedRights / "
        "Set-LapsADReadPasswordPermission) to the admins of each tier.",
        _names(hits),
    )


@check("AD-INF-007", "BadSuccessor: dMSA creation rights outside tier 0")
def bad_successor(snap: Snapshot) -> Finding | None:
    if not snap.has_2025:
        return None
    tier0 = _tier0_group_sids(snap)
    hits = set()
    for o in snap.objects:
        if o.kind not in ("ou", "domain", "container"):
            continue
        # an owner can always rewrite the DACL, so it can grant itself CreateChild
        if o.owner and o.owner not in tier0:
            hits.add(f"{o.name}: {snap.name_of(o.owner)} (owner)")
        for ace in o.aces:
            if ace.sid in tier0 or ace.sid == CREATOR_OWNER:
                continue
            if ace.creates(sd.DMSA_CLASS) or ace.takeover:
                hits.add(f"{o.name}: {snap.name_of(ace.sid)}")
    privileged = snap.privileged_dns()
    for a in snap.accounts:
        link = (a.preceded_by or "").lower()
        if link and (link in privileged or "krbtgt" in link):
            victim = (a.preceded_by or "").split(",", 1)[0].removeprefix("CN=")
            hits.add(f"{a.sam}: dMSA superseding {victim}")
    if not hits:
        return None
    seen = snap.dmsa_visible is not False or any(a.preceded_by for a in snap.accounts)
    blind = (
        ""
        if seen
        else " No dMSA was visible to this account, so existing dMSA links were not checked."
    )
    return _finding(
        "AD-INF-007",
        Severity.HIGH,
        "On Windows Server 2025 domains, anyone who can create a dMSA in a container can make it "
        "inherit the rights of any account, including domain admins. The August 2025 updates "
        "stop a one-sided link; a pairing with an account the attacker also controls still "
        "works." + blind,
        "Remove CreateChild/GenericAll/WriteDacl/WriteOwner for these principals and install "
        "the August 2025 updates (CVE-2025-53779); the update alone leaves these rights in place.",
        sorted(hits),
    )


@check("AD-GPO-002", "Non-tier-0 principals can link GPOs to the domain or DCs")
def gplink_write(snap: Snapshot) -> Finding | None:
    tier0 = _tier0_group_sids(snap)
    hits = set()
    for o in snap.objects:
        is_dc_ou = o.kind == "ou" and o.dn.lower().startswith("ou=domain controllers,")
        if o.kind != "domain" and not is_dc_ou:
            continue
        for ace in o.aces:
            if ace.sid in tier0:
                continue
            if ace.writes(sd.GP_LINK) or ace.takeover:
                where = "domain" if o.kind == "domain" else "Domain Controllers OU"
                hits.add(f"{where}: {snap.name_of(ace.sid)}")
    if not hits:
        return None
    return _finding(
        "AD-GPO-002",
        Severity.HIGH,
        "Linking an attacker-controlled GPO here runs it on every domain controller.",
        "Remove write access to gPLink for these principals.",
        sorted(hits),
    )


DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeEnableDelegationPrivilege",
    "SeTcbPrivilege",
    "SeCreateTokenPrivilege",
    "SeSecurityPrivilege",
}
DEFAULT_HOLDERS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


@check("AD-GPO-003", "Weak security settings in GPOs applied to DCs or the domain")
def gpo_security(snap: Snapshot) -> Finding | None:
    allowed = _tier0_group_sids(snap) | DEFAULT_HOLDERS
    hits, severity = [], Severity.MEDIUM
    for g in snap.gpos:
        s = snap.gpo_settings.get(g.guid)
        # same rule as the local group checks: an empty computer side or a GPO without the
        # security extension is never applied, whatever its GptTmpl.inf says
        if s is None or not g.linked_to or not gpo_scope.computer_side_applies(g, "restricted"):
            continue
        if s.lm_compatibility is not None and s.lm_compatibility < 3:
            hits.append(f"{g.name}: LmCompatibilityLevel {s.lm_compatibility} (LM/NTLMv1 allowed)")
            severity = Severity.HIGH
        if s.no_lm_hash == 0:
            hits.append(f"{g.name}: LM hashes stored (NoLMHash 0)")
        if s.clear_text_password == 1:
            hits.append(f"{g.name}: reversible password encryption enabled")
            severity = Severity.HIGH
        for privilege, holders in sorted(s.privileges.items()):
            if privilege not in DANGEROUS_PRIVILEGES:
                continue
            extra = [h for h in holders if h not in allowed]
            if extra:
                names = ", ".join(sorted(snap.name_of(h) for h in extra))
                hits.append(f"{g.name}: {privilege} granted to {names}")
                severity = Severity.HIGH
    if not hits:
        return None
    return _finding(
        "AD-GPO-003",
        severity,
        "These GPOs weaken authentication or hand out privileges that lead to SYSTEM on the "
        "computers they apply to.",
        "Set LmCompatibilityLevel to 5, NoLMHash to 1, disable reversible encryption and limit "
        "the privileges to the default holders.",
        sorted(hits),
    )


INTERDOMAIN_TRUST_ACCOUNT = 0x800


def _group_reach(snap: Snapshot, sid: str) -> set[str]:
    """Lower-cased DNs inside a group, nesting included; empty for anything else."""
    groups = {o.dn.lower(): o for o in snap.objects if o.kind == "group"}
    start = next((o for o in groups.values() if o.sid == sid), None)
    todo = [start] if start else []
    seen: set[str] = set()
    while todo:
        for member in todo.pop().members:
            key = member.lower()
            if key not in seen:
                seen.add(key)
                if key in groups:
                    todo.append(groups[key])
    return seen


FOREIGN_MEMBER = re.compile(r"^cn=(s-1-[0-9-]+),cn=foreignsecurityprincipals,", re.I)


def _channel_severe(snap: Snapshot, sid: str) -> bool:
    """A DC, trust account, tier-0 principal, tier-0 host or broad group on the list exposes
    the domain, directly or through any member: every member of a listed group is exempted."""
    accounts = {a.dn.lower(): a for a in snap.accounts}
    inside = _group_reach(snap, sid) | {a.dn.lower() for a in snap.accounts if a.sid == sid}
    sids = {sid}
    known = {o.dn.lower(): o.sid for o in snap.objects} | {k: a.sid for k, a in accounts.items()}
    for dn in inside:
        if foreign := FOREIGN_MEMBER.match(dn):
            sids.add(foreign.group(1).upper())
        elif dn in known:
            sids.add(known[dn])
    if sids & (snap.broad_sids() | snap.tier0_sids()):
        return True
    tier0 = snap.tier0_dns() | tier0_hosts(snap).keys()
    return any(
        dn in tier0 or (dn in accounts and accounts[dn].uac & INTERDOMAIN_TRUST_ACCOUNT)
        for dn in inside
    )


def _channel_row(snap: Snapshot, hit: gpo_scope.ChannelAllow) -> tuple[Severity, str] | None:
    where = f" on {', '.join(hit.dcs)}" + (f" [{'; '.join(hit.caveats)}]" if hit.caveats else "")
    try:
        allow, deny = sd.sddl_trustees(hit.sddl, snap.domain_sid, snap.root_sid)
    except ValueError:
        return Severity.MEDIUM, f"{hit.gpo.name}: list not understood{where}: {hit.sddl[:200]}"
    # Microsoft: a Deny entry acts as if the account was never added. Denying a group does
    # not take its members off here, which can only over-report.
    if {"S-1-1-0", "S-1-5-11"} & set(deny):
        return None
    listed = sorted(set(allow) - set(deny))
    if not listed:
        return None
    severe = any(_channel_severe(snap, sid) for sid in listed)
    names = ", ".join(sorted(snap.name_of(sid) for sid in listed))
    return Severity.HIGH if severe else Severity.MEDIUM, f"{hit.gpo.name}: {names}{where}"


@check("AD-GPO-008", "GPOs set the Netlogon vulnerable channel allow list on DCs (Onelogon)")
def netlogon_allow_list(snap: Snapshot) -> Finding | None:
    hits, _ = gpo_scope.dc_channel_allow(snap)
    rows = [(h.gpo.name, row) for h in hits if (row := _channel_row(snap, h))]
    if not rows:
        return None
    objects = {text: name for name, (_, text) in rows}
    finding = _finding(
        "AD-GPO-008",
        max(grade for _, (grade, _) in rows),
        "These GPOs let the listed accounts use Netlogon without secure RPC. Onelogon shows an "
        "unprivileged domain user can take over a listed account; a listed DC means the domain. "
        "Which GPO wins is not worked out. This only sees GPOs: a value in a DC's own registry "
        "is not visible, so no finding means no GPO sets it.",
        "Remove the setting 'Domain controller: Allow vulnerable Netlogon secure channel "
        "connections'. Microsoft treats it as temporary and warns against listing admin-level "
        "devices or trust accounts.",
        sorted(objects),
    )
    finding.keys = objects
    return finding


# --- registry policy: the effective value per computer ----------------------------------------


UNKNOWN_HOST = (
    "This reads Group Policy only: a value in a computer's own registry or local policy is not "
    "visible, so 'no GPO sets it' does not say what the computer really does."
)
MAX_NAMES = 5  # computers named on one row


@dataclass(frozen=True)
class _PolicyRow:
    account: Account
    severity: Severity
    text: str  # what this says about the computer; it groups the computers of a row


def _container_of(snap: Snapshot, dn: str) -> str:
    """An account's OU as a path from the domain head; the head as the domain's name."""
    parts = gpo_scope.RDN_SEPARATOR.split(dn, maxsplit=1)
    parent = parts[1] if len(parts) > 1 else ""
    if parent.lower() == snap.domain_dn.lower() or not parent:
        return snap.domain
    tail = parent[: -len(snap.domain_dn) - 1]
    return "/".join(p.split("=", 1)[-1] for p in reversed(gpo_scope.RDN_SEPARATOR.split(tail)))


def _policy_finding(
    snap: Snapshot, check_id: str, detail: str, remediation: str, rows: list[_PolicyRow]
) -> Finding | None:
    """One line per OU and per thing said: a domain can have thousands of computers."""
    if not rows:
        return None
    groups: dict[tuple[str, str], list[_PolicyRow]] = {}
    for row in rows:
        groups.setdefault((_container_of(snap, row.account.dn), row.text), []).append(row)
    objects: dict[str, str] = {}
    for (where, text), members in groups.items():
        names = sorted(r.account.sam.rstrip("$") for r in members)
        shown = ", ".join(names[:MAX_NAMES])
        more = f" +{len(names) - MAX_NAMES} more" if len(names) > MAX_NAMES else ""
        objects[f"{where}: {shown}{more}: {text}"] = f"{where}: {text}"
    finding = _finding(
        check_id,
        max(r.severity for r in rows),
        detail,
        remediation,
        sorted(objects),
    )
    finding.keys = objects
    return finding


def _undecided(effective: gpo_scope.Effective) -> str:
    return "; ".join(effective.why) or "not decided"


def _gpo_note(effective: gpo_scope.Effective) -> str:
    return f" by {effective.gpo}" if effective.gpo else ""


@check("AD-GPO-009", "LLMNR not disabled by Group Policy")
def llmnr_not_disabled(snap: Snapshot) -> Finding | None:
    view = gpo_scope.registry_view(snap)
    if view is None:
        return None
    rows = []
    for a in view.targets():
        e = view.value(a, regpol.LLMNR_KEY, regpol.LLMNR_VALUE)
        if not e.decided:
            rows.append(_PolicyRow(a, Severity.INFO, f"not decided: {_undecided(e)}"))
        elif not e.present:
            text = f"value deleted{_gpo_note(e)}" if e.gpo else "no GPO disables LLMNR"
            rows.append(_PolicyRow(a, Severity.LOW, text))
        elif e.value == 0:
            continue
        elif isinstance(e.value, int):
            text = f"EnableMulticast set to {e.value}{_gpo_note(e)}"
            rows.append(_PolicyRow(a, Severity.MEDIUM, text))
        else:
            rows.append(
                _PolicyRow(a, Severity.INFO, f"EnableMulticast is not a number{_gpo_note(e)}")
            )
    return _policy_finding(
        snap,
        "AD-GPO-009",
        "Group Policy does not turn off LLMNR on these computers. Windows answers it by default, "
        "and anyone on the subnet can answer a failed name lookup and capture the NTLM "
        f"authentication that follows. {UNKNOWN_HOST}",
        "Enable 'Turn off multicast name resolution' (Computer Configuration > Administrative "
        "Templates > Network > DNS Client) in a GPO that reaches these computers.",
        rows,
    )


def _is_http(data: object) -> bool:
    return isinstance(data, str) and data.strip().lower().startswith("http://")


@check("AD-GPO-010", "Group Policy points computers to WSUS over HTTP")
def wsus_over_http(snap: Snapshot) -> Finding | None:
    view = gpo_scope.registry_view(snap)
    if view is None:
        return None
    rows = []
    for a in view.targets():
        url = view.value(a, regpol.WSUS_KEY, regpol.WSUS_SERVER)
        use = view.value(a, regpol.WSUS_AU_KEY, regpol.WSUS_USE)
        plain = [o for o in url.outcomes if o.present and _is_http(o.data)]
        turned_on = any(o.unknown or (o.present and o.data == 1) for o in use.outcomes)
        if not plain or not turned_on:
            continue
        server = str(plain[0].data).strip()
        if url.decided and use.decided:
            severity = Severity.HIGH if a.is_registered_dc else Severity.MEDIUM
            rows.append(_PolicyRow(a, severity, f"{server}{_gpo_note(url)}"))
        else:
            why = "; ".join(sorted({*url.why, *use.why})) or "not decided"
            rows.append(_PolicyRow(a, Severity.INFO, f"{server} not decided: {why}"))
    return _policy_finding(
        snap,
        "AD-GPO-010",
        "These computers are told to fetch updates from WSUS over plain HTTP. Anyone who can get "
        "between them and the server can answer with a Microsoft-signed binary that runs as "
        "SYSTEM.",
        "Configure the WSUS server for HTTPS and change 'Specify intranet Microsoft update "
        "service location' to https:// in the GPO.",
        rows,
    )


def _powershell_row(view: gpo_scope.RegistryView, a: Account) -> _PolicyRow | None:
    problems: list[tuple[Severity, str]] = []
    open_points: list[str] = []
    block = view.value(a, regpol.SCRIPT_BLOCK_KEY, regpol.SCRIPT_BLOCK_VALUE)
    if not block.decided:
        open_points.append(f"script block logging ({_undecided(block)})")
    elif not block.present:
        problems.append((Severity.LOW, "script block logging not set"))
    elif block.value != 1:
        problems.append((Severity.MEDIUM, f"script block logging off{_gpo_note(block)}"))
    module = view.value(a, regpol.MODULE_KEY, regpol.MODULE_VALUE)
    if not module.decided:
        open_points.append(f"module logging ({_undecided(module)})")
    elif not module.present:
        problems.append((Severity.LOW, "module logging not set"))
    elif module.value != 1:
        problems.append((Severity.MEDIUM, f"module logging off{_gpo_note(module)}"))
    else:
        names = [
            view.value(a, regpol.MODULE_NAMES_KEY, n)
            for n in view.names(a, regpol.MODULE_NAMES_KEY)
        ]
        if not any(e.present for e in names):
            if any(not e.decided for e in names):
                reasons = sorted({w for e in names for w in e.why})
                open_points.append(f"module names ({'; '.join(reasons)})")
            else:
                problems.append((Severity.LOW, "module logging on with no module listed"))
    if not problems and not open_points:
        return None
    parts = [text for _, text in problems]
    parts += [f"not decided: {point}" for point in open_points]
    severity = max((s for s, _ in problems), default=Severity.INFO)
    return _PolicyRow(a, severity, "; ".join(parts))


@check("AD-GPO-011", "PowerShell script block or module logging not set by Group Policy")
def powershell_logging(snap: Snapshot) -> Finding | None:
    view = gpo_scope.registry_view(snap)
    if view is None:
        return None
    rows = [row for a in view.targets() if (row := _powershell_row(view, a))]
    return _policy_finding(
        snap,
        "AD-GPO-011",
        "Group Policy does not record PowerShell on these computers, so what an attacker runs "
        f"there is mostly lost. {UNKNOWN_HOST}",
        "Enable 'Turn on PowerShell Script Block Logging' and 'Turn on Module Logging' with "
        "module name * (Computer Configuration > Administrative Templates > Windows Components "
        "> Windows PowerShell).",
        rows,
    )


HARDENED_SHARES = ("SYSVOL", "NETLOGON")
# Windows 10 and Server 2016 require both protections on these shares without any policy. Only
# a name known to be that new gets credit for it: older editions have too many names to list.
# The year-less "Windows Server Standard" and "Datacenter" are the semi-annual channel, 2016 on.
HARDENED_DEFAULT_OS = re.compile(
    r"\bwindows 1\d\b|\bserver 20(?:1[6-9]|[2-9]\d)\b|\bwindows server (?:standard|datacenter)\b",
    re.I,
)


def _hardened(data: object) -> bool:
    """Whether a hardened path's flags require mutual authentication and integrity
    (RequirePrivacy implies integrity: SMB encryption protects the message as well)."""
    if not isinstance(data, str):
        return False
    flags: dict[str, str] = {}
    for part in data.split(","):
        name, sep, value = part.partition("=")
        if sep:
            flags[name.strip().lower()] = value.strip()
    integrity = flags.get("requireintegrity") == "1" or flags.get("requireprivacy") == "1"
    return flags.get("requiremutualauthentication") == "1" and integrity


def _named_hosts(view: gpo_scope.RegistryView, a: Account, share: str) -> list[str]:
    """Hardened paths that name particular servers for this share."""
    out = []
    for name in view.names(a, regpol.HARDENED_KEY):
        host, _, rest = name.lstrip("\\").partition("\\")
        if host != "*" and rest.rstrip("\\").lower() == share.lower():
            e = view.value(a, regpol.HARDENED_KEY, name)
            if e.present and _hardened(e.value):
                out.append(host)
    return sorted(out)


def _share_state(
    view: gpo_scope.RegistryView, a: Account, share: str
) -> tuple[Severity, str] | None:
    e = view.value(a, regpol.HARDENED_KEY, rf"\\*\{share}")
    if not e.decided:
        return Severity.INFO, f"not decided ({_undecided(e)})"
    if e.present:
        if _hardened(e.value):
            return None
        return Severity.MEDIUM, f"set without mutual authentication and integrity{_gpo_note(e)}"
    hosts = _named_hosts(view, a, share)
    if hosts:
        return Severity.INFO, f"hardened only for named servers ({', '.join(hosts)})"
    if not a.os:
        return Severity.INFO, "no GPO sets it and this computer's Windows version is not recorded"
    if HARDENED_DEFAULT_OS.search(re.sub("[\u00ae\u2122]", "", a.os)):
        return Severity.INFO, "no GPO sets it (Windows 10 and Server 2016 harden it by default)"
    return (
        Severity.MEDIUM,
        "no GPO hardens it and this Windows is older than Windows 10 and Server 2016 or not "
        "recognised, so no default can be assumed",
    )


@check("AD-GPO-012", "UNC hardened paths for SYSVOL and NETLOGON missing or weak")
def unc_hardened_paths(snap: Snapshot) -> Finding | None:
    view = gpo_scope.registry_view(snap)
    if view is None:
        return None
    rows = []
    for a in view.targets():
        states = {share: _share_state(view, a, share) for share in HARDENED_SHARES}
        found = {share: state for share, state in states.items() if state}
        if not found:
            continue
        if len(set(found.values())) == 1 and len(found) == len(HARDENED_SHARES):
            severity, text = next(iter(found.values()))
            rows.append(_PolicyRow(a, severity, f"SYSVOL and NETLOGON: {text}"))
        else:
            severity = max(state[0] for state in found.values())
            text = "; ".join(f"{share}: {state[1]}" for share, state in sorted(found.items()))
            rows.append(_PolicyRow(a, severity, text))
    return _policy_finding(
        snap,
        "AD-GPO-012",
        "Group Policy does not require mutual authentication and integrity for these computers' "
        "connections to SYSVOL and NETLOGON. Where the connection is not protected, someone in "
        "the middle can serve their own group policy and scripts (MS15-011). "
        f"{UNKNOWN_HOST}",
        "Set Hardened UNC Paths (Computer Configuration > Administrative Templates > Network > "
        "Network Provider) for \\\\*\\SYSVOL and \\\\*\\NETLOGON to "
        "RequireMutualAuthentication=1, RequireIntegrity=1.",
        rows,
    )


def _dcs_of(view: gpo_scope.RegistryView) -> list[Account]:
    return [a for a in view.targets() if a.is_registered_dc]


_AUDIT_NOT_CHANGED = (
    "setting value 0, which GPMC writes for 'No Auditing' and [MS-GPAC] calls unchanged"
)


def _audit_row(view: gpo_scope.RegistryView, a: Account) -> _PolicyRow | None:
    off: list[str] = []
    partial: list[str] = []
    zero: list[str] = []
    basic: list[str] = []
    basic_off: list[str] = []
    absent: list[str] = []
    open_points: list[str] = []
    categories = view.basic_audit(a)
    for sub in auditpol.RECOMMENDED:
        e = view.audit(a, sub.guid)
        if not e.decided:
            open_points.append(f"{sub.name} ({_undecided(e)})")
        elif not e.present:
            audits = categories.get(sub.legacy)
            (basic if audits else basic_off if audits is False else absent).append(sub.name)
        elif e.value == auditpol.NONE:
            off.append(f"{sub.name}{_gpo_note(e)}")
        elif e.value == auditpol.NOT_CHANGED:
            zero.append(f"{sub.name}{_gpo_note(e)}")
        elif isinstance(e.value, int) and e.value & sub.wanted != sub.wanted:
            missing = "failure" if e.value & auditpol.SUCCESS else "success"
            partial.append(f"{sub.name} without {missing}{_gpo_note(e)}")
    severity = Severity.MEDIUM if off else Severity.LOW if partial else Severity.INFO
    parts = []
    if off:
        parts.append(f"set to no auditing: {', '.join(off)}")
    if partial:
        parts.append(f"partly set: {', '.join(partial)}")
    if zero:
        parts.append(f"not judged ({_AUDIT_NOT_CHANGED}): {', '.join(zero)}")
    if open_points:
        parts.append(f"not decided: {', '.join(open_points)}")
    if basic:
        parts.append(
            "only basic audit policy covers these, and whether it applies depends on the "
            f"computer's SCENoApplyLegacyAuditPolicy: {', '.join(basic)}"
        )
    if basic_off:
        parts.append(f"basic audit policy sets no auditing for these: {', '.join(basic_off)}")
    if len(absent) == len(auditpol.RECOMMENDED):
        parts.append(f"no GPO sets any of the {len(absent)} recommended subcategories")
    elif absent:
        parts.append(f"no GPO sets: {', '.join(absent)}")
    return _PolicyRow(a, severity, "; ".join(parts)) if parts else None


@check("AD-GPO-013", "Domain controllers' audit policy below Microsoft's recommendation")
def dc_audit_policy(snap: Snapshot) -> Finding | None:
    view = gpo_scope.policy_view(snap)
    if view is None:
        return None
    rows = [row for a in _dcs_of(view) if (row := _audit_row(view, a))]
    return _policy_finding(
        snap,
        "AD-GPO-013",
        "The advanced audit policy Group Policy gives these domain controllers falls short of "
        "Microsoft's baseline for domain controllers, or leaves it open. Where a subcategory is "
        "not audited, the logon, group change and directory change events that show an intrusion "
        f"are not written. {UNKNOWN_HOST}",
        "Set the subcategories under Computer Configuration > Windows Settings > Security "
        "Settings > Advanced Audit Policy Configuration in a GPO linked to the Domain Controllers "
        "OU, as in Microsoft's System Audit Policy recommendations.",
        rows,
    )


@check("AD-GPO-014", "Group Policy sets automatic logon or stores its password")
def gpo_autologon(snap: Snapshot) -> Finding | None:
    if not snap.gpo_autologon:
        return None
    names = {g.guid.upper(): g.name for g in snap.gpos}
    objects = []
    stored = False
    for x in snap.gpo_autologon:
        where = f"{names.get(x.gpo.upper(), x.gpo)} ({x.path})"
        if x.password:
            stored = True
            state = "AutoAdminLogon is 1" if x.auto_on else "AutoAdminLogon not set in this file"
            objects.append(f"{where}: DefaultPassword stored in the file; {state}")
        else:
            objects.append(f"{where}: AutoAdminLogon is 1, no password in this file")
    return _finding(
        "AD-GPO-014",
        Severity.HIGH if stored else Severity.INFO,
        "A GPO file holding Winlogon DefaultPassword is readable in clear text by every domain "
        "user through SYSVOL, whether the GPO is linked or not (the value is not reproduced "
        "here)."
        if stored
        else "Group Policy turns on automatic logon. The password it uses is not in these files, "
        "and where it is kept on the computer cannot be seen from here.",
        "Remove the DefaultPassword value from the GPO, change that account's password and "
        "stop using automatic logon where possible.",
        sorted(objects),
    )


@check("AD-GPO-015", "Group Policy keeps NTLMv1-derived single sign-on in audit mode")
def block_ntlmv1_sso(snap: Snapshot) -> Finding | None:
    view = gpo_scope.policy_view(snap)
    if view is None:
        return None
    rows = []
    for a in view.targets():
        e = view.merged(a, regpol.MSV1_0_KEY, regpol.BLOCK_NTLMV1_SSO)
        if not e.decided:
            rows.append(_PolicyRow(a, Severity.INFO, f"not decided: {_undecided(e)}"))
        elif not e.present or e.value == 1:
            continue
        elif e.value == 0:
            rows.append(_PolicyRow(a, Severity.LOW, f"set to 0 (audit){_gpo_note(e)}"))
        else:
            rows.append(_PolicyRow(a, Severity.INFO, f"unrecognised value{_gpo_note(e)}"))
    return _policy_finding(
        snap,
        "AD-GPO-015",
        "Group Policy sets BlockNtlmv1SSO to 0 on these computers, which lets single sign-on use "
        "NTLMv1-derived credentials, with a warning event only. It applies to Windows 11 24H2 and "
        "later and Windows Server 2025 where Credential Guard is off; since the October 2026 "
        "updates Windows blocks this when the value is absent. Computers where no GPO sets it "
        "are not listed.",
        "Remove the value from the GPO or set it to 1, and move what depends on it (MS-CHAPv2 "
        "Wi-Fi or VPN, for example) to certificate authentication.",
        rows,
    )


ENCTYPE_DES = 0x1 | 0x2
ENCTYPE_RC4 = 0x4


@check("AD-GPO-016", "Group Policy allows weak Kerberos types as the domain default")
def default_enctypes(snap: Snapshot) -> Finding | None:
    view = gpo_scope.policy_view(snap)
    if view is None:
        return None
    rows = []
    for a in _dcs_of(view):
        e = view.merged(a, regpol.KDC_KEY, regpol.DEFAULT_ENCTYPES)
        if not e.decided:
            rows.append(_PolicyRow(a, Severity.INFO, f"not decided: {_undecided(e)}"))
        elif not e.present:
            continue
        elif not isinstance(e.value, int):
            rows.append(_PolicyRow(a, Severity.INFO, f"not a number{_gpo_note(e)}"))
        elif e.value & ENCTYPE_DES:
            rows.append(_PolicyRow(a, Severity.MEDIUM, f"{e.value:#x} allows DES{_gpo_note(e)}"))
        elif e.value & ENCTYPE_RC4:
            rows.append(_PolicyRow(a, Severity.LOW, f"{e.value:#x} allows RC4{_gpo_note(e)}"))
    return _policy_finding(
        snap,
        "AD-GPO-016",
        "Group Policy sets DefaultDomainSupportedEncTypes on these domain controllers to a value "
        "with DES or RC4. It decides what an account with an empty "
        "msDS-SupportedEncryptionTypes gets, so tickets for it can be requested in a type that "
        "is cheap to crack. Domain controllers where no GPO sets it are not listed.",
        "Set the value to 0x38 (AES only) once no account depends on RC4; 0x3C, Microsoft's "
        "intermediate step, still allows RC4.",
        rows,
    )


@check("AD-GPO-004", "GPOs editable outside tier 0")
def gpo_edit_any(snap: Snapshot) -> Finding | None:
    tier0 = snap.tier0_sids()
    allowed = tier0 | {CREATOR_OWNER}
    hits = []
    for g in snap.gpos:
        if g.linked_to:
            continue  # GPOs linked to the domain or DCs are AD-GPO-001
        who = sorted({snap.name_of(a.sid) for a in g.aces if a.takeover and a.sid not in allowed})
        if who:
            hits.append(f"{g.name} ({', '.join(who)})")
    if not hits:
        return None
    return _finding(
        "AD-GPO-004",
        Severity.MEDIUM,
        "Whoever can edit a GPO runs code on every computer or user it is linked to now or later.",
        "Restrict GPO edit rights to the admins of the tier the GPO applies to.",
        sorted(hits),
    )


@check("AD-GPP-002", "Credentials in SYSVOL or NETLOGON scripts")
def script_secrets(snap: Snapshot) -> Finding | None:
    if not snap.script_secrets:
        return None
    return _finding(
        "AD-GPP-002",
        Severity.HIGH,
        "Every domain user can read SYSVOL and NETLOGON; these lines appear to contain a "
        "literal password (the value is not reproduced here).",
        "Remove the credentials from the scripts and change the passwords.",
        sorted(f"{s.path}:{s.line} ({s.kind})" for s in snap.script_secrets),
    )


@check("AD-INF-008", "SMB signing not required on domain controllers")
def smb_signing(snap: Snapshot) -> Finding | None:
    weak = _weak_dcs(snap, "smb_signing_required", snap.probes.smb_signing_required, False)
    if not weak:
        return None
    return _finding(
        "AD-INF-008",
        Severity.HIGH,
        "Relayed NTLM authentication can be used against these DCs over SMB"
        + _of_probed(snap, weak, "smb_signing_required")
        + ".",
        "Enable 'Microsoft network server: Digitally sign communications (always)' on DCs.",
        weak,
    )


def _spooler_dcs(snap: Snapshot) -> list[str]:
    return _weak_dcs(snap, "spooler", snap.probes.spooler_on_dc, True)


@check("AD-INF-009", "Print Spooler running on domain controllers")
def spooler(snap: Snapshot) -> Finding | None:
    running = _spooler_dcs(snap)
    if not running:
        return None
    unconstrained = unconstrained_delegation(snap)
    detail = (
        "Any domain user can make the DC authenticate to a host of their choice through the "
        "spooler (PrinterBug), the starting point of relay and delegation attacks."
    )
    if unconstrained:
        detail += " Combined with unconstrained delegation this is a direct path to the domain."
    return _finding(
        "AD-INF-009",
        Severity.HIGH if unconstrained else Severity.MEDIUM,
        detail,
        "Stop and disable the Print Spooler service on domain controllers.",
        running,
    )


@check("AD-INF-010", "LDAPS channel binding not enforced")
def channel_binding(snap: Snapshot) -> Finding | None:
    weak = _weak_dcs(
        snap,
        "ldaps_channel_binding_required",
        snap.probes.ldaps_channel_binding_required,
        False,
    )
    if not weak:
        return None
    return _finding(
        "AD-INF-010",
        Severity.MEDIUM,
        "These DCs accepted an LDAPS bind without a channel binding token"
        + _of_probed(snap, weak, "ldaps_channel_binding_required")
        + ", so NTLM relayed from another connection can authenticate to LDAPS.",
        "Set 'Domain controller: LDAP server channel binding token requirements' to Always.",
        weak,
    )


BACKUP_MAX_AGE = timedelta(days=7)


@check("AD-INF-011", "No recent backup of the domain")
def backup_age(snap: Snapshot) -> Finding | None:
    last = snap.last_backup
    if not snap.backup_checked or (last and snap.collected_at - last <= BACKUP_MAX_AGE):
        return None
    detail = (
        "The domain partition has never been backed up."
        if last is None
        else f"The domain partition was last backed up {(snap.collected_at - last).days} days ago."
    )
    return _finding(
        "AD-INF-011",
        Severity.MEDIUM,
        detail + " Without one, recovering from ransomware or a forest compromise means "
        "rebuilding.",
        "Take system-state backups of at least one DC per domain daily and test restores.",
        [snap.domain],
    )


DENIED_RODC_GROUP_RID = 572


@check("AD-INF-012", "RODCs that may cache privileged credentials")
def rodc_policy(snap: Snapshot) -> Finding | None:
    privileged_groups = {
        o.dn.lower() for o in snap.objects if o.sid in _tier0_group_sids(snap) | snap.broad_sids()
    }
    denied = next(
        (o.dn.lower() for o in snap.objects if o.rid_is(snap, DENIED_RODC_GROUP_RID)),
        None,
    )
    hits = []
    for r in snap.rodcs:
        allowed = [d for d in r.reveal if d.lower() in privileged_groups]
        if allowed:
            hits.append(f"{r.name}: allowed {', '.join(_account_names(snap, allowed))}")
        if denied and denied not in {d.lower() for d in r.never_reveal}:
            hits.append(f"{r.name}: Denied RODC Password Replication Group not in never-reveal")
    if not hits:
        return None
    return _finding(
        "AD-INF-012",
        Severity.MEDIUM,
        "A stolen RODC would hand over the cached credentials of these principals.",
        "Keep privileged and broad groups out of msDS-RevealOnDemandGroup and keep the Denied "
        "RODC Password Replication Group in msDS-NeverRevealGroup.",
        sorted(hits),
    )


# --- Compound findings: combinations that are a known one-step compromise --------------


@check("AD-CHAIN-001", "Relay to resource-based delegation")
def chain_relay_rbcd(snap: Snapshot) -> Finding | None:
    relayable = [
        name
        for name, weak in (
            (
                "LDAP signing not required",
                snap.probes.overall("ldap_signing_required", snap.ldap_signing_required) is False,
            ),
            (
                "LDAPS channel binding not enforced",
                snap.probes.overall(
                    "ldaps_channel_binding_required", snap.probes.ldaps_channel_binding_required
                )
                is False,
            ),
        )
        if weak
    ]
    if snap.policy.machine_account_quota <= 0 or not relayable:
        return None
    return _finding(
        "AD-CHAIN-001",
        Severity.HIGH,
        f"{' and '.join(relayable)}, and any user can create computer accounts: coerced "
        "authentication from a server can be relayed to LDAP to set up resource-based "
        "delegation and log on to that server as an admin.",
        "Require LDAP signing and channel binding, and set ms-DS-MachineAccountQuota to 0.",
        [snap.domain],
    )


COERCION_ASSUMED = (
    "Coercion is assumed possible: no DC spooler was confirmed, but PetitPotam (EFSRPC) and "
    "DFSCoerce (MS-DFSNM) need no spooler, and nothing here proves them blocked."
)


def _spooler_route(dcs: list[str]) -> str:
    return f"Confirmed coercion route: the Print Spooler runs on {', '.join(dcs)}."


@check("AD-CHAIN-002", "Coercion plus unconstrained delegation")
def chain_coerce_unconstrained(snap: Snapshot) -> Finding | None:
    delegated = unconstrained_delegation(snap)
    if delegated is None:
        return None
    spooler = _spooler_dcs(snap)
    route = _spooler_route(spooler) if spooler else COERCION_ASSUMED
    return _finding(
        "AD-CHAIN-002",
        Severity.HIGH if spooler else Severity.MEDIUM,
        f"{route} A DC made to authenticate to a host with unconstrained delegation leaves its "
        "TGT there: whoever controls that host can DCSync. This path uses Kerberos, so "
        "RestrictSendingNTLMTraffic does not stop it.",
        "Remove unconstrained delegation: that closes this path. Disabling the spooler on DCs "
        "removes one route only.",
        delegated.objects,
    )


@check("AD-CHAIN-003", "Coercion plus web enrollment relay (ESC8)")
def chain_esc8(snap: Snapshot) -> Finding | None:
    if not snap.probes.web_enrollment_ntlm:
        return None
    spooler = _spooler_dcs(snap)
    ntlm = gpo_scope.dc_outgoing_ntlm(snap)
    route = _spooler_route(spooler) if spooler else COERCION_ASSUMED
    if ntlm.denied:
        severity = Severity.MEDIUM
        detail = (
            f"Group Policy blocks the NTLM half of this relay: {ntlm.detail}. Web enrollment "
            "still offers Windows authentication, and a coerced DC can also be relayed there "
            "with Kerberos, which that setting does not cover."
        )
    else:
        severity = Severity.HIGH if spooler else Severity.MEDIUM
        state = f"unknown ({ntlm.detail})" if ntlm.denied is None else ntlm.detail
        detail = (
            f"{route} A coerced DC's authentication can be relayed to web enrollment for a DC "
            f"certificate: domain compromise in two commands. Outgoing NTLM on DCs: {state}."
        )
    return _finding(
        "AD-CHAIN-003",
        severity,
        detail,
        "Fix web enrollment: require HTTPS with Extended Protection for Authentication, or "
        "remove it. Disabling the spooler on DCs removes one coercion route only.",
        sorted(snap.probes.web_enrollment_ntlm),
    )


# --- Round 4: every DC, Exchange, Entra Connect ---------------------------------------


@check("AD-INF-013", "Domain controllers that could not be probed")
def unprobed_dcs(snap: Snapshot) -> Finding | None:
    hits = sorted(f"{d.name}: {d.error}" for d in snap.probes.dcs if d.error)
    if not hits:
        return None
    return _finding(
        "AD-INF-013",
        Severity.LOW,
        "The SMB, signing and channel binding checks could not reach these DCs, so their "
        "results say nothing about them. Settings often drift between DCs.",
        "Run the scan from a host that reaches every DC (TCP 389, 445 and 636), or scan each "
        "DC separately.",
        hits,
    )


@check("AD-INF-018", "Domain controllers with an old machine password")
def dc_machine_password(snap: Snapshot) -> Finding | None:
    aged = []
    for a in snap.accounts:
        changed = a.password_changed
        if not a.is_computer or not a.enabled or not a.is_registered_dc or a.entra_kerberos:
            continue
        if changed is not None and snap.collected_at - changed > DC_PASSWORD_REVIEW:
            aged.append((a.sam, (snap.collected_at - changed).days))
    if not aged:
        return None
    aged.sort()
    return _finding(
        "AD-INF-018",
        Severity.MEDIUM if any(days > DC_PASSWORD_OLD.days for _, days in aged) else Severity.LOW,
        "Machine password age in days: "
        + ", ".join(f"{sam} {days}" for sam, days in aged)
        + ". A DC normally changes it every 30 days. Review it: rotation may be turned off, "
        "the DC may be failing or offline, or it may have been restored from an old copy.",
        "Check DisablePasswordChange and RefusePasswordChange in the Netlogon settings and the "
        "DC's replication health, then reset the machine password if it does not change.",
        [sam for sam, _ in aged],
    )


@check("AD-INF-019", "SYSVOL still replicated by FRS")
def sysvol_frs(snap: Snapshot) -> Finding | None:
    flags = snap.sysvol_dfsr_flags
    if not snap.sysvol_replication_checked or flags == SYSVOL_ELIMINATED:
        return None
    if flags == SYSVOL_REDIRECTED:
        return _finding(
            "AD-INF-019",
            Severity.LOW,
            "The FRS to DFS Replication migration stopped in the Redirected state: DFS "
            "Replication serves SYSVOL, but FRS still replicates the old copy.",
            "Finish the migration: dfsrmig /setglobalstate 3, once every DC has reached state 2.",
            [snap.domain],
        )
    if flags == SYSVOL_PREPARED:
        return _finding(
            "AD-INF-019",
            Severity.MEDIUM,
            "The FRS to DFS Replication migration stopped in the Prepared state: SYSVOL is "
            "still served from the copy FRS replicates.",
            "Continue the migration with dfsrmig /setglobalstate 2, then 3.",
            [snap.domain],
        )
    frs = {dn.lower() for dn in snap.sysvol_frs_dcs}
    dfsr = {dn.lower() for dn in snap.sysvol_dfsr_dcs}
    dcs = [a for a in snap.accounts if a.is_computer and a.is_registered_dc]
    frs_only = [a for a in dcs if a.dn.lower() in frs - dfsr]
    if frs_only:
        return _finding(
            "AD-INF-019",
            Severity.MEDIUM,
            "These DCs have an FRS SYSVOL subscription and no DFS Replication one, and no "
            "migration to DFS Replication has been recorded.",
            "Migrate SYSVOL to DFS Replication with dfsrmig; the migration is one-way.",
            _names(frs_only),
        )
    both = [a for a in dcs if a.dn.lower() in frs & dfsr]
    if both and flags == SYSVOL_START:
        return _finding(
            "AD-INF-019",
            Severity.MEDIUM,
            "The FRS to DFS Replication migration is in the Start state, so FRS still serves "
            "SYSVOL, although these DCs also hold a DFS Replication subscription.",
            "Review the state with dfsrmig /getmigrationstate, then migrate with dfsrmig; the "
            "migration is one-way.",
            _names(both),
        )
    if both:
        return _finding(
            "AD-INF-019",
            Severity.LOW,
            "These DCs hold both an FRS and a DFS Replication SYSVOL subscription, and the "
            "migration state could not be read. Review the state with dfsrmig /getglobalstate.",
            "If the migration is unfinished, complete it with dfsrmig.",
            _names(both),
        )
    return None


def _rdn_value(dn: str) -> str:
    return gpo_scope.RDN_SEPARATOR.split(dn, maxsplit=1)[0].split("=", 1)[1]


@check("AD-INF-020", "Sites and subnets that need review")
def site_topology(snap: Snapshot) -> Finding | None:
    if not snap.site_topology_checked:
        return None
    objects = [f"subnet {s.name}: maps to no site" for s in snap.subnets if not s.site]
    used = {s.site.lower() for s in snap.subnets if s.site}
    several = len(snap.sites) > 1
    any_server = any(s.servers for s in snap.sites)
    for site in snap.sites:
        problems = []
        if any_server and not site.servers:
            problems.append("no domain controller")
        if several and site.dn.lower() not in used:
            problems.append("no subnet")
        if several and site.servers and site.linked is False:
            problems.append("in no site link")
        if problems:
            objects.append(f"site {_rdn_value(site.dn)}: {', '.join(problems)}")
    if not objects:
        return None
    return _finding(
        "AD-INF-020",
        Severity.LOW,
        "Review these. A client on an unmapped subnet picks any DC, possibly across a slow "
        "link; a site with no DC relies on automatic site coverage; a site in no site link "
        "gets no automatically built replication.",
        "Map each subnet to a site, delete sites nobody uses, and put every site with a DC "
        "in a site link.",
        sorted(objects),
    )


@check("AD-INF-021", "Replication conflict objects and duplicate accounts")
def conflict_objects(snap: Snapshot) -> Finding | None:
    objects = [f"{c.dn} ({c.kind})" for c in snap.conflicts]
    by_sid: dict[str, list[str]] = {}
    by_sam: dict[str, list[str]] = {}
    for a in snap.accounts:
        if a.sid:
            by_sid.setdefault(a.sid, []).append(a.sam)
        if a.sam:
            by_sam.setdefault(a.sam.lower(), []).append(a.dn)
    shared_sids = {sid: sams for sid, sams in by_sid.items() if len(sams) > 1}
    objects += [
        f"sAMAccountName {sam}: {'; '.join(sorted(dns))}"
        for sam, dns in by_sam.items()
        if len(dns) > 1
    ]
    objects += [f"SID {sid}: {', '.join(sorted(sams))}" for sid, sams in shared_sids.items()]
    if not objects:
        return None
    return _finding(
        "AD-INF-021",
        Severity.MEDIUM if shared_sids else Severity.LOW,
        "Conflicts created when two DCs write the same object before replicating. Review which "
        "object is the real one; a leftover can keep group memberships and SIDs."
        + (" Accounts sharing a SID hold the same access." if shared_sids else ""),
        "Compare each pair (whenCreated, group membership), delete the unwanted object, and "
        "rename the survivor if needed.",
        sorted(objects),
    )


def _show_invisible(value: str) -> str:
    hidden = set(invisible_chars(value))
    return "".join(f"<U+{ord(c):04X}>" if c in hidden else c for c in value)


@check("AD-ACC-016", "Identity collisions to review: UPN, SPN and host name")
def identity_collisions(snap: Snapshot) -> Finding | None:
    objects = []
    by_sam = {a.sam.lower(): a for a in snap.accounts}
    computers = {a.sam.removesuffix("$").lower(): a for a in snap.accounts if a.is_computer}
    for a in snap.accounts:
        other = by_sam.get(a.upn.lower()) if a.upn and snap.upn_checked else None
        if other is not None and other is not a:
            objects.append(f"{a.sam}: UPN {a.upn} is the sAMAccountName of {other.sam}")
        objects += [f"{a.sam}: SPN {_show_invisible(s)}" for s in a.spns if invisible_chars(s)]
        if (
            a.is_computer
            and a.enabled
            and not a.managed
            and not a.entra_kerberos
            and a.dns_host
            and a.sam
            and snap.host_names_comparable
            and not dns_host_matches(a.dns_host, a.sam)
        ):
            owner = computers.get(a.dns_host.split(".", 1)[0].lower())
            taken = f" (the name of {owner.sam})" if owner is not None and owner is not a else ""
            objects.append(f"{a.sam}: dNSHostName {a.dns_host}{taken}")
    if not objects:
        return None
    return _finding(
        "AD-ACC-016",
        Severity.LOW,
        "Review these. A UPN equal to another account's sAMAccountName, an SPN with invisible "
        "characters and a dNSHostName that is not the computer's own name are the leftovers of "
        "known Kerberos identity attacks, but renames and appliances can look the same.",
        "Confirm who set each value and when (Event 5136, replication metadata), then correct "
        "the value. Install the 2026 Kerberos updates (CVE-2026-25177, CVE-2026-27912).",
        sorted(objects),
    )


def _pso_weaknesses(p: Pso) -> list[str]:
    out = []
    if p.min_length is not None and p.min_length < PSO_MIN_LENGTH:
        out.append(f"minimum length {p.min_length}")
    if p.complexity is False:
        out.append("complexity off")
    if p.lockout_threshold == 0:
        out.append("no lockout")
    if p.reversible:
        out.append("reversible encryption on")
    return out


def _winning_psos(snap: Snapshot) -> dict[str, list[Pso]]:
    """Enabled privileged user (sAMAccountName) -> the PSOs in force for it: those linked to
    the user beat those linked to its global groups, then the lowest precedence wins. Two
    PSOs tied on precedence stay both: Windows breaks the tie by GUID, which is not read."""
    privileged = snap.privileged_dns()
    users = [a for a in _enabled_users(snap) if a.dn.lower() in privileged]
    groups = [o for o in snap.objects if o.kind == "group"]
    parents: dict[str, list[str]] = {}
    for g in groups:
        for member in g.members:
            parents.setdefault(member.lower(), []).append(g.dn.lower())
    by_sid = {g.sid: g.dn.lower() for g in groups if g.sid}
    linked = [(p, {dn.lower() for dn in p.applies_to}) for p in snap.psos]
    no_effect = {id(p): {dn.lower() for dn in p.not_global} for p in snap.psos}
    out: dict[str, list[Pso]] = {}
    for user in users:
        dn = user.dn.lower()
        candidates = [p for p, links in linked if dn in links]
        if not candidates:
            seen: set[str] = set()
            primary = by_sid.get(f"{snap.domain_sid}-{user.primary_group}")
            todo = [*parents.get(dn, []), *([primary] if primary else [])]
            while todo:
                group = todo.pop()
                if group not in seen:
                    seen.add(group)
                    todo += parents.get(group, [])
            candidates = [p for p, links in linked if (links - no_effect[id(p)]) & seen]
        if candidates:
            lowest = min(p.precedence for p in candidates)
            out[user.sam] = [p for p in candidates if p.precedence == lowest]
    return out


@check("AD-POL-003", "Weak fine-grained password policies")
def weak_psos(snap: Snapshot) -> Finding | None:
    if not snap.psos:
        return None
    in_force: dict[str, list[str]] = {}
    for sam, winners in _winning_psos(snap).items():
        if all(_pso_weaknesses(p) for p in winners):
            for p in winners:
                in_force.setdefault(p.name, []).append(sam)
    objects = []
    keys = {}
    for p in sorted(snap.psos, key=lambda x: x.name):
        weak = _pso_weaknesses(p)
        if not weak or not set(map(str.lower, p.applies_to)) - set(map(str.lower, p.not_global)):
            continue
        text = f"{p.name}: {', '.join(weak)}"
        admins = sorted(in_force.get(p.name, []))
        if admins:
            more = f" (+{len(admins) - 5} more)" if len(admins) > 5 else ""
            text += f"; in force for {', '.join(admins[:5])}{more}"
        objects.append(text)
        keys[text] = p.name
    if not objects:
        return None
    sure = bool(in_force) and not snap.psos_unreadable
    finding = _finding(
        "AD-POL-003",
        Severity.MEDIUM if sure else Severity.LOW,
        "These password policies are weaker than the bar of AD-POL-001: an account they apply "
        "to can have a password that is cheap to guess or crack."
        + (
            " Privileged accounts use them."
            if sure
            else " Review them: no privileged account is known to use them."
            if not in_force
            else " Review them: a policy that could not be read may take precedence."
        ),
        "Raise the settings of each policy, or remove the link, and check the result with "
        "Get-ADUserResultantPasswordPolicy.",
        objects,
    )
    finding.keys = keys
    return finding


def _dmsa_controllers(
    snap: Snapshot, dmsa: Dmsa, tier0: set[str], superseded: str
) -> dict[str, str]:
    """Who outside tier 0 controls one dMSA, each with the right that gives it. The account
    being migrated holds rights on its dMSA until the migration completes, by design."""
    held: dict[str, str] = {}
    if dmsa.owner and dmsa.owner not in tier0:
        held[dmsa.owner] = "owner"
    machines = {a.sid for a in snap.accounts if a.is_computer}
    for ace in dmsa.aces:
        skip = ace.sid in tier0 or ace.sid in (PRINCIPAL_SELF, CREATOR_OWNER)
        if skip or (dmsa.state == DMSA_MIGRATING and ace.sid == superseded):
            continue
        if ace.takeover:
            held.setdefault(ace.sid, "control")
        elif ace.writes(sd.GROUP_MSA_MEMBERSHIP) or ace.writes(sd.MANAGED_ACCOUNT_PRECEDED_BY):
            held.setdefault(ace.sid, "writes its links")
    for sid in dmsa.readers:
        # the machines that run the service are meant to be listed here
        if sid not in tier0 | machines and not (dmsa.state == DMSA_MIGRATING and sid == superseded):
            held.setdefault(sid, DMSA_USE_RIGHT)
    return held


@check("AD-ACL-009", "Control over dMSAs that replace another account")
def dmsa_control(snap: Snapshot) -> Finding | None:
    by_dn = snap.by_dn()
    privileged = snap.tier0_dns()
    # the members of the tier-0 groups are tier 0 too, not only the groups
    tier0 = _tier0_group_sids(snap)
    tier0 |= {a.sid for a in snap.accounts if a.sid and a.dn.lower() in privileged}
    tier0 |= {o.sid for o in snap.objects if o.sid and o.dn.lower() in privileged}
    objects = []
    severity = Severity.LOW
    for d in snap.dmsas:
        if not d.preceded_by or not d.acl_read:
            continue
        link = d.preceded_by.lower()
        old = by_dn.get(link)
        held = _dmsa_controllers(snap, d, tier0, old.sid if old else "")
        if not held:
            continue
        who = [f"{snap.name_of(sid)} ({right})" for sid, right in sorted(held.items())]
        target = old.sam if old else _rdn_value(d.preceded_by)
        objects.append(f"{d.name}: replaces {target}; held by {', '.join(who)}")
        # a group of hosts in the use list is ordinary; only a right over the object counts
        control = any(right != DMSA_USE_RIGHT for right in held.values())
        if control and d.state == DMSA_MIGRATED and link in privileged:
            severity = Severity.MEDIUM
    # only a dMSA judged above: one whose link or descriptor did not come back was not
    known = {d.dn.lower() for d in snap.dmsas if d.preceded_by and d.acl_read}
    for a in snap.accounts:
        link = (a.superseded_by or "").lower()
        if link and link not in known:
            objects.append(
                f"{a.sam}: replaced by {_rdn_value(a.superseded_by or '')}; dMSA not readable, "
                "who controls it is unknown"
            )
    if not objects:
        return None
    return _finding(
        "AD-ACL-009",
        severity,
        "A dMSA receives the access of the account it replaces, so whoever controls the dMSA "
        "may gain that access. Review who holds these rights: the exact conditions of the "
        "published technique could not be confirmed.",
        "Remove the listed rights so that only tier 0 and the hosts running the service hold "
        "them. Finish or roll back migrations that are not in use.",
        sorted(objects),
    )


@check("AD-KRB-007", "Entra Kerberos objects to review: key age and look-alikes")
def entra_kerberos_objects(snap: Snapshot) -> Finding | None:
    if not snap.krbtgt_links_checked:
        return None
    by_dn = snap.by_dn()
    objects = []
    ages = []
    linked = set()
    for a in snap.accounts:
        key = by_dn.get((a.krbtgt_link or "").lower()) if a.entra_kerberos else None
        if key is None:
            continue
        linked.add(key.dn.lower())
        changed = key.password_changed
        if changed is not None and snap.collected_at - changed > ENTRA_KEY_REVIEW:
            ages.append(f"{key.sam} {(snap.collected_at - changed).days}")
            objects.append(f"{key.sam}: key of the Entra Kerberos object {a.sam}")
    for a in snap.accounts:
        if a.is_computer and a.sam.lower() == ENTRA_KERBEROS_COMPUTER and not a.entra_kerberos:
            objects.append(f"{a.sam}: named like the Entra Kerberos object, not built like it")
        elif a.sam.lower() in ENTRA_KERBEROS_USERS and a.dn.lower() not in linked:
            objects.append(f"{a.sam}: named like its key account, linked from no such object")
    if not objects:
        return None
    return _finding(
        "AD-KRB-007",
        Severity.LOW,
        (f"Key age in days: {', '.join(ages)}. " if ages else "")
        + "Review these. The key account protects tickets Microsoft Entra issues for this "
        "domain, and Microsoft says to rotate it on the schedule of the other krbtgt keys. "
        "An object that only has the name may be a leftover or may be meant to pass for it.",
        "Rotate with Set-AzureADKerberosServer -RotateServerKey. Look-alikes: find who "
        "created them, then remove them if nobody needs them.",
        sorted(objects),
    )


@check("AD-INF-014", "Rogue DC candidates: DC flag without an NTDS Settings object")
def rogue_dcs(snap: Snapshot) -> Finding | None:
    hits = [a for a in snap.accounts if a.rogue_dc]
    if not hits:
        return None
    live = [a for a in hits if a.enabled and a.has(UAC.SERVER_TRUST_ACCOUNT)]
    detail = (
        "These computers carry a domain controller flag in userAccountControl, but no nTDSDSA "
        "object in the Configuration partition says they are DCs. It can be a leftover of a "
        "failed promotion or demotion, or a computer turned into a fake DC."
    )
    if live:
        detail += (
            f" Enabled with SERVER_TRUST_ACCOUNT, so treated as DCs by Windows: "
            f"{', '.join(_names(live))}. With primary group Domain Controllers such an account "
            "holds that group's replication rights."
        )
    return _finding(
        "AD-INF-014",
        Severity.HIGH if live else Severity.MEDIUM,
        detail,
        "Find out who set the flag (replication metadata of userAccountControl). If it is not a "
        "DC, reset userAccountControl and primaryGroupID, then rotate its password; if it is "
        "a failed DC, finish metadata cleanup.",
        _names(hits),
    )


def _exchange_sids(snap: Snapshot) -> dict[str, str]:
    """SID -> name of the Exchange-created groups in the snapshot."""
    return {
        o.sid: o.name
        for o in snap.objects
        if o.kind == "group" and o.sid and o.name.lower() in EXCHANGE_GROUPS
    }


def _exchange_rights(ace: sd.Ace) -> list[str]:
    rights = []
    if ace.mask & sd.GENERIC_ALL:
        rights.append("full control")
    else:
        if ace.mask & sd.WRITE_DAC:
            rights.append("WriteDacl")
        if ace.mask & sd.WRITE_OWNER:
            rights.append("WriteOwner")
    return rights


@check("AD-ACL-007", "Exchange groups with rights over the domain (PrivExchange)")
def exchange_rights(snap: Snapshot) -> Finding | None:
    groups = _exchange_sids(snap)
    if not groups:
        return None
    hits = []
    direct = False
    for ace in snap.acls.get("domain", []):
        if ace.sid in groups:
            rights = _exchange_rights(ace)
            if ace.extended_right(sd.DS_REPL_GET_CHANGES_ALL):
                rights.append("replicate secrets")
            if rights:
                direct = True
                hits.append(f"{groups[ace.sid]}: {', '.join(rights)} on the domain object")
    head = next((o for o in snap.objects if o.kind == "domain"), None)
    for ace in head.inheritable if head else []:
        applies = ace.inherited_object_type in (None, sd.USER_CLASS, sd.GROUP_CLASS)
        rights = _exchange_rights(ace)
        if ace.sid in groups and applies and rights:
            hits.append(f"{groups[ace.sid]}: {', '.join(rights)} inherited by users and groups")
    if not hits:
        return None
    by_dn = snap.object_by_dn()
    servers = set()
    for o in snap.objects:
        if o.sid in groups:
            for m in o.members:
                member = by_dn.get(m.lower())
                if member is None or member.kind != "group":
                    servers.add(_account_names(snap, [m])[0])
    detail = (
        "Exchange setup gave its groups WriteDacl over the domain. Anyone who controls an "
        "Exchange server, or can make one authenticate and relay it to LDAP, can grant "
        "themselves DCSync."
        if direct
        else "Exchange groups hold WriteDacl on every user and group through inheritance, so "
        "whoever controls an Exchange server can take over any non-protected account."
    )
    if servers:
        detail += f" Members: {', '.join(sorted(servers, key=str.lower))}."
    return _finding(
        "AD-ACL-007",
        Severity.HIGH if direct else Severity.MEDIUM,
        detail,
        "Install a current Exchange cumulative update and run Setup /PrepareAD, which makes "
        "these ACEs inherit-only, or move to Active Directory split permissions. Treat "
        "Exchange servers as tier 0 until then.",
        sorted(hits),
    )


def _sync_accounts(snap: Snapshot) -> list[Account]:
    return [a for a in snap.accounts if a.sync_host and a.enabled]


def _dcsync_sids(snap: Snapshot) -> set[str]:
    aces = snap.acls.get("domain", [])
    get = {a.sid for a in aces if a.extended_right(sd.DS_REPL_GET_CHANGES)}
    get_all = {a.sid for a in aces if a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)}
    return get & get_all


def _sync_servers(snap: Snapshot, account: Account) -> list[Account]:
    host = (account.sync_host or "").lower()
    return [a for a in snap.accounts if a.is_computer and a.sam.lower().rstrip("$") == host]


@check("AD-PRIV-011", "Entra Connect servers hold DCSync but are not tier 0")
def entra_connect_tier0(snap: Snapshot) -> Finding | None:
    dcsync = _dcsync_sids(snap)
    tier0 = snap.tier0_dns()
    hits = []
    for a in _sync_accounts(snap):
        if a.sid not in dcsync:
            continue
        servers = _sync_servers(snap, a)
        if not servers:
            hits.append(f"{a.sam} (server {a.sync_host}, not found in the domain)")
            continue
        for s in servers:
            notes = []
            if s.dn.lower() not in tier0:
                notes.append("not in a tier-0 group")
            if s.has(UAC.TRUSTED_FOR_DELEGATION):
                notes.append("unconstrained delegation")
            if not s.laps:
                notes.append("no LAPS")
            if notes:
                hits.append(f"{a.sam} on {s.sam.rstrip('$')}: {', '.join(notes)}")
    if not hits:
        return None
    return _finding(
        "AD-PRIV-011",
        Severity.MEDIUM,
        "The Entra Connect sync account can DCSync for password hash sync, and its password "
        "sits on the sync server: a local admin on that server can replicate every hash in "
        "the domain, krbtgt's included.",
        "Treat the Entra Connect server as a domain controller: tier-0 admins only, no "
        "interactive logon for others, LAPS, no delegation. Drop the replication rights if "
        "password hash sync is not used.",
        sorted(hits),
    )


@check("AD-ACL-008", "Entra Connect sync account or server controllable outside tier 0")
def entra_connect_control(snap: Snapshot) -> Finding | None:
    dcsync = _dcsync_sids(snap)
    tier0 = _tier0_group_sids(snap)
    targets: dict[str, str] = {}  # DN -> why it matters
    for a in _sync_accounts(snap):
        if a.sid in dcsync:
            targets[a.dn.lower()] = "sync account"
            for s in _sync_servers(snap, a):
                targets[s.dn.lower()] = "sync server"
    hits = set()
    for o in snap.objects:
        role = targets.get(o.dn.lower())
        if role is None:
            continue
        if o.owner and o.owner not in tier0:
            hits.add(f"{o.name} ({role}): owned by {snap.name_of(o.owner)}")
        for ace in o.aces:
            if ace.sid in tier0 or ace.sid in (PRINCIPAL_SELF, CREATOR_OWNER):
                continue
            rights = _control_rights(snap, ace, o.kind)
            if rights:
                hits.add(f"{o.name} ({role}): {snap.name_of(ace.sid)} ({', '.join(rights)})")
    if not hits:
        return None
    return _finding(
        "AD-ACL-008",
        Severity.HIGH,
        "These principals can take over the Entra Connect sync account or its server, which "
        "can DCSync: a path to every password hash in the domain, and to the cloud tenant.",
        "Remove the rights and ownership; keep the sync account and server under tier-0 "
        "control only.",
        sorted(hits),
    )


# --- Round 5: the CA's own configuration (registry, over MS-RRP) -----------------------

PENDING_NOTE = (
    " {cas} hold every request for a CA manager (RequestDisposition has REQDISP_PENDING), "
    "which slows this down but does not stop a manager approving a forged request."
)
# KB5014754 strong certificate mapping, as the detail texts describe it
STRONG_MAPPING = regpol.STRONG_MAPPING


def _pending(c: CaConfig) -> bool:
    return c.request_disposition is not None and bool(c.request_disposition & sd.REQDISP_PENDING)


def _ca_finding(
    snap: Snapshot,
    check_id: str,
    match: Callable[[CaConfig], bool],
    severity: Severity,
    detail: str,
    remediation: str,
) -> Finding | None:
    """One finding over every CA that matches, a level lower when each of them holds
    every request for approval."""
    hits = sorted((c for c in snap.probes.ca_configs if match(c)), key=lambda c: c.name.lower())
    if not hits:
        return None
    pending = [c.name for c in hits if _pending(c)]
    if pending:
        detail += PENDING_NOTE.format(cas=", ".join(pending))
    if len(pending) == len(hits):
        severity = Severity(max(severity - 1, Severity.LOW))
    return _finding(check_id, severity, detail, remediation, [c.name for c in hits])


def _esc6(c: CaConfig) -> bool:
    return c.edit_flags is not None and bool(c.edit_flags & sd.EDITF_ATTRIBUTESUBJECTALTNAME2)


def _esc16(c: CaConfig) -> bool:
    return c.disabled_extensions is not None and sd.SZOID_NTDS_CA_SECURITY_EXT in {
        e.strip() for e in c.disabled_extensions
    }


CA_RIGHTS = ((sd.CA_MANAGE, "ManageCA"), (sd.CA_OFFICER, "ManageCertificates"))


FOREST_ADMIN_RIDS = ("500", "512", "518", "519")


def _ca_admins(snap: Snapshot) -> set[str]:
    """SIDs expected to manage a CA: tier 0, the CA servers themselves, and the admins of
    every domain in the forest (the default CA descriptor grants the CA's own domain's
    Domain Admins, and the CA can sit in another domain of the forest)."""
    tier0_dns = snap.tier0_dns()
    ca_hosts = {h.upper() for h in snap.ca_hosts}
    expected = _tier0_group_sids(snap)
    forest = {t.sid for t in snap.trusts if t.within_forest and t.sid}
    expected |= {f"{sid}-{rid}" for sid in forest for rid in FOREST_ADMIN_RIDS}
    expected |= {
        a.sid
        for a in snap.accounts
        if a.sid and (a.dn.lower() in tier0_dns or a.sam.upper() in ca_hosts)
    }
    expected |= {o.sid for o in snap.objects if o.sid and o.dn.lower() in tier0_dns}
    return expected


def _other_domain_admins(snap: Snapshot, sid: str) -> bool:
    """Administrator or Domain Admins of a domain other than the scanned one: what the
    default descriptor of a CA in another domain of the forest holds, when no trust
    object gives that domain's SID (a sibling or grandchild domain)."""
    prefix, _, rid = sid.rpartition("-")
    return (
        rid in ("500", "512")
        and prefix.startswith("S-1-5-21-")
        and prefix not in (snap.domain_sid, snap.root_sid)
    )


def ca_control(snap: Snapshot) -> list[tuple[CaConfig, str, str]]:
    """(CA, SID, right) for each non-tier-0 holder of ManageCA or ManageCertificates.

    The owner of the CA security descriptor can rewrite it, so it counts as ManageCA.
    """
    expected = _ca_admins(snap)
    out: set[tuple[str, str, str]] = set()
    configs = {c.name: c for c in snap.probes.ca_configs}
    for c in snap.probes.ca_configs:
        own_domain = c.host.lower().partition(".")[2] == snap.domain.lower()
        if c.owner and c.owner not in expected:
            out.add((c.name, c.owner, "ManageCA"))
        for ace in c.aces:
            if ace.sid in expected or (not own_domain and _other_domain_admins(snap, ace.sid)):
                continue
            out |= {(c.name, ace.sid, right) for bit, right in CA_RIGHTS if ace.mask & bit}
    return [(configs[ca], sid, right) for ca, sid, right in sorted(out)]


def officer_templates(snap: Snapshot) -> list[str]:
    """Published templates that turn ManageCertificates alone into a certificate for any
    user: the requester supplies the subject of an authentication certificate, and a
    certificate manager can approve the request or issue it after it was refused."""
    return sorted(
        t.name
        for t in snap.templates
        if t.published and t.enrollee_supplies_subject and _authenticates(t)
    )


@check("AD-ADCS-012", "ESC6: CA accepts a subject alternative name from request attributes")
def esc6(snap: Snapshot) -> Finding | None:
    return _ca_finding(
        snap,
        "AD-ADCS-012",
        _esc6,
        Severity.MEDIUM,
        "EDITF_ATTRIBUTESUBJECTALTNAME2 is set, so any enrollee can name another user in the "
        "SAN of any certificate the CA issues. The CA still embeds the requester's own SID, and "
        "DCs with the KB5014754 updates (May 2022 on) refuse a certificate whose SID does not "
        "match for Kerberos logon; the April 2023 updates removed the setting that turned this "
        "off. On its own this works against DCs without those updates and against services "
        "that map certificates by name alone. With ESC16 on the same CA it works everywhere "
        "(AD-CHAIN-004).",
        "certutil -config <host>\\<CA> -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, "
        "then restart certsvc; keep every DC on current updates (full enforcement).",
    )


@check("AD-ADCS-013", "ESC7: non-tier-0 principals manage the CA")
def esc7(snap: Snapshot) -> Finding | None:
    hits = ca_control(snap)
    if not hits:
        return None
    manage = any(right == "ManageCA" for _, _, right in hits)
    templates = officer_templates(snap)
    detail = (
        "ManageCA lets its holder reconfigure the CA: turn on ESC6, publish any template "
        "(SubCA included) and grant itself ManageCertificates, which ends in a certificate for "
        "any user. "
        if manage
        else ""
    )
    detail += "ManageCertificates lets its holder approve pending requests and issue refused ones."
    if templates:
        detail += (
            f" Published templates whose requester supplies the subject ({', '.join(templates)}) "
            "make that a certificate for any user: request one for a domain admin, then issue it."
        )
    else:
        detail += (
            " No published authentication template lets the requester supply the subject, so "
            "ManageCertificates alone does not yet give a certificate for another user."
        )
    return _finding(
        "AD-ADCS-013",
        Severity.HIGH if manage or templates else Severity.MEDIUM,
        detail,
        "Remove ManageCA and ManageCertificates from these principals in the CA's security "
        "settings (certsrv.msc > Properties > Security), or treat them as tier 0.",
        sorted(f"{c.name}: {snap.name_of(sid)} ({right})" for c, sid, right in hits),
    )


@check("AD-ADCS-014", "ESC11: CA does not require encryption for ICPR requests")
def esc11(snap: Snapshot) -> Finding | None:
    return _ca_finding(
        snap,
        "AD-ADCS-014",
        lambda c: (
            c.interface_flags is not None
            and not c.interface_flags & sd.IF_ENFORCEENCRYPTICERTREQUEST
        ),
        Severity.HIGH,
        "IF_ENFORCEENCRYPTICERTREQUEST is off, so the CA accepts certificate requests over RPC "
        "(ICPR) without packet privacy. Authentication coerced from a DC can be relayed to the "
        "CA for a certificate as that DC, which is valid under strong mapping and leads to "
        "DCSync.",
        "certutil -config <host>\\<CA> -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST, "
        "then restart certsvc.",
    )


@check("AD-ADCS-015", "ESC16: CA leaves the SID security extension out of certificates")
def esc16(snap: Snapshot) -> Finding | None:
    return _ca_finding(
        snap,
        "AD-ADCS-015",
        _esc16,
        Severity.MEDIUM,
        f"{sd.SZOID_NTDS_CA_SECURITY_EXT} is in DisableExtensionList, so no certificate from "
        "this CA carries the requester's SID: every authentication template behaves like ESC9, "
        "and whoever can change a victim's userPrincipalName can get a certificate that maps "
        "to the victim. DCs in full enforcement refuse such weakly mapped certificates: the "
        "default since the February 2025 updates, and the only mode after the September 2025 "
        f"updates, which no longer read {STRONG_MAPPING}. DCs without the September 2025 "
        "updates that were set back to compatibility mode accept them. With ESC6 on the same "
        "CA it works under full enforcement too (AD-CHAIN-004).",
        f"certutil -config <host>\\<CA> -setreg policy\\DisableExtensionList "
        f"-{sd.SZOID_NTDS_CA_SECURITY_EXT}, then restart certsvc; keep every DC on current "
        "updates (full enforcement).",
    )


_WEAK_MAPPINGS = ((0x4, "UPN"), (0x1, "subject/issuer"), (0x2, "issuer"))


def _esc10_row(view: gpo_scope.RegistryView, a: Account) -> _PolicyRow | None:
    problems: list[str] = []
    notes: list[str] = []
    absent: list[str] = []
    methods = view.merged(a, regpol.SCHANNEL_KEY, regpol.CERT_MAPPING)
    if not methods.decided:
        notes.append(f"{regpol.CERT_MAPPING} not decided ({_undecided(methods)})")
    elif not methods.present:
        absent.append(regpol.CERT_MAPPING)
    elif not isinstance(methods.value, int):
        notes.append(f"{regpol.CERT_MAPPING} is not a number{_gpo_note(methods)}")
    else:
        weak = [label for bit, label in _WEAK_MAPPINGS if methods.value & bit]
        if weak:
            problems.append(
                f"{regpol.CERT_MAPPING} {methods.value:#x} allows {', '.join(weak)} "
                f"mapping{_gpo_note(methods)}"
            )
    strong = view.merged(a, regpol.KDC_KEY, STRONG_MAPPING)
    if not strong.decided:
        notes.append(f"{STRONG_MAPPING} not decided ({_undecided(strong)})")
    elif not strong.present:
        absent.append(STRONG_MAPPING)
    elif strong.value in (0, 1):
        problems.append(f"{STRONG_MAPPING} set to {strong.value}{_gpo_note(strong)}")
    elif strong.value != 2:
        notes.append(f"{STRONG_MAPPING} has an unrecognised value{_gpo_note(strong)}")
    if absent:
        notes.append(f"no GPO sets {' or '.join(absent)}: unknown")
    if not problems and not notes:
        return None
    severity = Severity.MEDIUM if problems else Severity.INFO
    return _PolicyRow(a, severity, "; ".join([*problems, *notes]))


# NTAuth is not in the snapshot, so a third-party CA trusted through it cannot be seen
_NO_CA = "no enterprise CA or certificate template is in the snapshot"


def _certificates_seen(snap: Snapshot) -> bool:
    return bool(snap.templates or snap.ca_hosts or snap.enrollment_urls or snap.probes.ca_configs)


@check("AD-ADCS-020", "ESC10: weak certificate mapping set by Group Policy on domain controllers")
def esc10(snap: Snapshot) -> Finding | None:
    view = gpo_scope.policy_view(snap)
    if view is None:
        return None
    rows = [row for a in _dcs_of(view) if (row := _esc10_row(view, a))]
    lead = ""
    if not _certificates_seen(snap):
        # what no GPO sets is only worth checking where a certificate can be had; a weak value
        # a GPO does set is a fact, and it matters the day a CA is added
        rows = [
            replace(row, severity=Severity.INFO, text=f"{row.text}; {_NO_CA}")
            for row in rows
            if row.severity is Severity.MEDIUM
        ]
        lead = (
            f"Nothing here issues the certificates this needs: {_NO_CA}. A third-party CA trusted "
            "through NTAuth is not read and would. "
        )
    return _policy_finding(
        snap,
        "AD-ADCS-020",
        f"{lead}Whoever can change a victim's userPrincipalName can get a certificate that "
        "maps to the victim where these domain controllers accept weak mappings: "
        f"{STRONG_MAPPING} at 0 or 1 "
        "(Kerberos, DCs without the September 2025 updates, which no longer read it) or a "
        f"{regpol.CERT_MAPPING} with the UPN bit (Schannel). This shows only what Group Policy "
        "sets: both values are commonly set locally on each DC, so a DC listed as unknown may "
        "be weak or not.",
        f"Remove the values from the GPO, keep {STRONG_MAPPING} out of compatibility mode and "
        f"keep {regpol.CERT_MAPPING} at 0x18; check the registry of each DC listed as unknown.",
        rows,
    )


def ca_unjudged(c: CaConfig) -> list[tuple[str, str]]:
    """(setting, ESC) a readable CA did not answer for."""
    return [
        (name, esc)
        for name, esc, missing in (
            ("InterfaceFlags", "ESC11", c.interface_flags is None),
            # a real CA descriptor always has an owner: neither means it was not read
            ("security descriptor", "ESC7", c.owner is None and not c.aces),
            ("EditFlags", "ESC6", c.edit_flags is None and not c.third_party_policy),
            (
                "DisableExtensionList",
                "ESC16",
                c.disabled_extensions is None and not c.third_party_policy,
            ),
        )
        if missing
    ]


@check("AD-ADCS-016", "CA configuration could not be read")
def unread_ca_config(snap: Snapshot) -> Finding | None:
    hits = []
    for c in snap.probes.ca_configs:
        if c.error:
            hits.append(f"{c.host}: {c.error}")
            continue
        if c.third_party_policy:
            hits.append(
                f"{c.host}: policy module {c.policy_module} is not Microsoft's; "
                "ESC6 and ESC16 not judged"
            )
        absent = ca_unjudged(c)
        if absent:
            hits.append(
                f"{c.host}: {', '.join(n for n, _ in absent)} absent or empty; "
                f"{', '.join(e for _, e in absent)} not judged"
            )
        if c.audit_checked and c.audit_filter is None and not c.audit_absent:
            hits.append(f"{c.host}: AuditFilter unreadable; AD-ADCS-018 not judged")
    if not hits:
        return None
    return _finding(
        "AD-ADCS-016",
        Severity.LOW,
        "ESC6, ESC7, ESC11, ESC16 and the CA audit filter depend on CA settings that LDAP "
        "cannot show. On these CAs some of them could not be read or judged (a read error "
        "affects all of them; otherwise each line names the checks affected), so those checks "
        "say nothing about them.",
        "Run the scan from a host that reaches TCP 445 on each CA. RemoteRegistry must not be "
        "disabled, and SYSTEM\\CurrentControlSet\\Services\\CertSvc must stay in the winreg "
        "AllowedPaths list (a GPO that sets 'Network access: Remotely accessible registry "
        "paths and subpaths' replaces the whole list).",
        hits,
    )


# certutil CA\\AuditFilter: Securing PKI, Appendix B
CA_AUDIT_CATEGORIES = {
    1: "start and stop",
    2: "backup and restore",
    4: "certificate requests",
    8: "revocation and CRLs",
    16: "CA security settings",
    32: "archived keys",
    64: "CA configuration",
}
CA_AUDIT_ALL = 127
CA_AUDIT_REQUESTS = 4


@check("AD-ADCS-018", "CA audit filter not fully on")
def ca_audit_filter(snap: Snapshot) -> Finding | None:
    hits = sorted(
        (
            c
            for c in snap.probes.ca_configs
            if c.audit_absent
            or (c.audit_filter is not None and c.audit_filter & CA_AUDIT_ALL != CA_AUDIT_ALL)
        ),
        key=lambda c: c.name.lower(),
    )
    if not hits:
        return None
    objects = {}
    for c in hits:
        value = c.audit_filter or 0
        off = [name for bit, name in CA_AUDIT_CATEGORIES.items() if not value & bit]
        state = "not set" if c.audit_absent else str(value)
        objects[f"{c.name}: AuditFilter {state}, off: {', '.join(off)}"] = c.name
    blind = any(not (c.audit_filter or 0) & CA_AUDIT_REQUESTS for c in hits)
    finding = _finding(
        "AD-ADCS-018",
        Severity.MEDIUM if blind else Severity.LOW,
        "The CA does not audit every category."
        + (
            " Without certificate requests in the filter, the requests and issuance of an "
            "ESC1 or ESC8 intrusion leave no CA audit event."
            if blind
            else ""
        )
        + " The filter alone proves nothing: the Certification Services audit subcategory must "
        "also be on, and that is not read here.",
        "Run certutil -setreg CA\\AuditFilter 127 on the CA, restart CertSvc, and enable the "
        "Certification Services audit subcategory for success and failure.",
        sorted(objects),
    )
    finding.keys = objects
    return finding


@check("AD-ADCS-017", "ESC17: enrollee-supplied subject on a server authentication template")
def esc17(snap: Snapshot) -> Finding | None:
    return _template_finding(
        snap,
        "AD-ADCS-017",
        "Any member of the enrolling group can get a trusted TLS certificate for any host name, "
        "which allows impersonating an internal server such as WSUS. A Server Authentication "
        "certificate does not log on to the domain by itself (on a schema v1 template see "
        "AD-ADCS-008); abuse also needs a way into the traffic, such as a DNS record.",
        "Clear 'Supply in the request', require manager approval, or limit enrollment to the "
        "servers and admins that need it.",
        # anything that also authenticates is AD-ADCS-001 or -002
        lambda t: (
            t.enrollee_supplies_subject and EKU_SERVER_AUTH in t.ekus and not _authenticates(t)
        ),
        Severity.MEDIUM,
    )


@check("AD-CHAIN-004", "ESC6 plus ESC16 on the same CA")
def chain_esc6_esc16(snap: Snapshot) -> Finding | None:
    return _ca_finding(
        snap,
        "AD-CHAIN-004",
        lambda c: _esc6(c) and _esc16(c),
        Severity.HIGH,
        "The CA takes the SAN from request attributes and leaves out the SID extension, so a "
        "requester can put any user's SID in a SAN URL (tag:microsoft.com,2022-09-14:sid:...), "
        "which DCs accept as a strong mapping: any enrollee can authenticate as any user, a "
        "domain admin included, even against DCs in full enforcement.",
        "Fix either side: clear EDITF_ATTRIBUTESUBJECTALTNAME2, or remove "
        f"{sd.SZOID_NTDS_CA_SECURITY_EXT} from DisableExtensionList.",
    )


def san_ca(snap: Snapshot) -> CaConfig | None:
    """The CA of AD-CHAIN-004 as a path: the domain's only enterprise CA, because a
    snapshot does not say which CA publishes which template, and one that does not hold
    every request for a manager. None when the CA configuration was not read."""
    configs = snap.probes.ca_configs
    if len(snap.ca_hosts) != 1 or len(configs) != 1:
        return None
    c = configs[0]
    return c if _esc6(c) and _esc16(c) and not _pending(c) else None


def every_ca_holds(snap: Snapshot) -> bool:
    """Every enterprise CA's configuration was read and each holds every request for a
    manager: no certificate is issued on request, on any CA that could publish a template."""
    configs = snap.probes.ca_configs
    return (
        bool(snap.ca_hosts) and len(configs) >= len(snap.ca_hosts) and all(map(_pending, configs))
    )


def san_note(snap: Snapshot) -> list[str]:
    """A note when AD-CHAIN-004 holds but the graph cannot place it on a template."""
    hits = [c.name for c in snap.probes.ca_configs if _esc6(c) and _esc16(c)]
    if not hits or (len(snap.ca_hosts) == 1 and len(snap.probes.ca_configs) == 1):
        return []
    return [
        f"{', '.join(sorted(hits))} has ESC6 and ESC16, but this domain has more than one "
        "enterprise CA and a snapshot does not say which CA publishes which template: "
        "AD-PATH-001 has no ESC6 edge for it (AD-CHAIN-004 reports the CA)"
    ]


# --- Round 5: local group membership set by Group Policy -----------------------------

ADMIN_GROUPS = {sid for sid, g in LOCAL_GROUPS.items() if g.admin}
LOGON_GROUPS = {sid for sid, g in LOCAL_GROUPS.items() if not g.admin}
SHOWN_HOSTS = 5


def tier0_hosts(snap: Snapshot) -> dict[str, str]:
    """Lower-cased DN -> role of every computer whose administrators control the domain."""
    roles: dict[str, str] = {}
    computers = [a for a in snap.accounts if a.is_computer]
    ca_hosts = {h.upper() for h in snap.ca_hosts}
    exchange = exchange_members(snap.objects)
    privileged = snap.privileged_dns()
    dcsync = _dcsync_sids(snap)
    sync_servers = {s.dn.lower() for a in _sync_accounts(snap) for s in _sync_servers(snap, a)}
    for role, holds in (
        ("unregistered DC", lambda a: a.rogue_dc),
        ("domain controller", lambda a: a.is_dc),
        ("CA server", lambda a: a.sam.upper() in ca_hosts),
        ("Entra Connect server", lambda a: a.dn.lower() in sync_servers),
        ("Exchange server", lambda a: a.dn.lower() in exchange),
        ("tier-0 member", lambda a: a.dn.lower() in privileged or a.sid in dcsync),
    ):
        for a in computers:
            if holds(a):
                roles.setdefault(a.dn.lower(), role)
    return roles


def _local_broad(snap: Snapshot) -> set[str]:
    """Broad groups, plus INTERACTIVE: in a local group it covers everyone who logs on
    at the console or over RDP, and Domain Users may log on locally to workstations."""
    return snap.broad_sids() | {gpo_scope.INTERACTIVE}


def _group_label(snap: Snapshot, grant: Grant) -> str:
    sid = grant.item.group_sid
    if not grant.domain_group:
        return LOCAL_GROUPS[sid].name
    prefix = "BUILTIN\\" if sid.startswith("S-1-5-32-") else ""
    return f"{prefix}{snap.name_of(sid)} (domain, via DCs)"


def _grant_objects(snap: Snapshot, hits: list[tuple[Grant, str | None]]) -> list[str]:
    """One object per GPO, member and group, listing the hosts (first five) and caveats."""
    grouped: dict[tuple[str, str, str], tuple[set[str], set[str]]] = {}
    for grant, host in hits:
        key = (grant.gpo.name, snap.name_of(grant.item.member_sid), _group_label(snap, grant))
        hosts, caveats = grouped.setdefault(key, (set(), set()))
        if host:
            hosts.add(host)
        caveats.update(grant.caveats)
    out = []
    for (gpo, member, group), (hosts, caveats) in grouped.items():
        text = f"{gpo}: {member} -> {group}"
        if hosts:
            names = sorted(hosts, key=str.lower)
            more = len(names) - SHOWN_HOSTS
            text += (
                " on " + ", ".join(names[:SHOWN_HOSTS]) + (f" (+{more} more)" if more > 0 else "")
            )
        if caveats:
            text += f" [{', '.join(sorted(caveats))}]"
        out.append(text)
    return sorted(out)


def _host(grant: Grant, roles: dict[str, str]) -> str:
    assert grant.computer is not None
    role = roles.get(grant.computer.dn.lower())
    return f"{grant.computer.sam} ({role})" if role else grant.computer.sam


def _filtered_note(hits: list[tuple[Grant, str | None]]) -> str:
    if not any(gpo_scope.ILT_CAVEAT in g.caveats for g, _ in hits):
        return ""
    return (
        f" Entries marked '{gpo_scope.ILT_CAVEAT}' apply only where their targeting matches;"
        " they are listed for every computer the GPO reaches."
    )


@check("AD-GPO-005", "GPOs make broad groups local administrators")
def gpo_broad_admins(snap: Snapshot) -> Finding | None:
    scope = gpo_scope.resolve(snap)
    if not scope.grants:
        return None
    broad, tier0 = _local_broad(snap), _tier0_group_sids(snap)
    roles = tier0_hosts(snap)
    hits: list[tuple[Grant, str | None]] = []
    reached = set()
    for g in scope.grants:
        if g.item.member_sid not in broad:
            continue
        if g.domain_group and g.item.group_sid in tier0:
            hits.append((g, None))
        elif g.computer is not None and g.item.group_sid in ADMIN_GROUPS:
            hits.append((g, g.computer.sam))
            if g.computer.dn.lower() in roles:
                reached.add(_host(g, roles))
    if not hits:
        return None
    detail = (
        "Every account in these groups becomes an administrator (or the equivalent) of the "
        "computers the GPO reaches, so one phished user owns all of them."
    )
    if reached:
        detail += f" Including tier-0 servers: {', '.join(sorted(reached, key=str.lower))}."
    return _finding(
        "AD-GPO-005",
        Severity.HIGH,
        detail + _filtered_note(hits),
        "Remove the entry from the GPO (Restricted Groups or Preferences > Local Users and "
        "Groups) and grant local admin per tier through a dedicated group or LAPS.",
        _grant_objects(snap, hits),
    )


@check("AD-GPO-006", "GPOs grant admin rights on tier-0 servers outside tier 0")
def gpo_tier0_admins(snap: Snapshot) -> Finding | None:
    scope = gpo_scope.resolve(snap)
    if not scope.grants:
        return None
    broad, tier0 = _local_broad(snap), _tier0_group_sids(snap)
    roles = tier0_hosts(snap)
    hits: list[tuple[Grant, str | None]] = []
    for g in scope.grants:
        member = g.item.member_sid
        if member in tier0 or member in broad:  # broad groups are AD-GPO-005
            continue
        if g.domain_group and g.item.group_sid in tier0:
            hits.append((g, None))
        elif (
            g.computer is not None
            and g.item.group_sid in ADMIN_GROUPS
            and g.computer.dn.lower() in roles
        ):
            hits.append((g, _host(g, roles)))
    if not hits:
        return None
    return _finding(
        "AD-GPO-006",
        Severity.HIGH,
        "Group Policy makes these non-tier-0 principals administrators of servers that "
        "control the domain (or puts them in a tier-0 group through the DCs): whoever "
        "controls them controls the domain." + _filtered_note(hits),
        "Remove the entry, or move these servers to an OU that only tier-0 GPOs reach.",
        _grant_objects(snap, hits),
    )


@check("AD-GPO-007", "GPOs grant remote logon to broad groups or on tier-0 servers")
def gpo_remote_logon(snap: Snapshot) -> Finding | None:
    scope = gpo_scope.resolve(snap)
    if not scope.grants:
        return None
    broad, tier0 = _local_broad(snap), _tier0_group_sids(snap)
    roles = tier0_hosts(snap)
    hits: list[tuple[Grant, str | None]] = []
    severity = Severity.MEDIUM
    for g in scope.grants:
        member = g.item.member_sid
        if g.item.group_sid not in LOGON_GROUPS or not g.effective or member in tier0:
            continue
        on_tier0 = g.domain_group or (g.computer is not None and g.computer.dn.lower() in roles)
        if not on_tier0 and member not in broad:
            continue
        hits.append((g, None if g.computer is None else _host(g, roles)))
        if on_tier0:
            severity = Severity.HIGH
    if not hits:
        return None
    return _finding(
        "AD-GPO-007",
        severity,
        "Group Policy lets these principals log on remotely (RDP, WinRM or DCOM): broad groups "
        "anywhere, or non-tier-0 principals on servers that control the domain, where their "
        "logon leaves credentials to steal and a local exploit away from SYSTEM. Remote "
        "Desktop Users only counts where the remote logon right includes it (by default not "
        "on DCs)." + _filtered_note(hits),
        "Remove the entry, or limit it to the tier the servers belong to.",
        _grant_objects(snap, hits),
    )


# --- tier-0 logon restrictions, silos and change history ----------------------------------

_TIER0_LOGON_GROUPS = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
_DENY_LABELS = {
    "SeDenyInteractiveLogonRight": "local logon",
    "SeDenyRemoteInteractiveLogonRight": "RDP",
    "SeDenyBatchLogonRight": "batch",
    "SeDenyServiceLogonRight": "service",
}
# the two logon types people use by hand: leaving either open makes the row medium
_CREDENTIAL_RIGHTS = {"local logon", "RDP"}
RECENT_CHANGE_DAYS = 30
INSTALL_DAYS = 1  # changes this close to the domain's creation are the install


def _tier0_users(snap: Snapshot) -> list[Account]:
    """Enabled user accounts of the groups that administer the domain."""
    members = {dn.lower() for g in _TIER0_LOGON_GROUPS for dn in snap.privileged.get(g, [])}
    return [a for a in snap.accounts if a.enabled and not a.is_computer and a.dn.lower() in members]


def _deny_row(
    view: gpo_scope.RegistryView, a: Account, tokens: dict[str, set[str]]
) -> _PolicyRow | None:
    not_denied: list[str] = []
    undecided: list[str] = []
    left: set[str] = set()
    for right in gpo_scope.DENY_LOGON_RIGHTS:
        effective = view.user_right(a, right)
        state, missed = gpo_scope.denied_accounts(effective, tokens)
        if state is None:
            undecided.append(f"{_DENY_LABELS[right]} ({_undecided(effective)})")
        elif state is False:
            not_denied.append(_DENY_LABELS[right])
            left.update(missed)
    if not not_denied and not undecided:
        return None
    severity = Severity.INFO
    parts = []
    if not_denied:
        severity = Severity.MEDIUM if _CREDENTIAL_RIGHTS & set(not_denied) else Severity.LOW
        text = f"not denied to every tier-0 account: {', '.join(not_denied)}"
        if len(left) < len(tokens):
            names = sorted(left)
            more = f" +{len(names) - MAX_NAMES} more" if len(names) > MAX_NAMES else ""
            text += f" (left out: {', '.join(names[:MAX_NAMES])}{more})"
        parts.append(text)
    if undecided:
        parts.append(f"not decided: {', '.join(undecided)}")
    return _PolicyRow(a, severity, "; ".join(parts))


@check("AD-PRIV-013", "Tier-0 accounts not denied logon on lower-tier computers")
def tier0_logon_not_denied(snap: Snapshot) -> Finding | None:
    view = gpo_scope.logon_rights_view(snap)
    if view is None:
        return None
    users = _tier0_users(snap)
    if not users:
        return None
    tokens = {a.sam: view.r.token(a) for a in users}
    roles = tier0_hosts(snap)
    rows = [
        row
        for a in view.targets()
        if not a.is_registered_dc
        and a.dn.lower() not in roles
        and (row := _deny_row(view, a, tokens))
    ]
    return _policy_finding(
        snap,
        "AD-PRIV-013",
        "Group Policy does not stop tier-0 accounts from signing in on these computers. A sign-in "
        "there leaves credentials that anyone with admin rights on the computer can take, so "
        "control of one workstation becomes control of the domain. Domain controllers and the "
        "computers ad-doctor knows to be tier 0 are left out; a computer's own local policy "
        "cannot be seen from here, and a privileged access workstation you declare yourself is "
        "not known to this check.",
        "In a GPO linked to the lower-tier OUs, add the tier-0 groups to 'Deny log on locally', "
        "'Deny log on through Remote Desktop Services', 'Deny log on as a batch job' and 'Deny "
        "log on as a service'. Exclude the OUs of tier-0 servers and admin workstations.",
        rows,
    )


def _silo_gap(
    a: Account,
    silos: list[tuple[AuthSilo, set[str], set[str]]],
    policies: dict[str, AuthPolicy],
) -> str:
    """Why a tier-0 account is not restricted by a silo; "" when it is."""
    dn = a.dn.lower()
    named = [s for s, members, assigned in silos if dn in members or dn in assigned]
    if not named:
        return "in no silo"
    both = [s for s, members, assigned in silos if dn in members and dn in assigned]
    if not both:
        return (
            f"silo {named[0].name} has it on one side only: it needs to be a permitted member "
            "and assigned to the silo"
        )
    audited: list[str] = []
    for s in both:
        if not s.enforced:
            audited.append(f"silo {s.name} is in audit mode")
            continue
        policy = policies.get(s.user_policy.lower())
        if policy is None:
            audited.append(f"silo {s.name} has no user policy this account could read")
        elif not policy.enforced:
            audited.append(f"user policy {policy.name} is in audit mode")
        elif not policy.limits_user_from:
            audited.append(f"user policy {policy.name} does not limit where users sign in")
        else:
            return ""
    return "; ".join(audited)


@check("AD-PRIV-014", "Tier-0 accounts outside an enforced authentication policy silo")
def tier0_silos(snap: Snapshot) -> Finding | None:
    if not snap.silos_checked or 0 < snap.policy.functional_level < SILO_LEVEL:
        return None
    # the built-in Administrator stays out on purpose: it is the way back in when a silo breaks
    users = [a for a in _tier0_users(snap) if a.rid != 500]
    if not users:
        return None
    remediation = (
        "Create an authentication policy that limits where users may sign in, put it in a silo "
        "with both enforced, then permit and assign each tier-0 account. Keep a break-glass "
        "account outside."
    )
    if not snap.auth_silos:
        return _finding(
            "AD-PRIV-014",
            Severity.LOW,
            "No authentication policy silo exists, so nothing but Group Policy and habit limits "
            "where tier-0 accounts can sign in. A silo is enforced by the KDC, on the "
            "authentication itself.",
            remediation,
            _names(users),
        )
    policies = {p.dn.lower(): p for p in snap.auth_policies}
    silos = [
        (s, {m.lower() for m in s.members}, {m.lower() for m in s.assigned})
        for s in snap.auth_silos
    ]
    objects = [f"{a.sam}: {gap}" for a in users if (gap := _silo_gap(a, silos, policies))]
    if not objects:
        return None
    return _finding(
        "AD-PRIV-014",
        Severity.LOW,
        "These tier-0 accounts are not held by an enforced authentication policy silo with a "
        "policy that limits where they sign in. Only the silo and its user policy being enforced "
        "together keep them off lower-tier computers.",
        remediation,
        sorted(objects),
    )


def _recent_change(snap: Snapshot, when: datetime | None) -> bool:
    """Within the last RECENT_CHANGE_DAYS and not part of the domain's first day."""
    if when is None or when < snap.collected_at - timedelta(days=RECENT_CHANGE_DAYS):
        return False
    created = snap.domain_created
    return created is None or when >= created + timedelta(days=INSTALL_DAYS)


def _name_of_dn(snap: Snapshot, dn: str, names: dict[str, str]) -> str:
    return names.get(dn.lower()) or gpo_scope.RDN_SEPARATOR.split(dn)[0].split("=", 1)[-1]


@check("AD-PRIV-015", "Recent additions to tier-0 groups")
def recent_tier0_members(snap: Snapshot) -> Finding | None:
    if not snap.member_changes_checked:
        return None
    hits = [c for c in snap.member_changes if _recent_change(snap, c.added)]
    if not hits:
        return None
    names = {o.dn.lower(): o.name for o in snap.objects}
    names.update({a.dn.lower(): a.sam for a in snap.accounts})
    return _finding(
        "AD-PRIV-015",
        Severity.LOW,
        f"These members were added to tier-0 groups in the {RECENT_CHANGE_DAYS} days before this "
        "snapshot, by replication metadata. An attacker holding the keys does the same, so each "
        "should match a change someone can account for. Changes in the domain's first day are "
        "left out.",
        "Check each addition against your change record. If it has none, remove the member and "
        "investigate who made the change (event 4728, 4732 or 4756 on the DC).",
        sorted(
            f"{c.group}: {_name_of_dn(snap, c.member_dn, names)} added {c.added:%Y-%m-%d}"
            for c in hits
        ),
    )


@check("AD-ACL-010", "AdminSDHolder's ACL changed recently")
def recent_admin_sd_holder_change(snap: Snapshot) -> Finding | None:
    when = snap.admin_sd_holder_changed
    if not snap.admin_sd_holder_checked or when is None or not _recent_change(snap, when):
        return None
    return _finding(
        "AD-ACL-010",
        Severity.MEDIUM,
        f"AdminSDHolder's security descriptor changed in the {RECENT_CHANGE_DAYS} days before "
        "this snapshot, by replication metadata. SDProp copies this ACL over every protected "
        "account and group, so a change here is rare and is a known persistence technique. The "
        "metadata says when, not who or what: see AD-ACL-002 for who holds rights now.",
        "Match the change to a change record (event 5136 on the DC). Compare the ACL with a known "
        "good copy and remove what should not be there.",
        [f"AdminSDHolder: nTSecurityDescriptor changed {when:%Y-%m-%d}"],
    )


@check("AD-ACC-017", "Recent sIDHistory changes")
def recent_sid_history(snap: Snapshot) -> Finding | None:
    if not snap.sid_history_checked:
        return None
    accounts = snap.by_dn()
    hits = [
        (accounts[c.dn.lower()], c)
        for c in snap.sid_history_changes
        if c.dn.lower() in accounts and _recent_change(snap, c.changed)
    ]
    if not hits:
        return None
    same_domain = [
        a for a, _ in hits if any(s.startswith(snap.domain_sid + "-") for s in a.sid_history)
    ]
    detail = (
        f"sIDHistory was written on these accounts in the {RECENT_CHANGE_DAYS} days before this "
        "snapshot, by replication metadata. Outside a running domain migration it should not "
        "change at all."
    )
    if same_domain:
        detail += (
            " Accounts holding a SID of this same domain, which a migration does not produce: "
            f"{', '.join(_names(same_domain))}."
        )
    return _finding(
        "AD-ACC-017",
        Severity.MEDIUM if same_domain else Severity.LOW,
        detail,
        "Match each change to a migration. If there is none, clear sIDHistory and investigate "
        "the account.",
        sorted(f"{a.sam}: sIDHistory changed {c.changed:%Y-%m-%d}" for a, c in hits),
    )


# AD-PATH-001 lives in paths.py; importing it here registers it with every run.
from . import paths as _paths  # noqa: E402, F401
