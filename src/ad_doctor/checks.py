"""Checks: pure functions from a Snapshot to findings.

Each check returns at most one Finding that lists every affected object, so the report
stays one line per problem rather than one line per account.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, timedelta

from . import sd
from .model import (
    EXCHANGE_GROUPS,
    UAC,
    Account,
    CertTemplate,
    Finding,
    Severity,
    Snapshot,
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


# MITRE ATT&CK techniques each finding enables
MITRE: dict[str, tuple[str, ...]] = {
    "AD-KRB-001": ("T1558.001",),
    "AD-KRB-002": ("T1558.004",),
    "AD-KRB-003": ("T1558.003",),
    "AD-KRB-004": ("T1558",),
    "AD-DEL-001": ("T1558", "T1187"),
    "AD-DEL-002": ("T1558", "T1134"),
    "AD-DEL-003": ("T1558", "T1134"),
    "AD-ACC-001": ("T1078.002",),
    "AD-ACC-002": ("T1003",),
    "AD-ACC-003": ("T1078.002",),
    "AD-ACC-004": ("T1078.001",),
    "AD-ACC-005": ("T1078.002",),
    "AD-ACC-006": ("T1078.002",),
    "AD-ACC-007": ("T1134.005",),
    "AD-PRIV-001": ("T1078.002",),
    "AD-PRIV-002": ("T1558",),
    "AD-PRIV-003": ("T1078.002",),
    "AD-PRIV-004": ("T1574.002",),
    "AD-PRIV-005": ("T1087.002",),
    "AD-POL-001": ("T1110",),
    "AD-POL-002": ("T1136.002",),
    "AD-SEC-001": ("T1550.002",),
    "AD-INF-001": ("T1210",),
    "AD-INF-002": ("T1485",),
    "AD-INF-004": ("T1087.002", "T1098"),
    "AD-INF-005": ("T1557",),
    "AD-INF-006": ("T1134.005", "T1482"),
    "AD-ADCS-001": ("T1649",),
    "AD-ADCS-002": ("T1649",),
    "AD-ADCS-003": ("T1649",),
    "AD-ADCS-004": ("T1649",),
    "AD-ADCS-005": ("T1649",),
    "AD-ADCS-006": ("T1649",),
    "AD-ADCS-007": ("T1649",),
    "AD-ADCS-008": ("T1649",),
    "AD-ACL-001": ("T1003.006",),
    "AD-ACL-002": ("T1098",),
    "AD-ACL-003": ("T1098", "T1222"),
    "AD-GPO-001": ("T1484.001",),
    "AD-GPO-002": ("T1484.001",),
    "AD-GPO-003": ("T1557", "T1003"),
    "AD-GPO-004": ("T1484.001",),
    "AD-GPP-002": ("T1552.001",),
    "AD-ADCS-009": ("T1649",),
    "AD-ADCS-010": ("T1649", "T1557.001"),
    "AD-ADCS-011": ("T1649",),
    "AD-KRB-005": ("T1558.003",),
    "AD-KRB-006": ("T1558.002",),
    "AD-DEL-004": ("T1558", "T1134"),
    "AD-ACL-004": ("T1098", "T1556"),
    "AD-ACL-005": ("T1098",),
    "AD-ACL-006": ("T1555",),
    "AD-ACC-008": ("T1552",),
    "AD-ACC-009": ("T1552",),
    "AD-ACC-010": ("T1078.002",),
    "AD-ACC-011": ("T1078.002",),
    "AD-PRIV-006": ("T1078.002",),
    "AD-PRIV-007": ("T1078.002", "T1564"),
    "AD-PRIV-008": ("T1078.002",),
    "AD-PRIV-009": ("T1649",),
    "AD-PRIV-010": ("T1558",),
    "AD-SEC-002": ("T1555",),
    "AD-INF-007": ("T1098", "T1136.002"),
    "AD-INF-008": ("T1557",),
    "AD-INF-009": ("T1187",),
    "AD-INF-010": ("T1557",),
    "AD-INF-011": ("T1490",),
    "AD-INF-012": ("T1003",),
    "AD-PATH-001": ("T1098", "T1484"),
    "AD-CHAIN-001": ("T1557", "T1187", "T1134"),
    "AD-CHAIN-002": ("T1187", "T1558"),
    "AD-CHAIN-003": ("T1187", "T1557.001", "T1649"),
    "AD-GPP-001": ("T1552.006",),
    "AD-INF-013": ("T1557",),
    "AD-ACL-007": ("T1098", "T1557.001", "T1003.006"),
    "AD-PRIV-011": ("T1003.006", "T1078.002"),
    "AD-ACL-008": ("T1098", "T1003.006"),
}


KRBTGT_MAX_AGE = timedelta(days=180)
STALE_AFTER = timedelta(days=90)


@check("AD-KRB-001", "krbtgt password not rotated recently")
def krbtgt_age(snap: Snapshot) -> Finding | None:
    krbtgt = next((a for a in snap.accounts if a.sam.lower() == "krbtgt"), None)
    if krbtgt is None or krbtgt.pwd_last_set is None:
        return None
    age = snap.collected_at - krbtgt.pwd_last_set
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
        a for a in snap.accounts if a.enabled and a.has(UAC.TRUSTED_FOR_DELEGATION) and not a.is_dc
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
        and not a.is_dc
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
            who = {w for w in who if w.upper() not in snap.ca_hosts}
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
        "Clear CT_FLAG_NO_SECURITY_EXTENSION and keep StrongCertificateBindingEnforcement=2 "
        "on every domain controller.",
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
        lambda t: _authenticates(t) and any(p in snap.oid_group_links for p in t.issuance_policies),
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


@check("AD-INF-004", "Unsafe dsHeuristics settings")
def ds_heuristics(snap: Snapshot) -> Finding | None:
    h = snap.ds_heuristics
    issues, severity = [], Severity.MEDIUM
    if len(h) >= 7 and h[6] == "2":
        issues.append("anonymous LDAP operations allowed (7th character = 2)")
        severity = Severity.HIGH
    if len(h) >= 16 and h[15] != "0":
        issues.append("operator groups excluded from AdminSDHolder (16th character)")
    if not issues:
        return None
    return _finding(
        "AD-INF-004",
        severity,
        "dsHeuristics: " + "; ".join(issues) + ".",
        "Reset the affected characters of dsHeuristics to 0.",
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
TRUST_ENABLE_TGT_DELEGATION = 0x800
TRUST_INBOUND = 0x1
TRUST_OUTBOUND = 0x2


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


@check("AD-KRB-005", "Service accounts without AES Kerberos keys")
def rc4_only(snap: Snapshot) -> Finding | None:
    hits = [
        a
        for a in _enabled_users(snap)
        if a.spns
        and not a.sam.lower().startswith("krbtgt")
        and a.enc_types is not None
        and not a.enc_types & AES_TYPES
    ]
    if not hits:
        return None
    return _finding(
        "AD-KRB-005",
        Severity.MEDIUM,
        "msDS-SupportedEncryptionTypes excludes AES, so tickets for these SPNs use RC4, the "
        "fastest kind to crack offline.",
        "Enable AES128/AES256 (0x18) on the account and reset its password.",
        _names(hits),
    )


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
            service, _, rest = spn.partition("/")
            host = rest.split(":", 1)[0].split("/", 1)[0].lower()
            if (service.lower() in DC_SERVICES and host in dc_names) or service.lower() == "krbtgt":
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
    hits, severity = [], Severity.MEDIUM
    for g in snap.gmsas:
        is_priv = g.dn.lower() in privileged
        risky = [s for s in g.readers if s in broad or (is_priv and s not in tier0)]
        if risky:
            who = ", ".join(sorted(snap.name_of(s) for s in risky))
            hits.append(f"{g.name} (readable by {who})")
            if any(s in broad for s in risky) or g.dn.lower() in privileged:
                severity = Severity.HIGH
    if not hits:
        return None
    return _finding(
        "AD-ACL-006",
        severity,
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
        and not a.is_dc
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
        and a.pwd_last_set is not None
        and a.pwd_last_set < cutoff
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
            elif a.is_computer and not a.is_dc:
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
        elif not a.is_dc and a.primary_group in DC_PRIMARY_GROUPS:
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
    has_2025 = snap.policy.functional_level >= 10 or any(
        a.is_dc and a.os and "2025" in a.os for a in snap.accounts
    )
    if not has_2025:
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
    return _finding(
        "AD-INF-007",
        Severity.HIGH,
        "On Windows Server 2025 domains, anyone who can create a dMSA in a container can make it "
        "inherit the rights of any account, including domain admins.",
        "Remove CreateChild/GenericAll/WriteDacl/WriteOwner for these principals and install "
        "the August 2025 updates (CVE-2025-53779).",
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
        if s is None or not g.linked_to:
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


@check("AD-CHAIN-002", "Coercion plus unconstrained delegation")
def chain_coerce_unconstrained(snap: Snapshot) -> Finding | None:
    delegated = unconstrained_delegation(snap)
    if not _spooler_dcs(snap) or delegated is None:
        return None
    return _finding(
        "AD-CHAIN-002",
        Severity.HIGH,
        "The DC's spooler can be made to authenticate to a host with unconstrained "
        "delegation, which then holds the DC's TGT: whoever controls that host can DCSync.",
        "Disable the spooler on DCs and remove unconstrained delegation.",
        delegated.objects,
    )


@check("AD-CHAIN-003", "Coercion plus web enrollment relay (ESC8)")
def chain_esc8(snap: Snapshot) -> Finding | None:
    if not snap.probes.web_enrollment_ntlm or not _spooler_dcs(snap):
        return None
    return _finding(
        "AD-CHAIN-003",
        Severity.HIGH,
        "Any user can coerce the DC through the spooler and relay its authentication to web "
        "enrollment for a DC certificate: domain compromise in two commands.",
        "Fix either side: disable the spooler on DCs, or HTTP/NTLM on web enrollment.",
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


# AD-PATH-001 lives in paths.py; importing it here registers it with every run.
from . import paths as _paths  # noqa: E402, F401
