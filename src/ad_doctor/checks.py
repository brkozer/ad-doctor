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
from .model import UAC, Account, CertTemplate, Finding, Severity, Snapshot

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
    return [a for a in snap.accounts if a.enabled and not a.is_computer]


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
    "AD-GPP-001": ("T1552.006",),
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
    hits = [a for a in snap.accounts if a.is_computer and a.enabled and not a.is_dc and not a.laps]
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
) -> Finding | None:
    hits = []
    for t in snap.templates:
        who = _broad_enroll(snap, t)
        if who and _issuable(t) and match(t):
            hits.append(f"{t.name} (enroll: {', '.join(who)})")
    if not hits:
        return None
    return _finding(check_id, Severity.HIGH, detail, remediation, sorted(hits))


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
        "Certificates from these templates carry no SID, so with weak certificate mapping "
        "anyone who can change a victim's UPN can authenticate as that victim.",
        "Clear CT_FLAG_NO_SECURITY_EXTENSION and set StrongCertificateBindingEnforcement=2 "
        "on the domain controllers.",
        lambda t: t.no_security_extension and _authenticates(t),
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
        if a.admin_count and a.dn.lower() not in privileged and a.sam.lower() != "krbtgt"
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


@check("AD-INF-005", "LDAP signing not required")
def ldap_signing(snap: Snapshot) -> Finding | None:
    if snap.ldap_signing_required is not False:
        return None
    return _finding(
        "AD-INF-005",
        Severity.MEDIUM,
        "The DC accepted an unsigned NTLM bind on plain LDAP, so relayed authentication "
        "(for example from coerced machine accounts) can be used to modify the directory.",
        "Set 'Domain controller: LDAP server signing requirements' to Require signing and "
        "enable LDAP channel binding.",
        [snap.domain],
    )


TRUST_QUARANTINED = 0x4
TRUST_FOREST = 0x8
TRUST_WITHIN_FOREST = 0x20
TRUST_TREAT_AS_EXTERNAL = 0x40
TRUST_ENABLE_TGT_DELEGATION = 0x800
TRUST_OUTBOUND = 0x2


@check("AD-INF-006", "Trusts that let SIDs or TGTs through")
def trusts(snap: Snapshot) -> Finding | None:
    hits = []
    for t in snap.trusts:
        if t.attributes & TRUST_WITHIN_FOREST or not t.direction & TRUST_OUTBOUND:
            continue
        forest = bool(t.attributes & TRUST_FOREST)
        if not forest and not t.attributes & TRUST_QUARANTINED:
            hits.append(f"{t.name} (external, SID filtering disabled)")
        if forest and t.attributes & TRUST_TREAT_AS_EXTERNAL:
            hits.append(f"{t.name} (forest, SID history enabled)")
        if forest and t.attributes & TRUST_ENABLE_TGT_DELEGATION:
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
