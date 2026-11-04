"""Checks: pure functions from a Snapshot to findings.

Each check returns at most one Finding that lists every affected object, so the report
stays one line per problem rather than one line per account.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta

from .model import UAC, Account, Finding, Severity, Snapshot

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
    return Finding(check_id, title, severity, detail, remediation, objects)


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
