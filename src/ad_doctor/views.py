"""Two reading views of a snapshot: service accounts and a tier-0 scorecard.

Both use only what a snapshot already holds. The directory says nothing about tier 1 or
tier 2, so the scorecard stops at tier 0 and does not grade the rest.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from .checks import tier0_hosts
from .coverage import named_checks
from .fixes import _name, one_line
from .model import UAC, Account, Finding, Severity, Snapshot

STALE_PASSWORD = timedelta(days=365)
KRBTGT = "krbtgt"


def _days(now: datetime, then: datetime | None) -> int | None:
    return None if then is None else (now - then).days


def _password_age(a: Account, now: datetime) -> int | None:
    """Days since the password was set; None when pwdLastSet was 0 or unread."""
    return None if a.pwd_must_change else _days(now, a.password_changed)


def _delegation(a: Account) -> list[str]:
    kinds = []
    if a.has(UAC.TRUSTED_FOR_DELEGATION):
        kinds.append("unconstrained")
    if a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION):
        kinds.append("protocol transition")
    if a.allowed_to_delegate_to and not a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION):
        kinds.append("constrained")
    if a.rbcd:
        kinds.append("resource-based")
    return kinds


def _kind(a: Account) -> str | None:
    if a.managed:
        return "managed"
    if a.is_computer:
        return None
    if a.sync_host:
        return "sync"
    return "user with SPN" if a.spns else None


def service_accounts(snap: Snapshot) -> list[dict[str, Any]]:
    """Managed accounts, Entra Connect sync accounts and users with an SPN, by name."""
    tier0 = snap.tier0_dns()
    rows = []
    for a in sorted(snap.accounts, key=lambda x: x.sam.lower()):
        kind = _kind(a)
        if kind is None or a.sam.lower() == KRBTGT:
            continue
        rows.append(
            {
                "name": a.sam,
                "kind": kind,
                "enabled": a.enabled,
                "password_age_days": _password_age(a, snap.collected_at),
                "last_logon_days": _days(snap.collected_at, a.last_logon),
                "spns": len(a.spns),
                "delegation": _delegation(a),
                "tier0": a.dn.lower() in tier0,
            }
        )
    return rows


def tier0_scorecard(snap: Snapshot, findings: list[Finding]) -> dict[str, Any]:
    """Counts about tier 0, with no score: each row can be recounted from the snapshot."""
    tier0 = snap.tier0_dns()
    users = [
        a
        for a in snap.accounts
        if a.dn.lower() in tier0 and not a.is_computer and a.sam.lower() != KRBTGT
    ]
    enabled = [a for a in users if a.enabled]
    ages = [_password_age(a, snap.collected_at) for a in enabled]
    hosts = tier0_hosts(snap)
    names = {a.sam.lower() for a in users}
    counts = {str(s): 0 for s in reversed(Severity)}
    for f in findings:
        if any(_name(o).lower() in names for o in f.objects):
            counts[str(f.severity)] += 1
    path = next((f for f in findings if f.check_id == "AD-PATH-001"), None)
    exposed = None if path is None else path.data.get("exposed")
    total = None if path is None else path.data.get("users")
    return {
        "domain": snap.domain,
        "collected_at": snap.collected_at.isoformat(),
        "accounts": len(users),
        "enabled_accounts": len(enabled),
        # None: whether a member of a tier-0 group is missing from the counts cannot be told
        "members_not_readable": len(snap.unreadable_members)
        if snap.tier0_members_checked
        else None,
        "checks_not_judged": sorted({c for n in snap.notes for c in named_checks(n)}),
        "passwords_over_a_year": sum(1 for x in ages if x is not None and x > 365),
        "password_age_unknown": sum(1 for x in ages if x is None),
        "with_spn": sum(1 for a in enabled if a.spns),
        "without_preauth": sum(1 for a in enabled if a.has(UAC.DONT_REQ_PREAUTH)),
        "password_not_required": sum(1 for a in enabled if a.has(UAC.PASSWD_NOTREQD)),
        "unconstrained_delegation": sum(1 for a in enabled if a.has(UAC.TRUSTED_FOR_DELEGATION)),
        "hosts": len(hosts),
        "domain_controllers": sum(1 for r in hosts.values() if r == "domain controller"),
        "findings_on_tier0_accounts": counts,
        "users_with_a_path_to_tier0": exposed,
        "users": total,
    }


def render_service_accounts(rows: list[dict[str, Any]], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(rows, indent=2)
    header = (
        f"{'NAME':32} {'KIND':14} {'ON':>3} {'PWD DAYS':>8} {'LOGON DAYS':>10} {'SPN':>3} "
        f"{'T0':>3}  DELEGATION"
    )
    lines = [header]
    for r in rows:
        pwd = "?" if r["password_age_days"] is None else r["password_age_days"]
        logon = "never" if r["last_logon_days"] is None else r["last_logon_days"]
        lines.append(
            f"{one_line(r['name'])[:32]:32} {r['kind']:14} {'yes' if r['enabled'] else 'no':>3} "
            f"{pwd:>8} {logon:>10} {r['spns']:>3} {'yes' if r['tier0'] else '':>3}  "
            f"{', '.join(r['delegation'])}"
        )
    lines.append(f"{len(rows)} service accounts")
    return "\n".join(lines)


def render_scorecard(card: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(card, indent=2)
    counts = card["findings_on_tier0_accounts"]
    exposed = card["users_with_a_path_to_tier0"]
    hidden = card["members_not_readable"]
    rows = [
        ("Tier-0 accounts (enabled)", f"{card['accounts']} ({card['enabled_accounts']})"),
        (
            "Tier-0 members not readable",
            "not known, counts may be short" if hidden is None else hidden,
        ),
        ("Passwords over a year old", card["passwords_over_a_year"]),
        ("Password age unknown", card["password_age_unknown"]),
        ("With an SPN", card["with_spn"]),
        ("Without Kerberos pre-authentication", card["without_preauth"]),
        ("Password not required", card["password_not_required"]),
        ("Unconstrained delegation", card["unconstrained_delegation"]),
        ("Tier-0 hosts (DCs)", f"{card['hosts']} ({card['domain_controllers']})"),
        (
            "Findings on tier-0 accounts",
            ", ".join(f"{k} {counts[k]}" for k in ("high", "medium", "low", "info")),
        ),
        (
            "Users with a path to tier 0",
            "not known" if exposed is None else f"{exposed} of {card['users']}",
        ),
        ("Checks the notes say are not judged", len(card["checks_not_judged"])),
    ]
    lines = [f"Tier-0 scorecard for {one_line(card['domain'])}", ""]
    lines += [f"{label:38} {value}" for label, value in rows]
    lines += ["", "Tier 1 and tier 2 are not in the directory, so they are not scored."]
    return "\n".join(lines)
