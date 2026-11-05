"""Accepted risks: findings an owner has signed off on, each with a reason and an expiry.

    [[accept]]
    check = "AD-KRB-003"
    objects = ["svc_backup"]     # optional; without it the whole check is accepted
    reason = "vendor appliance, 30-char password"
    expires = 2027-03-31
    owner = "infra-team"         # optional
    ticket = "OPS-123"           # optional

Besides filtering findings, the file is audited: expired acceptances turn back into
findings, acceptances that no longer match anything are reported as stale, and the ones
expiring within 30 days are listed so they can be renewed or fixed in time.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from pathlib import Path

from .model import Finding
from .report import Accepted

EXPIRY_WARNING = timedelta(days=30)


class AcceptError(Exception):
    pass


@dataclass
class Entry:
    check: str
    objects: set[str]
    reason: str
    expires: date
    owner: str = ""
    ticket: str = ""
    used: bool = field(default=False, compare=False)


def load(path: Path) -> list[Entry]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AcceptError(f"{path}: {exc}") from exc
    entries = []
    for i, item in enumerate(data.get("accept", []), 1):
        missing = {"check", "reason", "expires"} - item.keys()
        if missing:
            raise AcceptError(f"{path}: entry {i} is missing {', '.join(sorted(missing))}")
        if not isinstance(item["expires"], date):
            raise AcceptError(f"{path}: entry {i}: expires must be a date like 2027-03-31")
        entries.append(
            Entry(
                check=item["check"].upper(),
                objects=set(item.get("objects", [])),
                reason=item["reason"],
                expires=item["expires"],
                owner=item.get("owner", ""),
                ticket=item.get("ticket", ""),
            )
        )
    return entries


def apply(
    findings: list[Finding],
    entries: list[Entry],
    today: date,
    ran: set[str] | None = None,
) -> tuple[list[Finding], list[Accepted], list[str]]:
    """Remove accepted objects; return the kept findings, what was accepted and notes.

    `ran` is the set of check IDs that ran; acceptances for other checks are left alone
    (neither applied nor reported as stale). Names compare case-insensitively, like AD.
    An object matches by its full text, its leading name or its identity (`Finding.key`:
    the start principal of an AD-PATH-001 path, so "Domain Users" accepts that path).
    """
    accepted: list[Accepted] = []
    notes: list[str] = []
    active = []
    for e in entries:
        if e.expires < today:
            notes.append(f"acceptance of {e.check} expired on {e.expires}{_who(e)}")
        else:
            active.append(e)
    kept = []
    for f in findings:
        remaining = list(f.objects)
        for e in active:
            if e.check != f.check_id:
                continue
            wanted = {o.lower() for o in e.objects}
            hit = (
                remaining
                if not e.objects
                else [
                    o for o in remaining if wanted & {o.lower(), _base(o).lower(), f.key(o).lower()}
                ]
            )
            if hit:
                e.used = True
                accepted.append(Accepted(e.check, sorted(hit), e.reason, e.expires.isoformat()))
                remaining = [o for o in remaining if o not in hit]
        if remaining:
            kept.append(replace(f, objects=remaining))
    for e in active:
        if ran is not None and e.check not in ran:
            continue
        if not e.used:
            notes.append(f"acceptance of {e.check} matches no finding any more (stale){_who(e)}")
        elif e.expires - today <= EXPIRY_WARNING:
            notes.append(f"acceptance of {e.check} expires on {e.expires}{_who(e)}")
    return kept, accepted, notes


def status(e: Entry, today: date, ran: set[str] | None = None) -> str:
    """expired, stale, expiring, active, or skipped (its check did not run). Call it after
    apply(), which records whether the entry matched anything."""
    if e.expires < today:
        return "expired"
    if ran is not None and e.check not in ran:
        return "skipped"
    if not e.used:
        return "stale"
    return "expiring" if e.expires - today <= EXPIRY_WARNING else "active"


def _who(e: Entry) -> str:
    parts = [p for p in (e.owner, e.ticket) if p]
    return f" ({', '.join(parts)})" if parts else ""


def _base(obj: str) -> str:
    """Objects can carry context ('svc_iis -> cifs/fs01'); match on the leading name."""
    return obj.split(" ", 1)[0]
