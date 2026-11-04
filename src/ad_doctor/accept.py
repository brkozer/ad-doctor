"""Accepted risks: findings an owner has signed off on, each with a reason and an expiry.

[[accept]]
check = "AD-KRB-003"
objects = ["svc_backup"]     # optional; without it the whole check is accepted
reason = "vendor appliance, 30-char password, rotation ticket OPS-123"
expires = 2027-03-31
"""

from __future__ import annotations

import tomllib
from dataclasses import replace
from datetime import date
from pathlib import Path

from .model import Finding
from .report import Accepted


class AcceptError(Exception):
    pass


def load(path: Path) -> list[tuple[str, set[str], str, date]]:
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
            (item["check"].upper(), set(item.get("objects", [])), item["reason"], item["expires"])
        )
    return entries


def apply(
    findings: list[Finding], entries: list[tuple[str, set[str], str, date]], today: date
) -> tuple[list[Finding], list[Accepted], list[str]]:
    """Remove accepted objects; expired acceptances are ignored and reported as notes."""
    accepted: list[Accepted] = []
    notes: list[str] = []
    active = []
    for check_id, objects, reason, expires in entries:
        if expires < today:
            notes.append(f"acceptance of {check_id} expired on {expires}")
        else:
            active.append((check_id, objects, reason, expires))
    kept = []
    for f in findings:
        remaining = list(f.objects)
        for check_id, objects, reason, expires in active:
            if check_id != f.check_id:
                continue
            hit = remaining if not objects else [o for o in remaining if _base(o) in objects]
            if hit:
                accepted.append(Accepted(check_id, sorted(hit), reason, expires.isoformat()))
                remaining = [o for o in remaining if o not in hit]
        if remaining:
            kept.append(replace(f, objects=remaining))
    return kept, accepted, notes


def _base(obj: str) -> str:
    """Objects can carry context ('svc_iis -> cifs/fs01'); match on the leading name."""
    return obj.split(" ", 1)[0]
