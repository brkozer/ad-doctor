"""Policy as code: the state the team expects, checked against a snapshot.

[groups]                       # exact membership (sAMAccountName), transitive users
"Domain Admins" = ["Administrator", "adm_alice"]
"Schema Admins" = []

[limits]
tier0_users = 5                # at most this many distinct users in tier-0 groups

[settings]                     # domain settings that must hold
machine_account_quota = 0
min_pwd_length = 14
lockout_threshold = 10         # at least
recycle_bin = true

[dcsync]                       # principals allowed to replicate secrets
allowed = ["MSOL_0123abcd"]

[templates]                    # the only templates that may be published
published = ["User", "Machine", "DomainController", "WebServer"]
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from . import sd
from .model import DirObject, Finding, Severity, Snapshot


class InvariantError(Exception):
    pass


AT_LEAST = {"min_pwd_length", "lockout_threshold", "functional_level"}
SETTINGS = {
    "machine_account_quota": lambda s: s.policy.machine_account_quota,
    "min_pwd_length": lambda s: s.policy.min_pwd_length,
    "lockout_threshold": lambda s: s.policy.lockout_threshold,
    "pwd_complexity": lambda s: s.policy.pwd_complexity,
    "functional_level": lambda s: s.policy.functional_level,
    "recycle_bin": lambda s: s.recycle_bin,
    "ldap_signing_required": lambda s: s.probes.overall(
        "ldap_signing_required", s.ldap_signing_required
    ),
}


def load(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InvariantError(f"{path}: {exc}") from exc
    unknown = set(data.get("settings", {})) - SETTINGS.keys()
    if unknown:
        raise InvariantError(f"{path}: unknown settings {', '.join(sorted(unknown))}")
    return data


def _finding(
    check_id: str, title: str, severity: Severity, detail: str, objects: list[str]
) -> Finding:
    return Finding(
        check_id,
        title,
        severity,
        detail,
        "Bring the directory back to the declared state, or update the invariants file "
        "through review if the change was intended.",
        objects,
    )


def evaluate(snap: Snapshot, spec: dict[str, Any]) -> list[Finding]:
    findings = []
    by_dn = snap.by_dn()

    drift = []
    privileged = {k.lower(): v for k, v in snap.privileged.items()}
    groups = {o.name.lower(): o for o in snap.objects if o.kind == "group"}
    for group, expected in sorted(spec.get("groups", {}).items()):
        # AD names are case-insensitive; compare lower-cased, report as declared/found
        if group.lower() in privileged:
            dns = privileged[group.lower()]
        else:
            dns = _transitive_members(groups.get(group.lower()), snap.object_by_dn())
        actual = {
            by_dn[d.lower()].sam.lower(): by_dn[d.lower()].sam for d in dns if d.lower() in by_dn
        }
        want = {m.lower(): m for m in expected}
        drift += [f"{group}: unexpected {actual[m]}" for m in sorted(actual.keys() - want.keys())]
        drift += [f"{group}: missing {want[m]}" for m in sorted(want.keys() - actual.keys())]
    if drift:
        findings.append(
            _finding("AD-INV-001", "Group membership differs from the declared state",
                     Severity.HIGH, "Membership of declared groups drifted.", drift)
        )  # fmt: skip

    limit = spec.get("limits", {}).get("tier0_users")
    if limit is not None:
        users = {d.lower() for members in snap.privileged.values() for d in members}
        if len(users) > limit:
            findings.append(
                _finding("AD-INV-002", "Tier 0 is larger than declared", Severity.MEDIUM,
                         f"{len(users)} distinct accounts in tier-0 groups; the limit is {limit}.",
                         sorted(by_dn[d].sam for d in users if d in by_dn))
            )  # fmt: skip

    mismatches = []
    for name, want in sorted(spec.get("settings", {}).items()):
        have = SETTINGS[name](snap)
        ok = have is not None and have >= want if name in AT_LEAST else have == want
        if not ok:
            op = ">= " if name in AT_LEAST else ""
            mismatches.append(f"{name}: {have!r} (declared {op}{want!r})")
    if mismatches:
        findings.append(
            _finding("AD-INV-003", "Domain settings differ from the declared state",
                     Severity.MEDIUM, "Declared settings do not hold.", mismatches)
        )  # fmt: skip

    if "dcsync" in spec:
        allowed = {a.lower() for a in spec["dcsync"].get("allowed", [])}
        tier0 = snap.tier0_sids()
        aces = snap.acls.get("domain", [])
        get = {a.sid for a in aces if a.extended_right(sd.DS_REPL_GET_CHANGES)}
        get_all = {a.sid for a in aces if a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)}
        holders = [snap.name_of(s) for s in (get & get_all) - tier0]
        extra = sorted(h for h in holders if h.lower() not in allowed)
        if extra:
            findings.append(
                _finding("AD-INV-004", "DCSync rights outside the declared list", Severity.HIGH,
                         "These principals can replicate secrets but are not declared.", extra)
            )  # fmt: skip

    if "templates" in spec:
        allowed_t = {n.lower() for n in spec["templates"].get("published", [])}
        extra_t = sorted(
            t.name for t in snap.templates if t.published and t.name.lower() not in allowed_t
        )
        if extra_t:
            findings.append(
                _finding("AD-INV-005", "Templates published outside the declared list",
                         Severity.MEDIUM, "Published but not declared.", extra_t)
            )  # fmt: skip
    return findings


def _transitive_members(group: DirObject | None, objects: dict[str, DirObject]) -> list[str]:
    """Member DNs of a group with nested groups expanded (cycles are cut)."""
    if group is None:
        return []
    out, seen, stack = [], {group.dn.lower()}, list(group.members)
    while stack:
        dn = stack.pop()
        nested = objects.get(dn.lower())
        if nested is not None and nested.kind == "group":
            if nested.dn.lower() not in seen:
                seen.add(nested.dn.lower())
                stack.extend(nested.members)
        else:
            out.append(dn)
    return out
