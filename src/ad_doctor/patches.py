"""Compare a host's build and UBR with Microsoft's fixed builds (patches.toml).

The comparison says only that a host's number is below the one Microsoft published. It does
not test the flaw, so these findings rank below configuration findings, which read the
setting itself.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib import resources

from .model import HostPatch, Snapshot

CERTIGHOST = "CVE-2026-54121"
CHECK_FOR_ROLE = {"dc": "AD-INF-029", "ca": "AD-ADCS-022"}


@dataclass(frozen=True)
class Cve:
    id: str
    title: str
    released: date
    roles: tuple[str, ...]
    url: str
    fixed: dict[int, int]


@dataclass(frozen=True)
class Table:
    updated: date
    stale_after_days: int
    cves: tuple[Cve, ...]

    def get(self, cve_id: str) -> Cve:
        return next(c for c in self.cves if c.id == cve_id)

    def for_role(self, role: str) -> list[Cve]:
        return [c for c in self.cves if role in c.roles]


@cache
def table() -> Table:
    text = resources.files(__package__).joinpath("patches.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    return Table(
        date.fromisoformat(data["updated"]),
        int(data["stale_after_days"]),
        tuple(
            Cve(
                c["id"],
                c["title"],
                date.fromisoformat(c["released"]),
                tuple(c["roles"]),
                c["url"],
                {int(build): int(ubr) for build, ubr in c["fixed"].items()},
            )
            for c in data["cve"]
        ),
    )


def below(host: HostPatch, cve: Cve) -> bool:
    """True only when the build is in the table and the UBR is known and lower."""
    if host.build is None or host.ubr is None:
        return False
    fixed = cve.fixed.get(host.build)
    return fixed is not None and host.ubr < fixed


def version(build: int, ubr: int) -> str:
    return f"10.0.{build}.{ubr}"


def missing_fixes(host: HostPatch, role: str, t: Table | None = None) -> list[Cve]:
    t = t or table()
    return [c for c in t.for_role(role) if below(host, c)]


def _known_build(host: HostPatch, role: str, t: Table) -> bool:
    return any(host.build in c.fixed for c in t.for_role(role))


def notes(snap: Snapshot, t: Table | None = None) -> list[str]:
    """What the table cannot say about this snapshot: its age and the hosts it does not cover."""
    t = t or table()
    if not snap.probes.patch_checked:
        return []
    out = []
    age = (snap.collected_at.date() - t.updated).days
    if age > t.stale_after_days:
        out.append(
            f"patch table dated {t.updated} is {age} days older than this scan: AD-INF-029 and "
            "AD-ADCS-022 may miss newer fixes, so update ad-doctor"
        )
    cas = {c.host.lower(): c for c in snap.probes.ca_configs}
    for host in sorted(snap.probes.patch_levels, key=lambda h: h.name.lower()):
        if host.build is None or host.ubr is None:
            continue
        for role in host.roles:
            if role in CHECK_FOR_ROLE and not _known_build(host, role, t):
                out.append(
                    f"{host.name}: build {host.build} is not in the patch table: "
                    f"{CHECK_FOR_ROLE[role]} did not judge it"
                )
        if "ca" in host.roles and below(host, t.get(CERTIGHOST)):
            cfg = cas.get(host.name.lower())
            if cfg is None or cfg.edit_flags is None:
                out.append(
                    f"{host.name}: below the {CERTIGHOST} fix, but the CA's EditFlags could not "
                    "be read: AD-ADCS-022 did not judge it"
                )
    return out
