"""Declared tier 0: assets a user adds to the tier-0 set, from a file or `--tier0`.

Two sets stay apart. Built-in tier 0 is what the snapshot proves, and every check keeps
reading only that, so a declaration can neither silence a finding nor make a built-in path
go away. A declared asset is an extended target: AD-PATH-001, `paths` and the viewer add the
paths that end at one and mark each of them. `whatif` and `plan` go through the same names
and the same test, and there the asset counts as tier 0 for the cut, as `--tier0` always did.

The file alone cannot be the whole story. A collection reads the owner and DACL of groups,
OUs and tier-0 accounts only, so for any other user or computer it holds no such thing.
Give the same file to `collect` or `scan` and the DACL is read; otherwise the asset says
"not evaluated", and the paths shown are only those that need no DACL of its own.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import paths
from .model import DirObject, Snapshot
from .resolve import Resolver, SpecError

EVALUATED, NOT_EVALUATED = "evaluated", "not_evaluated"
BUILT_IN, DECLARED = "built-in", "declared"
NOT_COLLECTED = (
    "its owner and DACL are not in this snapshot (give the same names to collect or scan)"
)
UNREADABLE = "its owner and DACL could not be read when the snapshot was collected"

Groups = list[tuple[str, list[str]]]  # (where the names came from, the names)


class DeclaredError(ValueError):
    pass


def load_file(path: Path) -> list[str]:
    """The names of a tier-0 file: `tier0 = ["JUMP01$", "svc_backup"]`."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise DeclaredError(f"{path}: {exc}") from exc
    unknown = sorted(data.keys() - {"tier0"})
    if unknown:
        raise DeclaredError(f"{path}: unknown key {unknown[0]!r} (the file holds tier0 = [...])")
    names = data.get("tier0")
    if not isinstance(names, list) or not all(isinstance(n, str) and n.strip() for n in names):
        raise DeclaredError(f'{path}: tier0 must be a list of names, like tier0 = ["JUMP01$"]')
    return [n.strip() for n in names]


def nodes(resolver: Resolver, names: Iterable[str], lenient: bool = False) -> list[str]:
    """The graph nodes of these names, each once, in order. A name the snapshot does not
    hold is an error (with `lenient`, skipped: an older snapshot used as a baseline)."""
    out = []
    for name in names:
        node = resolver.node(name)
        if node is not None and not _sid_held(resolver, name, node):
            node = None
        if node is not None:
            out.append(node)
        elif not lenient:
            raise SpecError(f"--tier0 / [assume] tier0: no {name!r} in this snapshot")
    return list(dict.fromkeys(out))


def _sid_held(resolver: Resolver, name: str, node: str) -> bool:
    """False for a SID that appears nowhere in the snapshot: it is taken as written, so a typo
    would otherwise pass as an asset nothing reaches."""
    sid = name.strip()
    return not sid.lower().startswith("s-1-") or node in resolver.g.names or resolver.sid_known(sid)


def _objects(snap: Snapshot, g: paths.Graph) -> dict[str, DirObject]:
    assert g.prov is not None
    return {g.prov.node_of(o.dn): o for o in snap.objects}


def _gap(objects: dict[str, DirObject], node: str) -> str:
    """Why this node's owner and DACL are unknown; empty when the snapshot holds them."""
    o = objects.get(node)
    if o is None:
        return NOT_COLLECTED
    return "" if o.owner and o.aces else UNREADABLE


def _gap_note(name: str, reason: str) -> str:
    return (
        f"declared tier 0: {name}: not evaluated, {reason}; AD-PATH-001 did not judge who "
        "controls it directly, and shows only the paths that need no DACL of its own"
    )


def unevaluated(snap: Snapshot, g: paths.Graph, declared: Iterable[str]) -> dict[str, str]:
    """Declared node outside built-in tier 0 -> why its DACL is unknown."""
    objects = _objects(snap, g)
    return {n: gap for n in declared if n not in g.tier0 and (gap := _gap(objects, n))}


def gap_notes(snap: Snapshot, g: paths.Graph, declared: Iterable[str]) -> list[str]:
    return [_gap_note(g.name(n), gap) for n, gap in unevaluated(snap, g, declared).items()]


@dataclass
class Asset:
    name: str
    node: str
    kind: str
    source: str
    set: str  # BUILT_IN when the name turned out to be tier 0 already, else DECLARED
    status: str
    reason: str = ""

    def to_json(self, principals: int | None) -> dict[str, Any]:
        out = dict(self.__dict__)
        if not self.reason:
            del out["reason"]
        if principals is not None:
            out["principals"] = principals
        return out


@dataclass
class Declaration:
    graph: paths.Graph
    analysis: paths.Analysis
    assets: list[Asset]
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """What a report, `paths -f json` and the viewer say about the declared set."""
        a = self.analysis
        reach = a.declared  # None when every name was built-in tier 0 already
        return {
            "assets": [
                x.to_json(reach.principals.get(x.node) if reach else None) for x in self.assets
            ],
            "paths": len(reach.paths) if reach else 0,
            "exposed_with_declared": reach.exposed if reach else a.exposed,
            "users_with_declared": reach.users if reach else a.users,
        }


def declare(snap: Snapshot, groups: Groups, lenient: bool = False) -> Declaration:
    """The graph (with provenance, which name lookup needs) and its analysis with this
    declaration. Built-in tier 0 and the graph's edges are what they are without one."""
    g = paths.build(snap, provenance=True)
    resolver = Resolver(snap, g)
    objects = _objects(snap, g)
    assets: dict[str, Asset] = {}
    for source, names in groups:
        for node in nodes(resolver, names, lenient):
            if node in assets:
                continue
            gap = "" if node in g.tier0 else _gap(objects, node)
            assets[node] = Asset(
                g.name(node),
                node,
                g.kind(node),
                source,
                BUILT_IN if node in g.tier0 else DECLARED,
                NOT_EVALUATED if gap else EVALUATED,
                gap,
            )
    g.declared = {a.node for a in assets.values() if a.set == DECLARED}
    rows = list(assets.values())
    notes = [_gap_note(a.name, a.reason) for a in rows if a.status == NOT_EVALUATED]
    return Declaration(g, paths.analyze(snap, g), rows, notes)
