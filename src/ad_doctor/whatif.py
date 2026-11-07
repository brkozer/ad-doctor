"""What-if, forward: the effect of a set of changes on a snapshot, never on AD.

Level 1 masks the graph: edges whose change is in the set are dropped and everything else
keeps its order, so `paths.paths_to_tier0`, `direct_holders`, `exposure` and `reachable`
give the same answer, ties included, as a graph built from the changed snapshot (the
graph-equality tests check this edge for edge). Changes that can move GPO scope (links,
security filters) are not masked: they go through a rebuild.

Level 2 takes the changes out of the snapshot in place and runs every check again, which
also shows findings that would appear. The AD-PATH-001 holders and exposure of both levels
must match; a difference is a bug in the model and raises ModelMismatch.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import changes, paths
from .checks import run_all
from .model import Finding, Snapshot
from .paths import Graph, Path
from .provenance import Gated, Options, Provenance
from .report import fingerprint

CA_KINDS = {"member", "ca-right", "template-flag"}  # changes that can change tier 0


class ModelMismatch(Exception):
    """Level 1 (masked graph) and level 2 (changed snapshot) disagree: a model bug."""


def _alive(
    prov: Provenance,
    extra: dict[tuple[str, int], Options | Gated],
    src: str,
    i: int,
    why: int,
    how: str,
    removed: set[int] | frozenset[int],
    closed_gates: set[int],
) -> str | None:
    """The edge instance's label after the removals, or None when it is gone."""
    ex = extra.get((src, i))
    if ex is None:
        return how if why < 0 or why not in removed else None
    if isinstance(ex, Options):
        for p, label in ex.items:
            if p < 0 or p not in removed:
                return label
        return None
    if ex.prim in removed or ex.gate in closed_gates:
        return None
    return how


class _Index:
    """Which sources hold edges of each change and gate (built on first use)."""

    def __init__(self, prov: Provenance) -> None:
        self.srcs: dict[int, list[str]] = {}
        self.logon_srcs: dict[int, list[str]] = {}
        self.gate_srcs: dict[int, list[str]] = {}
        for table, why_map, extra in (
            (self.srcs, prov.why, prov.extra),
            (self.logon_srcs, prov.logon_why, prov.logon_extra),
        ):
            for src, arr in why_map.items():
                for p in set(arr):
                    if p >= 0:
                        table.setdefault(p, []).append(src)
            for (src, _), ex in extra.items():
                prims = [p for p, _ in ex.items] if isinstance(ex, Options) else [ex.prim]
                for p in prims:
                    if p >= 0 and src not in table.get(p, ()):
                        table.setdefault(p, []).append(src)
                if isinstance(ex, Gated):
                    srcs = self.gate_srcs.setdefault(ex.gate, [])
                    if src not in srcs:
                        srcs.append(src)


def _index(prov: Provenance) -> _Index:
    idx = getattr(prov, "_mask_index", None)
    if idx is None:
        idx = _Index(prov)
        prov._mask_index = idx  # type: ignore[attr-defined]
    return idx


def masked(
    g: Graph, snap: Snapshot, removed: Iterable[int], tier0_extra: Iterable[str] = ()
) -> Graph:
    """The graph without the edges of the removed changes, in build order. `snap` must
    be the snapshot the graph was built from, before any change. `tier0_extra` adds
    nodes to tier 0 (the `[assume] tier0` of a plan)."""
    prov = g.prov
    assert prov is not None, "build the graph with provenance=True"
    gone = frozenset(removed)
    extra_t0 = set(tier0_extra)
    if not gone and not extra_t0:
        return g
    idx = _index(prov)
    closed = {
        gi
        for p in gone
        if prov.prims[p][0] == "template-flag"
        for gi, gate in enumerate(prov.gates)
        if p in gate.flags
    }
    closed = {gi for gi in closed if not prov.gate_open(gi, gone)}
    touched: dict[str, None] = {}
    for p in gone:
        for src in idx.srcs.get(p, ()):
            touched[src] = None
    for gi in closed:
        for src in idx.gate_srcs.get(gi, ()):
            touched[src] = None

    edges = dict(g.edges)
    moved: list[tuple[int, str]] = []
    for src in touched:
        outs = g.edges[src]
        why = prov.why[src]
        kept: list[paths.Edge] = []
        first = -1
        for i, (dst, how) in enumerate(outs):
            label = _alive(prov, prov.extra, src, i, why[i], how, gone, closed)
            if label is not None:
                if first < 0:
                    first = i
                kept.append((dst, label))
        if not kept:
            del edges[src]
        else:
            edges[src] = kept
            if first > 0:  # the rebuilt graph meets this source later
                moved.append((prov.seq[src][first], src))
    if moved:
        edges = _reorder(edges, prov, moved)

    logon = g.logon_edges
    logon_touched = {src for p in gone for src in idx.logon_srcs.get(p, ())}
    if logon_touched:
        logon = dict(logon)
        for src in logon_touched:
            arr = prov.logon_why[src]
            kept = []
            for i, (dst, how) in enumerate(g.logon_edges[src]):
                label = _alive(prov, prov.logon_extra, src, i, arr[i], how, gone, closed)
                if label is not None:
                    kept.append((dst, label))
            if kept:
                logon[src] = kept
            else:
                del logon[src]

    tier0 = g.tier0
    if extra_t0 or any(prov.prims[p][0] in CA_KINDS for p in gone):
        tier0 = _tier0(g, snap, prov, gone, closed) | extra_t0
    return Graph(edges, g.names, tier0, logon, g.edge_props, g.kinds, prov)


def _reorder(
    edges: dict[str, list[paths.Edge]], prov: Provenance, moved: list[tuple[int, str]]
) -> dict[str, list[paths.Edge]]:
    """Sources in the order a rebuild would first add an edge of theirs."""
    late = {src for _, src in moved}
    moved.sort()
    out: dict[str, list[paths.Edge]] = {}
    j = 0
    for src, outs in edges.items():
        if src in late:
            continue
        first = prov.seq[src][0]
        while j < len(moved) and moved[j][0] < first:
            out[moved[j][1]] = edges[moved[j][1]]
            j += 1
        out[src] = outs
    for _, src in moved[j:]:
        out[src] = edges[src]
    return out


def _tier0(
    g: Graph, snap: Snapshot, prov: Provenance, gone: frozenset[int], closed: set[int]
) -> set[str]:
    pairs = {(prov.prims[p][1], prov.prims[p][2]) for p in gone if prov.prims[p][0] == "member"}
    privileged = changes.privileged_without(snap, pairs)
    ca_nodes = []
    for src, i, dst in prov.ca_edges:
        label = _alive(prov, prov.extra, src, i, prov.why[src][i], "", gone, closed)
        if label is not None:
            ca_nodes.append(dst)
    alive_ca = set(ca_nodes)
    names = [
        n
        for n in g.names
        if n.startswith("tier0:") and (not n.startswith("tier0:ca:") or n in alive_ca)
    ]
    return paths.tier0_nodes(
        snap, prov.node_of, prov.domain_node, ca_nodes, names, snap.tier0_dns(privileged)
    )


def maskable(prov: Provenance, removed: Iterable[int]) -> bool:
    """False when a change can move GPO scope: level 1 then rebuilds the graph."""
    return not any(prov.scope_sensitive(p) for p in removed)


def reaching(g: Graph) -> set[str]:
    """Every node with a path to tier 0, tier 0 included (paths_to_tier0 without the
    paths)."""
    reverse: dict[str, list[str]] = {}
    for src, outs in g.edges.items():
        for dst, _ in outs:
            reverse.setdefault(dst, []).append(src)
    seen = set(g.tier0)
    queue = deque(g.tier0)
    while queue:
        node = queue.popleft()
        for src in reverse.get(node, ()):
            if src not in seen:
                seen.add(src)
                queue.append(src)
    return seen


@dataclass
class State:
    """AD-PATH-001's numbers for one graph."""

    graph: Graph
    found: dict[str, Path]
    holders: dict[str, Path]
    exposed: int
    users: int

    @property
    def holder_ids(self) -> list[str]:
        return sorted(self.holders)


def state(snap: Snapshot, g: Graph) -> State:
    found = paths.paths_to_tier0(g)
    holders = paths.direct_holders(g, found)
    exposed, users = paths.exposure(snap, g, found)
    return State(g, found, holders, exposed, users)


def signature(g: Graph) -> dict[str, Any]:
    """What must match between a masked graph and a rebuilt one: every edge in order,
    the order of sources, tier 0, the properties, names and kinds of the edges and nodes
    that are there, and the logon edges."""
    nodes = set(g.edges) | {dst for outs in g.edges.values() for dst, _ in outs}
    props = {
        (src, dst, how): g.edge_props[(src, dst, how)]
        for src, outs in g.edges.items()
        for dst, how in outs
        if (src, dst, how) in g.edge_props
    }
    return {
        "edges": [(src, list(outs)) for src, outs in g.edges.items()],
        "tier0": sorted(g.tier0),
        "props": props,
        "names": {n: g.name(n) for n in sorted(nodes)},
        "kinds": {n: g.kind(n) for n in sorted(nodes)},
        "logon": [(src, list(outs)) for src, outs in g.logon_edges.items()],
    }


# -- forward what-if ---------------------------------------------------------------------


@dataclass
class Result:
    removed: list[int]
    absent: list[int]
    maskable: bool
    before: State
    after: State
    closed: list[str] = field(default_factory=list)  # holder nodes with no path left
    rerouted: list[str] = field(default_factory=list)  # still a path, another one
    open: list[str] = field(default_factory=list)  # same path as before
    findings_rechecked: bool = False
    cleared: list[dict[str, str]] = field(default_factory=list)
    new: list[dict[str, str]] = field(default_factory=list)
    changed: list[dict[str, str]] = field(default_factory=list)
    accounts: list[dict[str, Any]] = field(default_factory=list)


def classify(before: State, after: State) -> tuple[list[str], list[str], list[str]]:
    """Each holder of before: closed (no path), rerouted (a path, not the same) or open."""
    closed: list[str] = []
    rerouted: list[str] = []
    still: list[str] = []
    for node in before.holders:
        if node not in after.found and node not in after.holders:
            closed.append(node)
        else:
            old = before.holders[node].render(before.graph)
            new = after.holders.get(node) or after.found.get(node)
            same = new is not None and new.render(after.graph) == old
            (still if same else rerouted).append(node)
    return closed, rerouted, still


def _blast(snap: Snapshot, g: Graph, account: str) -> dict[str, int]:
    starts = paths.identity_nodes(snap, account)
    controlled, tier0 = paths.blast_radius(g, starts)
    return {"count": len(controlled), "tier0": len(tier0)}


def run(
    snap: Snapshot,
    g: Graph,
    removed: Iterable[int],
    accounts: Iterable[str] = (),
    paths_only: bool = False,
    tier0_extra: Iterable[str] = (),
    baseline: list[Finding] | None = None,
) -> Result:
    """Forward what-if. `g` is `paths.build(snap, provenance=True)`. Without
    `paths_only` the snapshot is changed in place (level 2); keep a copy on disk."""
    prov = g.prov
    assert prov is not None
    gone = sorted(set(removed))
    extra = list(tier0_extra)
    base_graph = masked(g, snap, (), extra)
    before = state(snap, base_graph)
    ok = maskable(prov, gone)
    blast_before = {a: _blast(snap, base_graph, a) for a in accounts}
    findings_before: list[Finding] = []
    if not paths_only:
        findings_before = baseline if baseline is not None else run_all(snap)
    if ok:
        after = state(snap, masked(g, snap, gone, extra))
        counts = None
    else:
        counts = changes.apply(snap, prov, gone)
        rebuilt = paths.build(snap)
        rebuilt = Graph(
            rebuilt.edges,
            rebuilt.names,
            rebuilt.tier0 | set(extra),
            rebuilt.logon_edges,
            rebuilt.edge_props,
            rebuilt.kinds,
        )
        after = state(snap, rebuilt)
    closed, rerouted, still = classify(before, after)
    result = Result(gone, [], ok, before, after, closed, rerouted, still)
    result.accounts = [
        {"account": a, "before": blast_before[a], "after": _blast(snap, after.graph, a)}
        for a in accounts
    ]
    if paths_only:
        return result
    if counts is None:
        counts = changes.apply(snap, prov, gone)
    result.absent = [p for p in gone if counts.get(p, 0) == 0]
    findings_after = run_all(snap)
    result.findings_rechecked = True
    check_level2(after, findings_after, extra)
    result.cleared, result.new, result.changed = diff(findings_before, findings_after)
    return result


def check_level2(after: State, findings: list[Finding], tier0_extra: list[str]) -> None:
    """The level-1 == level-2 assertion: AD-PATH-001 holders and exposure agree."""
    if tier0_extra:
        return  # the checks do not know about assumed tier-0 nodes
    f = next((x for x in findings if x.check_id == "AD-PATH-001"), None)
    holders = sorted(p["start"]["id"] for p in f.data["paths"]) if f else []
    exposed = f.data["exposed"] if f else 0
    if holders != after.holder_ids or (f is not None and exposed != after.exposed):
        level1 = set(after.holder_ids)
        differ = sorted(level1.symmetric_difference(holders))
        raise ModelMismatch(
            f"model mismatch: level 1 has {len(level1)} holders and {after.exposed} exposed "
            f"users, level 2 has {len(holders)} and {exposed}; differing nodes: "
            + ", ".join(differ[:20])
        )


def diff(
    before: list[Finding], after: list[Finding]
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """Findings cleared, new and changed (same identity, other text), by finding key."""

    def keyed(findings: list[Finding]) -> dict[tuple[str, str], str]:
        return {(f.check_id, f.key(o)): o for f in findings for o in f.objects}

    old, new = keyed(before), keyed(after)

    def record(key: tuple[str, str], obj: str) -> dict[str, str]:
        return {"check": key[0], "object": obj, "fingerprint": fingerprint(*key)}

    cleared = [record(k, old[k]) for k in sorted(old.keys() - new.keys())]
    appeared = [record(k, new[k]) for k in sorted(new.keys() - old.keys())]
    changed = [record(k, new[k]) for k in sorted(old.keys() & new.keys()) if old[k] != new[k]]
    return cleared, appeared, changed
