"""The control graph for the viewer's Blast radius screen (`ad-doctor view --graph`).

- `full`: the whole graph in compact form (a node table, out-degrees and parallel
  integer edge arrays, edge labels as indexes into a label table) plus every account, so
  the page runs the same breadth-first search as `paths.reachable` for any account. The
  JavaScript port is checked against Python's output by Node tests.
- `paths`: for large domains. No graph; the blast radius is computed here for the
  principals that hold a right on a control path and for the accounts given with
  `--blast-radius-for`, and the page shows those.
- `none`: neither.

`auto` picks `full` up to FULL_GRAPH_OBJECTS directory objects and `paths` above.
"""

from __future__ import annotations

import heapq
from typing import Any

from . import paths
from .model import Snapshot

FULL_GRAPH_OBJECTS = 50_000
HOLDERS = 25  # path holders precomputed in paths mode, in report order
TIER0_PATHS = 20  # tier-0 paths kept per precomputed subject
PER_KIND = 50  # controlled objects kept per kind per precomputed subject
# implicit groups an identity starts from (paths._identity)
WELL_KNOWN = ("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-9")
MACHINE, DC, ENABLED, COMPUTER, GMSA = 1, 2, 4, 8, 16


def nodes_of(g: paths.Graph) -> list[str]:
    """Every node that has an edge or is tier 0, in a stable order."""
    nodes = set(g.edges) | g.tier0
    for outs in g.edges.values():
        nodes.update(dst for dst, _ in outs)
    return sorted(nodes)


def size(snap: Snapshot) -> int:
    """Directory objects in the snapshot: about the graph's node count, without building it."""
    return len(snap.accounts) + len(snap.objects) + len(snap.gpos) + len(snap.templates)


def choose(mode: str, snap: Snapshot) -> str:
    if mode != "auto":
        return mode
    return "full" if size(snap) <= FULL_GRAPH_OBJECTS else "paths"


def compact(g: paths.Graph, snap: Snapshot) -> dict[str, Any]:
    """The graph as arrays: node i is names[i] of kinds[kind[i]]; its out-edges are the
    next deg[i] entries of dst/how, in the order paths.build added them (the search
    visits them in that order, so paths come out the same as in Python)."""
    order = nodes_of(g)
    index = {n: i for i, n in enumerate(order)}
    labels: dict[str, int] = {}
    kinds: dict[str, int] = {}
    deg, dst, how = [], [], []
    for node in order:
        outs = g.edges.get(node, [])
        deg.append(len(outs))
        for target, label in outs:
            dst.append(index[target])
            how.append(labels.setdefault(paths.edge_text(g, node, target, label), len(labels)))
    kind = [kinds.setdefault(g.kind(n), len(kinds)) for n in order]
    primaries = {513, 515} | {a.primary_group for a in snap.accounts if a.primary_group}
    sids = [*WELL_KNOWN, *(f"{snap.domain_sid}-{rid}" for rid in sorted(primaries))]
    accounts = []
    for a in snap.accounts:
        if not a.sid:
            continue
        flags = (MACHINE if a.is_computer or a.managed else 0) | (DC if a.is_dc else 0)
        flags |= (ENABLED if a.enabled else 0) | (COMPUTER if a.is_computer else 0)
        flags |= GMSA if a.managed else 0
        accounts.append([a.sam, a.sid, index.get(f"sid:{a.sid}", -1), a.primary_group, flags])
    return {
        "names": [g.name(n) for n in order],
        "kind": kind,
        "kinds": list(kinds),
        "tier0": sorted(index[n] for n in g.tier0),
        "deg": deg,
        "dst": dst,
        "how": how,
        "labels": list(labels),
        "domain_sid": snap.domain_sid,
        "sids": {s: index[f"sid:{s}"] for s in sids if f"sid:{s}" in index},
        "accounts": accounts,
    }


def _step(g: paths.Graph, node: str, how: str) -> list[Any]:
    return [how, g.name(node), g.kind(node), int(node in g.tier0)]


def path_record(g: paths.Graph, p: paths.Path) -> dict[str, Any]:
    """A path as the page draws it: start name, then [how, name, kind, tier 0] steps."""
    return {"start": g.name(p.start), "steps": [_step(g, n, how) for n, how in p.steps]}


class Indexed:
    """The compact graph with Python lists, for searching many subjects quickly: node
    indexes instead of node IDs, and only the paths that are kept get built."""

    def __init__(self, data: dict[str, Any], order: list[str]) -> None:
        self.names: list[str] = data["names"]
        self.kind: list[str] = [data["kinds"][k] for k in data["kind"]]
        self.labels: list[str] = data["labels"]
        self.dst: list[int] = data["dst"]
        self.how: list[int] = data["how"]
        self.off = [0]
        for d in data["deg"]:
            self.off.append(self.off[-1] + d)
        self.tier0 = bytearray(len(order))
        for i in data["tier0"]:
            self.tier0[i] = 1
        self.index = {n: i for i, n in enumerate(order)}

    def search(self, starts: list[str]) -> tuple[list[int], list[int], list[int]]:
        """paths.reachable over indexes: (discovery order, parent, edge label). Nodes are
        numbered in node-ID order, so sorted indexes start the queue as Python does."""
        n = len(self.names)
        prev, via = [-1] * n, [-1] * n
        seen = bytearray(n)
        queue = sorted({self.index[s] for s in starts if s in self.index})
        for s in queue:
            seen[s] = 1
        order: list[int] = []
        off, dst, how = self.off, self.dst, self.how
        head = 0
        while head < len(queue):
            node = queue[head]
            head += 1
            for e in range(off[node], off[node + 1]):
                d = dst[e]
                if not seen[d]:
                    seen[d] = 1
                    prev[d], via[d] = node, how[e]
                    order.append(d)
                    queue.append(d)
        return order, prev, via

    def steps(self, prev: list[int], via: list[int], end: int) -> tuple[int, list[list[Any]]]:
        out, node = [], end
        while prev[node] != -1:
            out.append(
                [self.labels[via[node]], self.names[node], self.kind[node], self.tier0[node]]
            )
            node = prev[node]
        out.reverse()
        return node, out


def subject(c: Indexed, starts: list[str], name: str, kind: str, **extra: Any) -> dict[str, Any]:
    """One precomputed blast radius (paths.blast_radius), in the shape the page also
    builds from the full graph: counts per kind, the tier-0 paths, and the first
    PER_KIND objects of each kind with the step that reaches them."""
    order, prev, via = c.search(starts)
    depth: dict[int, int] = {}
    for d in order:
        depth[d] = depth.get(prev[d], 0) + 1
    order = [d for d in order if c.kind[d] != "scope"]  # not controlled objects
    tier0: list[dict[str, Any]] = []
    for end in sorted((d for d in order if c.tier0[d]), key=depth.__getitem__):
        root, steps = c.steps(prev, via, end)
        tier0.append({"start": c.names[root], "steps": steps})
    first = c.index.get(starts[0], -1) if starts else -1
    lead: dict[str, Any] | None = None
    if first >= 0 and c.tier0[first]:
        lead = {"start": c.names[first], "steps": []}
    else:
        for s in starts[1:]:
            i = c.index.get(s, -1)
            if i >= 0 and c.tier0[i]:
                lead = {"start": name, "steps": [["primary group", c.names[i], c.kind[i], 1]]}
                break
    if lead is not None:
        tier0.insert(0, lead)
    by_kind: dict[str, list[int]] = {}
    for d in order:
        by_kind.setdefault(c.kind[d], []).append(d)
    objects = []
    for k in sorted(by_kind):
        kept = heapq.nsmallest(
            PER_KIND, by_kind[k], key=lambda d: (not c.tier0[d], c.names[d].lower())
        )
        for d in kept:
            objects.append([c.names[d], k, c.tier0[d], c.labels[via[d]], c.names[prev[d]]])
    return {
        "name": name,
        "kind": kind,
        **extra,
        "reaches": bool(tier0),
        "count": len(order),
        "kinds": {k: len(v) for k, v in by_kind.items()},
        "tier0": tier0[:TIER0_PATHS],
        "tier0_count": len(tier0),
        "objects": objects,
        "truncated": any(len(v) > PER_KIND for v in by_kind.values()),
    }


def precomputed(
    g: paths.Graph, snap: Snapshot, analysis: paths.Analysis, accounts: list[str]
) -> list[dict[str, Any]]:
    """Blast radius of the named accounts and of the first HOLDERS principals that hold a
    right on a control path (report order: broad groups first, then shortest). A holder
    that is an account is searched as `ad-doctor blast-radius` searches it: from the
    account and its implicit groups (paths.identity_nodes); a group from its own node."""
    c = Indexed(compact(g, snap), nodes_of(g))
    by_sid = {a.sid.lower(): a for a in snap.accounts if a.sid}
    out = []

    def account(a: Any, **extra: Any) -> dict[str, Any]:
        kind = "gmsa" if a.managed else "computer" if a.is_computer else "user"
        starts = paths.identity_nodes(snap, a.sid or a.sam)
        return subject(c, starts, a.sam, kind, sid=a.sid, account=True, **extra)

    for name in accounts:
        key = name.lower()
        a = next((x for x in snap.accounts if key in (x.sam.lower(), x.sid.lower())), None)
        if a is None:
            raise ValueError(f"--blast-radius-for: no account {name!r} in the snapshot")
        out.append(account(a))
    seen = {s.get("sid") for s in out}
    holders = 0
    for p in analysis.paths:
        if holders >= HOLDERS:
            break
        sid = p.start.removeprefix("sid:")
        if sid in seen:
            continue
        seen.add(sid)
        holders += 1
        a = by_sid.get(sid.lower())
        if a is not None:
            out.append(account(a, holder=True))
        else:
            out.append(
                subject(c, [p.start], g.name(p.start), g.kind(p.start), sid=sid, holder=True)
            )
    return out
