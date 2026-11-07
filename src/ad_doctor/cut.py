"""What-if, reverse: the cheapest set of changes that closes every path ad-doctor sees.

The flow network is built on the path subgraph only (reached from a source and reaching
tier 0). Each change is one arc `p_in -> p_out` with its cost (node splitting), an edge
made by change p becomes `u -> p_in` and `p_out -> v`, fixed edges and kept changes are
infinite, and tier 0 is the sink. A maximum flow then gives the cheapest cut in the
model, exact when every change is one arc that cannot join routes that do not exist: all
its edges share a source node, or all share a target (tier 0 counts as one target).
`inexact` counts the changes where that fails; the cut is still valid then, but only a
lower bound (change-disjoint paths) can prove it minimal.

Capacities are `cost * (N + 1)^2 + warn * (N + 1) + 1` with N changes in the network, so
the flow is cheapest first, then avoids warn-class changes at equal cost, then fewest.

Sources that reach tier 0 over infinite arcs only cannot be closed by removal; they are
reported with the reason, and treating the node as tier 0 (`[assume] tier0`) is the
suggestion. The order of the cut (bundle greedy) and the budget plan are heuristics and
say so.
"""

from __future__ import annotations

import itertools
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from fractions import Fraction

from . import changes, paths
from .model import Snapshot
from .paths import Graph
from .provenance import Gated, Options, Provenance, fixed_reason
from .whatif import masked, reaching

INF = 1 << 100
GOALS = ("exposure", "all-paths")


class Net:
    """A flow network in arrays; arcs come in pairs (arc, arc ^ 1 = its reverse)."""

    def __init__(self) -> None:
        self.head: list[list[int]] = []
        self.to: list[int] = []
        self.cap: list[int] = []

    def node(self) -> int:
        self.head.append([])
        return len(self.head) - 1

    def arc(self, a: int, b: int, c: int) -> int:
        self.head[a].append(len(self.to))
        self.to.append(b)
        self.cap.append(c)
        self.head[b].append(len(self.to))
        self.to.append(a)
        self.cap.append(0)
        return len(self.to) - 2

    def maxflow(self, s: int, t: int, cap: list[int]) -> int:
        """Dinic, iterative (no recursion: paths can be long). `cap` is changed into the
        residual capacities."""
        head, to = self.head, self.to
        n = len(head)
        flow = 0
        while True:
            level = [-1] * n
            level[s] = 0
            queue = deque([s])
            while queue:
                x = queue.popleft()
                for e in head[x]:
                    if cap[e] > 0 and level[to[e]] < 0:
                        level[to[e]] = level[x] + 1
                        queue.append(to[e])
            if level[t] < 0:
                return flow
            it = [0] * n
            while True:
                stack = [s]
                path: list[int] = []
                while stack and stack[-1] != t:
                    x = stack[-1]
                    while it[x] < len(head[x]):
                        e = head[x][it[x]]
                        y = to[e]
                        if cap[e] > 0 and level[y] == level[x] + 1:
                            stack.append(y)
                            path.append(e)
                            break
                        it[x] += 1
                    else:
                        stack.pop()
                        level[x] = -1  # dead end for this phase
                        if path:
                            path.pop()
                            it[stack[-1]] += 1
                if not stack:
                    break
                push = min(cap[e] for e in path)
                for e in path:
                    cap[e] -= push
                    cap[e ^ 1] += push
                flow += push

    def residual_from(self, s: int, cap: list[int]) -> list[bool]:
        seen = [False] * len(self.head)
        seen[s] = True
        queue = deque([s])
        while queue:
            x = queue.popleft()
            for e in self.head[x]:
                if cap[e] > 0 and not seen[self.to[e]]:
                    seen[self.to[e]] = True
                    queue.append(self.to[e])
        return seen

    def residual_to(self, t: int, cap: list[int]) -> list[bool]:
        seen = [False] * len(self.head)
        seen[t] = True
        queue = deque([t])
        while queue:
            x = queue.popleft()
            for e in self.head[x]:  # e = x -> y; the residual arc y -> x is e ^ 1
                y = self.to[e]
                if cap[e ^ 1] > 0 and not seen[y]:
                    seen[y] = True
                    queue.append(y)
        return seen


@dataclass
class Unclosable:
    node: str
    why: str  # the fixed or kept route, as text
    suggest: str


@dataclass
class Model:
    """The path subgraph as a network, with what is needed to read a cut back."""

    g: Graph
    snap: Snapshot
    prov: Provenance
    tier0: set[str]
    sources: dict[str, int]  # closable source node -> weight (users it stands for)
    unclosable: list[Unclosable]
    sink_like: set[str]
    keeps: dict[int, str]
    net: Net
    s: int
    t: int
    base_cap: list[int]
    prim_arc: dict[int, int]  # change -> its arc
    cost: dict[int, int]
    warn: dict[int, str]
    inexact: int
    scale: int  # (N + 1)
    node_ids: dict[str, int]
    source_arcs: dict[str, int] = field(default_factory=dict)
    # enabled users: (own node, implicit group nodes), for the exposure count
    users: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)

    def prim_cap(self, p: int) -> int:
        n1 = self.scale
        return self.cost[p] * n1 * n1 + (1 if p in self.warn else 0) * n1 + 1


@dataclass
class Step:
    n: int
    title: str
    changes: list[int]
    exposed_after: int
    holders_after: int
    routes_after: int


@dataclass
class Plan:
    goal: str
    near: str
    changes: list[int]  # in step order
    cost: int
    lower_bound: tuple[int, int]  # (changes, cost)
    exact: bool
    inexact: int
    proven: bool
    alternatives: bool
    unclosable: list[Unclosable]
    steps: list[Step]
    before: tuple[int, int, int]  # exposed, holders, routes
    sources: int
    note: str = ""
    method_order: str = "greedy"


def sources_for(
    snap: Snapshot,
    g: Graph,
    goal: str,
    names: Iterable[str] = (),
    excluded: Iterable[str] = (),
) -> dict[str, int]:
    """Source nodes with a weight: for `exposure`, the identity nodes of enabled
    non-tier-0 users (weight = users); for `all-paths`, every AD-PATH-001 holder; with
    names, those principals' nodes. `excluded` holds node IDs left out (accepted
    holders)."""
    skip = set(excluded)
    out: dict[str, int] = {}
    if names:
        for name in names:
            for node in paths.identity_nodes(snap, name)[:1] or [_node_by_name(g, name)]:
                if node and node not in skip:
                    out[node] = out.get(node, 0) + 1
        return out
    if goal == "all-paths":
        found = paths.paths_to_tier0(g)
        for node in paths.direct_holders(g, found):
            if node not in skip:
                out[node] = 1
        return out
    for a in snap.accounts:
        if not a.enabled or a.is_computer or a.managed or not a.sid:
            continue
        own = paths._sid_node(a.sid)
        if own in g.tier0 or own in skip:
            continue
        for node in paths._identity(snap, a):
            if node not in skip:
                out[node] = out.get(node, 0) + 1
    return out


def _node_by_name(g: Graph, name: str) -> str:
    key = name.lower()
    for node, n in g.names.items():
        if n.lower() == key or node.lower() == f"sid:{key}":
            return node
    return ""


def accepted_holders(g: Graph, holders: Iterable[str]) -> set[str]:
    """Nodes whose AD-PATH-001 identity (`Graph.ident`) is accepted: not sources."""
    wanted = {h.lower() for h in holders}
    nodes = set(g.edges) | {d for outs in g.edges.values() for d, _ in outs}
    return {n for n in nodes if g.ident(n).lower() in wanted}


def _instances(prov: Provenance, src: str, i: int, why: int) -> tuple[list[int], int | None]:
    """The changes behind one edge instance (any of them keeps it) and its gate."""
    ex = prov.extra.get((src, i))
    if ex is None:
        return ([] if why < 0 else [why]), None
    if isinstance(ex, Options):
        prims = [p for p, _ in ex.items]
        return ([] if any(p < 0 for p in prims) else prims), None
    assert isinstance(ex, Gated)
    return [ex.prim], ex.gate


def build_model(
    snap: Snapshot,
    g: Graph,
    sources: dict[str, int],
    keeps: dict[int, str] | None = None,
    tier0_extra: Iterable[str] = (),
    removed: Iterable[int] = (),
) -> Model:
    """The network for these sources. `g` is built with provenance; `removed` are
    changes already made (their edges are gone)."""
    prov = g.prov
    assert prov is not None
    keeps = dict(keeps or {})
    view = masked(g, snap, removed, tier0_extra)
    gone = set(removed)
    tier0 = set(view.tier0)
    reach = reaching(view)
    srcs = {s: w for s, w in sources.items() if s in reach}

    # forward from the sources, inside what reaches tier 0, stopping at tier 0
    fwd = set(srcs)
    queue = deque(fwd - tier0)
    while queue:
        x = queue.popleft()
        for v, _ in view.edges.get(x, ()):
            if v in reach and v not in fwd:
                fwd.add(v)
                if v not in tier0:
                    queue.append(v)

    def finite(p: int) -> bool:
        return p not in keeps

    # instances of the subgraph: (u, v, changes, gate, label)
    inst: list[tuple[str, str, list[int], int | None, str]] = []
    for u in sorted(fwd):  # sorted: the network, and so the lower bound, are deterministic
        if u in tier0:
            continue
        why = prov.why[u]
        for i, (v, how) in enumerate(g.edges.get(u, ())):
            if v not in fwd:
                continue
            prims, gate = _instances(prov, u, i, why[i])
            if prims and all(p in gone for p in prims):
                continue
            if gate is not None and not prov.gate_open(gate, gone):
                continue
            inst.append((u, v, [p for p in prims if p not in gone], gate, how))

    # gates: which flags can close each one, as arcs the network can hold
    gates_used = sorted({gt for _, _, _, gt, _ in inst if gt is not None})
    kills = {gi: prov.gate_kills(gi) for gi in gates_used}
    inexact_gates = 0
    gate_plan: dict[int, tuple[list[int], list[int]]] = {}  # gate -> (series, parallel)
    appear: dict[int, int] = {}
    for gi in gates_used:
        for k in kills[gi] or []:
            for f in k:
                appear[f] = appear.get(f, 0) + 1
    for gi in gates_used:
        ks = kills[gi]
        if ks is None:
            gate_plan[gi] = ([], [])
            inexact_gates += 1
            continue
        singles = [next(iter(k)) for k in ks if len(k) == 1]
        multis = [sorted(k) for k in ks if len(k) > 1]
        if len(multis) > 1:
            inexact_gates += 1
            multis = multis[:0]
        group = multis[0] if multis else []
        shared = [f for f in singles if appear.get(f, 0) > 1]
        private = [f for f in singles if appear.get(f, 0) <= 1]
        if (group and shared) or len(shared) > 1:
            inexact_gates += 1  # a shared flag can only end a gate: drop the rest
            shared = shared[:0] if group else shared[:1]
        series = private + shared  # a shared flag last
        gate_plan[gi] = (series, group)
    for gi, (series, group) in gate_plan.items():
        if all(f in keeps for f in series) and (not group or any(f in keeps for f in group)):
            gate_plan[gi] = ([], [])  # cannot close: same as no gate

    def instance_finite(prims: list[int], gate: int | None) -> bool:
        if prims and all(finite(p) for p in prims):
            return True
        if gate is not None:
            series, group = gate_plan[gate]
            return bool(series or group)
        return False

    # nodes that reach tier 0 over infinite edges only: no removal closes them
    rev_inf: dict[str, list[str]] = {}
    route: dict[str, tuple[str, str]] = {}
    for u, v, prims, gate, how in inst:
        if not instance_finite(prims, gate):
            rev_inf.setdefault(v, []).append(u)
            route.setdefault(u, (v, how))
    sink_like = set(tier0)
    queue = deque(t for t in tier0 if t in fwd)
    via: dict[str, tuple[str, str]] = {}
    while queue:
        x = queue.popleft()
        for u in rev_inf.get(x, ()):
            if u not in sink_like:
                sink_like.add(u)
                via[u] = (x, _route_label(g, prov, u, x, keeps))
                queue.append(u)

    unclosable = []
    for node in sorted(sink_like - tier0):
        if node in fwd and view.kind(node) != "scope":  # scope nodes are plumbing
            unclosable.append(_unclosable(view, node, via))
    for node in sorted(srcs):
        if node in tier0:
            unclosable.append(
                Unclosable(
                    node,
                    f"{view.name(node)} is tier 0 and an implicit group of users",
                    "move the users out of that group, or accept it",
                )
            )

    net = Net()
    s, t = net.node(), net.node()
    node_ids: dict[str, int] = {}

    def nid(x: str) -> int:
        if x in sink_like:
            return t
        if x not in node_ids:
            node_ids[x] = net.node()
        return node_ids[x]

    finite_prims = sorted(
        {p for _, _, prims, _, _ in inst for p in prims if finite(p)}
        | {f for series, group in gate_plan.values() for f in series + group if finite(f)}
    )
    cost: dict[int, int] = {}
    warn: dict[int, str] = {}
    ctx = changes.Context(snap)
    for p in finite_prims:
        verdict = changes.assess(snap, prov.prims[p], tier0, ctx)
        cost[p] = verdict.cost
        if verdict.cls == "warn":
            warn[p] = verdict.warning
    scale = len(finite_prims) + 1
    prim_in: dict[int, int] = {}
    prim_out: dict[int, int] = {}
    prim_arc: dict[int, int] = {}

    def split(p: int) -> tuple[int, int]:
        if p not in prim_in:
            prim_in[p], prim_out[p] = net.node(), net.node()
            c = cost[p] * scale * scale + (1 if p in warn else 0) * scale + 1
            prim_arc[p] = net.arc(prim_in[p], prim_out[p], c)
        return prim_in[p], prim_out[p]

    gate_entry: dict[int, int] = {}

    def entry(gi: int) -> int:
        if gi in gate_entry:
            return gate_entry[gi]
        series, group = gate_plan[gi]
        first = net.node()
        gate_entry[gi] = first
        if not series and not group:
            net.arc(first, t, INF)
            return first
        x = first
        for k, f in enumerate(series):
            last = k == len(series) - 1 and not group
            y = t if last else net.node()
            if finite(f):
                fin, fout = split(f)
                net.arc(x, fin, INF)
                net.arc(fout, y, INF)
            else:
                net.arc(x, y, INF)
            x = y
        for f in group:
            if finite(f):
                a, b = split(f)
                net.arc(x, a, INF)
                net.arc(b, t, INF)
            else:
                net.arc(x, t, INF)
        return first

    linked: set[tuple[int, int]] = set()
    src_of: dict[int, set[int]] = {}
    dst_of: dict[int, set[int]] = {}
    for u, v, prims, gate, _ in inst:
        if u in sink_like:
            continue  # part of the sink already
        a = nid(u)
        target = entry(gate) if gate is not None else nid(v)
        if not prims or not all(finite(p) for p in prims):
            net.arc(a, target, INF)
            continue
        for p in prims:
            pin, pout = split(p)
            if (a, pin) not in linked:
                linked.add((a, pin))
                net.arc(a, pin, INF)
            if (pout, target) not in linked:
                linked.add((pout, target))
                net.arc(pout, target, INF)
            src_of.setdefault(p, set()).add(a)
            dst_of.setdefault(p, set()).add(target)
    inexact = sum(1 for p in src_of if len(src_of[p]) > 1 and len(dst_of[p]) > 1)
    inexact += inexact_gates

    closable = {x: w for x, w in srcs.items() if x not in sink_like}
    source_arcs = {}
    for x in sorted(closable):
        source_arcs[x] = net.arc(s, nid(x), INF)
    return Model(
        g,
        snap,
        prov,
        tier0,
        closable,
        unclosable,
        sink_like,
        keeps,
        net,
        s,
        t,
        list(net.cap),
        prim_arc,
        cost,
        warn,
        inexact,
        scale,
        node_ids,
        source_arcs,
        _users(snap),
    )


def _users(snap: Snapshot) -> list[tuple[str, tuple[str, ...]]]:
    """paths.exposure's population: enabled users that are not computers or gMSAs."""
    out = []
    for a in snap.accounts:
        if a.enabled and not a.is_computer and not a.managed and a.sid:
            nodes = paths._identity(snap, a)
            out.append((nodes[0], tuple(nodes[1:])))
    return out


def _route_label(g: Graph, prov: Provenance, u: str, v: str, keeps: dict[int, str]) -> str:
    why = prov.why.get(u)
    for i, (dst, how) in enumerate(g.edges.get(u, ())):
        if dst != v or why is None:
            continue
        w = why[i]
        if w < 0 and (u, i) not in prov.extra:
            return f"{how} (fixed: {fixed_reason(w)})"
        prims, _ = _instances(prov, u, i, w)
        kept = [keeps[p] for p in prims if p in keeps]
        if kept:
            return f"{how} (kept: {kept[0]})"
        return how
    return "?"


def _unclosable(g: Graph, node: str, via: dict[str, tuple[str, str]]) -> Unclosable:
    text, x = g.name(node), node
    for _ in range(50):
        if x not in via:
            break
        x, how = via[x]
        text += f" -[{how}]-> {g.name(x)}"
    return Unclosable(
        node,
        text,
        f"treat {g.name(node)} as tier 0 ([assume] tier0), or move what makes the route",
    )


# -- the cut ----------------------------------------------------------------------------


def min_cut(m: Model, near: str = "tier0") -> tuple[int, list[int]]:
    """(flow, changes) of the minimum cut nearest tier 0 or nearest the sources (each is
    unique, whatever order the flow took)."""
    cap = list(m.base_cap)
    flow = m.net.maxflow(m.s, m.t, cap)
    if near == "source":
        side = m.net.residual_from(m.s, cap)
        cut = [p for p, e in m.prim_arc.items() if side[m.net.to[e ^ 1]] and not side[m.net.to[e]]]
    else:
        side = m.net.residual_to(m.t, cap)
        cut = [p for p, e in m.prim_arc.items() if not side[m.net.to[e ^ 1]] and side[m.net.to[e]]]
    return flow, sorted(cut, key=lambda p: changes.change_id(m.prov.prims[p]))


def decode(m: Model, flow: int) -> int:
    """The cost part of a flow value."""
    return flow // (m.scale * m.scale)


def routes(m: Model, removed: Iterable[int] = ()) -> int:
    """Changes still needed in the model with every change at cost 1: the progress
    measure while exposure does not move."""
    cap = list(m.base_cap)
    gone = set(removed)
    for p, e in m.prim_arc.items():
        cap[e] = 0 if p in gone else 1
    flow = m.net.maxflow(m.s, m.t, cap)
    return flow if flow < INF else -1


def closes(m: Model, removed: Iterable[int]) -> bool:
    """Whether the changes close every closable source in the masked graph (exact, no
    network)."""
    view = masked(m.g, m.snap, removed, m.tier0 - m.g.tier0)
    reach = _reach_to(view, m.sink_like)
    return not any(s in reach for s in m.sources)


def _reach_to(g: Graph, targets: set[str]) -> set[str]:
    reverse: dict[str, list[str]] = {}
    for src, outs in g.edges.items():
        if src in targets:
            continue
        for dst, _ in outs:
            reverse.setdefault(dst, []).append(src)
    seen = set(targets)
    queue = deque(targets)
    while queue:
        x = queue.popleft()
        for src in reverse.get(x, ()):
            if src not in seen:
                seen.add(src)
                queue.append(src)
    return seen


def prune(m: Model, cut: list[int]) -> list[int]:
    """Reverse delete: drop each change (dearest first) whose removal is not needed."""
    keep = list(cut)
    for p in sorted(cut, key=lambda p: (-m.cost[p], changes.change_id(m.prov.prims[p]))):
        trial = [q for q in keep if q != p]
        if closes(m, trial):
            keep = trial
    return keep


def lower_bound(m: Model, limit: int = 2000) -> tuple[int, int]:
    """(changes, cost) that any closing set needs: greedy paths from the sources whose
    changes are pairwise disjoint; each needs a change of its own."""
    g, prov = m.g, m.prov
    adj: dict[str, list[tuple[str, frozenset[int]]]] = {}
    for u in m.node_ids:
        why = prov.why.get(u)
        if why is None:
            continue
        pairs: dict[str, set[int]] = {}
        blocked: set[str] = set()
        for i, (v, _) in enumerate(g.edges.get(u, ())):
            if v not in m.node_ids and v not in m.sink_like:
                continue
            prims, gate = _instances(prov, u, i, why[i])
            touch = set(prims)
            if gate is not None:
                touch |= set(prov.gates[gate].flags)
            finite_touch = {p for p in touch if p not in m.keeps}
            if not finite_touch:
                blocked.add(v)  # cannot be broken: counts as fixed
            pairs.setdefault(v, set()).update(finite_touch)
        adj[u] = [(v, frozenset() if v in blocked else frozenset(t)) for v, t in pairs.items()]
    used: set[int] = set()
    count = cost = 0
    for _ in range(limit):
        prev: dict[str, tuple[str, frozenset[int]] | None] = {}
        queue: deque[str] = deque()
        for s in sorted(m.sources):
            prev[s] = None
            queue.append(s)
        end = None
        while queue and end is None:
            x = queue.popleft()
            for v, edge_touch in adj.get(x, ()):
                if v in prev or edge_touch & used:
                    continue
                prev[v] = (x, edge_touch)
                if v in m.sink_like:
                    end = v
                    break
                queue.append(v)
        if end is None:
            break
        touches: list[frozenset[int]] = []
        x = end
        step = prev[x]
        while step is not None:
            touches.append(step[1])
            x = step[0]
            step = prev[x]
        breakable = [t for t in touches if t]
        if not breakable:
            break  # unclosable route (should not happen: sink_like covers it)
        cheapest = min(min(m.cost.get(q, changes.WARN_COST) for q in t) for t in breakable)
        for t in touches:
            used |= t
        count += 1
        cost += cheapest
    return count, cost


# -- evaluation and ordering --------------------------------------------------------------


@dataclass(frozen=True)
class Numbers:
    exposed: int
    holders: int
    routes: int


def numbers(m: Model, removed: Iterable[int]) -> Numbers:
    """Exposure, holders and routes after the changes (exact, on the masked graph)."""
    gone = list(removed)
    view = masked(m.g, m.snap, gone, m.tier0 - m.g.tier0)
    reach = reaching(view)
    exposed = 0
    for own, implicit in m.users:
        if own in view.tier0:
            continue
        if own in reach or any(n in reach for n in implicit):
            exposed += 1
    holders = 0
    for node in reach:
        if node in view.tier0 or not node.startswith("sid:"):
            continue
        if any(how != "member of" and dst in reach for dst, how in view.edges.get(node, ())):
            holders += 1
    return Numbers(exposed, holders, routes(m, gone))


def _bundle(m: Model, start: str, allowed: set[int], applied: set[int]) -> list[int]:
    """The cheapest changes among `allowed` that cut `start` off tier 0 (empty when
    they cannot)."""
    if start not in m.node_ids:
        return []
    cap = list(m.base_cap)
    for p, e in m.prim_arc.items():
        cap[e] = 0 if p in applied else (m.prim_cap(p) if p in allowed else INF)
    for arc in m.source_arcs.values():
        cap[arc] = 0
    a = m.net.arc(m.s, m.node_ids[start], INF)
    cap += [INF, 0]
    try:
        flow = m.net.maxflow(m.s, m.t, cap)
        if flow >= INF:
            return []
        side = m.net.residual_to(m.t, cap)
        return sorted(
            p
            for p, e in m.prim_arc.items()
            if not side[m.net.to[e ^ 1]] and side[m.net.to[e]] and p not in applied
        )
    finally:  # drop the temporary arc again
        m.net.head[m.s].pop()
        m.net.head[m.node_ids[start]].pop()
        del m.net.to[a:], m.net.cap[a:]


def _credit(m: Model, applied: list[int]) -> list[str]:
    """Nodes on the most shortest paths of sources (weighted by users) and holders."""
    view = masked(m.g, m.snap, applied, m.tier0 - m.g.tier0)
    found = paths.paths_to_tier0(view)
    credit: dict[str, int] = {}
    starts = dict(m.sources)
    for node in paths.direct_holders(view, found):
        starts[node] = starts.get(node, 0) + 1
    for node, weight in starts.items():
        p = found.get(node)
        if p is None:
            continue
        for x in [node, *(n for n, _ in p.steps)]:
            if x in m.sink_like:
                break
            credit[x] = credit.get(x, 0) + weight
    return [x for x, _ in sorted(credit.items(), key=lambda kv: (-kv[1], kv[0]))]


def _pool(m: Model, ranked: list[str], size: int = 200) -> set[int]:
    """Budget candidates: the changes behind the edges out of the nodes most paths run
    through, in that order."""
    out: list[int] = []
    for node in ranked:
        why = m.prov.why.get(node)
        if why is None:
            continue
        for i in range(len(why)):
            prims, _ = _instances(m.prov, node, i, why[i])
            out += [p for p in prims if p in m.prim_arc and p not in out]
        if len(out) >= size:
            break
    return set(out[:size])


def _key(m: Model, chosen: list[int]) -> tuple[int, int, list[str]]:
    kinds = [changes.KIND_ORDER.index(m.prov.prims[p][0]) for p in chosen]
    ids = sorted(changes.change_id(m.prov.prims[p]) for p in chosen)
    return len(chosen), min(kinds), ids


def order(
    m: Model, plan: list[int], top: int = 20, budget: int | None = None
) -> tuple[list[Step], str]:
    """Bundle greedy (a heuristic): repeatedly take the candidate that clears the most
    users per cost, then holders, then routes. Candidates are each remaining change and,
    for the `top` nodes most paths run through, the cheapest bundle that cuts that node
    off. With `budget`, candidates come from every change in the network and the loop
    stops at the budget."""
    applied: list[int] = []
    remaining = list(plan)
    current = numbers(m, applied)
    steps: list[Step] = []
    note = ""
    while remaining if budget is None else len(applied) < budget:
        last = budget is None and len(remaining) == 1
        ranked = [] if last else _credit(m, applied)
        if budget is None:
            singles = set(remaining)
            bundle_from = set(remaining)
        else:
            singles = (set(plan) | _pool(m, ranked)) - set(applied)
            bundle_from = set(m.prim_arc) - set(applied)
        cands: dict[tuple[int, ...], list[int]] = {(p,): [p] for p in sorted(singles)}
        if len(cands) > 1 or budget is not None:
            for v in ranked[:top]:
                bundle = _bundle(m, v, bundle_from, set(applied))
                if bundle:
                    cands.setdefault(tuple(bundle), bundle)
        best: tuple[tuple[Fraction, Fraction, Fraction], list[int], Numbers] | None = None
        for chosen in cands.values():
            if budget is not None and len(applied) + len(chosen) > budget:
                continue
            after = numbers(m, applied + chosen)
            c = sum(m.cost[p] for p in chosen)
            score = (
                Fraction(current.exposed - after.exposed, c),
                Fraction(current.holders - after.holders, c),
                Fraction(current.routes - after.routes, c),
            )
            if best is None or _better(m, score, chosen, best[0], best[1]):
                best = (score, chosen, after)
        if best is None:
            break
        if budget is not None and best[0] == (Fraction(0), Fraction(0), Fraction(0)):
            # nothing clears anyone within the budget: fall back to the cut, in order
            fallback = [p for p in plan if p not in applied][: budget - len(applied)]
            if not fallback:
                break
            best = ((Fraction(0),) * 3, fallback, numbers(m, applied + fallback))
            note = "no candidate within the budget clears anything; the cut is used, truncated"
        _, chosen, after = best
        applied += chosen
        remaining = [p for p in remaining if p not in chosen]
        steps.append(
            Step(
                len(steps) + 1,
                _title(m, chosen),
                chosen,
                after.exposed,
                after.holders,
                after.routes,
            )
        )
        current = after
        if budget is None and not remaining:
            break
    return steps, note


def _better(
    m: Model,
    score: tuple[Fraction, Fraction, Fraction],
    chosen: list[int],
    best_score: tuple[Fraction, Fraction, Fraction],
    best: list[int],
) -> bool:
    if score != best_score:
        return score > best_score
    return _key(m, chosen) < _key(m, best)


def _title(m: Model, chosen: list[int]) -> str:
    if len(chosen) == 1:
        return label(m.snap, m.prov.prims[chosen[0]])
    return f"{len(chosen)} changes"


def label(snap: Snapshot, prim: tuple[str, ...]) -> str:
    """A short description of a change for people."""
    f = changes.fields(prim)
    kind = f["kind"]

    def rdn(field_name: str) -> str:
        return f[field_name].split(",", 1)[0].split("=", 1)[-1]

    def who(field_name: str) -> str:
        return snap.name_of(f[field_name])

    if kind in ("ace", "inherited-ace"):
        what = "inheritable ACEs" if kind == "inherited-ace" else "ACEs"
        return f"remove the {what} of {who('trustee')} on {rdn('object')}"
    if kind == "adminsdholder-ace":
        return f"remove the ACEs of {who('trustee')} on AdminSDHolder"
    if kind == "owner":
        return f"give {rdn('object')} a tier-0 owner"
    if kind == "member":
        return f"remove {rdn('member')} from {rdn('group')}"
    if kind == "gplink":
        return f"unlink GPO {f['gpo']} from {rdn('container')}"
    if kind == "gpo-entry":
        return f"remove {who('member')} from {who('group')} in GPO {f['gpo']}"
    if kind == "template-ace":
        return f"remove the ACEs of {who('trustee')} on template {f['template']}"
    if kind == "template-flag":
        return f"template {f['template']}: turn off {f['flag']}"
    if kind == "pki-ace":
        return f"remove the ACEs of {who('trustee')} on {f['object']}"
    if kind == "ca-right":
        return f"remove {f['right']} of {who('trustee')} on CA {f['ca']}"
    if kind == "gmsa-reader":
        return f"remove {who('reader')} from the password readers of {rdn('gmsa')}"
    return f"remove {f['what']} delegation of {rdn('account')}"


# -- the whole reverse what-if -------------------------------------------------------------


def plan(
    snap: Snapshot,
    g: Graph,
    goal: str = "exposure",
    near: str = "tier0",
    names: Iterable[str] = (),
    keeps: dict[int, str] | None = None,
    allow: Iterable[str] = (),
    tier0_extra: Iterable[str] = (),
    accepted: Iterable[str] = (),
    max_changes: int | None = None,
) -> Plan:
    """The cheapest closing set for the goal, pruned, with its lower bound and an order
    (heuristic). `g` is built with provenance."""
    prov = g.prov
    assert prov is not None
    allowed = set(allow)
    all_keeps = {} if "warn" in allowed else changes.default_keeps(snap, prov)
    all_keeps.update(keeps or {})
    extra = set(tier0_extra)
    view = masked(g, snap, (), extra)
    srcs = sources_for(snap, view, goal, names, accepted_holders(g, accepted))
    m = build_model(snap, g, srcs, all_keeps, extra)
    _, cut = min_cut(m, near)
    _, other = min_cut(m, "source" if near == "tier0" else "tier0")
    alternatives = sorted(other) != sorted(cut)
    cut = prune(m, cut)
    lb = lower_bound(m)
    cost = sum(m.cost[p] for p in cut)
    exact = m.inexact == 0
    proven = exact or cost == lb[1]
    before = numbers(m, [])
    if max_changes is None:
        steps, note = order(m, cut)
        chosen = [p for s in steps for p in s.changes]
    else:
        steps, note = order(m, cut, budget=max_changes)
        chosen = [p for s in steps for p in s.changes]
        note = (note + "; " if note else "") + "heuristic: no guarantee"
    return Plan(
        goal,
        near,
        chosen,
        cost if max_changes is None else sum(m.cost[p] for p in chosen),
        lb,
        exact,
        m.inexact,
        proven and max_changes is None,
        alternatives,
        m.unclosable,
        steps,
        (before.exposed, before.holders, before.routes),
        len(m.sources),
        note,
    )


def brute_force_minimum(
    m: Model, candidates: list[int], max_size: int = 5
) -> tuple[int, list[int]] | None:
    """For tests: the cheapest closing set among subsets of `candidates` up to
    `max_size` (cost, changes), checked on the masked graph."""
    best: tuple[int, list[int]] | None = None
    for size in range(0, max_size + 1):
        for combo in itertools.combinations(candidates, size):
            c = sum(m.cost[p] for p in combo)
            if best is not None and c >= best[0]:
                continue
            if closes(m, combo):
                best = (c, list(combo))
    return best
