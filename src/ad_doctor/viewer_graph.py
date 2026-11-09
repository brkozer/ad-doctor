"""The control graph for the viewer's Blast radius screen (`ad-doctor view --graph`).

- `full`: the whole graph in compact form (a node table, out-degrees and parallel
  integer edge arrays, edge labels as indexes into a label table) plus every account, so
  the page runs the same breadth-first search as `paths.reachable` for any account. The
  JavaScript port is checked against Python's output by Node tests.
- `paths`: for large domains. No graph; the blast radius is computed here for the
  principals that hold a right on a control path and for the accounts given with
  `--blast-radius-for`, and the page shows those.
- `none`: neither.

In `full` mode `whatif_model` adds what the page needs to evaluate a set of removals.

`auto` picks `full` up to FULL_GRAPH_OBJECTS directory objects and `paths` above.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterable
from typing import Any

from . import changes, checks, cut, paths, whatif
from .model import Snapshot
from .provenance import FACT_GATES, FIXED_REASONS, Options, Provenance

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


# -- what-if in the page -------------------------------------------------------------------


def _deltas(values: Iterable[int]) -> list[int]:
    out, last = [], 0
    for value in values:
        out.append(value - last)
        last = value
    return out


def prim_numbers(g: paths.Graph) -> dict[int, int]:
    """Provenance primitive -> the page's number for it: by first appearance in the compact
    edge order, then the primitives no edge names (gate facts, logon edges). The `prim`
    array of the model then is mostly "the next new one", which packs to almost nothing."""
    prov = g.prov
    assert prov is not None
    numbers: dict[int, int] = {}
    for node in nodes_of(g):
        for p in prov.why.get(node, ()):
            if p >= 0:
                numbers.setdefault(p, len(numbers))
    for p in range(len(prov.prims)):
        numbers.setdefault(p, len(numbers))
    return numbers


def _gates(prov: Provenance, numbers: dict[int, int]) -> list[list[Any]]:
    """Each gate as [kind, template, flags]; a flag is [number, template, flag], the last
    two empty for a fact that is no template flag (a CA flag, a policy link, a delegation)."""
    gates = []
    for gate in prov.gates:
        flags: list[list[Any]] = []
        for p in gate.flags:
            key = prov.prims[p]
            is_flag = key[0] == "template-flag"
            flags.append([numbers[p], key[1] if is_flag else None, key[2] if is_flag else None])
        template = "" if gate.kind in FACT_GATES else gate.template
        gates.append([gate.kind, template, flags])
    return gates


def _tier0_model(
    g: paths.Graph,
    snap: Snapshot,
    prov: Provenance,
    index: dict[str, int],
    numbers: dict[int, int],
    base: dict[str, int],
) -> dict[str, Any]:
    """What whatif._tier0 reads: the nodes no membership or CA right decides, the ESC7
    edges that keep a CA node in tier 0, and the privileged lists with the group chains
    behind them (changes.privileged_without). Member and group DNs are small numbers:
    groups first, so a number below len(groups) is a group."""
    fixed_names = [n for n in g.names if n.startswith("tier0:") and not n.startswith("tier0:ca:")]
    fixed = paths.tier0_nodes(
        snap, prov.node_of, prov.domain_node, [], fixed_names, snap.tier0_dns({})
    )
    groups = {o.dn.lower(): o for o in snap.objects if o.kind == "group"}
    by_sid = {o.sid: o.dn.lower() for o in groups.values() if o.sid}

    def root_of(name: str) -> str | None:
        sid = changes.PRIVILEGED_BUILTIN.get(name)
        if name in changes.PRIVILEGED_RIDS:
            sid = f"{snap.domain_sid}-{changes.PRIVILEGED_RIDS[name]}"
        return by_sid.get(sid or "")

    order: dict[str, int] = {}
    stack = [r for r in map(root_of, snap.privileged) if r is not None]
    for top in stack:
        order.setdefault(top, len(order))
    while stack:
        for m in groups[stack.pop()].members:
            key = m.lower()
            if key in groups and key not in order:
                order[key] = len(order)
                stack.append(key)
    dn_ids = dict(order)
    for dn in order:
        for m in groups[dn].members:
            dn_ids.setdefault(m.lower(), len(dn_ids))
    lists = []
    for name, dns in snap.privileged.items():
        root = root_of(name)
        rids = {changes.PRIVILEGED_RIDS[name]} if name in changes.PRIVILEGED_RIDS else set()
        if name == "Administrators":
            rids = set(changes.PRIVILEGED_RIDS.values())
        hidden = {
            a.dn.lower() for a in snap.accounts if not a.is_computer and a.primary_group in rids
        }
        rows = [
            [index[prov.node_of(d)], dn_ids.get(d.lower(), -1), int(d.lower() in hidden)]
            for d in dns
        ]
        lists.append([order[root] if root is not None else -1, rows])
    pairs = []
    for p, prim in enumerate(prov.prims):
        if prim[0] == "member" and prim[1] in order and prim[2] in dn_ids:
            pairs.append([numbers[p], order[prim[1]], dn_ids[prim[2]]])
    return {
        "fixed": sorted(index[n] for n in fixed),
        "groups": [[dn_ids[m.lower()] for m in groups[dn].members] for dn in order],
        "pairs": pairs,
        "lists": lists,
        "ca": [[base[src] + i, index[dst]] for src, i, dst in prov.ca_edges],
        "kinds": sorted(whatif.CA_KINDS),
    }


def _offered(g: paths.Graph, edges: Iterable[tuple[str, str]]) -> set[int]:
    """The primitives behind these edges (source, target; parallel ones too): the page can
    add a change from a path it shows, so those are the ones it has to name."""
    prov = g.prov
    assert prov is not None
    out: set[int] = set()
    for src, target in set(edges):
        for i, (dst, _) in enumerate(g.edges.get(src, ())):
            if dst != target:
                continue
            ex = prov.extra.get((src, i))
            if isinstance(ex, Options):
                out.update(p for p, _ in ex.items if p >= 0)
            elif ex is not None:
                out.add(ex.prim)
            elif prov.why[src][i] >= 0:
                out.add(prov.why[src][i])
    return out


def _rebuild_reason(prov: Provenance, p: int) -> str:
    """Why the page cannot evaluate this change (Provenance.needs_rebuild), or ""."""
    if not prov.needs_rebuild(p):
        return ""
    if prov.scope_sensitive(p):
        return "it can move GPO scope"
    if prov.prims[p][1] in prov.condition_groups:
        return "it decides whether a delegation edge exists"
    return "it can take a CA right holder out of tier 0, which adds an edge"


def _change_rows(
    g: paths.Graph,
    snap: Snapshot,
    numbers: dict[int, int],
    wanted: Iterable[int],
    tier0: set[str],
) -> list[list[Any]]:
    """[number, change ID, identity values, label, cost, warning, why it needs a rebuild] of
    the changes on the page's paths and in its plan. Only these: at 10,000 users a row
    for every primitive would cost more than the rest of the model."""
    prov = g.prov
    assert prov is not None
    where = changes.Where(snap, prov)
    ctx = changes.Context(snap)
    keeps = changes.default_keeps(snap, prov)
    rows = []
    for p in sorted(wanted, key=numbers.__getitem__):
        key = prov.prims[p]
        verdict = changes.assess(snap, key, tier0, ctx)
        warning = keeps.get(p, "") or (verdict.warning if verdict.cls == "warn" else "")
        label = changes.describe(snap, key, where)
        cid = changes.change_id(key)
        rows.append(
            [numbers[p], cid, list(key[1:]), label, verdict.cost, warning, _rebuild_reason(prov, p)]
        )
    return rows


def _flow(
    snap: Snapshot,
    g: paths.Graph,
    view: paths.Graph,
    numbers: dict[int, int],
    extra: list[str],
    goal: str,
) -> dict[str, Any]:
    """The network behind `routes` (cut.build_model with `whatif`'s default keeps). arcs:
    the forward arcs in runs by source, [source delta, count, target deltas...]. prim:
    [pin delta, number] per change, in order of pin; a change is the arc pin -> pin + 1.
    dropped: the changes it has no arc for (cut.routes builds a new network for those; the
    page does not)."""
    prov = g.prov
    assert prov is not None
    sources = cut.sources_for(snap, view, goal)
    m = cut.build_model(snap, g, sources, changes.default_keeps(snap, prov), extra)
    to = m.net.to
    pairs = sorted((to[i + 1], to[i]) for i in range(0, len(to), 2))
    arcs: list[int] = []
    last_src = 0
    at = 0
    while at < len(pairs):
        src = pairs[at][0]
        end = at
        while end < len(pairs) and pairs[end][0] == src:
            end += 1
        arcs += [src - last_src, end - at, *_deltas(b for _, b in pairs[at:end])]
        last_src, at = src, end
    pins = sorted((to[e + 1], numbers[p]) for p, e in m.prim_arc.items())
    assert all(to[e] == to[e + 1] + 1 for e in m.prim_arc.values())
    prim: list[int] = []
    last = 0
    for pin, num in pins:
        prim += [pin - last, num]
        last = pin
    return {
        "n": len(m.net.head),
        "s": m.s,
        "t": m.t,
        "arcs": arcs,
        "prim": prim,
        "dropped": sorted(numbers[p] for p in m.dropped),
    }


def whatif_model(
    g: paths.Graph,
    snap: Snapshot,
    data: dict[str, Any],
    plan_ids: Iterable[str] = (),
    assume: Iterable[str] = (),
    goal: str = "exposure",
    path_edges: Iterable[tuple[str, str]] = (),
) -> dict[str, Any]:
    """What the page needs to evaluate a set of removals (`g` built with provenance, `data`
    its compact form, whose label table gains the labels an edge falls back to). core.js
    ports whatif.masked and the state of AD-PATH-001 over this; the Node tests compare it
    with Python for every fixture. Primitives are numbers; `changes` names the ones behind
    `path_edges` (the steps of the paths the page shows) and in the plan. `assume` holds the
    nodes a plan treats as tier 0.

    - prim: per edge, -1 - reason for a fixed edge, 0 for the next new primitive, else
      1 + an earlier primitive. options and gated hold the edges with more than one
      reason, gates what closes those.
    - order: the sources that can reach tier 0, each with the add order (paths.build's) of
      the edges that can become its first. Only that order decides ties in the reverse
      search, and a source that cannot reach tier 0 before a removal cannot after one.
    - rebuild: primitives the mask does not model (Provenance.needs_rebuild); the page
      sends those to the command line and shows no number for them.
    - changes, fields: what the page shows of a change and writes to a plan file.
    - net: the flow network the routes number comes from (`goal` picks its sources).
    """
    prov = g.prov
    assert prov is not None
    order = nodes_of(g)
    index = {n: i for i, n in enumerate(order)}
    numbers = prim_numbers(g)
    extra = [n for n in dict.fromkeys(assume) if n in index]
    view = whatif.masked(g, snap, (), extra)
    base: dict[str, int] = {}
    total = 0
    prim: list[int] = []
    fresh = 0
    for node in order:
        base[node] = total
        total += len(g.edges.get(node, ()))
        for why in prov.why.get(node, ()):
            if why < 0:
                prim.append(why)
            elif numbers[why] == fresh:
                prim.append(0)
                fresh += 1
            else:
                prim.append(numbers[why] + 1)

    labels = {text: i for i, text in enumerate(data["labels"])}

    def label_of(src: str, dst: str, how: str) -> int:
        text = paths.edge_text(g, src, dst, how)
        if text not in labels:
            labels[text] = len(data["labels"])
            data["labels"].append(text)
        return labels[text]

    options: list[list[Any]] = []
    gated: list[list[int]] = []
    for (src, i), ex in sorted(prov.extra.items(), key=lambda item: base[item[0][0]] + item[0][1]):
        edge = base[src] + i
        if isinstance(ex, Options):
            dst = g.edges[src][i][0]
            options.append(
                [edge, [[numbers[p] if p >= 0 else p, label_of(src, dst, h)] for p, h in ex.items]]
            )
        else:
            gated.append([edge, numbers[ex.prim], ex.gate])

    reach = whatif.reaching(view)
    seq: list[int] = []
    last = 0
    for i, node in enumerate(order):
        if node not in reach or node not in g.edges:
            continue
        why_of = prov.why[node]
        count = 1
        while count < len(why_of) and (why_of[count - 1] >= 0 or (node, count - 1) in prov.extra):
            count += 1
        seq += [i - last, count, *_deltas(prov.seq[node][:count])]
        last = i

    kinds: dict[str, int] = {}
    prim_kind = [0] * len(prov.prims)
    for p, key in enumerate(prov.prims):
        prim_kind[numbers[p]] = kinds.setdefault(key[0], len(kinds))
    wanted = set(plan_ids)
    plan = {}
    named = _offered(g, path_edges)
    if wanted:
        for p, key in enumerate(prov.prims):
            cid = changes.change_id(key)
            if cid in wanted:
                plan[cid] = numbers[p]
                named.add(p)
    rows = _change_rows(g, snap, numbers, named, set(view.tier0))
    return {
        "prim": prim,
        "prim_kind": prim_kind,
        "kinds": list(kinds),
        "rebuild": _deltas(
            sorted(numbers[p] for p in range(len(prov.prims)) if prov.needs_rebuild(p))
        ),
        "options": options,
        "gated": gated,
        "gates": _gates(prov, numbers),
        "templates": {
            name: [
                f.published,
                f.enrollee_supplies_subject,
                f.manager_approval,
                f.authorized_signatures,
                list(f.ekus),
            ]
            for name, f in prov.templates.items()
        }
        if prov.gates
        else {},
        "eku": {
            "any": checks.EKU_ANY,
            "agent": checks.EKU_REQUEST_AGENT,
            "client": sorted(checks.EKU_CLIENT_AUTH),
        },
        "seq": seq,
        "not_sid": _deltas(i for i, n in enumerate(order) if not n.startswith("sid:")),
        "tier0": _tier0_model(g, snap, prov, index, numbers, base),
        "plan": plan,
        "fixed": list(FIXED_REASONS),
        "fields": {kind: list(names) for kind, names in changes.FIELDS.items()},
        "changes": rows,
        "net": _flow(snap, g, view, numbers, extra, goal),
        "goal": goal,
        "assume": [[index[n], n] for n in extra],
        "path_nodes": [],
    }
