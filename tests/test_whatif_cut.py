"""What-if, reverse: the minimum cut against brute force on small graphs, its exactness
condition, the lower bound, keeps, warn class, unclosable sources, ordering, determinism."""

from __future__ import annotations

import itertools
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from ad_doctor import changes, cut, paths, whatif
from ad_doctor.model import Snapshot
from ad_doctor.provenance import FIXED, Provenance

from .test_checks import snapshot
from .test_round3 import path_snapshot
from .test_round4 import entra_snapshot
from .whatif_fixtures import kitchen_sink, lab_snapshots, load, rebuilt

DOM = "S-1-5-21-9-9-9"
CERT_PUBLISHERS = f"{DOM}-517"  # a warn-class trustee


def toy(
    edges: list[tuple[str, str, object]], tier0: set[str], order_seed: int | None = None
) -> tuple[Snapshot, paths.Graph]:
    """A hand-made graph with provenance. An edge's reason is a change name (an `ace`
    change of that name, cost 1; names starting with "W" are warn class, "G" a gplink
    with cost 3) or None for a fixed edge."""
    snap = snapshot(domain_sid=DOM)
    prov = Provenance(snap, lambda dn: f"dn:{dn.lower()}", "dn:dc=lab,dc=test")
    items = list(edges)
    if order_seed is not None:
        random.Random(order_seed).shuffle(items)
    g = paths.Graph({}, {}, set(tier0), prov=prov)
    for src, dst, why in items:
        g.edges.setdefault(src, []).append((dst, f"e {src}->{dst}"))
        if why is None:
            prov.push(src, FIXED["contains"])
        elif str(why).startswith("G"):
            prov.push(src, prov.prim(("gplink", "{G}", str(why).lower())))
        elif str(why).startswith("W"):
            prov.push(src, prov.prim(("ace", f"cn={why}", CERT_PUBLISHERS)))
        else:
            prov.push(src, prov.prim(("ace", f"cn={why}", f"{DOM}-1000")))
    return snap, g


def model(snap: Snapshot, g: paths.Graph, sources: list[str], **kw: object) -> cut.Model:
    return cut.build_model(snap, g, {s: 1 for s in sources}, **kw)  # type: ignore[arg-type]


def names(g: paths.Graph, prims: list[int]) -> list[str]:
    assert g.prov is not None
    return sorted(g.prov.prims[p][1] for p in prims)


def random_case(seed: int) -> tuple[list[tuple[str, str, object]], set[str], list[str]]:
    rng = random.Random(seed)
    nodes = [f"n{i}" for i in range(rng.randint(5, 9))]
    tier0 = {"T0", "T1"} if rng.random() < 0.5 else {"T0"}
    edges: list[tuple[str, str, object]] = []
    changes_by_src: dict[str, list[str]] = {}
    count = 0
    for _ in range(rng.randint(8, 16)):
        u = rng.choice(nodes)
        v = rng.choice(nodes + sorted(tier0) * 2)
        if u == v:
            continue
        r = rng.random()
        if r < 0.15:
            why: object = None
        elif r < 0.35 and changes_by_src.get(u):
            why = rng.choice(changes_by_src[u])  # one change, several edges, one source
        elif count < 12:
            count += 1
            prefix = "W" if rng.random() < 0.1 else "G" if rng.random() < 0.1 else "c"
            why = f"{prefix}{count}"
            changes_by_src.setdefault(u, []).append(str(why))
        else:
            why = None
        edges.append((u, v, why))
    sources = rng.sample(nodes, rng.randint(1, 3))
    return edges, tier0, sources


def true_minimum(m: cut.Model) -> tuple[int, int] | None:
    """(cost, changes) of the cheapest closing set, over every subset."""
    cands = sorted(m.prim_arc)
    best: tuple[int, int] | None = None
    for size in range(len(cands) + 1):
        for combo in itertools.combinations(cands, size):
            c = (sum(m.cost[p] for p in combo), size)
            if (best is None or c < best) and cut.closes(m, combo):
                best = c
    return best


@pytest.mark.parametrize("seed", range(80))
def test_cut_matches_brute_force(seed: int) -> None:
    edges, tier0, sources = random_case(seed)
    snap, g = toy(edges, tier0)
    m = model(snap, g, sources)
    flow, chosen = cut.min_cut(m)
    best = true_minimum(m)
    assert best is not None
    cost = sum(m.cost[p] for p in chosen)
    assert cut.closes(m, chosen)
    lb = cut.lower_bound(m)
    assert lb[1] <= best[0] <= cost
    assert lb[0] <= best[1]
    if m.inexact == 0:
        assert cut.decode(m, flow) == best[0] == cost
        assert len(chosen) == best[1]
    pruned = cut.prune(m, chosen)
    assert cut.closes(m, pruned)
    assert set(pruned) <= set(chosen)
    for near in ("tier0", "source"):
        assert cut.closes(m, cut.min_cut(m, near)[1])


@pytest.mark.parametrize("seed", range(20))
def test_cut_does_not_depend_on_edge_order(seed: int) -> None:
    edges, tier0, sources = random_case(seed)
    found = set()
    for order in (None, 1, 2, 3):
        snap, g = toy(edges, tier0, order)
        found.add(tuple(names(g, cut.min_cut(model(snap, g, sources))[1])))
    assert len(found) == 1


def test_change_with_several_sources_and_targets_is_inexact() -> None:
    # c1 makes a->x and b->y: node splitting joins a to y, a route that does not exist
    edges: list[tuple[str, str, object]] = [
        ("a", "x", "c1"),
        ("b", "y", "c1"),
        ("x", "T0", "c2"),
        ("y", "T0", "c3"),
    ]
    snap, g = toy(edges, {"T0"})
    m = model(snap, g, ["a", "b"])
    assert m.inexact == 1
    p = cut.plan(snap, g, names=())  # sources from users: none here
    assert p.changes == []
    _, chosen = cut.min_cut(m)
    assert cut.closes(m, chosen)
    best = true_minimum(m)
    assert best is not None and best[0] <= sum(m.cost[q] for q in chosen)


def test_shared_target_or_source_stays_exact() -> None:
    edges: list[tuple[str, str, object]] = [
        ("a", "T0", "c1"),
        ("b", "T0", "c1"),  # one target (tier 0)
        ("a", "x", "c2"),
        ("a", "y", "c2"),  # one source
        ("x", "T0", None),
        ("y", "T0", None),
    ]
    snap, g = toy(edges, {"T0"})
    assert model(snap, g, ["a", "b"]).inexact == 0


def test_keeps_and_fixed_edges_are_never_cut() -> None:
    edges: list[tuple[str, str, object]] = [
        ("s", "x", "c1"),
        ("x", "T0", "c2"),
        ("s", "y", None),
        ("y", "T0", "c3"),
    ]
    snap, g = toy(edges, {"T0"})
    assert g.prov is not None
    c2 = g.prov.lookup(("ace", "cn=c2", f"{DOM}-1000"))
    assert c2 is not None
    m = model(snap, g, ["s"], keeps={c2: "needed"})
    _, chosen = cut.min_cut(m)
    assert names(g, chosen) == ["cn=c1", "cn=c3"]


def test_warn_only_without_an_equal_cost_alternative() -> None:
    # s -> x by a warn change (cost 10), x -> T0 by ten changes of cost 1
    ten: list[tuple[str, str, object]] = [("x", f"t{i}", f"c{i}") for i in range(10)]
    ten += [(f"t{i}", "T0", None) for i in range(10)]
    snap, g = toy([("s", "x", "W1"), *ten], {"T0"})
    _, chosen = cut.min_cut(model(snap, g, ["s"]))
    assert len(chosen) == 10  # equal cost: the warn change is avoided
    snap, g = toy([("s", "x", "W1"), *ten, ("x", "t0", "c99")], {"T0"})
    _, chosen = cut.min_cut(model(snap, g, ["s"]))
    assert names(g, chosen) == ["cn=W1"]  # now it is the cheapest


def test_unclosable_sources_are_reported_not_cut() -> None:
    edges: list[tuple[str, str, object]] = [("s", "T0", None), ("u", "T0", "c1")]
    snap, g = toy(edges, {"T0"})
    m = model(snap, g, ["s", "u"])
    assert [x.node for x in m.unclosable] == ["s"]
    assert "fixed" in m.unclosable[0].why and "tier 0" in m.unclosable[0].suggest
    assert names(g, cut.min_cut(m)[1]) == ["cn=c1"]


def test_tier0_assumption_closes_at_the_assumed_node() -> None:
    snap = entra_snapshot(helpdesk_reset=True)
    g = paths.build(snap, provenance=True)
    plain = cut.plan(snap, g, goal="all-paths")
    assert any("MSOL" in u.why for u in plain.unclosable)
    server = "sid:S-1-5-21-1-2-3-1401"
    assumed = cut.plan(snap, g, goal="all-paths", tier0_extra=[server])
    assert all(u.node != server for u in assumed.unclosable)


def test_plan_closes_the_path_snapshot_and_is_proven() -> None:
    snap = path_snapshot()
    g = paths.build(snap, provenance=True)
    p = cut.plan(snap, g)
    assert p.exact and p.proven and p.cost == len(p.changes) == 2
    assert p.steps[-1].exposed_after == 0
    assert g.prov is not None
    after = whatif.state(snap, whatif.masked(g, snap, p.changes))
    assert after.exposed == 0
    rebuilt_graph = rebuilt(snap, g.prov, p.changes)
    assert paths.exposure(snap, rebuilt_graph, paths.paths_to_tier0(rebuilt_graph))[0] == 0


def test_accepted_holders_are_not_sources() -> None:
    snap = path_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    p = cut.plan(snap, g, accepted=["helpdesk"])
    trustees = {g.prov.prims[c][-1] for c in p.changes}
    assert "S-1-5-21-1-2-3-1105" not in trustees  # helpdesk's own right stays
    assert p.changes  # the Helpdesk group's members still lose their path


def test_invariants_keep_the_declared_state() -> None:
    snap = entra_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    spec = {"dcsync": {"allowed": ["MSOL_0123456789ab"]}}
    keeps = changes.invariant_keeps(snap, g.prov, spec)
    assert [g.prov.prims[p] for p in keeps] == [("ace", "dc=lab,dc=test", "S-1-5-21-1-2-3-1400")]
    snap = kitchen_sink()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    keeps = changes.invariant_keeps(snap, g.prov, {"groups": {"Nested": ["alice"]}})
    assert [g.prov.prims[p][0] for p in keeps] == ["member"]


def test_budget_plan_is_labelled_heuristic() -> None:
    snap = kitchen_sink()
    g = paths.build(snap, provenance=True)
    p = cut.plan(snap, g, max_changes=1)
    assert len(p.changes) <= 1 and "heuristic" in p.note and not p.proven


def test_plan_is_the_same_under_another_hash_seed() -> None:
    script = (
        "from tests.whatif_fixtures import kitchen_sink\n"
        "from ad_doctor import cut, paths, changes\n"
        "s = kitchen_sink(); g = paths.build(s, provenance=True); p = cut.plan(s, g)\n"
        "print([changes.change_id(g.prov.prims[c]) for c in p.changes], p.cost,"
        " p.lower_bound, [(x.n, x.exposed_after, x.routes_after) for x in p.steps])\n"
    )
    root = Path(__file__).resolve().parents[1]
    outs = set()
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        run = subprocess.run(
            [sys.executable, "-c", script], cwd=root, env=env, capture_output=True, text=True
        )
        assert run.returncode == 0, run.stderr
        outs.add(run.stdout)
    assert len(outs) == 1


# -- the lab (AD_DOCTOR_WHATIF_SNAPSHOTS) ------------------------------------------------


@pytest.mark.parametrize("path", lab_snapshots(), ids=str)
def test_lab_plan(path: Path) -> None:
    snap = load(path)
    g = paths.build(snap, provenance=True)
    prov = g.prov
    assert prov is not None
    p = cut.plan(snap, g)
    kinds = [prov.prims[c][0] for c in p.changes]
    # the ESC1-3 enrollment of Domain Users goes as one bundle among the first steps
    first = [prov.prims[c] for s in p.steps[:2] for c in s.changes]
    assert sum(1 for k in first if k[0] == "template-ace") == 3
    # each AdminSDHolder trustee is one change (its copies are not listed), the sync
    # account's DCSync is not proposed
    assert kinds.count("adminsdholder-ace") >= 1
    protected = {g.prov.prims[c][1] for c in p.changes if "adminsdholder" in g.prov.prims[c][0]}
    assert len(protected) == kinds.count("adminsdholder-ace")
    keeps = changes.default_keeps(snap, prov)
    assert keeps and not set(keeps) & set(p.changes)
    assert any("DCSync" in u.why and "kept" in u.why for u in p.unclosable)
    # the plan closes every closable source in the rebuilt snapshot (only the kept sync
    # account stays exposed)
    copy = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    gone = changes.apply(copy, prov, p.changes)
    assert all(gone.values())
    a = paths.analyze(copy)
    users = {f"sid:{x.sid}" for x in snap.accounts if not x.is_computer and x.enabled}
    assert a.exposed == len([u for u in p.unclosable if u.node in users])
    # all-paths: the sync server is reported, with the tier-0 suggestion
    q = cut.plan(snap, g, goal="all-paths")
    sync_hosts = {f"sid:{x.sid}" for x in snap.accounts if x.is_computer} & {
        u.node for u in q.unclosable
    }
    assert sync_hosts and all("tier 0" in u.suggest for u in q.unclosable)
