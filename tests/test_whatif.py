"""What-if engine: provenance, the masked graph against a rebuilt snapshot, the rules where
the snapshot and AD differ, mutators, and the level-1 == level-2 assertion."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from ad_doctor import changes, paths, sd, whatif
from ad_doctor.model import Snapshot
from ad_doctor.provenance import FIXED_REASONS, Gated, Options
from ad_doctor.sd import Ace

from .test_acl_adcs import ace_bytes, descriptor
from .test_gpo_local import _tier0_lab
from .test_round3 import path_snapshot
from .test_round4 import entra_snapshot, exchange_snapshot
from .viewer_fixtures import bench_snapshot, xss_snapshot
from .whatif_fixtures import (
    DA,
    HELPDESK,
    HOLDER,
    OPS,
    TEAM_OU,
    kitchen_sink,
    lab_snapshots,
    load,
    parity,
    random_sets,
)

FIXTURES: dict[str, Callable[[], Snapshot]] = {
    "kitchen-sink": kitchen_sink,
    "kitchen-sink-old": lambda: kitchen_sink(inherited_bit=False),
    "paths": path_snapshot,
    "exchange": exchange_snapshot,
    "entra": lambda: entra_snapshot(helpdesk_reset=True),
    "gpo-local": _tier0_lab,
    "xss": xss_snapshot,
}


def graph(snap: Snapshot) -> paths.Graph:
    return paths.build(snap, provenance=True)


def reasons(g: paths.Graph, src: str) -> dict[tuple[str, str], int]:
    assert g.prov is not None
    return dict(zip(g.edges[src], g.prov.why[src], strict=True))


def prim_of(g: paths.Graph, key: tuple[str, ...]) -> int:
    assert g.prov is not None
    p = g.prov.lookup(key)
    assert p is not None, f"{key} not in {g.prov.prims}"
    return p


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_provenance_leaves_the_graph_alone(name: str) -> None:
    snap = FIXTURES[name]()
    assert whatif.signature(paths.build(snap)) == whatif.signature(graph(snap))
    assert paths.build(snap).prov is None


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_every_edge_has_a_change_or_a_fixed_reason(name: str) -> None:
    g = graph(FIXTURES[name]())
    prov = g.prov
    assert prov is not None and prov.unsupported == 0
    assert list(prov.why) == [src for src in g.edges]
    for src, outs in g.edges.items():
        assert len(prov.why[src]) == len(outs) == len(prov.seq[src])
        for i, why in enumerate(prov.why[src]):
            assert why < len(prov.prims) and -why - 1 < len(FIXED_REASONS)
            ex = prov.extra.get((src, i))
            if isinstance(ex, Options):
                assert ex.items[0][0] == why
            elif isinstance(ex, Gated):
                assert ex.prim == why and ex.gate < len(prov.gates)
    for src, outs in g.logon_edges.items():
        assert len(prov.logon_why[src]) == len(outs)


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_every_single_change_masks_like_a_rebuild(name: str) -> None:
    snap = FIXTURES[name]()
    g = graph(snap)
    assert g.prov is not None
    result = parity(snap, [[p] for p in range(len(g.prov.prims))], g)
    assert result["differs"] == []
    # only changes that can move GPO scope take the rebuild path
    assert set(result["rebuild"]) <= {"gplink", "member", "ace", "inherited-ace"}


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_random_change_sets_mask_like_a_rebuild(name: str) -> None:
    snap = FIXTURES[name]()
    g = graph(snap)
    assert g.prov is not None
    sets = random_sets(len(g.prov.prims), 40, seed=len(name))
    assert parity(snap, sets, g)["differs"] == []


def test_bench_sample_masks_like_a_rebuild() -> None:
    snap = bench_snapshot(1500)
    g = graph(snap)
    assert g.prov is not None
    singles = random_sets(len(g.prov.prims), 60, seed=3, most=1)
    result = parity(snap, singles + random_sets(len(g.prov.prims), 5, seed=4), g)
    assert result["differs"] == []


@pytest.mark.slow
def test_bench_10k_sample_masks_like_a_rebuild() -> None:
    """500 singles and 20 sets on a 10,000-user bench domain (minutes; -m slow)."""
    snap = bench_snapshot(10_000)
    g = graph(snap)
    assert g.prov is not None
    n = len(g.prov.prims)
    singles = random_sets(n, 500, seed=5, most=1)
    result = parity(snap, singles + random_sets(n, 20, seed=6), g)
    assert result["differs"] == []


@pytest.mark.parametrize("path", lab_snapshots(), ids=str)
def test_lab_every_single_change_and_random_sets(path: Path) -> None:
    """Exhaustive on a real lab snapshot (AD_DOCTOR_WHATIF_SNAPSHOTS)."""
    snap = load(path)
    g = graph(snap)
    assert g.prov is not None
    n = len(g.prov.prims)
    result = parity(snap, [[p] for p in range(n)] + random_sets(n, 200, seed=11), g)
    assert result["differs"] == []


def test_monotone_fewer_facts_never_add_a_path() -> None:
    for name in ("kitchen-sink", "gpo-local", "paths"):
        snap = FIXTURES[name]()
        g = graph(snap)
        assert g.prov is not None
        for small in random_sets(len(g.prov.prims), 25, seed=9, most=4):
            big = small + random_sets(len(g.prov.prims), 1, seed=len(small), most=4)[0]
            reach_small = whatif.reaching(whatif.masked(g, snap, small))
            reach_big = whatif.reaching(whatif.masked(g, snap, big))
            assert reach_big - whatif.masked(g, snap, big).tier0 <= reach_small


# -- the rules ---------------------------------------------------------------------------


def test_sdprop_copy_goes_with_the_adminsdholder_change() -> None:
    snap = kitchen_sink()
    g = graph(snap)
    holder = prim_of(g, ("adminsdholder-ace", HELPDESK))
    own = prim_of(g, ("ace", f"cn=domain admins,cn=users,{snap.domain_dn.lower()}", HELPDESK))
    # helpdesk's full control on Domain Admins and on AdminSDHolder: one change
    edges = reasons(g, f"sid:{HELPDESK}")
    assert edges[(f"sid:{DA}", "full control")] == holder
    assert edges[(f"dn:{HOLDER.lower()}", "full control")] == holder
    # the WriteOwner ACE is not on AdminSDHolder: a change of its own
    assert edges[(f"sid:{DA}", "write/WriteDacl/WriteOwner")] == own
    gone = changes.apply(snap, g.prov, [holder])  # type: ignore[arg-type]
    assert gone[holder] == 3  # AdminSDHolder (object and acls) and the copy
    da = next(o for o in snap.objects if o.sid == DA)
    assert da.aces == [Ace(HELPDESK, sd.WRITE_OWNER)]


def test_inherited_copy_goes_with_the_container() -> None:
    snap = kitchen_sink()
    g = graph(snap)
    team = prim_of(g, ("inherited-ace", TEAM_OU.lower(), OPS))
    edges = reasons(g, f"sid:{OPS}")
    bob = "sid:S-1-5-21-1-2-3-3002"
    assert edges[(bob, "reset password")] == team  # the copy on bob
    assert edges[(bob, "reset password (inherited)")] == team  # the OU's ACE
    changes.apply(snap, g.prov, [team])  # type: ignore[arg-type]
    bob_obj = next(o for o in snap.objects if o.sid == "S-1-5-21-1-2-3-3002")
    assert bob_obj.aces == []


def test_older_snapshot_keeps_inherited_copies_apart() -> None:
    snap = kitchen_sink(inherited_bit=False)
    g = graph(snap)
    team = prim_of(g, ("inherited-ace", TEAM_OU.lower(), OPS))
    copy = prim_of(g, ("ace", f"cn=bob,{TEAM_OU.lower()}", OPS))
    assert team != copy  # the plan may list both: too large, never too small


def test_one_ace_in_both_lists_is_one_change() -> None:
    snap = exchange_snapshot()
    head = next(o for o in snap.objects if o.kind == "domain")
    head.inheritable = list(head.aces)
    g = graph(snap)
    assert g.prov is not None
    keys = [
        k for k in g.prov.prims if k[0] in ("ace", "inherited-ace") and k[1] == "dc=lab,dc=test"
    ]
    assert len(keys) == 1 and keys[0][0] == "inherited-ace"


def test_member_change_moves_tier_zero_like_a_rebuild() -> None:
    snap = kitchen_sink()
    g = graph(snap)
    nested = prim_of(g, ("member", f"cn=domain admins,cn=users,{snap.domain_dn.lower()}",
                         f"cn=nested,{TEAM_OU.lower()}"))  # fmt: skip
    alice = "sid:S-1-5-21-1-2-3-3001"
    assert alice in g.tier0
    m = whatif.masked(g, snap, [nested])
    assert alice not in m.tier0
    assert parity(snap, [[nested]], g)["differs"] == []


def test_gate_flag_closes_enrollment() -> None:
    snap = kitchen_sink()
    g = graph(snap)
    assert g.prov is not None
    flag = prim_of(g, ("template-flag", "Esc1", "enrollee-supplies-subject"))
    m = whatif.masked(g, snap, [flag])
    users = f"sid:{snap.domain_sid}-513"
    assert ("tier0:template:Esc1", "enroll (ESC1-3)") in g.edges[users]
    assert ("tier0:template:Esc1", "enroll (ESC1-3)") not in m.edges.get(users, [])
    esc = next(i for i, gt in enumerate(g.prov.gates) if gt.template == "Esc1")
    kills = g.prov.gate_kills(esc)
    assert kills is not None and frozenset({flag}) in kills


def test_parse_dacl_keeps_the_inherited_flag() -> None:
    raw = descriptor(
        ace_bytes(HELPDESK, sd.GENERIC_ALL, flags=sd.INHERITED_ACE),
        ace_bytes(OPS, sd.WRITE_DAC),
    )
    assert [a.inherited for a in sd.parse_dacl(raw)] == [True, False]


def test_older_snapshot_loads_without_the_new_fields() -> None:
    data = json.loads(json.dumps(kitchen_sink().to_json()))
    assert data["ace_inheritance_checked"] is True
    del data["ace_inheritance_checked"]
    for o in data["objects"]:
        for a in o["aces"] + o["inheritable"]:
            a.pop("inherited", None)
    snap = Snapshot.from_json(data)
    assert snap.ace_inheritance_checked is False
    assert not any(a.inherited for o in snap.objects for a in o.aces)
    again = kitchen_sink()
    assert Snapshot.from_json(json.loads(json.dumps(again.to_json()))) == again


# -- change IDs, classes -------------------------------------------------------------------


def test_change_id_normalises_case() -> None:
    a = changes.change_id(("ace", "cn=x,dc=lab,dc=test", "s-1-5-21-1-2-3-1105"))
    b = changes.change_id(("ace", "CN=X,DC=lab,DC=test", "S-1-5-21-1-2-3-1105"))
    assert a == b and a.startswith("c:") and len(a) == 14


def test_classes_and_costs() -> None:
    snap = kitchen_sink()
    g = graph(snap)
    ctx = changes.Context(snap)
    da = f"cn=domain admins,cn=users,{snap.domain_dn.lower()}"
    member = ("member", da, f"cn=nested,{TEAM_OU.lower()}")
    assert changes.assess(snap, member, g.tier0, ctx) == changes.Assessment("removable", 5)
    flag = ("template-flag", "Esc1", "enrollee-supplies-subject")
    assert changes.assess(snap, flag, g.tier0, ctx).cls == "warn"
    pre2k = ("ace", da, changes.PRE2K)
    assert changes.assess(snap, pre2k, g.tier0, ctx).cost == changes.WARN_COST
    assert changes.assess(snap, ("gplink", "{X}", "ou=x"), g.tier0, ctx).cost == 3


def test_sync_dcsync_is_kept_by_default() -> None:
    snap = entra_snapshot()
    g = graph(snap)
    assert g.prov is not None
    keeps = changes.default_keeps(snap, g.prov)
    assert [g.prov.prims[p] for p in keeps] == [("ace", "dc=lab,dc=test", "S-1-5-21-1-2-3-1400")]


# -- forward what-if ------------------------------------------------------------------------


def test_run_closes_reroutes_and_rechecks_findings() -> None:
    snap = path_snapshot()
    g = graph(snap)
    it = prim_of(g, ("ace", "cn=it,ou=groups,dc=lab,dc=test", HELPDESK))
    r = whatif.run(snap, g, [it])
    assert r.maskable and r.findings_rechecked
    assert r.closed == [f"sid:{HELPDESK}"]
    assert r.open == ["sid:S-1-5-21-1-2-3-1900"]
    assert any(c["check"] == "AD-PATH-001" for c in r.cleared)


def test_member_removal_shows_findings_that_appear() -> None:
    snap = kitchen_sink()
    g = graph(snap)
    da = f"cn=domain admins,cn=users,{snap.domain_dn.lower()}"
    nested = prim_of(g, ("member", da, f"cn=nested,{TEAM_OU.lower()}"))
    r = whatif.run(snap, g, [nested])
    assert any(f["check"] == "AD-ACC-006" and f["object"].startswith("alice") for f in r.new)


def test_broken_provenance_raises_model_mismatch() -> None:
    snap = path_snapshot()
    g = graph(snap)
    assert g.prov is not None
    it = prim_of(g, ("ace", "cn=it,ou=groups,dc=lab,dc=test", HELPDESK))
    # test hook: pretend the IT ACE made the Helpdesk group's edge too
    hd = "sid:S-1-5-21-1-2-3-1900"
    g.prov.why[hd][0] = it
    with pytest.raises(whatif.ModelMismatch):
        whatif.run(snap, g, [it])


def test_paths_only_leaves_the_snapshot_alone() -> None:
    snap = path_snapshot()
    before = json.dumps(snap.to_json())
    g = graph(snap)
    it = prim_of(g, ("ace", "cn=it,ou=groups,dc=lab,dc=test", HELPDESK))
    r = whatif.run(snap, g, [it], accounts=["helpdesk"], paths_only=True)
    assert not r.findings_rechecked
    assert json.dumps(snap.to_json()) == before
    assert r.accounts[0]["before"]["tier0"] > r.accounts[0]["after"]["tier0"] == 0
