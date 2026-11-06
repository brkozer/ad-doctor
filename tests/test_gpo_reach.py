"""GPO reach in the control graph: from whoever can write a GPO, through its links, to the
accounts it applies to."""

from __future__ import annotations

import json
from typing import Any

from ad_doctor import gpo_scope, opengraph, paths, sd, viewer_graph
from ad_doctor.model import Account, DirObject, Gpo, Snapshot

from .test_checks import user
from .test_gpo_local import (
    APPLY,
    AU,
    DC_OU,
    DOM,
    GUID_A,
    GUID_B,
    HEAD,
    HELPDESK,
    ISOLATED,
    LAB,
    READ,
    dc,
    gpo,
    host,
    link,
)
from .test_gpo_local import gsnap as base_snap

WRITE = sd.Ace(HELPDESK, sd.GENERIC_WRITE)
OPEN = [READ, APPLY, WRITE]
SITE = "CN=Branch,CN=Sites,CN=Configuration,DC=lab,DC=test"
INNER = f"OU=Inner,{ISOLATED}"
FILTER_GROUP = f"{DOM}-1300"


def gsnap(*accounts: Account, gpos: list[Gpo], **kw: Any) -> Snapshot:
    """A snapshot that also holds each GPO as a directory object, so its ACEs give edges."""
    dn = "CN={},CN=Policies,CN=System," + HEAD
    held = [DirObject(dn.format(g.guid), g.name, "gpo", aces=g.aces) for g in gpos]
    kw["objects"] = [*kw.get("objects", []), *held]
    return base_snap(*accounts, gpos=gpos, **kw)


def person(name: str, ou: str = LAB, rid: int = 3000, **kw: Any) -> Account:
    base = user(name, **kw)
    base.dn = f"CN={name},{ou}"
    base.sid = f"{DOM}-{rid}"
    return base


def blocked(*dns: str) -> list[DirObject]:
    return [DirObject(dn, dn.split(",")[0][3:], "ou", gp_blocked=True) for dn in dns]


def reach_of(snap: Snapshot, start: str = HELPDESK) -> set[str]:
    """The accounts the writer of a GPO controls."""
    g = paths.build(snap)
    controlled, _ = paths.blast_radius(g, [f"sid:{start}"])
    return {g.name(n) for n in controlled if g.kind(n) in ("computer", "user")}


def writer(*links: Any, **kw: Any) -> list[Gpo]:
    kw.setdefault("aces", OPEN)
    return [gpo("Reach", GUID_A, *links, **kw)]


def test_link_reaches_computers_and_users_at_and_below_the_ou() -> None:
    snap = gsnap(
        host("SRV", LAB),
        host("DEEP", ISOLATED, 2001),
        host("OUT", HEAD, 2002),
        person("ann", ISOLATED),
        gpos=writer(link(LAB)),
        entries=[],
    )
    assert reach_of(snap) == {"SRV$", "DEEP$", "ann"}


def test_path_names_every_hop() -> None:
    snap = gsnap(host("DEEP", ISOLATED), gpos=writer(link(LAB)), entries=[])
    g = paths.build(snap)
    controlled, _ = paths.blast_radius(g, [f"sid:{HELPDESK}"])
    (path,) = [p for n, p in controlled.items() if g.kind(n) == "computer"]
    assert [how for _, how in path.steps[1:]] == [
        "GPO applies to",
        "GPO inherited by",
        "GPO reaches",
    ]
    assert g.name(path.steps[1][0]) == "computers under Lab"
    assert g.name(path.steps[2][0]) == "computers under Lab/Isolated"


def test_disabled_link_reaches_nothing_even_enforced() -> None:
    snap = gsnap(
        host("SRV"),
        gpos=writer(link(LAB, enabled=False), link(HEAD, enabled=False, enforced=True)),
        entries=[],
    )
    assert reach_of(snap) == set()


def test_block_inheritance_stops_a_link_above_but_not_its_own() -> None:
    accounts = (host("IN", ISOLATED), host("OUT", LAB, 2001))
    above = gsnap(*accounts, gpos=writer(link(LAB)), entries=[], objects=blocked(ISOLATED))
    assert reach_of(above) == {"OUT$"}
    own = gsnap(*accounts, gpos=writer(link(ISOLATED)), entries=[], objects=blocked(ISOLATED))
    assert reach_of(own) == {"IN$"}


def test_enforced_link_goes_through_every_block() -> None:
    accounts = (host("OUT", LAB), host("IN", ISOLATED, 2001), host("DEEP", INNER, 2002))
    objects = blocked(ISOLATED, INNER)
    enforced = gsnap(*accounts, gpos=writer(link(HEAD, enforced=True)), entries=[], objects=objects)
    assert reach_of(enforced) == {"OUT$", "IN$", "DEEP$"}
    plain = gsnap(*accounts, gpos=writer(link(HEAD)), entries=[], objects=objects)
    assert reach_of(plain) == {"OUT$"}


def test_enforced_link_without_a_block_shares_the_plain_scope() -> None:
    gpos = [
        gpo("A", GUID_A, link(LAB, enforced=True), aces=OPEN),
        gpo("B", GUID_B, link(LAB), aces=OPEN),
    ]
    reach = gpo_scope.reach(gsnap(host("SRV"), gpos=gpos, entries=[]))
    assert len(reach.names) == 1 and len({node for _, node, _ in reach.applies}) == 1


def test_side_flags_split_users_from_computers() -> None:
    accounts = (host("SRV"), person("ann"))
    computer_off = gsnap(*accounts, gpos=writer(link(LAB), flags=2), entries=[])
    assert reach_of(computer_off) == {"ann"}
    user_off = gsnap(*accounts, gpos=writer(link(LAB), flags=1), entries=[])
    assert reach_of(user_off) == {"SRV$"}
    all_off = gsnap(*accounts, gpos=writer(link(LAB), flags=3), entries=[])
    assert reach_of(all_off) == set()


def test_an_empty_gpo_is_what_its_writer_fills_in() -> None:
    snap = gsnap(
        host("SRV"),
        gpos=writer(link(LAB), machine_version=0, machine_extensions=[]),
        entries=[],
    )
    assert reach_of(snap) == {"SRV$"}


def test_security_filter_keeps_only_the_token_holders() -> None:
    inside = host("IN", LAB, 2001)
    group = DirObject(f"CN=Filter,{HEAD}", "Filter", "group", sid=FILTER_GROUP, members=[inside.dn])
    aces = [
        sd.Ace(AU, 0x20094),
        sd.Ace(FILTER_GROUP, sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY),
        WRITE,
    ]
    snap = gsnap(
        inside,
        host("OUT", LAB, 2002),
        person("ann"),
        gpos=writer(link(LAB), aces=aces),
        entries=[],
        objects=[group],
        principals={FILTER_GROUP: "Filter", HELPDESK: "helpdesk"},
    )
    assert reach_of(snap) == {"IN$"}
    names = paths.build(snap).names.values()
    assert "computers under Lab filtered to Filter" in names


def test_filter_on_domain_computers_leaves_out_users_and_dcs() -> None:
    aces = [
        sd.Ace(f"{DOM}-515", 0x20094),
        sd.Ace(f"{DOM}-515", sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY),
        WRITE,
    ]
    snap = gsnap(
        host("SRV", HEAD),
        host("DC02", DC_OU, 1000, 0x2000, primary_group=516),
        person("ann", HEAD),
        gpos=writer(link(HEAD), aces=aces),
        entries=[],
    )
    assert reach_of(snap) == {"SRV$"}


def test_gpos_with_one_filter_share_their_scopes() -> None:
    aces = [sd.Ace(f"{DOM}-515", 0x20094 | sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)]
    gpos = [gpo("A", GUID_A, link(LAB), aces=aces), gpo("B", GUID_B, link(LAB), aces=aces)]
    reach = gpo_scope.reach(gsnap(host("SRV"), gpos=gpos, entries=[]))
    assert len(reach.names) == 1


def test_unreadable_filter_reaches_with_a_caveat() -> None:
    wmi = gpo("Reach", GUID_A, link(LAB), aces=[], wmi_filter="Laptops")
    snap = gsnap(host("SRV"), gpos=[wmi], entries=[])
    g = paths.build(snap)
    (props,) = g.edge_props.values()
    assert props["caveats"] == ["security filtering not readable", "WMI filter Laptops"]
    assert any(how == paths.GPO_REACHES for outs in g.edges.values() for _, how in outs)


def test_reach_is_not_ou_control() -> None:
    """Group Policy does not reach groups, sub-OU nodes or the OU's ACLs."""
    group = DirObject(f"CN=Team,{LAB}", "Team", "group", sid=f"{DOM}-1301")
    sub = DirObject(ISOLATED, "Isolated", "ou")
    snap = gsnap(host("SRV"), gpos=writer(link(LAB)), entries=[], objects=[group, sub])
    g = paths.build(snap)
    controlled, _ = paths.blast_radius(g, [f"sid:{HELPDESK}"])
    assert {g.kind(n) for n in controlled} == {"gpo", "computer"}


def test_protected_accounts_are_reached_though_acl_inheritance_skips_them() -> None:
    admin = person("adm", admin_count=True)
    assert reach_of(gsnap(admin, gpos=writer(link(LAB)), entries=[])) == {"adm"}


def test_accounts_that_process_no_policy_are_left_out() -> None:
    off = host("OFF", uac=0x1002)
    gone = person("gone", uac=0x202)
    assert reach_of(gsnap(off, gone, gpos=writer(link(LAB)), entries=[])) == set()


def test_only_site_acts_above_the_domain_head() -> None:
    accounts = (host("SRV", LAB), person("ann", HEAD), dc())
    snap = gsnap(*accounts, gpos=writer(link(SITE, "site")), entries=[], site_count=1)
    assert reach_of(snap) == {"SRV$", "ann", "DC02$"}
    assert gpo_scope.site_note(snap) == []
    block = gsnap(
        *accounts,
        gpos=writer(link(SITE, "site")),
        entries=[],
        site_count=1,
        objects=blocked(HEAD),
    )
    assert reach_of(block) == set()


def test_several_sites_reach_the_dcs_of_that_site_and_say_so() -> None:
    here, there = dc("DC02", 1000), dc("DC03", 1001)
    snap = gsnap(
        host("SRV", LAB),
        here,
        there,
        gpos=writer(link(SITE, "site")),
        entries=[],
        site_count=2,
        dc_sites={here.dn.lower(): SITE, there.dn.lower(): "CN=Other"},
    )
    assert reach_of(snap) == {"DC02$"}
    g = paths.build(snap)
    assert "domain controllers in site Branch" in g.names.values()
    (note,) = gpo_scope.site_note(snap)
    assert "Reach" in note and "domain controllers only" in note


def test_block_above_a_dc_stops_an_unenforced_site_link() -> None:
    here = dc("DC02")
    fields: dict[str, Any] = {
        "entries": [],
        "site_count": 2,
        "dc_sites": {here.dn.lower(): SITE},
        "objects": blocked(DC_OU),
    }
    assert reach_of(gsnap(here, gpos=writer(link(SITE, "site")), **fields)) == set()
    enforced = writer(link(SITE, "site", enforced=True))
    assert reach_of(gsnap(here, gpos=enforced, **fields)) == {"DC02$"}


def test_tier0_host_in_an_ou_gives_a_control_path() -> None:
    server = host("CA01", LAB)
    snap = gsnap(server, dc(), gpos=writer(link(LAB)), entries=[], ca_hosts=["CA01$"])
    analysis = paths.analyze(snap)
    (path,) = [p for p in analysis.paths if p.start == f"sid:{HELPDESK}"]
    assert path.render(analysis.graph).endswith(
        "-[GPO applies to]-> computers under Lab -[GPO reaches]-> CA01$"
    )


def test_link_edge_to_tier0_needs_the_gpo_to_reach_a_dc() -> None:
    def linked(**kw: Any) -> set[str]:
        fields = {"aces": OPEN, **kw}
        g = gpo("Reach", GUID_A, link(DC_OU), **fields)
        g.linked_to = ["Domain Controllers OU"]
        built = paths.build(gsnap(dc(), gpos=[g], entries=[]))
        return {h for outs in built.edges.values() for _, h in outs if h.startswith("linked to")}

    assert linked() == {"linked to Domain Controllers OU"}
    assert linked(flags=2) == set()  # user side only: nothing runs on the DCs
    only_group = [sd.Ace(FILTER_GROUP, 0x20094 | sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY), WRITE]
    assert linked(aces=only_group) == set()


def test_older_snapshot_without_links_keeps_the_link_edge() -> None:
    old = gpo("Old", GUID_A, aces=OPEN)
    old.linked_to = ["domain"]
    g = paths.build(gsnap(dc(), gpos=[old], entries=[]))
    assert any(how == "linked to domain" for outs in g.edges.values() for _, how in outs)
    assert not any(g.kind(n) == "scope" for n in g.names)


def test_graph_grows_with_links_not_with_gpos_times_accounts() -> None:
    computers = [host(f"H{i}", LAB, 2000 + i) for i in range(40)]

    def edges(count: int) -> int:
        gpos = [
            gpo(f"G{i}", f"{{{i:08X}-0000-0000-0000-000000000000}}", link(LAB), aces=OPEN)
            for i in range(count)
        ]
        g = paths.build(gsnap(*computers, gpos=gpos, entries=[]))
        return sum(1 for outs in g.edges.values() for _, how in outs if how.startswith("GPO "))

    assert edges(10) - edges(1) == 9  # one more edge per GPO, none per account


def test_scope_nodes_are_not_controlled_objects() -> None:
    snap = gsnap(host("SRV"), gpos=writer(link(LAB)), entries=[])
    g = paths.build(snap)
    controlled, _ = paths.blast_radius(g, [f"sid:{HELPDESK}"])
    assert sorted(g.kind(n) for n in controlled) == ["computer", "gpo"]
    c = viewer_graph.Indexed(viewer_graph.compact(g, snap), viewer_graph.nodes_of(g))
    got = viewer_graph.subject(c, [f"sid:{HELPDESK}"], "helpdesk", "group")
    assert got["count"] == 2 and "scope" not in got["kinds"]


def test_opengraph_exports_the_chain_as_traversable() -> None:
    snap = gsnap(host("DEEP", ISOLATED), gpos=writer(link(LAB)), entries=[])
    payload = json.loads(json.dumps(opengraph.export(snap)))
    edges = payload["graph"]["edges"]
    kinds = {e["kind"] for e in edges if e["properties"]["label"].startswith("GPO ")}
    assert kinds == {"ADD_GPOAppliesTo", "ADD_GPOInheritedBy", "ADD_GPOReaches"}
    assert all(e["properties"]["traversable"] for e in edges)
    ids = {n["id"] for n in payload["graph"]["nodes"]}
    assert all(":" not in i for i in ids)
