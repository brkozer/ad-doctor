"""Delegation and SID history edges of the control graph, and their what-if changes."""

from __future__ import annotations

import json
import struct

import pytest

from ad_doctor import changes, cut, fixes, opengraph, paths, planfile, viewer_graph, whatif
from ad_doctor.collect import Collector
from ad_doctor.model import UAC, Account, DirObject, Snapshot
from ad_doctor.provenance import Gated
from ad_doctor.redact import redact
from ad_doctor.resolve import Resolver, SpecError

from .test_checks import NORMAL, computer, snapshot, user
from .test_gpo_local import DOM
from .whatif_fixtures import delegation_snapshot, parity, random_sets

DA = f"{DOM}-512"
PT = NORMAL | UAC.TRUSTED_TO_AUTH_FOR_DELEGATION


def account(snap: Snapshot, sam: str) -> Account:
    return next(a for a in snap.accounts if a.sam == sam)


def out_of(snap: Snapshot, sam: str) -> list[tuple[str, str]]:
    return paths.build(snap).edges.get(f"sid:{account(snap, sam).sid}", [])


def domain(*accounts: Account, **kw: object) -> Snapshot:
    """A domain with one delegable Domain Admin, a DC and an aliased service class."""
    for i, a in enumerate(accounts):
        a.sid = a.sid or f"{DOM}-{4000 + i}"
    admin = user("da1", sid=f"{DOM}-3900")
    fields: dict[str, object] = {
        "domain_sid": DOM,
        "privileged": {"Domain Admins": [admin.dn]},
        "spn_mappings": ["host=cifs,http"],
    }
    fields.update(kw)
    return snapshot(admin, *accounts, **fields)


def server(name: str = "APP01", **kw: object) -> Account:
    defaults: dict[str, object] = {"spns": [f"HOST/{name.lower()}.lab.test"]}
    defaults.update(kw)
    return computer(name, **defaults)


def kcd(targets: list[str], uac: int = PT, spns: tuple[str, ...] = ("http/x.lab.test",)) -> Account:
    return user("svc", uac, spns=list(spns), allowed_to_delegate_to=targets)


CIFS = "cifs/app01.lab.test"


# -- constrained delegation --------------------------------------------------------------


def test_constrained_delegation_needs_protocol_transition() -> None:
    target = server()
    edges = out_of(domain(kcd([CIFS]), target), "svc")
    assert edges == [(f"sid:{target.sid}", paths.CONSTRAINED)]
    assert out_of(domain(kcd([CIFS], NORMAL), server()), "svc") == []


def test_constrained_delegation_needs_an_spn_on_a_user_source() -> None:
    assert out_of(domain(kcd([CIFS], spns=()), server()), "svc") == []
    source = computer("WEB01", PT & ~NORMAL | 0x1000, allowed_to_delegate_to=[CIFS])
    target = server()
    assert out_of(domain(source, target), "WEB01$") == [(f"sid:{target.sid}", paths.CONSTRAINED)]


def test_constrained_delegation_needs_a_host_that_holds_the_spn() -> None:
    assert out_of(domain(kcd([CIFS]), server(spns=[])), "svc") == []


def test_spn_held_by_a_user_or_twice_is_no_edge() -> None:
    held = user("svc_sql", spns=[CIFS])
    assert out_of(domain(kcd([CIFS]), held), "svc") == []
    one, two = server(spns=[CIFS]), server("APP02", spns=[CIFS])
    assert out_of(domain(kcd([CIFS]), one, two), "svc") == []


def test_alias_resolves_only_through_spn_mappings() -> None:
    assert out_of(domain(kcd([CIFS]), server(), spn_mappings=[]), "svc") == []


def test_disabled_host_and_managed_account_are_no_targets() -> None:
    off = computer("APP01", 0x1000 | UAC.ACCOUNTDISABLE, spns=["HOST/app01.lab.test"])
    assert out_of(domain(kcd([CIFS]), off), "svc") == []
    gmsa = server(managed=True)
    assert out_of(domain(kcd([CIFS]), gmsa), "svc") == []


def test_no_impersonable_admin_means_no_edge() -> None:
    snap = domain(kcd([CIFS]), server())
    admin = account(snap, "da1")
    snap.protected_users = [admin.dn]
    assert out_of(snap, "svc") == []
    snap.protected_users = []
    admin.uac |= UAC.NOT_DELEGATED
    assert out_of(snap, "svc") == []
    admin.uac = NORMAL | UAC.ACCOUNTDISABLE
    assert out_of(snap, "svc") == []


def test_a_dc_can_be_impersonated_even_when_every_admin_is_protected() -> None:
    dc = computer("DC01", 0x2000 | UAC.TRUSTED_FOR_DELEGATION, spns=["ldap/dc01.lab.test"])
    snap = domain(kcd(["ldap/dc01.lab.test"]), dc)
    snap.protected_users = [account(snap, "da1").dn]
    assert (f"sid:{dc.sid}", paths.CONSTRAINED) in out_of(snap, "svc")
    # only a DC target has that way: a member server stays closed
    snap2 = domain(kcd([CIFS]), server())
    snap2.protected_users = [account(snap2, "da1").dn]
    assert out_of(snap2, "svc") == []


def test_member_server_edge_says_what_it_assumes() -> None:
    target = server()
    snap = domain(kcd([CIFS]), target)
    g = paths.build(snap)
    assert g.name(f"sid:{target.sid}") == "APP01$"
    label = f"{paths.CONSTRAINED} ({paths.LOCAL_ADMIN_CAVEAT})"
    assert label in viewer_graph.compact(g, snap)["labels"]
    props = g.edge_props[
        (f"sid:{account(snap, 'svc').sid}", f"sid:{target.sid}", paths.CONSTRAINED)
    ]
    assert props["caveats"] == [paths.LOCAL_ADMIN_CAVEAT]


# -- resource-based delegation ------------------------------------------------------------


def rbcd_target(*listed: str) -> Account:
    target = server()
    target.rbcd, target.rbcd_principals = True, list(listed)
    return target


def test_rbcd_listed_computer_and_user_with_spn() -> None:
    target = rbcd_target(f"{DOM}-4000", f"{DOM}-4001", f"{DOM}-4002")
    source = user("svc_spn", spns=["http/s.lab.test"], sid=f"{DOM}-4000")
    machine = computer("WEB01", sid=f"{DOM}-4001")
    no_spn = user("plain", sid=f"{DOM}-4002")
    snap = domain(source, machine, no_spn, target)
    want = [(f"sid:{target.sid}", paths.RESOURCE_BASED)]
    assert out_of(snap, "svc_spn") == want and out_of(snap, "WEB01$") == want
    assert out_of(snap, "plain") == []


def test_rbcd_group_needs_a_member_that_can_run_s4u() -> None:
    target = rbcd_target(f"{DOM}-5000", f"{DOM}-5001")
    held = user("svc_spn", spns=["http/s.lab.test"], sid=f"{DOM}-4000")
    plain = user("plain", sid=f"{DOM}-4001")
    useful = DirObject(
        "CN=Useful,DC=lab,DC=test", "Useful", "group", sid=f"{DOM}-5000", members=[held.dn]
    )
    empty = DirObject(
        "CN=Empty,DC=lab,DC=test", "Empty", "group", sid=f"{DOM}-5001", members=[plain.dn]
    )
    snap = domain(held, plain, target, objects=[useful, empty])
    g = paths.build(snap)
    assert (f"sid:{target.sid}", paths.RESOURCE_BASED) in g.edges[f"sid:{held.sid}"]
    assert f"sid:{DOM}-5000" not in g.edges
    assert (f"sid:{target.sid}", paths.RESOURCE_BASED) not in g.edges[f"sid:{plain.sid}"]


def test_rbcd_broad_group_and_unknown_principal() -> None:
    target = rbcd_target("S-1-5-11", "S-1-5-21-7-7-7-1104")
    snap = domain(target)
    snap.policy.machine_account_quota = 10
    g = paths.build(snap)
    assert g.edges["sid:S-1-5-11"] == [(f"sid:{target.sid}", paths.RESOURCE_BASED)]
    assert "sid:S-1-5-21-7-7-7-1104" not in g.edges


def test_rbcd_on_a_user_gives_no_edge() -> None:
    target = user("svc_target", sid=f"{DOM}-4100")
    target.rbcd, target.rbcd_principals = True, [f"{DOM}-4101"]
    source = computer("WEB01", sid=f"{DOM}-4101")
    assert out_of(domain(target, source), "WEB01$") == []


def test_unknown_rbcd_list_is_no_edge_and_a_note() -> None:
    target = server()
    target.rbcd = True  # the list could not be read
    snap = domain(computer("WEB01", sid=f"{DOM}-4101"), target)
    assert out_of(snap, "WEB01$") == []
    data = json.loads(json.dumps(snap.to_json()))
    assert data["accounts"][-1]["rbcd_principals"] is None  # noted when it was collected
    assert not any("delegation edges" in n for n in Snapshot.from_json(data).notes)
    del data["accounts"][-1]["rbcd_principals"]  # an older snapshot
    assert any("delegation edges" in n for n in Snapshot.from_json(data).notes)


# -- SID history ------------------------------------------------------------------------


def test_sid_history_acts_as_that_principal() -> None:
    holder = user("oldadmin", sid_history=[DA])
    snap = domain(
        holder,
        objects=[
            DirObject(
                f"CN=Domain Admins,CN=Users,{'DC=lab,DC=test'}", "Domain Admins", "group", sid=DA
            )
        ],
    )
    assert out_of(snap, "oldadmin") == [(f"sid:{DA}", paths.SID_HISTORY)]
    a = paths.analyze(snap)
    assert [p.start for p in a.paths] == [f"sid:{holder.sid}"]
    assert a.exposed == 1


def test_built_in_sids_in_history_are_no_edge() -> None:
    assert out_of(domain(user("odd", sid_history=["S-1-5-32-544"])), "odd") == []


# -- what-if -----------------------------------------------------------------------------


def built() -> tuple[Snapshot, paths.Graph]:
    snap = delegation_snapshot()
    return snap, paths.build(snap, provenance=True)


def prim(g: paths.Graph, *key: str) -> int:
    assert g.prov is not None
    return g.prov.index[key]


def test_edges_have_the_facts_behind_them() -> None:
    snap, g = built()
    assert g.prov is not None
    src = f"sid:{account(snap, 'svc_kcd').sid}"
    kinds = {g.prov.prims[p][0] for p in g.prov.why[src]}
    assert kinds == {"delegation"}
    assert all(isinstance(g.prov.extra[(src, i)], Gated) for i in range(len(g.edges[src])))


def test_every_change_of_the_fixture_masks_like_a_rebuild() -> None:
    snap, g = built()
    assert g.prov is not None
    result = parity(snap, [[p] for p in range(len(g.prov.prims))], g)
    assert result["differs"] == []
    assert any("delegation" in k for k in result["equal"])
    assert any("rbcd-principal" in k for k in result["equal"])
    assert any("sid-history" in k for k in result["equal"])
    sets = random_sets(len(g.prov.prims), 200, 7)
    assert parity(snap, sets, g)["differs"] == []


def test_removing_one_listed_principal_leaves_the_others() -> None:
    snap, g = built()
    a = account(snap, "APP01$")
    p = prim(g, "rbcd-principal", a.dn.lower(), account(snap, "svc_rbcd").sid)
    assert g.prov is not None
    gone_counts = changes.apply(snap, g.prov, [p])
    assert gone_counts[p] == 1 and len(a.rbcd_principals or []) == 1 and a.rbcd


def test_clearing_the_attribute_closes_the_gate_for_every_principal() -> None:
    snap, g = built()
    assert g.prov is not None
    app = account(snap, "APP01$")
    p = prim(g, "delegation", app.dn.lower(), "rbcd")
    view = whatif.masked(g, snap, [p])
    app_sid = f"sid:{app.sid}"
    assert not any(
        d == app_sid and h == paths.RESOURCE_BASED for o in view.edges.values() for d, h in o
    )
    changes.apply(snap, g.prov, [p])
    assert app.rbcd is False and app.rbcd_principals == []
    assert whatif.signature(paths.build(snap)) == whatif.signature(view)


def test_protocol_transition_change_closes_both_targets() -> None:
    snap, g = built()
    assert g.prov is not None
    kcd_node = f"sid:{account(snap, 'svc_kcd').sid}"
    p = prim(g, "delegation", account(snap, "svc_kcd").dn.lower(), "protocol-transition")
    assert kcd_node not in whatif.masked(g, snap, [p]).edges
    changes.apply(snap, g.prov, [p])
    assert not account(snap, "svc_kcd").has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)


def test_removing_the_last_delegable_admin_goes_through_a_rebuild() -> None:
    snap, g = built()
    assert g.prov is not None
    dn = next(o.dn for o in snap.objects if o.name == "Domain Admins").lower()
    p = prim(g, "member", dn, account(snap, "admin1").dn.lower())
    assert not whatif.maskable(g.prov, [p])
    res = whatif.run(snap, g, [p], paths_only=True)
    app = f"sid:{account(snap, 'APP01$').sid}"
    assert res.maskable is False
    # the DC keeps its edge (its own account); the member server has no admin left
    delegated = {paths.CONSTRAINED, paths.RESOURCE_BASED}
    assert not any(
        d == app and h in delegated for o in res.after.graph.edges.values() for d, h in o
    )
    assert any(h == paths.CONSTRAINED for o in res.after.graph.edges.values() for _, h in o)


def test_leaving_protected_users_opens_the_edge_again() -> None:
    snap = delegation_snapshot()
    snap.privileged = {"Domain Admins": [account(snap, "admin2").dn]}
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    assert all(
        h != paths.CONSTRAINED or d.endswith("-1000") for o in g.edges.values() for d, h in o
    )
    group = next(o for o in snap.objects if o.name == "Protected Users")
    p = prim(g, "member", group.dn.lower(), account(snap, "admin2").dn.lower())
    assert not whatif.maskable(g.prov, [p])
    res = whatif.run(snap, g, [p], paths_only=True)
    assert snap.protected_users == []
    app = f"sid:{account(snap, 'APP01$').sid}"
    assert any(
        d == app and h == paths.CONSTRAINED for o in res.after.graph.edges.values() for d, h in o
    )


def test_level1_and_level2_agree_for_each_new_kind() -> None:
    for key in ("delegation", "rbcd-principal", "sid-history"):
        snap, g = built()
        assert g.prov is not None
        p = next(i for i, k in enumerate(g.prov.prims) if k[0] == key)
        assert whatif.run(snap, g, [p]).findings_rechecked


def test_minimum_cut_matches_brute_force() -> None:
    snap, g = built()
    assert g.prov is not None
    srcs = cut.sources_for(snap, g, "all-paths")
    m = cut.build_model(snap, g, srcs)
    flow, chosen = cut.min_cut(m)
    candidates = sorted(m.prim_arc)
    assert m.inexact == 0 and len(candidates) <= 15
    best = cut.brute_force_minimum(m, candidates, 7)
    assert best is not None and cut.decode(m, flow) == best[0]
    assert cut.closes(m, chosen)


def test_a_gate_on_one_source_cuts_every_target_at_once() -> None:
    snap, g = built()
    assert g.prov is not None
    kcd_node = f"sid:{account(snap, 'svc_kcd').sid}"
    m = cut.build_model(snap, g, {kcd_node: 1})
    _, chosen = cut.min_cut(m)
    assert [g.prov.prims[p][2] for p in chosen] == ["protocol-transition"]


def test_foreign_sid_history_is_warn_class_and_same_domain_is_not() -> None:
    snap, g = built()
    assert g.prov is not None
    old = next(k for k in g.prov.prims if k[0] == "sid-history" and "7-7-7" in k[2])
    same = next(k for k in g.prov.prims if k[0] == "sid-history" and "7-7-7" not in k[2])
    assert changes.assess(snap, old, set()).cls == "warn"
    assert changes.assess(snap, same, set()) == changes.Assessment("removable", 1)


def test_specs_resolve() -> None:
    snap, g = built()
    assert g.prov is not None
    r = Resolver(snap, g)
    app = account(snap, "APP01$").dn.lower()
    got = r.resolve("rbcd:APP01$:svc_rbcd")
    assert got.status == "applied"
    assert g.prov.prims[got.prims[0]] == ("rbcd-principal", app, account(snap, "svc_rbcd").sid)
    migrated = account(snap, "migrated").dn.lower()
    got = r.resolve("sid-history:migrated")
    assert g.prov.prims[got.prims[0]] == ("sid-history", migrated, DA)
    assert r.resolve("sid-history:migrated:S-1-5-21-1-1-1-1").status == "absent"
    with pytest.raises(SpecError):
        r.resolve("rbcd:APP01$")
    assert r.resolve("delegation:svc_kcd:protocol-transition").status == "applied"
    assert r.resolve("all-rights-of:migrated").status == "applied"


def test_delegation_of_a_dc_is_still_refused() -> None:
    snap, g = built()
    with pytest.raises(SpecError, match="domain controller"):
        Resolver(snap, g).resolve("delegation:DC02$:unconstrained")


def test_finding_maps_to_the_sid_history_change() -> None:
    from ad_doctor.resolve import finding_specs

    assert finding_specs("AD-ACC-007", "migrated") == ['sid-history:"migrated"']


def test_fix_and_rollback_lines() -> None:
    snap, g = built()
    assert g.prov is not None
    where = changes.Where(snap, g.prov)
    app = account(snap, "APP01$").dn.lower()
    rbcd_p = g.prov.index[("rbcd-principal", app, account(snap, "svc_rbcd").sid)]
    sid_p = g.prov.index[("sid-history", account(snap, "migrated").dn.lower(), DA)]
    facts = changes.facts(snap, g.prov, where, [rbcd_p, sid_p])
    other = next(
        s
        for s in account(snap, "APP01$").rbcd_principals or []
        if s != account(snap, "svc_rbcd").sid
    )
    fix = fixes.change_lines(facts[rbcd_p], snap)
    assert fix[0].endswith(f"-PrincipalsAllowedToDelegateToAccount '{other}' -WhatIf")
    back = fixes.rollback_lines(facts[rbcd_p], snap)
    assert back[0].endswith("-WhatIf") and account(snap, "svc_rbcd").sid in back[0]
    line = fixes.change_lines(facts[sid_p], snap)[0]
    assert f"-Remove @{{'sIDHistory' = '{DA}'}} -WhatIf" in line
    assert fixes.rollback_lines(facts[sid_p], snap)[0].startswith("#")


def test_plan_file_round_trip_for_the_new_kinds() -> None:
    _, g = built()
    assert g.prov is not None
    keys = [k for k in g.prov.prims if k[0] in ("delegation", "rbcd-principal", "sid-history")]
    assert {k[0] for k in keys} == {"delegation", "rbcd-principal", "sid-history"}
    for key in keys:
        entry = planfile.entry_for(key, "label")
        back = planfile.loads(planfile.dumps(planfile.PlanFile(changes=[entry])))
        assert back.changes[0].prim == key and back.changes[0].id == entry.expected_id


def test_opengraph_kinds() -> None:
    assert opengraph.edge_kinds(paths.CONSTRAINED) == [("ADD_AllowedToDelegate", False)]
    assert opengraph.edge_kinds(paths.RESOURCE_BASED) == [("ADD_AllowedToAct", False)]
    assert opengraph.edge_kinds(paths.SID_HISTORY) == [("ADD_HasSIDHistory", False)]


def test_findings_outside_the_paths_do_not_move() -> None:
    from ad_doctor.checks import run_all

    snap = delegation_snapshot()
    ids = {f.check_id for f in run_all(snap)}
    assert {"AD-PATH-001", "AD-DEL-002", "AD-DEL-003", "AD-ACC-007"} <= ids


# -- collection and redaction -------------------------------------------------------------


def sid_bytes(sid: str) -> bytes:
    parts = [int(x) for x in sid.split("-")[3:]]
    return (
        bytes([1, len(parts)]) + b"\0\0\0\0\0\x05" + b"".join(struct.pack("<I", p) for p in parts)
    )


def rbcd_sd(allow: list[str], deny: list[str] = ()) -> bytes:
    """A self-relative descriptor with the DACL Set-ADComputer writes (an empty one when
    both lists are empty)."""
    aces = b""
    for kind, sids in ((1, deny), (0, allow)):
        for sid in sids:
            body = struct.pack("<I", 0xF01FF) + sid_bytes(sid)
            aces += struct.pack("<BBH", kind, 0, 4 + len(body)) + body
    dacl = struct.pack("<BBHHH", 4, 0, 8 + len(aces), len(allow) + len(deny), 0) + aces
    return struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + dacl


def test_collector_reads_the_list_with_deny_applied() -> None:
    c = Collector.__new__(Collector)
    c.notes = []
    raw = rbcd_sd([f"{DOM}-1", f"{DOM}-2"], [f"{DOM}-2"])
    got = c._rbcd_principals({"msds-allowedtoactonbehalfofotheridentity": [raw]})
    assert got == [f"{DOM}-1"] and c.notes == []


def test_malformed_list_is_unknown_and_noted() -> None:
    c = Collector.__new__(Collector)
    c.notes = []
    e = {"msds-allowedtoactonbehalfofotheridentity": [b"\x01" * 30], "samaccountname": [b"FS01$"]}
    assert c._rbcd_principals(e) is None
    assert "could not be parsed" in c.notes[0] and c.notes[0].startswith("FS01$")


def test_redact_covers_the_list() -> None:
    target = rbcd_target(f"{DOM}-4000")
    snap = domain(user("svc_spn", spns=["http/web.lab.test"], sid=f"{DOM}-4000"), target)
    out = redact(snap.to_json(), b"key")
    listed = [a["rbcd_principals"] for a in out["accounts"] if a.get("rbcd_principals")]
    assert listed and not any(DOM in s for s in listed[0])
    assert all(s.startswith("S-1-5-21-") for s in listed[0])
