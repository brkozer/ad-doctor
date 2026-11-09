"""Regressions from the review of the delegation and certificate edges."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ad_doctor import changes, cut, fixes, paths, planfile, sd, whatif
from ad_doctor.checks import EKU_ANY
from ad_doctor.cli import main
from ad_doctor.model import UAC, CaConfig, DirObject, Gmsa, Snapshot
from ad_doctor.resolve import Resolver

from .test_acl_adcs import template
from .test_checks import computer, user
from .test_delegation_edges import CIFS, account, domain, kcd, out_of, server
from .test_gpo_local import DOM
from .whatif_fixtures import OID, adcs_snapshot, delegation_snapshot, enroll

DU = f"{DOM}-513"
DG = f"{DOM}-514"
DC = f"{DOM}-515"
ENTRY = ("cifs/app01.lab.test",)


def listing(*sids: str) -> Any:
    """A domain controller (tier 0, so paths count) whose resource-based list holds these."""
    target = computer("DC9", 0x2000, sid=f"{DOM}-4900", spns=["HOST/dc9.lab.test"])
    target.rbcd, target.rbcd_principals = True, list(sids)
    return target


def plain() -> Any:
    return user("plainuser", sid=f"{DOM}-4001")


def workstation() -> Any:
    return computer("WS01", sid=f"{DOM}-4002", spns=["HOST/ws01.lab.test"])


def group(sid: str, *members: str, name: str = "Team") -> DirObject:
    return DirObject(f"CN={name},DC=lab,DC=test", name, "group", sid=sid, members=list(members))


def rbcd_edges(snap: Snapshot, target: Any) -> set[str]:
    want = (f"sid:{target.sid}", paths.RESOURCE_BASED)
    return {src for src, outs in paths.build(snap).edges.items() if want in outs}


# -- who can run S4U2self -------------------------------------------------------------------


def test_a_group_gives_the_edge_to_the_members_that_can_run_s4u() -> None:
    target = listing(f"{DOM}-5000")
    p, ws = plain(), workstation()
    snap = domain(p, ws, target, objects=[group(f"{DOM}-5000", p.dn, ws.dn)])
    assert rbcd_edges(snap, target) == {f"sid:{ws.sid}"}
    a = paths.analyze(snap)
    assert f"sid:{p.sid}" not in paths.paths_to_tier0(a.graph)
    assert a.exposed == 0


def test_nested_members_get_the_edge_and_a_loop_ends() -> None:
    target = listing(f"{DOM}-5000")
    p, ws = plain(), workstation()
    inner = group(f"{DOM}-5001", ws.dn, "CN=Team,DC=lab,DC=test", name="Inner")
    outer = group(f"{DOM}-5000", p.dn, inner.dn)
    assert rbcd_edges(domain(p, ws, target, objects=[outer, inner]), target) == {f"sid:{ws.sid}"}


def test_a_listed_user_without_an_spn_has_no_path_directly_or_through_a_group() -> None:
    target = listing(f"{DOM}-5000")
    p = plain()
    assert rbcd_edges(domain(p, target, objects=[group(f"{DOM}-5000", p.dn)]), target) == set()
    alone = listing(p.sid)
    assert rbcd_edges(domain(p, alone), alone) == set()


@pytest.mark.parametrize("quota", [0, 10])
def test_domain_users_counts_only_its_spn_holders(quota: int) -> None:
    target = listing(DU)
    p = plain()
    held = user("svc_spn", sid=f"{DOM}-4003", spns=["http/s.lab.test"])
    snap = domain(p, held, workstation(), target)
    snap.policy.machine_account_quota = quota
    assert rbcd_edges(snap, target) == {f"sid:{held.sid}"}
    a = paths.analyze(snap)
    assert a.broad == [] and "every user" not in (paths.tier0_paths(snap) or _none).detail
    assert f"sid:{p.sid}" not in paths.paths_to_tier0(a.graph)


class _none:  # no finding at all also means no claim
    detail = ""


def test_domain_users_with_no_spn_holder_has_no_edge() -> None:
    target = listing(DU)
    snap = domain(plain(), target)
    snap.policy.machine_account_quota = 10
    assert rbcd_edges(snap, target) == set()
    assert paths.tier0_paths(snap) is None


@pytest.mark.parametrize("broad", ["S-1-5-11", "S-1-1-0"])
def test_every_logon_needs_the_quota_or_an_account_that_can_run_s4u(broad: str) -> None:
    target = listing(broad)
    snap = domain(plain(), target)
    assert rbcd_edges(snap, target) == set()  # quota 0: only the target itself could
    snap.policy.machine_account_quota = 10
    assert rbcd_edges(snap, target) == {f"sid:{broad}"}
    assert paths.analyze(snap).exposed == 1


def test_every_logon_at_quota_zero_gives_the_edge_to_enabled_holders_only() -> None:
    target = listing("S-1-5-11")
    ws = workstation()
    off = computer("OLD01", 0x1000 | UAC.ACCOUNTDISABLE, sid=f"{DOM}-4004")
    p = plain()
    snap = domain(p, ws, off, target)
    assert rbcd_edges(snap, target) == {f"sid:{ws.sid}"}
    a = paths.analyze(snap)
    assert a.broad == [] and a.exposed == 0


def test_domain_computers_qualifies() -> None:
    target = listing(DC)
    assert rbcd_edges(domain(target), target) == {f"sid:{DC}"}


@pytest.mark.parametrize("sid", ["S-1-5-7", DG])
@pytest.mark.parametrize("quota", [0, 10])
def test_anonymous_and_guests_never_qualify(sid: str, quota: int) -> None:
    target = listing(sid)
    snap = domain(workstation(), target)
    snap.policy.machine_account_quota = quota
    assert rbcd_edges(snap, target) == set()


def test_a_broad_group_nested_in_a_listed_group_follows_the_same_rule() -> None:
    target = listing(f"{DOM}-5000")
    fsp = "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=lab,DC=test"
    snap = domain(workstation(), target, objects=[group(f"{DOM}-5000", fsp)])
    assert rbcd_edges(snap, target) == {f"sid:{DOM}-4002"}
    snap.policy.machine_account_quota = 10
    assert rbcd_edges(snap, target) == {"sid:S-1-5-11"}


def test_a_member_leaving_the_listed_group_closes_its_edge_in_what_if() -> None:
    target = listing(f"{DOM}-5000")
    ws = workstation()
    team = group(f"{DOM}-5000", ws.dn)
    snap = domain(ws, target, objects=[team])
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    p = g.prov.prim(("member", team.dn.lower(), ws.dn.lower()))
    assert not whatif.maskable(g.prov, [p])
    res = whatif.run(snap, g, [p], paths_only=True)
    assert f"sid:{ws.sid}" not in res.after.graph.edges


def test_the_listing_of_a_group_is_one_change_for_all_its_members() -> None:
    target = listing(f"{DOM}-5000")
    one, two = workstation(), computer("WS02", sid=f"{DOM}-4005", spns=["HOST/ws02.lab.test"])
    snap = domain(one, two, target, objects=[group(f"{DOM}-5000", one.dn, two.dn)])
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    p = g.prov.index[("rbcd-principal", target.dn.lower(), f"{DOM}-5000")]
    view = whatif.masked(g, snap, [p])
    assert not any(h == paths.RESOURCE_BASED for o in view.edges.values() for _, h in o)
    m = cut.build_model(snap, g, {f"sid:{one.sid}": 1, f"sid:{two.sid}": 1})
    flow, chosen = cut.min_cut(m)
    assert m.inexact == 0 and cut.decode(m, flow) == 1 and len(chosen) == 1


# -- ESC13 on a CA that holds requests --------------------------------------------------------


def esc13_edges(snap: Snapshot) -> list[tuple[str, str]]:
    return [e for o in paths.build(snap).edges.values() for e in o if e[1] == paths.ENROLL_ESC13]


def test_esc13_is_gone_when_the_only_ca_holds_every_request() -> None:
    snap = adcs_snapshot()
    assert esc13_edges(snap)
    snap.probes.ca_configs[0].request_disposition = sd.REQDISP_PENDING
    assert esc13_edges(snap) == []


def test_esc13_stays_while_another_ca_issues_or_a_ca_was_not_read() -> None:
    snap = adcs_snapshot()
    snap.probes.ca_configs[0].request_disposition = sd.REQDISP_PENDING
    snap.ca_hosts = ["CA01$", "CA02$"]  # the second CA's configuration was not read
    assert esc13_edges(snap)
    snap.probes.ca_configs.append(CaConfig("other", "ca02.lab.test", request_disposition=1))
    assert esc13_edges(snap)
    snap.probes.ca_configs[1].request_disposition = sd.REQDISP_PENDING
    assert esc13_edges(snap) == []
    snap.probes.ca_configs[0].request_disposition = None  # unread on one: not known to hold
    assert esc13_edges(snap)


# -- who can be impersonated ------------------------------------------------------------------


def rodc_domain(writable: bool = True) -> tuple[Snapshot, Any]:
    svc = kcd(["cifs/rodc1.lab.test"])
    svc.sid = f"{DOM}-5004"
    rodc = computer(
        "RODC1",
        UAC.WORKSTATION_TRUST_ACCOUNT | UAC.PARTIAL_SECRETS_ACCOUNT,
        sid=f"{DOM}-5006",
        spns=["HOST/rodc1.lab.test"],
    )
    extra = (
        [computer("DC1", UAC.SERVER_TRUST_ACCOUNT, sid=f"{DOM}-1000", spns=["HOST/dc1.lab.test"])]
        if writable
        else []
    )
    return domain(svc, rodc, *extra), svc


def test_a_writable_dc_account_does_not_open_an_rodc() -> None:
    snap, svc = rodc_domain()
    assert out_of(snap, svc.sam)  # a delegable Domain Admin still does
    account(snap, "da1").uac |= UAC.NOT_DELEGATED
    assert out_of(snap, svc.sam) == []


def test_an_rodc_opens_for_an_administrator_or_enterprise_admin() -> None:
    snap, svc = rodc_domain()
    account(snap, "da1").uac |= UAC.NOT_DELEGATED
    other = user("ea1", sid=f"{DOM}-3901")
    snap.accounts.append(other)
    snap.privileged["Enterprise Admins"] = [other.dn]
    assert out_of(snap, svc.sam)


def test_a_writable_dc_still_opens_through_its_own_account() -> None:
    dc = computer(
        "DC01", 0x2000 | UAC.TRUSTED_FOR_DELEGATION, sid=f"{DOM}-1000", spns=["ldap/dc01.lab.test"]
    )
    snap = domain(kcd(["ldap/dc01.lab.test"]), dc)
    account(snap, "da1").uac |= UAC.NOT_DELEGATED
    assert out_of(snap, "svc")


@pytest.mark.parametrize(("level", "edge"), [(5, True), (6, False), (7, False), (10, False)])
def test_protected_users_counts_from_the_2012_r2_level(level: int, edge: bool) -> None:
    snap = domain(kcd([CIFS]), server())
    snap.protected_users = [account(snap, "da1").dn]
    snap.policy.functional_level = level
    assert bool(out_of(snap, "svc")) is edge


@pytest.mark.parametrize("level", [5, 6, 10])
def test_sensitive_accounts_stay_out_at_every_level(level: int) -> None:
    snap = domain(kcd([CIFS]), server())
    account(snap, "da1").uac |= UAC.NOT_DELEGATED
    snap.policy.functional_level = level
    assert out_of(snap, "svc") == []


# -- fix lines that write a whole list ---------------------------------------------------------


def written(line: str) -> list[str]:
    """The list a Set-AD* line leaves behind."""
    value = line.split("-PrincipalsAllowed", 1)[1].split(" ", 1)[1].removesuffix(" -WhatIf")
    return [] if value == "$null" else [v.strip().strip("'") for v in value.split(",")]


def rbcd_facts(snap: Snapshot, g: paths.Graph, *more: tuple[str, ...]) -> tuple[list[int], Any]:
    assert g.prov is not None
    app = account(snap, "APP01$")
    keys = [("rbcd-principal", app.dn.lower(), s) for s in app.rbcd_principals or []]
    prims = [g.prov.index[k] for k in keys] + [g.prov.index[k] for k in more]
    return prims, changes.facts(snap, g.prov, changes.Where(snap, g.prov), prims)


def test_two_principals_of_one_computer_are_both_gone_after_the_fix_lines() -> None:
    snap = delegation_snapshot()
    g = paths.build(snap, provenance=True)
    original = list(account(snap, "APP01$").rbcd_principals or [])
    prims, facts = rbcd_facts(snap, g)
    for p in prims:
        assert written(fixes.change_lines(facts[p], snap)[0]) == []
    for order in (prims, list(reversed(prims))):
        final: list[str] = []
        for p in order:
            final = written(fixes.rollback_lines(facts[p], snap)[0])
        assert final == original


def test_one_principal_of_two_keeps_the_other_in_the_fix_line() -> None:
    snap = delegation_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    app = account(snap, "APP01$")
    first, second = app.rbcd_principals or []
    p = g.prov.index[("rbcd-principal", app.dn.lower(), first)]
    facts = changes.facts(snap, g.prov, changes.Where(snap, g.prov), [p])
    assert written(fixes.change_lines(facts[p], snap)[0]) == [second]
    assert sorted(written(fixes.rollback_lines(facts[p], snap)[0])) == sorted([first, second])


def test_a_principal_change_does_not_write_back_a_cleared_attribute() -> None:
    snap = delegation_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    app = account(snap, "APP01$")
    clear = ("delegation", app.dn.lower(), "rbcd")
    first = (app.rbcd_principals or [])[0]
    p = g.prov.index[("rbcd-principal", app.dn.lower(), first)]
    q = g.prov.index[clear]
    facts = changes.facts(snap, g.prov, changes.Where(snap, g.prov), [p, q])
    assert written(fixes.change_lines(facts[p], snap)[0]) == []
    assert "-Clear" in fixes.change_lines(facts[q], snap)[0]


def test_two_gmsa_readers_are_both_gone_after_the_fix_lines() -> None:
    a, b, c = f"{DOM}-1108", f"{DOM}-3999", f"{DOM}-4000"
    gm = Gmsa("svc_gmsa", "CN=svc_gmsa,CN=Managed Service Accounts,DC=lab,DC=test", [a, b, c])
    snap = domain(gmsas=[gm])
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    prims = [g.prov.index[("gmsa-reader", gm.dn.lower(), s)] for s in (a, b)]
    facts = changes.facts(snap, g.prov, changes.Where(snap, g.prov), prims)
    for p in prims:
        assert written(fixes.change_lines(facts[p], snap)[0]) == [c]
        assert sorted(written(fixes.rollback_lines(facts[p], snap)[0])) == sorted([a, b, c])


# -- require-approval closes both gates of a template --------------------------------------------


def enrollers(count: int) -> list[Any]:
    return [user(f"u{i}", sid=f"{DOM}-{6000 + i}") for i in range(count)]


def esc_snapshot(count: int, edit_flags: int = sd.EDITF_ATTRIBUTESUBJECTALTNAME2) -> Snapshot:
    snap = adcs_snapshot()
    people = enrollers(count)
    snap.accounts += people
    snap.oid_group_links = {}
    snap.templates = [
        template("T", enrollee_supplies_subject=True, aces=[enroll(p.sid) for p in people])
    ]
    snap.probes.ca_configs[0].edit_flags = edit_flags
    return snap


def flag_key(g: paths.Graph) -> int:
    assert g.prov is not None
    return g.prov.index[("template-flag", "T", "require-approval")]


def test_one_template_flag_beats_every_enroller_when_it_closes_both_gates() -> None:
    snap = esc_snapshot(11)
    g = paths.build(snap, provenance=True)
    plan = cut.plan(snap, g)
    assert plan.exact and plan.proven and plan.cost == 10
    assert [g.prov.prims[p] for p in plan.changes] == [  # type: ignore[union-attr]
        ("template-flag", "T", "require-approval")
    ]


@pytest.mark.parametrize(("goal", "cost"), [("exposure", 10), ("all-paths", 11)])
def test_the_minimum_matches_brute_force_above_the_flag_cost(goal: str, cost: int) -> None:
    snap = esc_snapshot(11)
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    m = cut.build_model(snap, g, cut.sources_for(snap, g, goal))
    flow, chosen = cut.min_cut(m)
    assert m.inexact == 0
    flags = [p for p in m.prim_arc if g.prov.prims[p][0] != "template-ace"]
    best = cut.brute_force_minimum(m, flags, 3)
    assert best is not None and cut.decode(m, flow) == best[0] == cost  # all-paths: Linked too
    assert cut.closes(m, chosen)


def test_a_kept_enroller_does_not_hide_the_cheaper_flag() -> None:
    snap = esc_snapshot(2)
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    kept = g.prov.index[("template-ace", "T", f"{DOM}-6000")]
    plan = cut.plan(snap, g, keeps={kept: "kept"})
    assert plan.cost == 10
    assert [g.prov.prims[p][:2] for p in plan.changes] == [("template-flag", "T")]


def test_without_esc6_the_flag_is_still_the_plan() -> None:
    snap = esc_snapshot(11, edit_flags=0)
    g = paths.build(snap, provenance=True)
    plan = cut.plan(snap, g)
    assert plan.proven and plan.cost == 10


def test_routes_after_the_flag_are_zero_like_a_rebuild() -> None:
    snap = esc_snapshot(11)
    g = paths.build(snap, provenance=True)
    m = cut.build_model(snap, g, cut.sources_for(snap, g, "exposure"))
    assert cut.routes(m, [flag_key(g)]) == 0


def test_routes_are_right_for_a_flag_the_network_leaves_out() -> None:
    snap = adcs_snapshot()
    snap.templates = [
        template("LinkedA", issuance_policies=[OID], aces=[enroll(f"{DOM}-3300")]),
    ]
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    m = cut.build_model(snap, g, {f"sid:{DOM}-3300": 1})
    p = g.prov.index[("template-flag", "LinkedA", "require-approval")]
    assert p in m.dropped and m.inexact == 0
    assert cut.routes(m, [p]) == 0
    assert cut.closes(m, [p])


def test_two_templates_after_a_shared_ca_flag_are_not_called_exact() -> None:
    snap = esc_snapshot(2)
    extra = [user(f"v{i}", sid=f"{DOM}-{6100 + i}") for i in range(2)]
    snap.accounts += extra
    snap.templates.append(
        template("T2", enrollee_supplies_subject=True, aces=[enroll(p.sid) for p in extra])
    )
    g = paths.build(snap, provenance=True)
    m = cut.build_model(snap, g, cut.sources_for(snap, g, "all-paths"))
    assert m.inexact > 0


# -- SPN case ----------------------------------------------------------------------------------


def case_snapshot() -> Snapshot:
    snap = delegation_snapshot()
    account(snap, "svc_kcd").allowed_to_delegate_to = list(ENTRY)
    return snap


def test_a_spec_in_another_case_is_the_entry_the_account_holds() -> None:
    snap = case_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    got = Resolver(snap, g).resolve("delegation:svc_kcd:constrained:CIFS/APP01.lab.test")
    assert got.status == "applied"
    assert g.prov.prims[got.prims[0]][2] == "constrained:cifs/app01.lab.test"
    res = whatif.run(snap, g, got.prims)
    assert res.findings_rechecked  # the two levels agree: no model mismatch
    assert res.after.exposed == res.before.exposed - 1


def test_a_spec_for_an_entry_the_account_does_not_hold_stays_as_typed() -> None:
    snap = case_snapshot()
    g = paths.build(snap, provenance=True)
    got = Resolver(snap, g).resolve("delegation:svc_kcd:constrained:CIFS/other.lab.test")
    assert got.status == "absent"


def test_a_plan_file_in_another_case_resolves_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = case_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap.to_json()))
    key = next(k for k in g.prov.prims if k[0] == "delegation" and "constrained" in k[2])
    typed = (key[0], key[1], key[2].upper().replace("CONSTRAINED", "constrained"))
    plan = tmp_path / "plan.toml"
    plan.write_text(planfile.dumps(planfile.PlanFile(changes=[planfile.entry_for(typed, "x")])))
    code = main(["whatif", str(path), "--plan", str(plan), "-f", "json"])
    out = capsys.readouterr()
    assert code == 0, out.err
    doc = json.loads(out.out)
    assert [c["edges_removed"] for c in doc["changes"]] == [1]


# -- what a change takes away ----------------------------------------------------------------


def counts_of(snap: Snapshot, g: paths.Graph, *keys: tuple[str, ...]) -> dict[str, tuple[int, int]]:
    from ad_doctor.whatif_cmd import _edge_counts

    assert g.prov is not None
    prims = [g.prov.index[k] for k in keys]
    got = _edge_counts(g, whatif.state(snap, g), prims)
    return {g.prov.prims[p][-1]: got[p][:2] for p in prims}


def test_a_change_that_closes_a_gate_counts_the_edges_of_the_gate() -> None:
    snap = delegation_snapshot()
    g = paths.build(snap, provenance=True)
    dn = account(snap, "APP01$").dn.lower()
    assert counts_of(snap, g, ("delegation", dn, "rbcd")) == {"rbcd": (2, 2)}
    svc = account(snap, "svc_kcd").dn.lower()
    assert counts_of(snap, g, ("delegation", svc, "protocol-transition")) == {
        "protocol-transition": (2, 2)
    }


def test_flags_count_the_edges_they_close_and_a_prim_only_its_own() -> None:
    snap = adcs_snapshot()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    got = counts_of(
        snap,
        g,
        ("ca-flag", "lab-CA", "no-sid-extension"),
        ("oid-link", OID, "cn=linked,ou=lab,dc=lab,dc=test"),
    )
    assert got["no-sid-extension"][0] > 0
    assert got["cn=linked,ou=lab,dc=lab,dc=test"][0] > 0


def test_a_flag_that_leaves_the_gate_open_takes_no_edges() -> None:
    snap = esc_snapshot(2)
    snap.templates[0].ekus = [EKU_ANY, "1.3.6.1.5.5.7.3.2"]
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    # the template still authenticates through the other EKU, so its ESC6 gate stays open
    key = g.prov.prim(("template-flag", "T", "any-purpose-eku"))
    assert prov_open(g, key)
    assert counts_of(snap, g, ("template-flag", "T", "any-purpose-eku"))["any-purpose-eku"][0] == 0


def prov_open(g: paths.Graph, flag: int) -> bool:
    assert g.prov is not None
    return all(
        g.prov.gate_open(i, {flag})
        for i in range(len(g.prov.gates))
        if flag in g.prov.gates[i].flags
    )


def test_the_cli_field_matches_the_before_and_after(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = delegation_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap.to_json()))
    code = main(["whatif", str(path), "--remove", "delegation:APP01$:rbcd", "-f", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["changes"][0]["edges_removed"] == 2 and doc["changes"][0]["edges_on_paths"] == 2


def test_fix_list_helper_reads_null() -> None:
    line = "Set-ADComputer -Identity 'x' -PrincipalsAllowedToDelegateToAccount $null -WhatIf"
    assert written(line) == []
