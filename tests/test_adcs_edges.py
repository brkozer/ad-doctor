"""ESC6 and ESC13 edges of the control graph, what they leave out, and their what-if changes."""

from __future__ import annotations

import pytest

from ad_doctor import changes, cut, fixes, opengraph, paths, planfile, sd, whatif
from ad_doctor.checks import run_all, san_note
from ad_doctor.model import CaConfig, Snapshot
from ad_doctor.provenance import Gated
from ad_doctor.resolve import Resolver, finding_specs
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_USERS, template
from .whatif_fixtures import (
    CLIENT_AUTH,
    OID,
    SERVER_AUTH,
    adcs_snapshot,
    parity,
    random_sets,
)

GROUP = "S-1-5-21-1-2-3-3400"
ESC_USER = "sid:S-1-5-21-1-2-3-3300"
ESC_OTHER = "sid:S-1-5-21-1-2-3-3301"
ESC6_USER = "sid:S-1-5-21-1-2-3-3302"
LINKED = f"sid:{GROUP}"
DU = f"sid:{DOMAIN_USERS}"
GROUP_DN = "cn=linked,ou=lab,dc=lab,dc=test"


def built() -> tuple[Snapshot, paths.Graph]:
    snap = adcs_snapshot()
    return snap, paths.build(snap, provenance=True)


def out_of(snap: Snapshot, node: str) -> list[tuple[str, str]]:
    return paths.build(snap).edges.get(node, [])


def only_template(*templates: object, **ca: object) -> Snapshot:
    snap = adcs_snapshot()
    snap.templates = list(templates)  # type: ignore[arg-type]
    for key, value in ca.items():
        setattr(snap.probes.ca_configs[0], key, value)
    return snap


def key_of(g: paths.Graph, *key: str) -> int:
    assert g.prov is not None
    return g.prov.index[tuple(key)]


# -- ESC13 -------------------------------------------------------------------------------


def test_esc13_enrollee_becomes_the_linked_group() -> None:
    snap = only_template(template("T", issuance_policies=[OID]))
    snap.probes.ca_configs.clear()
    assert out_of(snap, DU) == [(LINKED, paths.ENROLL_ESC13)]
    found = paths.paths_to_tier0(paths.build(snap))
    assert found[DU].steps[0] == (LINKED, paths.ENROLL_ESC13)


@pytest.mark.parametrize(
    "kw",
    [
        {"published": False},
        {"manager_approval": True},
        {"authorized_signatures": 1},
        {"ekus": [SERVER_AUTH]},
        {"issuance_policies": ["1.2.3"]},
    ],
)
def test_esc13_needs_a_logon_certificate_issued_on_request(kw: dict[str, object]) -> None:
    values: dict[str, object] = {"issuance_policies": [OID], **kw}
    snap = only_template(template("T", **values))
    assert all(how != paths.ENROLL_ESC13 for _, how in out_of(snap, DU))


def test_autoenroll_alone_requests_no_certificate() -> None:
    aces = [Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, sd.CERT_AUTOENROLL)]
    snap = only_template(template("T", issuance_policies=[OID], aces=aces))
    assert out_of(snap, DU) == []


def test_a_group_nobody_can_use_gives_no_path_to_tier0() -> None:
    snap = only_template(template("T", issuance_policies=[OID]))
    snap.probes.ca_configs.clear()
    snap.objects = [o for o in snap.objects if o.name != "Domain Admins"]
    g = paths.build(snap)
    assert g.edges[DU] == [(LINKED, paths.ENROLL_ESC13)]
    assert LINKED not in paths.paths_to_tier0(g)


# -- ESC6 with ESC16 ----------------------------------------------------------------------


def edge_to(name: str) -> tuple[str, str]:
    return (f"tier0:template:{name}", paths.ENROLL_ESC6)


def test_esc6_with_esc16_needs_an_authentication_template() -> None:
    client = template("Client", ekus=[CLIENT_AUTH])
    server = template("Server", ekus=[SERVER_AUTH])
    any_purpose = template("Any", ekus=[])
    snap = only_template(client, server, any_purpose)
    esc6 = {e for e in out_of(snap, DU) if e[1] == paths.ENROLL_ESC6}
    assert esc6 == {edge_to("Client"), edge_to("Any")}


@pytest.mark.parametrize(
    "ca",
    [
        {"edit_flags": 0},
        {"edit_flags": None},
        {"disabled_extensions": []},
        {"disabled_extensions": None},
        {"request_disposition": 0x100},
    ],
)
def test_esc6_needs_every_flag_and_no_manager(ca: dict[str, object]) -> None:
    assert out_of(only_template(template("Client"), **ca), DU) == []


def test_esc6_alone_is_blocked_by_strong_mapping() -> None:
    assert out_of(only_template(template("Client"), disabled_extensions=[]), DU) == []


@pytest.mark.parametrize("hosts", [["CA01$", "CA02$"], []])
def test_more_than_one_ca_gives_no_esc6_edge(hosts: list[str]) -> None:
    snap = only_template(template("Client"))
    snap.ca_hosts = hosts
    assert out_of(snap, DU) == []
    if hosts:
        assert "does not say which CA" in san_note(snap)[0]


def test_two_configs_give_no_esc6_edge_and_a_note() -> None:
    snap = only_template(template("Client"))
    snap.probes.ca_configs.append(CaConfig("other", "ca02.lab.test"))
    assert out_of(snap, DU) == []
    assert "lab-CA" in san_note(snap)[0]


def test_one_ca_needs_no_note_and_clean_cas_none_either() -> None:
    assert san_note(adcs_snapshot()) == []
    snap = adcs_snapshot()
    snap.probes.ca_configs[0].edit_flags = 0
    snap.ca_hosts = ["CA01$", "CA02$"]
    assert san_note(snap) == []


# -- what is left out ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "t",
    [
        template("Esc9", no_security_extension=True),
        template("Esc15", schema_version=1, enrollee_supplies_subject=True, ekus=[SERVER_AUTH]),
    ],
    ids=["esc9", "esc15"],
)
def test_esc9_and_esc15_are_no_edges(t: object) -> None:
    assert out_of(only_template(t, edit_flags=0), DU) == []


# -- what-if -------------------------------------------------------------------------------


def test_edges_have_the_facts_behind_them() -> None:
    _, g = built()
    assert g.prov is not None
    for src in (ESC_USER, ESC_OTHER, ESC6_USER):
        assert {g.prov.prims[p][0] for p in g.prov.why[src]} == {"template-ace"}
        assert all(isinstance(g.prov.extra[(src, i)], Gated) for i in range(len(g.edges[src])))
    link = key_of(g, "oid-link", OID, GROUP_DN)
    san, nosid = (
        key_of(g, "ca-flag", "lab-CA", f) for f in ("san-from-request", "no-sid-extension")
    )
    assert {link, san, nosid} <= {f for gate in g.prov.gates for f in gate.flags}


def test_every_change_of_the_fixture_masks_like_a_rebuild() -> None:
    snap, g = built()
    assert g.prov is not None
    result = parity(snap, [[p] for p in range(len(g.prov.prims))], g)
    assert result["differs"] == []
    for kind in ("template-ace", "template-flag", "oid-link", "ca-flag"):
        assert any(kind in k for k in result["equal"]), kind
    sets = random_sets(len(g.prov.prims), 200, 3)
    assert parity(snap, sets, g)["differs"] == []


def test_removing_the_link_closes_every_template_of_the_policy() -> None:
    snap, g = built()
    assert g.prov is not None
    p = key_of(g, "oid-link", OID, GROUP_DN)
    view = whatif.masked(g, snap, [p])
    assert ESC_USER not in [
        s for s, outs in view.edges.items() if (LINKED, paths.ENROLL_ESC13) in outs
    ]
    assert (LINKED, paths.ENROLL_ESC13) not in view.edges.get(ESC_OTHER, [])
    assert (edge_to("LinkedA")[0], paths.ENROLL_ESC6) in view.edges[ESC_OTHER]
    gone = changes.apply(snap, g.prov, [p])
    assert gone[p] == 1 and snap.oid_group_links == {}


def test_clearing_either_ca_flag_closes_every_esc6_edge() -> None:
    for flag in ("san-from-request", "no-sid-extension"):
        snap, g = built()
        assert g.prov is not None
        p = key_of(g, "ca-flag", "lab-CA", flag)
        view = whatif.masked(g, snap, [p])
        assert ESC6_USER not in view.edges
        assert (LINKED, paths.ENROLL_ESC13) in view.edges[ESC_OTHER]
        assert changes.apply(snap, g.prov, [p])[p] == 1
    snap, g = built()
    c = snap.probes.ca_configs[0]
    assert g.prov is not None
    changes.apply(snap, g.prov, [key_of(g, "ca-flag", "lab-CA", "no-sid-extension")])
    assert c.disabled_extensions == []
    assert c.edit_flags == sd.EDITF_ATTRIBUTESUBJECTALTNAME2


def test_template_flag_closes_only_that_template() -> None:
    snap, g = built()
    assert g.prov is not None
    p = key_of(g, "template-flag", "LinkedA", "require-approval")
    view = whatif.masked(g, snap, [p])
    assert all(d != LINKED and "LinkedA" not in d for d, _ in view.edges.get(ESC_USER, []))
    assert (LINKED, paths.ENROLL_ESC13) in view.edges[ESC_OTHER]  # through LinkedB


def test_level1_and_level2_agree_for_the_new_kinds() -> None:
    for kind in ("oid-link", "ca-flag"):
        snap, g = built()
        assert g.prov is not None
        p = next(i for i, k in enumerate(g.prov.prims) if k[0] == kind)
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


def test_cut_picks_a_ca_flag_over_every_enrollee() -> None:
    snap, g = built()
    assert g.prov is not None
    m = cut.build_model(snap, g, {ESC_USER: 1, ESC_OTHER: 1, ESC6_USER: 1})
    _, chosen = cut.min_cut(m)
    kinds = sorted(g.prov.prims[p][0] for p in chosen)
    # the group's ACE on Domain Admins (cost 1) is cheaper than unlinking the policy (cost 3)
    assert kinds == ["ace", "ca-flag"]


def test_a_kept_flag_is_no_cut() -> None:
    snap, g = built()
    assert g.prov is not None
    keeps = {
        key_of(g, "ca-flag", "lab-CA", "san-from-request"): "kept",
        key_of(g, "ca-flag", "lab-CA", "no-sid-extension"): "kept",
        key_of(g, "template-flag", "Plain", "require-approval"): "kept",
    }
    m = cut.build_model(snap, g, {ESC6_USER: 1}, keeps)
    _, chosen = cut.min_cut(m)
    assert [g.prov.prims[p] for p in chosen] == [("template-ace", "Plain", ESC6_USER[4:])]


def test_specs_resolve_and_plan_file_round_trip() -> None:
    snap, g = built()
    assert g.prov is not None
    r = Resolver(snap, g)
    got = r.resolve(f"oid-link:{OID}")
    assert g.prov.prims[got.prims[0]] == ("oid-link", OID, GROUP_DN)
    got = r.resolve("ca-flag:lab-CA:no-sid-extension")
    assert g.prov.prims[got.prims[0]] == ("ca-flag", "lab-CA", "no-sid-extension")
    assert r.resolve("oid-link:1.2.3").status == "absent"
    assert r.resolve("ca-flag:other:san-from-request").status == "absent"
    for key in g.prov.prims:
        if key[0] in ("oid-link", "ca-flag"):
            entry = planfile.entry_for(key, "label")
            back = planfile.loads(planfile.dumps(planfile.PlanFile(changes=[entry])))
            assert back.changes[0].prim == key and back.changes[0].id == entry.expected_id
    assert r.anchor_exists(("oid-link", OID, GROUP_DN))
    assert r.exists(("ca-flag", "lab-CA", "san-from-request"))
    bad = ("ca-flag", "lab-CA", "typo")
    problem = r.entry_problem(bad)
    assert problem is not None and "unknown CA flag" in problem


def test_findings_map_to_the_changes() -> None:
    assert finding_specs("AD-ADCS-012", "lab-CA") == ['ca-flag:"lab-CA":san-from-request']
    assert finding_specs("AD-ADCS-015", "lab-CA") == ['ca-flag:"lab-CA":no-sid-extension']
    assert finding_specs("AD-CHAIN-004", "lab-CA") == ['ca-flag:"lab-CA":san-from-request']


def test_fix_and_rollback_lines() -> None:
    snap, g = built()
    assert g.prov is not None
    where = changes.Where(snap, g.prov)
    prims = [key_of(g, "oid-link", OID, GROUP_DN)]
    prims += [key_of(g, "ca-flag", "lab-CA", f) for f in ("san-from-request", "no-sid-extension")]
    facts = changes.facts(snap, g.prov, where, prims)
    oid_fix = fixes.change_lines(facts[prims[0]], snap)[0]
    assert oid_fix.endswith("Set-ADObject -Identity $dn -Clear 'msDS-OIDToGroupLink' -WhatIf")
    assert f"(msPKI-Cert-Template-OID={OID})" in oid_fix
    oid_back = fixes.rollback_lines(facts[prims[0]], snap)[0]
    assert (
        "-Replace @{'msDS-OIDToGroupLink' = 'CN=Linked,OU=Lab,DC=lab,DC=test'} -WhatIf" in oid_back
    )
    san_fix = fixes.change_lines(facts[prims[1]], snap)
    assert "-band -bnot 0x40000" in san_fix[0] and san_fix[0].endswith("-WhatIf")
    assert "Restart-Service certsvc" in san_fix[1] and san_fix[1].startswith("#")
    nosid_fix = fixes.change_lines(facts[prims[2]], snap)[0]
    assert "DisableExtensionList" in nosid_fix and nosid_fix.endswith("-WhatIf")
    for p in prims:
        for line in fixes.rollback_lines(facts[p], snap):
            assert line.startswith("#") or line.endswith("-WhatIf")


def test_opengraph_kinds() -> None:
    assert opengraph.edge_kinds(paths.ENROLL_ESC13) == [("ADD_EnrollIssuancePolicyGroup", False)]
    assert opengraph.edge_kinds(paths.ENROLL_ESC6) == [("ADD_EnrollAnySubject", False)]


def test_only_the_paths_change_when_the_edges_appear() -> None:
    snap = adcs_snapshot()
    without = adcs_snapshot()
    without.oid_group_links = {}
    without.probes.ca_configs[0].edit_flags = 0
    without.probes.ca_configs[0].disabled_extensions = []

    def rows(s: Snapshot) -> dict[str, tuple[int, ...]]:
        return {f.check_id: tuple(sorted(hash(o) for o in f.objects)) for f in run_all(s)}

    before, after = rows(without), rows(snap)
    for check, objects in before.items():
        if check != "AD-PATH-001" and check not in ("AD-ADCS-007", "AD-ADCS-012", "AD-ADCS-015"):
            assert after[check] == objects, check
