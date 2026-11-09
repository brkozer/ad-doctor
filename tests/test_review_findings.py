"""Regression tests for the review of the key credential, GPO reach, ghost SPN and HTTPS
enrollment work: each test is a case a reviewer reproduced."""

from __future__ import annotations

import argparse
import http.client
import json
import random
import re
from typing import Any

import pytest

from ad_doctor import cli, gpo_scope, keycred, paths, probes, redact, report, sd
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector, Target
from ad_doctor.gpo_scope import FILTER_CAVEAT, SITE_CAVEAT
from ad_doctor.model import (
    DcProbe,
    DirObject,
    Finding,
    KeyCredential,
    Probes,
    Severity,
    Snapshot,
)
from ad_doctor.report import finding_keys, render_markdown, render_text

from .test_checks import NOW, computer, ids, only, snapshot, user
from .test_enrollment_https import CES, broken, collector, fake, run
from .test_gpo_local import (
    ADMINS,
    AU,
    DC_OU,
    DOM,
    GUID_A,
    HEAD,
    HELPDESK,
    LAB,
    dc,
    entry,
    gpo,
    host,
    link,
)
from .test_gpo_reach import FILTER_GROUP, OPEN, SITE, WRITE, gsnap, person, reach_of, writer
from .test_keycred import (
    DEVICE,
    MATERIAL,
    STRONG,
    WHEN,
    admin,
    admin_snapshot,
    blob,
    computer_blob,
    filetime,
    hello,
    row,
    value,
)
from .test_keycred import entry as key_entry
from .test_round6_data import DOMAIN, Recorder
from .test_trust_ghost import HOST_MAP, delegating, fs01, targets, trust

PROTOCOL_TRANSITION = 0x200 | 0x1000000
OTHER_DOMAIN_GROUP = "S-1-5-21-9-9-9-1500"
READ_APPLY = 0x20094 | sd.CONTROL_ACCESS


def shaped(material: bytes = MATERIAL, *extra: bytes) -> KeyCredential:
    parts = (
        key_entry(3, material),
        key_entry(4, b"\x01"),
        key_entry(5, b"\x00"),
        key_entry(9, filetime(WHEN)),
    )
    return keycred.parse_blob(blob(*parts, *extra))


def ca_host(*keys: KeyCredential) -> Snapshot:
    return snapshot(computer("CA01", key_credentials=list(keys)), ca_hosts=["CA01$"])


# --- AD-ACC-013: grades and identity ------------------------------------------------------


@pytest.mark.parametrize("uac", [0x2000, 0x04000000 | 0x1000])
def test_any_key_on_a_dc_is_high_and_not_labelled_as_its_own(uac: int) -> None:
    f = only(snapshot(computer("DC02", uac, laps=False, key_credentials=[shaped()])), "AD-ACC-013")
    assert f.severity is Severity.HIGH
    assert "computer key" not in f.objects[0]


def test_an_unreadable_key_on_a_dc_is_high() -> None:
    key = KeyCredential(readable=False, added=NOW)
    f = only(snapshot(computer("DC02", 0x2000, laps=False, key_credentials=[key])), "AD-ACC-013")
    assert f.severity is Severity.HIGH


def test_one_shaped_key_on_a_member_computer_stays_low() -> None:
    f = only(ca_host(shaped()), "AD-ACC-013")
    assert f.severity is Severity.LOW and f.objects[0].startswith("CA01$: computer key")


def test_two_keys_on_a_computer_are_high_and_stay_two_objects() -> None:
    f = only(ca_host(shaped(), shaped(bytes(200))), "AD-ACC-013")
    assert f.severity is Severity.HIGH and len(f.objects) == 2


def test_a_second_key_keeps_its_device_id_in_the_text() -> None:
    second = keycred.parse_blob(
        blob(key_entry(3, MATERIAL), key_entry(4, b"\x01"), key_entry(6, DEVICE.bytes_le))
    )
    f = only(ca_host(shaped(), second), "AD-ACC-013")
    assert any(str(DEVICE) in o for o in f.objects)


def test_two_identical_keys_are_still_two_objects() -> None:
    f = only(ca_host(KeyCredential(readable=False), KeyCredential(readable=False)), "AD-ACC-013")
    assert len(f.objects) == len(set(f.keys.values())) == 2


def test_custom_key_information_on_a_computer_is_not_called_abnormal() -> None:
    """DSInternals says Windows writes this entry on computer keys, against the spec."""
    key = shaped(MATERIAL, key_entry(7, b"\x01\x00"))
    assert key.custom_info and not key.self_written
    f = only(ca_host(key), "AD-ACC-013")
    assert f.severity is Severity.MEDIUM and "custom key information" in f.objects[0]


def test_a_device_id_on_a_computer_key_is_not_self_written() -> None:
    key = shaped(MATERIAL, key_entry(6, DEVICE.bytes_le))
    assert not key.self_written and not key.custom_info
    assert only(ca_host(key), "AD-ACC-013").severity is Severity.HIGH


def test_a_managed_account_gets_no_computer_key_grade() -> None:
    gmsa = computer("gmsa1", managed=True, key_credentials=[shaped()])
    snap = snapshot(gmsa, ca_hosts=["GMSA1$"])
    assert only(snap, "AD-ACC-013").severity is Severity.HIGH


def test_a_second_key_with_a_known_device_id_is_new() -> None:
    first = hello()
    first.key_id = "a" * 16
    second = hello()
    second.key_id = "b" * 16
    before = run_all(admin_snapshot(admin(key_credentials=[first])))
    after = run_all(admin_snapshot(admin(key_credentials=[first, second])))
    assert only_keys(after) - only_keys(before)


def test_a_second_mapping_of_the_same_shape_is_new() -> None:
    other = "X509:<I>DC=evil,CN=rogue-CA<SR>deadbeef"
    before = run_all(admin_snapshot(admin(alt_security_identities=[STRONG])))
    after = run_all(admin_snapshot(admin(alt_security_identities=[STRONG, other])))
    assert only_keys(after) - only_keys(before)
    (f,) = [x for x in after if x.check_id == "AD-ACC-013"]
    assert len(f.objects) == 2 and "rogue" not in " ".join(f.objects)


def only_keys(findings: list[Finding]) -> set[tuple[str, str]]:
    return {k for k in finding_keys(findings) if k[0] == "AD-ACC-013"}


def test_kerberos_mapping_has_its_own_words() -> None:
    a = admin(alt_security_identities=["Kerberos:bob@MIT.EXAMPLE"])
    f = only(admin_snapshot(a), "AD-ACC-013")
    assert "Kerberos name mapping" in f.objects[0]
    assert "other realm" in f.detail


def test_keys_on_ca_and_sync_servers_and_sync_accounts_are_reported() -> None:
    assert "AD-ACC-013" in ids(run_all(ca_host(hello())))
    msol = user("MSOL_0a", sync_host="SYNC01", key_credentials=[hello()])
    assert "MSOL_0a" in only(snapshot(msol), "AD-ACC-013").objects[0]
    server = computer("SYNC01", key_credentials=[hello()])
    f = only(snapshot(user("MSOL_0a", sync_host="SYNC01"), server), "AD-ACC-013")
    assert f.objects[0].startswith("SYNC01$")


def test_ca_and_sync_servers_are_read_for_keys() -> None:
    ca = computer("CA01")
    sync = computer("SYNC01")
    account = user("MSOL_0a", sync_host="SYNC01")
    plain = computer("WS01")
    c = Recorder({})
    c.ca_hosts = ["CA01$"]
    c._objects(DOMAIN, [ca, sync, account, plain], set())
    asked = {base for base, attrs in c.reads if keycred.ATTRIBUTE in attrs}
    assert asked == {ca.dn, sync.dn, account.dn}


def test_a_value_that_does_not_parse_leaves_the_metadata_rows_of_others_alone() -> None:
    good = value(computer_blob())
    prefix = computer_blob().hex()[:40]
    keys = keycred.read(["B:4:zz", good], row(data=prefix) + row(data="deadbeef"))
    assert len(keys) == 2
    assert all(k.added is not None for k in keys)
    assert [k.parsed for k in keys] == [False, True]


# --- GPO reach ----------------------------------------------------------------------------


def filtered_to(sid: str, *others: sd.Ace) -> list[sd.Ace]:
    return [sd.Ace(sid, READ_APPLY, sd.APPLY_GROUP_POLICY), *others]


def edges_of(g: paths.Graph) -> set[str]:
    return {how for outs in g.edges.values() for _, how in outs}


def linked_gpo(container: str, where: str, **kw: Any) -> list[Any]:
    g = gpo("Reach", GUID_A, link(container), **kw)
    g.linked_to = [where]
    return [g]


@pytest.mark.parametrize("flags", [2, 3])
def test_a_side_switched_off_keeps_its_way_into_tier_0(flags: int) -> None:
    for container, where in ((DC_OU, "Domain Controllers OU"), (HEAD, "domain")):
        snap = gsnap(dc(), gpos=linked_gpo(container, where, aces=OPEN, flags=flags), entries=[])
        g = paths.build(snap)
        assert f"linked to {where}" in edges_of(g)
        caveats = [c for p in g.edge_props.values() for c in p["caveats"]]
        assert "computer side disabled, the writer can enable it" in caveats


def test_a_path_shows_what_it_assumes() -> None:
    snap = gsnap(
        dc(), gpos=linked_gpo(DC_OU, "Domain Controllers OU", aces=OPEN, flags=2), entries=[]
    )
    g = paths.build(snap)
    text = paths.paths_to_tier0(g)[f"sid:{HELPDESK}"].render(g)
    assert "computer side disabled, the writer can enable it" in text
    assert report.PATH_STEP.split(text, 1)[0] == g.name(f"sid:{HELPDESK}")


def test_a_filter_on_another_domains_group_is_assumed_to_apply() -> None:
    gpos = writer(link(LAB), aces=filtered_to(OTHER_DOMAIN_GROUP, WRITE))
    snap = gsnap(
        host("SRV"), person("tier0admin"), gpos=gpos, entries=[], root_sid="S-1-5-21-9-9-9"
    )
    assert reach_of(snap) == {"SRV$", "tier0admin"}
    props = paths.build(snap).edge_props
    assert all(FILTER_CAVEAT in p["caveats"] for p in props.values()) and props


def test_a_filter_on_a_group_of_this_snapshot_is_still_judged() -> None:
    group = DirObject(f"CN=F,{LAB}", "F", "group", sid=FILTER_GROUP)
    snap = gsnap(
        host("SRV"),
        gpos=writer(link(LAB), aces=filtered_to(FILTER_GROUP, WRITE)),
        entries=[],
        objects=[group],
    )
    assert reach_of(snap) == set()
    assert gpo_scope.filter_note(snap) == []


def test_restricted_groups_survive_a_filter_on_another_domain() -> None:
    g = gpo("Grant", GUID_A, link(LAB), aces=filtered_to(OTHER_DOMAIN_GROUP))
    snap = gsnap(host("SRV"), gpos=[g], entries=[entry(GUID_A, ADMINS, HELPDESK)])
    (grant,) = gpo_scope.resolve(snap).grants
    assert FILTER_CAVEAT in grant.caveats


def test_an_unplaced_filter_group_keeps_the_dc_edge_and_names_the_gpo() -> None:
    aces = filtered_to("S-1-5-21-111-222-333-4444", WRITE)
    snap = gsnap(dc(), gpos=linked_gpo(DC_OU, "Domain Controllers OU", aces=aces), entries=[])
    g = paths.build(snap)
    assert "linked to Domain Controllers OU" in edges_of(g)
    assert FILTER_CAVEAT in str(g.edge_props)
    (note,) = gpo_scope.filter_note(snap)
    assert note.endswith(": Reach")


def test_whoever_can_rewrite_the_dacl_gets_past_a_filter() -> None:
    group = DirObject(f"CN=F,{LAB}", "F", "group", sid=FILTER_GROUP)
    desk = DirObject(f"CN=H,{LAB}", "H", "group", sid=HELPDESK)
    full = sd.Ace(HELPDESK, sd.GENERIC_ALL)
    snap = gsnap(
        dc(),
        host("SRV"),
        gpos=linked_gpo(DC_OU, "Domain Controllers OU", aces=filtered_to(FILTER_GROUP, full)),
        entries=[],
        objects=[group, desk],
    )
    g = paths.build(snap)
    found = paths.paths_to_tier0(g)[f"sid:{HELPDESK}"]
    assert any("with its filter changed" in g.name(node) for node, _ in found.steps)


def test_a_writer_of_values_does_not_get_past_a_filter() -> None:
    group = DirObject(f"CN=F,{LAB}", "F", "group", sid=FILTER_GROUP)
    snap = gsnap(
        dc(),
        gpos=linked_gpo(DC_OU, "Domain Controllers OU", aces=filtered_to(FILTER_GROUP, WRITE)),
        entries=[],
        objects=[group],
    )
    assert f"sid:{HELPDESK}" not in paths.paths_to_tier0(paths.build(snap))


def test_the_owner_of_a_gpo_gets_past_a_filter_too() -> None:
    group = DirObject(f"CN=F,{LAB}", "F", "group", sid=FILTER_GROUP)
    gpos = writer(link(LAB), aces=filtered_to(FILTER_GROUP))
    snap = gsnap(host("SRV"), gpos=gpos, entries=[], objects=[group])
    (held,) = [o for o in snap.objects if o.kind == "gpo"]
    held.owner = HELPDESK
    assert reach_of(snap) == {"SRV$"}


def user_filter(*extra: sd.Ace) -> tuple[list[Any], list[DirObject]]:
    members = f"CN=ann,{LAB}"
    group = DirObject(f"CN=F,{LAB}", "F", "group", sid=FILTER_GROUP, members=[members])
    return writer(link(LAB), aces=[*filtered_to(FILTER_GROUP), WRITE, *extra]), [group]


def test_user_policy_needs_a_computer_that_can_read_the_gpo() -> None:
    gpos, groups = user_filter()
    snap = gsnap(host("SRV"), person("ann"), gpos=gpos, entries=[], objects=groups)
    assert reach_of(snap) == set()


@pytest.mark.parametrize("reader", [AU, f"{DOM}-515"])
def test_read_for_computers_lets_the_user_filter_work(reader: str) -> None:
    gpos, groups = user_filter(sd.Ace(reader, 0x20094))
    snap = gsnap(host("SRV"), person("ann"), gpos=gpos, entries=[], objects=groups)
    assert reach_of(snap) == {"ann"}


def test_a_dc_of_unknown_site_is_reached_as_resolve_assumes() -> None:
    gpos = writer(link(SITE, "site"))
    snap = gsnap(dc(), gpos=gpos, entries=[], site_count=2, dc_sites={})
    assert reach_of(snap) == {"DC02$"}
    assert SITE_CAVEAT in str(paths.build(snap).edge_props)


def test_a_gpo_reaching_only_an_rodc_is_no_path_into_the_domain() -> None:
    rodc_group = f"{DOM}-521"
    rodc = host("RODC1", DC_OU, 1001, 0x04000000 | 0x1000)
    gpos = linked_gpo(HEAD, "domain", aces=filtered_to(rodc_group, WRITE))
    snap = gsnap(dc(), rodc, gpos=gpos, entries=[])
    g = paths.build(snap)
    assert "linked to domain" not in edges_of(g)
    assert "RODC1$" in reach_of(snap)


def test_scope_names_survive_a_dotted_capital_i() -> None:
    inner = f"OU=İzmir Şube,OU=İstanbul,{HEAD}"
    snap = gsnap(host("SRV", inner), gpos=writer(link(f"OU=İstanbul,{HEAD}")), entries=[])
    names = set(paths.build(snap).names.values())
    assert "computers under İstanbul" in names
    assert "computers under İstanbul/İzmir Şube" in names


def test_an_escaped_comma_does_not_share_another_ous_chain() -> None:
    other = f"OU=Z,{LAB}"
    tricky = person("a", LAB)
    tricky.dn = f"CN=a\\,OU=Z,{LAB}"
    snap = gsnap(tricky, host("VICTIM", other), gpos=writer(link(other)), entries=[])
    assert reach_of(snap) == {"VICTIM$"}


def test_filters_that_pass_the_same_accounts_share_their_scopes() -> None:
    group = DirObject(f"CN=F,{LAB}", "F", "group", sid=FILTER_GROUP, members=[f"CN=SRV,{LAB}"])
    idle = DirObject(f"CN=I,{LAB}", "I", "group", sid=f"{DOM}-1301")
    aces = filtered_to(FILTER_GROUP, WRITE)
    second = gpo("Two", "{B}", link(LAB), aces=[*aces, sd.Ace(f"{DOM}-1301", 0x20094)])
    first = gpo("One", GUID_A, link(LAB), aces=aces)
    snap = gsnap(host("SRV"), host("NOT", rid=2001), gpos=[first, second], entries=[],
                 objects=[group, idle])  # fmt: skip
    built = gpo_scope.reach(snap)
    assert len({node for _, node, _ in built.applies}) == 1


def test_a_filter_that_leaves_nobody_out_is_no_filter() -> None:
    aces = filtered_to(f"{DOM}-515", WRITE)
    built = gpo_scope.reach(gsnap(host("SRV"), gpos=writer(link(LAB), aces=aces), entries=[]))
    assert set(built.names.values()) == {"computers under Lab"}


# --- AD-DEL-005 ---------------------------------------------------------------------------


def test_a_custom_class_on_a_live_host_is_graded_like_a_dead_one() -> None:
    live = delegating("custom/fs01.lab.test", uac=PROTOCOL_TRANSITION)
    dead = delegating("custom/gone.lab.test", uac=PROTOCOL_TRANSITION)
    assert only(targets(live, fs01()), "AD-DEL-005").severity is Severity.HIGH
    assert only(targets(dead, fs01()), "AD-DEL-005").severity is Severity.HIGH


@pytest.mark.parametrize("target", ["http/fs01.lab.test:8080", "cifs/fs01.lab.test/share"])
def test_a_mapped_class_keeps_its_port_and_instance(target: str) -> None:
    f = only(targets(delegating(target), fs01()), "AD-DEL-005")
    assert f.objects == [f"svc_app -> {target} (no account holds it, the host exists)"]


def test_a_mapped_spn_with_the_same_port_is_held() -> None:
    web = user("svc_web", spns=["host/web1.lab.test:8080"])
    assert "AD-DEL-005" not in ids(run_all(targets(delegating("http/web1.lab.test:8080"), web)))


def test_another_domain_cannot_work_and_can_be_claimed() -> None:
    f = only(targets(delegating("cifs/fs.partner.test")), "AD-DEL-005")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [
        "svc_app -> cifs/fs.partner.test (another domain, this delegation cannot reach it)"
    ]
    assert "still exist" not in f.remediation
    high = delegating("cifs/fs.partner.test", uac=PROTOCOL_TRANSITION)
    assert only(targets(high), "AD-DEL-005").severity is Severity.HIGH


# --- redaction ----------------------------------------------------------------------------


def redacted(snap: Snapshot) -> dict[str, Any]:
    return redact.redact(json.loads(json.dumps(snap.to_json())), b"k")


def test_a_comma_in_a_cn_and_an_ou_is_hidden_in_every_dn() -> None:
    a = user("ayilmaz")
    a.dn = "CN=Yilmaz\\, Ayse,OU=Muhasebe\\, Finans,DC=lab,DC=test"
    ou = DirObject("OU=Muhasebe\\, Finans,DC=lab,DC=test", "Muhasebe, Finans", "ou")
    text = json.dumps(redacted(snapshot(a, objects=[ou])))
    for word in ("Yilmaz", "Ayse", "Muhasebe", "Finans"):
        assert word not in text, word


def test_escaped_and_plain_forms_share_a_token() -> None:
    r = redact.Redactor(b"k")
    data = json.loads(json.dumps(snapshot().to_json()))
    data["accounts"][0]["dn"] = "CN=Doe\\, John,DC=lab,DC=test"
    r.collect(data)
    assert r.text("Doe, John") in r.text("CN=Doe\\, John,DC=x")


def test_a_dotted_capital_i_is_hidden() -> None:
    ou = DirObject(f"OU=İzmir Şube,{HEAD}", "İzmir Şube", "ou")
    assert "zmir" not in json.dumps(redacted(snapshot(objects=[ou])), ensure_ascii=False)


def test_urls_that_exist_only_in_notes_are_hidden() -> None:
    url = "https://u1ser:pa55@ces01.corpsecret.example/Acme-Issuing-CA_CES_Kerberos/service.svc/CES"
    snap = snapshot(enrollment_urls=[url], notes=[f"{url} not probed: timed out"])
    text = json.dumps(redacted(snap))
    for word in ("ces01", "corpsecret", "Acme", "u1ser", "pa55"):
        assert word not in text, word
    assert "service.svc/CES" in text


def test_a_broken_url_is_hidden_too() -> None:
    snap = snapshot(enrollment_urls=["https://[corpsecret/x"], notes=["https://[corpsecret/x bad"])
    assert "corpsecret" not in json.dumps(redacted(snap))


@pytest.mark.parametrize("url", ["https://10.1.2.5/certsrv/", "https://[fe80::1]/certsrv/"])
def test_an_address_in_a_url_leaves_the_snapshot_loadable(url: str) -> None:
    snap = snapshot(probes=Probes(enrollment_https=[url]), enrollment_urls=[url])
    back = Snapshot.from_json(redacted(snap))
    assert back.collected_at == snap.collected_at


def test_a_digit_only_name_leaves_the_timestamps_alone() -> None:
    back = Snapshot.from_json(redacted(snapshot(user("2026"), user("10"))))
    assert back.collected_at == NOW


@pytest.mark.parametrize("label", ["group", "computer", "container", "ou", "dc", "cn"])
def test_a_host_label_cannot_rewrite_fixed_words(label: str) -> None:
    web = user("svc", spns=[f"http/{label}.lab.test"])
    objects = [
        DirObject(f"CN=G,{HEAD}", "G", "group"),
        DirObject(f"CN=C,{HEAD}", "C", "container"),
    ]
    out = redacted(snapshot(web, objects=objects))
    assert [o["kind"] for o in out["objects"]] == ["group", "container"]
    assert out["objects"][0]["dn"].startswith("CN=") and "DC=" in out["objects"][0]["dn"]


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("X509:CN=Secret Person,OU=Hidden,DC=corp", "Secret"),
        ("X509:prefixsecret<I>DC=corp<SR>0a", "prefixsecret"),
        ("X509:<I>DC=corp<S>CN=Smith<Bobsecret,OU=X", "Bobsecret"),
        ("X509:<secrettag>abc", "secrettag"),
        ("bob.secret@corp.example:abc", "bob.secret"),
    ],
)
def test_a_malformed_mapping_leaks_nothing(raw: str, secret: str) -> None:
    assert secret not in redact.Redactor(b"k").mapping(raw)


def test_a_well_formed_mapping_keeps_its_shape() -> None:
    out = redact.Redactor(b"k").mapping(STRONG)
    assert re.fullmatch(r"X509:<I>x[0-9a-f]{8}<SR>x[0-9a-f]{8}", out)


def test_service_classes_and_bare_targets_are_learned() -> None:
    svc = user(
        "svc",
        spns=["acmepay/web.lab.test", "MSSQLSvc/db.lab.test:1433"],
        allowed_to_delegate_to=["noslashhost.corpsecret.example"],
    )
    snap = snapshot(svc, spn_mappings=["host=alerter,acmebilling,cifs"])
    text = json.dumps(redacted(snap))
    for word in ("acmepay", "acmebilling", "noslashhost", "corpsecret"):
        assert word not in text, word
    assert "host=alerter," in text and ",cifs" in text


def test_a_custom_mapping_still_explains_a_target_after_redaction() -> None:
    sql = user("svc_sql", spns=["sqlhost/db.lab.test"])
    snap = targets(
        delegating("report/db.lab.test"), sql, mappings=[*HOST_MAP, "sqlhost=report,etl"]
    )
    assert "AD-DEL-005" not in ids(run_all(Snapshot.from_json(redacted(snap))))


def test_the_entra_realm_survives_so_its_trust_stays_skipped() -> None:
    entra = trust("kerberos.microsoftonline.com", when_changed=NOW.replace(year=2020))
    snap = snapshot(trusts=[entra])
    assert {"AD-INF-015", "AD-INF-016"}.isdisjoint(ids(run_all(snap)))
    assert ids(run_all(snap)) == ids(run_all(Snapshot.from_json(redacted(snap))))


def test_key_ids_are_replaced() -> None:
    key = hello()
    snap = admin_snapshot(admin(key_credentials=[key]))
    out = redacted(snap)
    (stored,) = [a for a in out["accounts"] if a["key_credentials"]]
    assert len(stored["key_credentials"][0]["key_id"]) == 16
    assert key.key_id != stored["key_credentials"][0]["key_id"]


def old_replace(r: redact.Redactor, value: str) -> str:
    """The single alternation the lookup replaced: it must give the same answer."""
    names = sorted(r.names, key=len, reverse=True)
    pattern = re.compile(
        rf"(?<![\w$])(?:{'|'.join(re.escape(n) for n in names)})(?![\w$])", re.IGNORECASE
    )
    return pattern.sub(lambda m: r.names[m.group(0).lower()], value)


def test_word_lookup_matches_the_alternation_it_replaced() -> None:
    r = redact.Redactor(b"k")
    data = json.loads(json.dumps(snapshot().to_json()))
    samples = ["web", "web01", "web01$", "Acme Corp", "Acme", "a-b", "a-b.c", "(Test) Group", "x.y"]
    data["accounts"] = data["accounts"][:1]
    data["accounts"][0]["sam"] = "krbtgt"
    data["objects"] = [{"name": n, "dn": "DC=lab,DC=test", "kind": "group"} for n in samples]
    r.collect(data)
    rng = random.Random(7)
    pieces = [*samples, " ", ",", "-", ".", "$", "z", "CN=", "/", "ACME", "acme corp"]
    for _ in range(3000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 8)))
        assert r._replace_names(text) == old_replace(r, text), text


# --- enrollment probes --------------------------------------------------------------------


def test_a_host_with_a_space_gives_a_note_and_no_traceback() -> None:
    c = collector()
    c.ces_urls = ["https://a b/x", "http://c d/y"]
    c._probe_enrollment("dc01.corp.example", Probes())
    assert len(c.notes) == 2 and all("not probed" in n for n in c.notes)


def test_a_host_with_a_space_fails_inside_the_probe() -> None:
    url, error = probes.web_enrollment_ntlm("a b", "a b", 80, "/x")
    assert url is None and error
    assert isinstance(http.client.InvalidURL("x"), http.client.HTTPException)


def test_a_published_url_that_refuses_is_noted_a_guessed_one_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", broken(ConnectionRefusedError()))
    assert probes.enrollment_https("h", "h", 443) == (None, None)
    url, error = probes.enrollment_https("h", "h", 443, "/CES", published=True)
    assert url is None and error == "connection refused, EPA and NTLM not judged"


@pytest.mark.parametrize("status", [200, 302, 403, 404, 500, 503])
def test_a_published_url_that_answers_otherwise_is_noted(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", fake(status, ()))
    assert probes.enrollment_https("h", "h", 443) == (None, None)
    url, error = probes.enrollment_https("h", "h", 443, "/CES", published=True)
    assert url is None and error == f"answered {status}, EPA and NTLM not judged"


def test_basic_only_on_a_published_url_is_a_real_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", fake(401, ("Basic",)))
    assert probes.enrollment_https("h", "h", 443, "/CES", published=True) == (None, None)


def test_the_collector_marks_directory_urls_as_published(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def tls(connect: str, header: str, port: int, path: str, published: bool = False) -> Any:
        seen.append(published)
        return None, None

    monkeypatch.setattr(probes, "enrollment_https", tls)
    c = collector()
    c.ca_dns_hosts = ["ca01"]
    c.ces_urls = [CES]
    c._probe_enrollment("dc01", Probes())
    assert seen == [False, True]


def test_userinfo_stays_out_of_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collector()
    c.ces_urls = ["https://u1ser:pa55@ces03.corp.example/x/CES"]
    run(c, monkeypatch, {})
    assert c.calls[0][2] == "ces03.corp.example"  # type: ignore[attr-defined]


def target_of(**kw: Any) -> Target:
    fields: dict[str, Any] = {
        "host": "h", "port": None, "ldaps": False, "no_sysvol": False, "smb_port": 445,
        "signing_probe_port": 389, "http_port": 80, "https_port": 443, "no_probes": False,
        "dc_probes": False,
        "no_patch_level": False,
        "kerberos": False, "single_dc": False, "no_ca_registry": False, "user": None,
    }  # fmt: skip
    return cli._target(argparse.Namespace(**{**fields, **kw}))


def test_no_probes_also_stops_the_signing_bind() -> None:
    assert target_of().plain_port == 389
    assert target_of(no_probes=True).plain_port == 0


def test_skipped_probes_say_what_was_not_judged() -> None:
    c = Collector(None, Target("h", probes=False, plain_port=0))  # type: ignore[arg-type]
    c.ca_dns_hosts = ["ca01"]
    result = c._probes("dc01", [])
    assert result.dcs == []
    assert any("AD-INF-005" in n for n in c.notes)
    assert any("AD-ADCS-019" in n for n in c.notes)


def test_port_zero_says_so_as_well() -> None:
    c = Collector(None, Target("h", https_port=0, http_port=0, plain_port=0, all_dcs=False))  # type: ignore[arg-type]
    c.ces_urls = [CES]
    c._probe_dc = lambda *_: DcProbe("x")  # type: ignore[attr-defined,method-assign,assignment]
    c._probes("dc01", [])
    assert any("AD-ADCS-019" in n for n in c.notes)


# --- reports ------------------------------------------------------------------------------


def hostile() -> report.Report:
    target = "cifs/gone\x1b[31m.lab.test"
    snap = targets(delegating(target, "cifs/<img src=x>.lab.test"))
    snap.notes.append("a <b>note\x1b[0m")
    return report.Report(snap, run_all(snap))


def test_text_report_shows_control_characters_as_escapes() -> None:
    text = render_text(hostile())
    assert "\x1b" not in text and "\\x1b" in text


def test_markdown_outside_code_spans_has_no_raw_tags() -> None:
    lines = render_markdown(hostile()).splitlines()
    prose = [line for line in lines if not line.startswith("- `")]
    assert not [line for line in prose if re.search(r"(?<!\\)<(?:img|b)\b", line)]
