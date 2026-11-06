"""Coercion gate, property sets, rogue DCs, dMSA blindness, ESC17, dsHeuristics characters."""

from __future__ import annotations

import json

import pytest

from ad_doctor import checks, collect, gpo_scope, paths, sd, sysvol
from ad_doctor.checks import ds_heuristic_issues, run_all
from ad_doctor.collect import is_entra_kerberos, mark_rogue_dcs
from ad_doctor.model import (
    UAC,
    Account,
    CertTemplate,
    DirObject,
    GpLink,
    Gpo,
    GpoSettings,
    Probes,
    Severity,
    Snapshot,
)
from ad_doctor.sd import Ace

from .test_checks import computer, ids, only, snapshot

SID = "S-1-5-21-1-2-3"
USERS = f"{SID}-513"
HEAD = "DC=lab,DC=test"
URL = "http://ca.lab.test/certsrv/"
EVERYONE_APPLIES = Ace("S-1-5-11", sd.READ_PROPERTY | sd.CONTROL_ACCESS)


def delegated() -> Account:
    return computer("APP01", 0x1000 | UAC.TRUSTED_FOR_DELEGATION, sid=f"{SID}-2000")


def gpo(name: str, guid: str, **kw: object) -> Gpo:
    values: dict[str, object] = {
        "linked_to": ["domain"],
        "aces": [EVERYONE_APPLIES],
        "links": [GpLink(HEAD, "domain", True, False, 0)],
        "machine_version": 1,
        "machine_extensions": [gpo_scope.CSE_SECURITY],
    }
    return Gpo(name, guid, **{**values, **kw})  # type: ignore[arg-type]


def ntlm_snapshot(value: int | None, **kw: object) -> Snapshot:
    """A domain with web enrollment over NTLM and one GPO that sets the NTLM policy."""
    g = gpo("Hardening", "{A}")
    defaults: dict[str, object] = {
        "probes": Probes(web_enrollment_ntlm=[URL]),
        "gpos": [g],
        "gpo_settings": {g.guid: GpoSettings(restrict_sending_ntlm=value)},
        "ntlm_policy_collected": True,
    }
    snap = snapshot(**{**defaults, **kw})
    next(a for a in snap.accounts if a.sam == "DC01$").sid = f"{SID}-1000"
    return snap


# --- item 1: the coercion gate --------------------------------------------------------


def test_chain_002_fires_without_a_spooler_as_assumed() -> None:
    for probes in (Probes(), Probes(spooler_on_dc=False)):
        f = only(snapshot(delegated(), probes=probes), "AD-CHAIN-002")
        assert f.severity is Severity.MEDIUM
        assert "assumed possible" in f.detail and "PetitPotam" in f.detail
        assert f.objects == ["APP01$"]


def test_chain_002_is_high_with_a_confirmed_spooler() -> None:
    f = only(snapshot(delegated(), probes=Probes(spooler_on_dc=True)), "AD-CHAIN-002")
    assert f.severity is Severity.HIGH
    assert "Confirmed coercion route" in f.detail


def test_chain_002_needs_unconstrained_delegation() -> None:
    assert "AD-CHAIN-002" not in ids(run_all(snapshot(probes=Probes(spooler_on_dc=True))))


def test_chain_002_ignores_the_ntlm_policy_because_it_is_kerberos() -> None:
    snap = ntlm_snapshot(2)
    snap.accounts.append(delegated())
    assert gpo_scope.dc_outgoing_ntlm(snap).denied is True
    f = only(snap, "AD-CHAIN-002")
    assert f.severity is Severity.MEDIUM
    assert "uses Kerberos" in f.detail


def test_chain_003_fires_without_a_spooler_as_assumed() -> None:
    f = only(ntlm_snapshot(None), "AD-CHAIN-003")
    assert f.severity is Severity.MEDIUM
    assert "assumed possible" in f.detail
    assert "no GPO reaching DC01 denies outgoing NTLM" in f.detail
    assert f.objects == [URL]


def test_chain_003_is_high_with_a_confirmed_spooler() -> None:
    probes = Probes(web_enrollment_ntlm=[URL], spooler_on_dc=True)
    assert only(ntlm_snapshot(None, probes=probes), "AD-CHAIN-003").severity is Severity.HIGH


def test_chain_003_is_medium_when_every_dc_denies_ntlm_even_with_a_spooler() -> None:
    probes = Probes(web_enrollment_ntlm=[URL], spooler_on_dc=True)
    f = only(ntlm_snapshot(2, probes=probes), "AD-CHAIN-003")
    assert f.severity is Severity.MEDIUM
    assert "Hardening denies outgoing NTLM on every DC" in f.detail
    assert "Kerberos" in f.detail


def test_chain_003_audit_value_is_not_a_mitigation() -> None:
    assert only(ntlm_snapshot(1), "AD-CHAIN-003").severity is Severity.MEDIUM


def test_chain_003_needs_web_enrollment() -> None:
    assert "AD-CHAIN-003" not in ids(run_all(ntlm_snapshot(2, probes=Probes(spooler_on_dc=True))))


def test_ntlm_state_is_unknown_when_sysvol_was_not_read() -> None:
    snap = ntlm_snapshot(2, ntlm_policy_collected=False)
    state = gpo_scope.dc_outgoing_ntlm(snap)
    assert state.denied is None
    f = only(snap, "AD-CHAIN-003")
    assert f.severity is Severity.MEDIUM and "unknown (GPO security settings" in f.detail


def test_ntlm_state_is_unknown_when_a_gpo_file_was_not_readable() -> None:
    state = gpo_scope.dc_outgoing_ntlm(ntlm_snapshot(2, gpo_settings={}))
    assert state.denied is None and "not readable (Hardening)" in state.detail


def test_ntlm_state_is_unknown_when_gpos_disagree() -> None:
    other = gpo("Loose", "{B}")
    snap = ntlm_snapshot(2)
    snap.gpos.append(other)
    snap.gpo_settings[other.guid] = GpoSettings(restrict_sending_ntlm=0)
    state = gpo_scope.dc_outgoing_ntlm(snap)
    assert state.denied is None and "disagree" in state.detail


def test_ntlm_state_is_unknown_with_a_wmi_filter() -> None:
    g = gpo("Hardening", "{A}", wmi_filter="DCs only")
    state = gpo_scope.dc_outgoing_ntlm(ntlm_snapshot(2, gpos=[g]))
    assert state.denied is None and "may not apply" in state.detail


def test_ntlm_deny_must_reach_every_dc() -> None:
    other = computer("DC02", 0x2000, sid=f"{SID}-1001")
    other.dn = f"CN=DC02,OU=Domain Controllers,{HEAD}"
    only_dc01 = gpo(
        "Hardening", "{A}", links=[GpLink(f"OU=Elsewhere,{HEAD}", "ou", True, False, 0)]
    )
    assert gpo_scope.dc_outgoing_ntlm(ntlm_snapshot(2, gpos=[only_dc01])).denied is False
    snap = ntlm_snapshot(2)
    blocked = DirObject(f"OU=Domain Controllers,{HEAD}", "Domain Controllers", "ou")
    blocked.gp_blocked = True
    snap.accounts.append(other)
    snap.objects.append(blocked)
    state = gpo_scope.dc_outgoing_ntlm(snap)
    assert state.denied is False and "DC02" in state.detail


def test_ntlm_ignores_a_gpo_that_is_filtered_away_from_the_dc() -> None:
    g = gpo("Hardening", "{A}", aces=[Ace(f"{SID}-9999", sd.READ_PROPERTY | sd.CONTROL_ACCESS)])
    assert gpo_scope.dc_outgoing_ntlm(ntlm_snapshot(2, gpos=[g])).denied is False


def test_gpttmpl_registry_value_is_read() -> None:
    text = (
        "[Registry Values]\n"
        r"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,2"
        "\n"
    )
    assert sysvol.parse_gpttmpl(text).restrict_sending_ntlm == 2
    assert sysvol.parse_gpttmpl("[Registry Values]\n").restrict_sending_ntlm is None


def test_older_gpo_settings_load_as_unknown() -> None:
    snap = ntlm_snapshot(2)
    data = snap.to_json()
    del data["ntlm_policy_collected"]
    for settings in data["gpo_settings"].values():
        del settings["restrict_sending_ntlm"]
    assert gpo_scope.dc_outgoing_ntlm(Snapshot.from_json(data)).denied is None


# --- item 2: WriteAccountRestrictions --------------------------------------------------


def test_property_set_write_counts_as_rbcd() -> None:
    ace = Ace(f"{SID}-1105", sd.WRITE_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET)
    assert ace.writes(sd.ALLOWED_TO_ACT)
    assert not ace.takeover
    assert not ace.writes(sd.KEY_CREDENTIAL_LINK)
    assert checks._risky_rights(ace, "computer") == ["write RBCD"]
    assert checks._risky_rights(ace, "user") == []


def test_reading_the_property_set_is_not_a_write() -> None:
    ace = Ace("S-1-5-11", sd.READ_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET)
    assert not ace.writes(sd.ALLOWED_TO_ACT)


def dc_object(*aces: Ace) -> DirObject:
    return DirObject(
        f"CN=DC01$,CN=Computers,{HEAD}", "DC01$", "computer", sid=f"{SID}-1000", aces=list(aces)
    )


def test_acl_004_and_the_graph_see_the_property_set() -> None:
    writer = f"{SID}-1105"
    dc = computer("DC01", 0x2000, laps=False, sid=f"{SID}-1000")
    dc.dn = f"CN=DC01$,CN=Computers,{HEAD}"
    snap = snapshot(
        objects=[dc_object(Ace(writer, sd.WRITE_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET))],
        principals={writer: "joiner"},
    )
    snap.accounts = [a for a in snap.accounts if a.sam != "DC01$"] + [dc]
    assert only(snap, "AD-ACL-004").objects == ["DC01$: joiner (write RBCD)"]
    assert (f"sid:{dc.sid}", "write RBCD") in paths.build(snap).edges[f"sid:{writer}"]


def test_property_set_write_inherited_from_an_ou_reaches_computers_only() -> None:
    writer = f"{SID}-1105"
    ou = DirObject(
        f"OU=Servers,{HEAD}",
        "Servers",
        "ou",
        inheritable=[
            Ace(writer, sd.WRITE_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET, sd.COMPUTER_CLASS)
        ],
    )
    host = computer("SRV01", sid=f"{SID}-1200")
    host.dn = f"CN=SRV01,OU=Servers,{HEAD}"
    person = Account(f"CN=bob,OU=Servers,{HEAD}", "bob", 0x200, sid=f"{SID}-1201")
    g = paths.build(snapshot(host, person, objects=[ou]))
    assert (f"sid:{host.sid}", "write RBCD (inherited)") in g.edges[f"sid:{writer}"]
    assert not any(dst == f"sid:{person.sid}" for dst, _ in g.edges[f"sid:{writer}"])


def test_default_holders_of_the_set_are_quiet() -> None:
    # the creator's ACE (here Domain Admins, as in the lab) and read ACEs on every computer
    aces = [
        Ace(f"{SID}-512", sd.WRITE_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET),
        Ace("S-1-5-11", sd.READ_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET),
        Ace(checks.PRINCIPAL_SELF, sd.WRITE_PROPERTY, sd.ACCOUNT_RESTRICTIONS_SET),
    ]
    dc = computer("DC01", 0x2000, laps=False, sid=f"{SID}-1000")
    dc.dn = f"CN=DC01$,CN=Computers,{HEAD}"
    snap = snapshot(objects=[dc_object(*aces)])
    snap.accounts = [a for a in snap.accounts if a.sam != "DC01$"] + [dc]
    assert "AD-ACL-004" not in ids(run_all(snap))


# --- item 5: rogue DCs -----------------------------------------------------------------


def rogue(sam: str = "FAKE", uac: int = 0x2000, **kw: object) -> Account:
    return computer(sam, uac, rogue_dc=True, sid=f"{SID}-3000", **kw)


def test_mark_rogue_dcs_compares_with_the_registered_set() -> None:
    real = computer("DC01", 0x2000)
    rodc = computer("RODC1", UAC.PARTIAL_SECRETS_ACCOUNT | 0x1000)
    fake = computer("FAKE", 0x2000)
    fake_rodc = computer("FAKE2", UAC.PARTIAL_SECRETS_ACCOUNT | 0x1000)
    member = computer("SRV01")
    registered = {real.dn.upper().lower(), rodc.dn.lower()}
    mark_rogue_dcs([real, rodc, fake, fake_rodc, member], registered)
    assert [a.rogue_dc for a in (real, rodc, fake, fake_rodc, member)] == [
        False,
        False,
        True,
        True,
        False,
    ]
    assert rodc.is_registered_dc and not fake.is_registered_dc and fake.is_dc


def test_entra_kerberos_is_matched_by_structure() -> None:
    dn = f"CN=AzureADKerberos,OU=Domain Controllers,{HEAD}"
    rodc = UAC.PARTIAL_SECRETS_ACCOUNT | 0x1000
    link = f"CN=krbtgt_AzureAD,CN=Users,{HEAD}"
    assert is_entra_kerberos(dn, rodc, link)
    assert is_entra_kerberos(dn.lower(), rodc, link)
    assert not is_entra_kerberos(dn, rodc, "")  # the name alone is not enough
    assert not is_entra_kerberos(dn, 0x2000, link)  # a writable DC is not this object
    assert not is_entra_kerberos(dn, rodc | 0x2000, link)
    assert not is_entra_kerberos(f"CN=AzureADKerberos,OU=Other,{HEAD}", rodc, link)
    assert not is_entra_kerberos(f"CN=FAKE,OU=Domain Controllers,{HEAD}", rodc, link)


def test_entra_kerberos_is_not_rogue_and_stays_tier_0() -> None:
    entra = computer("AzureADKerberos", UAC.PARTIAL_SECRETS_ACCOUNT | 0x1000, entra_kerberos=True)
    mark_rogue_dcs([entra], {"cn=dc01,cn=computers,dc=lab,dc=test"})
    assert not entra.rogue_dc and entra.is_dc
    assert entra.dn.lower() in snapshot(entra).tier0_dns()
    assert "AD-INF-014" not in ids(run_all(snapshot(entra)))


def test_rogue_finding_grades() -> None:
    f = only(snapshot(rogue()), "AD-INF-014")
    assert f.severity is Severity.HIGH and f.objects == ["FAKE$"]
    disabled = rogue(uac=0x2000 | UAC.ACCOUNTDISABLE)
    assert only(snapshot(disabled), "AD-INF-014").severity is Severity.MEDIUM
    read_only = rogue(uac=UAC.PARTIAL_SECRETS_ACCOUNT | 0x1000)
    assert only(snapshot(read_only), "AD-INF-014").severity is Severity.MEDIUM


def test_rogue_dc_is_not_hidden_by_dc_exemptions() -> None:
    fake = rogue(
        uac=0x2000 | UAC.TRUSTED_FOR_DELEGATION | UAC.PASSWD_NOTREQD,
        laps=False,
        logon_count=0,
        primary_group=516,
    )
    snap = snapshot(fake, privileged={"Domain Admins": [fake.dn]})
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-DEL-001"].objects == ["FAKE$"]
    assert "FAKE$" in found["AD-SEC-001"].objects
    assert found["AD-ACC-010"].objects == ["FAKE$"]
    assert "Domain Admins: FAKE$ (computer)" in found["AD-PRIV-006"].objects
    assert "FAKE$ (primary group Domain Controllers, but not a DC)" in found["AD-PRIV-007"].objects


def test_rogue_dc_stays_a_tier_0_target() -> None:
    fake = rogue()
    snap = snapshot(fake)
    assert fake.dn.lower() in snap.tier0_dns()
    assert checks.tier0_hosts(snap)[fake.dn.lower()] == "unregistered DC"


def test_rogue_dc_is_not_treated_as_a_dc_by_the_local_group_logic() -> None:
    from ad_doctor.model import GpoLocalGroup

    fake = rogue()
    g = gpo("LocalAdmins", "{C}")
    item = GpoLocalGroup(
        "{C}", "restricted", "x", "S-1-5-32-544", "Administrators", USERS, "Domain Users", "add"
    )
    grants = gpo_scope.resolve(
        snapshot(fake, gpos=[g], gpo_local_groups=[item], local_groups_collected=True)
    ).grants
    assert [(x.domain_group, x.computer and x.computer.sam) for x in grants if x.computer] == [
        (False, "FAKE$")
    ]


def test_older_snapshot_degrades_with_a_note() -> None:
    old = snapshot(computer("DC02", 0x2000)).to_json()
    del old["dc_registration_checked"]
    for account in old["accounts"]:
        del account["rogue_dc"], account["entra_kerberos"]
    snap = Snapshot.from_json(old)
    assert any("AD-INF-014" in n for n in snap.notes)
    assert all(a.is_registered_dc for a in snap.accounts if a.is_dc)
    assert "AD-INF-014" not in ids(run_all(snap))
    assert not any("AD-INF-014" in n for n in Snapshot.from_json(snapshot().to_json()).notes)


def snapshot_entries(with_ntds: bool) -> list[dict[str, list[object]]]:
    site = "CN=Default,CN=Sites,CN=Configuration,DC=lab,DC=test"
    server = f"CN=DC01,CN=Servers,{site}"
    entries: list[dict[str, list[object]]] = [
        {
            "distinguishedname": [server],
            "objectclass": [b"top", b"server"],
            "serverreference": [f"CN=DC01,OU=Domain Controllers,{HEAD}".encode()],
        },
        {
            "distinguishedname": [f"CN=OLD,CN=Servers,{site}"],
            "objectclass": [b"server"],
            "serverreference": [f"CN=OLD,OU=Domain Controllers,{HEAD}".encode()],
        },
    ]
    if with_ntds:
        entries.append(
            {
                "distinguishedname": [f"CN=NTDS Settings,{server}"],
                "objectclass": [b"top", b"applicationSettings", b"nTDSDSA"],
            }
        )
    return entries


def test_registered_dcs_needs_an_ntds_child(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    monkeypatch.setattr(c, "optional", lambda *a, **k: snapshot_entries(False))
    # a bare server object alone proves nothing
    assert c._registered_dcs("CN=Configuration") is None
    monkeypatch.setattr(c, "optional", lambda *a, **k: snapshot_entries(True))
    assert f"cn=dc01,ou=domain controllers,{HEAD}".lower() in (
        c._registered_dcs("CN=Configuration") or set()
    )


def test_unreadable_registration_is_a_note_not_a_clean_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    monkeypatch.setattr(c, "optional", lambda *a, **k: snapshot_entries(False))
    assert c._registered_dcs("CN=Configuration") is None
    assert any("AD-INF-014" in n and "not judged" in n for n in c.notes)


def test_ds_heuristics_unreadable_is_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    monkeypatch.setattr(c, "optional", lambda *a, **k: [])
    assert c._ds_heuristics("CN=Configuration") == ""
    assert any("AD-INF-004 not judged" in n for n in c.notes)


# --- item 7: dMSA blindness ------------------------------------------------------------


def dmsa_snapshot(**kw: object) -> Snapshot:
    ou = DirObject(f"OU=Apps,{HEAD}", "Apps", "ou", aces=[Ace(USERS, sd.CREATE_CHILD)])
    return snapshot(objects=[ou], principals={USERS: "Domain Users"}, **kw)


def test_dmsa_blind_sentence_when_none_is_visible() -> None:
    assert "were not checked" in only(dmsa_snapshot(), "AD-INF-007").detail
    assert "were not checked" not in only(dmsa_snapshot(dmsa_visible=True), "AD-INF-007").detail


def test_dmsa_text_does_not_claim_the_patch_closes_it() -> None:
    f = only(dmsa_snapshot(), "AD-INF-007")
    assert "one-sided link" in f.detail and "still works" in f.detail
    assert "leaves these rights" in f.remediation


def test_dmsa_seen_from_object_class() -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    entry = {
        "distinguishedname": [f"CN=d,{HEAD}"],
        "objectclass": [b"computer", b"msDS-DelegatedManagedServiceAccount"],
        "samaccountname": [b"d$"],
    }
    assert c._account(entry).managed and c.dmsa_seen


# --- item 8: ESC17 ---------------------------------------------------------------------


def template(name: str, ekus: list[str], **kw: object) -> CertTemplate:
    values: dict[str, object] = {
        "name": name,
        "published": True,
        "enrollee_supplies_subject": True,
        "manager_approval": False,
        "authorized_signatures": 0,
        "ekus": ekus,
        "aces": [Ace(USERS, sd.CONTROL_ACCESS, sd.CERT_ENROLL)],
    }
    return CertTemplate(**{**values, **kw})  # type: ignore[arg-type]


SERVER = checks.EKU_SERVER_AUTH
CLIENT = "1.3.6.1.5.5.7.3.2"


def test_esc17_fires_on_a_server_only_template() -> None:
    f = only(snapshot(templates=[template("Web", [SERVER])]), "AD-ADCS-017")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["Web (enroll: Domain Users)"]


@pytest.mark.parametrize(
    ("ekus", "reported_by"),
    [
        ([SERVER, CLIENT], "AD-ADCS-001"),
        ([SERVER, checks.EKU_ANY], "AD-ADCS-002"),
        ([], "AD-ADCS-002"),
    ],
)
def test_esc17_skips_what_esc1_and_esc2_report(ekus: list[str], reported_by: str) -> None:
    found = ids(run_all(snapshot(templates=[template("T", ekus)])))
    assert reported_by in found and "AD-ADCS-017" not in found


@pytest.mark.parametrize(
    "kw",
    [
        {"enrollee_supplies_subject": False},
        {"manager_approval": True},
        {"authorized_signatures": 1},
        {"published": False},
        {"aces": [Ace(f"{SID}-1105", sd.CONTROL_ACCESS, sd.CERT_ENROLL)]},
    ],
)
def test_esc17_stays_quiet(kw: dict[str, object]) -> None:
    assert "AD-ADCS-017" not in ids(run_all(snapshot(templates=[template("T", [SERVER], **kw)])))


# --- item 11: dsHeuristics -------------------------------------------------------------


def heuristics(**chars: str) -> str:
    """A valid string with the check characters in place; keys are c<position>."""
    out = list("0" * 31)
    out[9], out[19], out[29] = "1", "2", "3"
    for key, value in chars.items():
        out[int(key[1:]) - 1] = value
    return "".join(out)


def issue(h: str) -> tuple[Severity, str]:
    found = ds_heuristic_issues(h)
    assert len(found) == 1, found
    return found[0]


@pytest.mark.parametrize("value", ["", "0", "0000000", "000000000100", heuristics()])
def test_defaults_are_clean(value: str) -> None:
    assert ds_heuristic_issues(value) == []


def test_unset_or_audit_characters_28_and_29_are_not_reported() -> None:
    assert ds_heuristic_issues(heuristics(c28="0", c29="0")) == []
    assert ds_heuristic_issues(heuristics(c28="1", c29="1")) == []
    assert ds_heuristic_issues("00000000010000000002") == []


def test_positions_are_one_based() -> None:
    assert heuristics(c3="1")[2] == "1" and heuristics(c31="1")[30] == "1"
    assert "3rd character" in issue("001")[1]
    # the same value one place off means nothing
    assert ds_heuristic_issues("01") == [] and ds_heuristic_issues("0001") == []


def test_character_3_list_object() -> None:
    severity, text = issue(heuristics(c3="1"))
    assert severity is Severity.LOW and "List Object" in text
    assert ds_heuristic_issues(heuristics(c3="2")) == []  # only "1" turns it on


def test_character_7_and_8_are_separate() -> None:
    assert issue("0000002")[0] is Severity.HIGH
    assert ds_heuristic_issues("0000001") == []
    severity, text = issue("00000001")
    assert severity is Severity.HIGH and "NSPI" in text
    assert "NSPI" not in issue("0000002")[1]


@pytest.mark.parametrize(
    ("value", "words"),
    [
        ("1", ["UPN"]),
        ("2", ["SPN uniqueness"]),
        ("3", ["UPN", "SPN uniqueness"]),
        ("4", ["SPN alias"]),
        ("7", ["UPN", "SPN uniqueness", "SPN alias"]),
    ],
)
def test_character_21_bits(value: str, words: list[str]) -> None:
    severity, text = issue(heuristics(c21=value))
    assert severity is Severity.MEDIUM
    assert all(w in text for w in words) and f"character 21 = {value}" in text


@pytest.mark.parametrize("position", ["c28", "c29"])
def test_characters_28_and_29(position: str) -> None:
    severity, text = issue(heuristics(**{position: "2"}))
    assert severity is Severity.MEDIUM and "disabled" in text
    assert position[1:] + "th character" in text
    assert issue(heuristics(**{position: "3"}))[0] is Severity.LOW
    # MS-ADTS: any other value counts as 1, which enforces
    assert ds_heuristic_issues(heuristics(**{position: "9"})) == []


@pytest.mark.parametrize(
    ("value", "word"), [("1", "readable"), ("2", "on modify"), ("4", "on add")]
)
def test_character_31_bits(value: str, word: str) -> None:
    severity, text = issue(heuristics(c31=value))
    assert severity is Severity.MEDIUM and word in text


def test_unknown_bitwise_values_are_not_judged_rather_than_clean() -> None:
    for h in (heuristics(c21="x"), heuristics(c21="8"), heuristics(c31="z")):
        severity, text = issue(h)
        assert severity is Severity.LOW and "not judged" in text


def test_finding_takes_the_highest_grade_and_keeps_the_string_as_object() -> None:
    h = heuristics(c3="1", c7="2", c28="2")
    f = only(snapshot(ds_heuristics=h), "AD-INF-004")
    assert f.severity is Severity.HIGH and f.objects == [h]
    assert "List Object" in f.detail and "anonymous LDAP" in f.detail
    assert only(snapshot(ds_heuristics=heuristics(c3="1")), "AD-INF-004").severity is Severity.LOW
    medium = only(snapshot(ds_heuristics=heuristics(c21="1")), "AD-INF-004")
    assert medium.severity is Severity.MEDIUM


def test_new_snapshot_fields_survive_json() -> None:
    fake = rogue()
    snap = snapshot(fake, dmsa_visible=True, ntlm_policy_collected=True)
    again = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert again.dmsa_visible and again.ntlm_policy_collected
    assert next(a for a in again.accounts if a.sam == "FAKE$").rogue_dc
