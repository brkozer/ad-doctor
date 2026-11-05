"""Regression tests for the defects found in the independent review."""

from __future__ import annotations

import json
import struct
import uuid
from pathlib import Path

import pytest

from ad_doctor import accept, invariants, paths, probes, redact, sd
from ad_doctor.checks import run_all
from ad_doctor.cli import main
from ad_doctor.fixes import render_fixes
from ad_doctor.model import DirObject, Finding, Severity, Snapshot, Trust
from ad_doctor.report import Report, render_junit, render_sarif
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_SID, ace_bytes, sid_bytes, template
from .test_checks import NOW, only, snapshot, user

DA = f"{DOMAIN_SID}-512"
HELPDESK = f"{DOMAIN_SID}-1105"
ROOT_SID = "S-1-5-21-7-8-9"
DOMAIN_DN = "DC=lab,DC=test"


def ids(snap: Snapshot) -> set[str]:
    return {f.check_id for f in run_all(snap)}


def domain_head(*aces: Ace) -> DirObject:
    return DirObject(DOMAIN_DN, "lab", "domain", sid=DOMAIN_SID, owner=DA, aces=list(aces))


# --- detection -------------------------------------------------------------------------


def test_child_domain_trusts_forest_root_admins() -> None:
    ea = f"{ROOT_SID}-519"
    head = domain_head(Ace(ea, sd.GENERIC_ALL))
    snap = snapshot(objects=[head], acls={"domain": head.aces}, root_sid=ROOT_SID)
    assert not ids(snap) & {"AD-ACL-001", "AD-ACL-003", "AD-PATH-001"}
    snap.root_sid = ""  # without the root SID the same ACE looks foreign
    assert "AD-ACL-003" in ids(snap)


def test_managed_accounts_are_not_roastable_users() -> None:
    gmsa = user("gmsa_sql$", spns=["MSSQLSvc/sql01:1433"], managed=True, enc_types=0x4)
    assert not ids(snapshot(gmsa)) & {"AD-KRB-003", "AD-KRB-005"}


def test_add_self_and_membership_property_set() -> None:
    group = DirObject("CN=IT,DC=lab,DC=test", "IT", "group", sid=f"{DOMAIN_SID}-1700")
    da = DirObject(
        "CN=Domain Admins,DC=lab,DC=test", "Domain Admins", "group", sid=DA, members=[group.dn]
    )
    group.aces = [
        Ace(HELPDESK, sd.SELF, sd.MEMBER),
        Ace(f"{DOMAIN_SID}-1106", sd.WRITE_PROPERTY, sd.MEMBERSHIP_SET),
    ]
    snap = snapshot(
        objects=[group, da], principals={HELPDESK: "helpdesk", f"{DOMAIN_SID}-1106": "ops"}
    )
    found = set(only(snap, "AD-PATH-001").objects)
    assert "helpdesk -[add self]-> IT -[member of]-> Domain Admins" in found
    assert "ops -[write members]-> IT -[member of]-> Domain Admins" in found


def test_alt_security_identities_write_on_tier0() -> None:
    admin = user("adm_bob", sid=f"{DOMAIN_SID}-1500")
    obj = DirObject(
        admin.dn,
        "adm_bob",
        "user",
        sid=admin.sid,
        owner=DA,
        aces=[Ace(HELPDESK, sd.WRITE_PROPERTY, sd.PUBLIC_INFORMATION_SET)],
    )
    snap = snapshot(
        admin,
        privileged={"Domain Admins": [admin.dn]},
        objects=[obj],
        principals={HELPDESK: "helpdesk"},
    )
    assert only(snap, "AD-ACL-004").objects == [
        "adm_bob: helpdesk (write altSecurityIdentities (ESC14))"
    ]


def test_bad_successor_containers_and_owners() -> None:
    computers = DirObject(
        "CN=Computers,DC=lab,DC=test",
        "Computers",
        "container",
        aces=[Ace(HELPDESK, sd.CREATE_CHILD)],
    )
    servers = DirObject("OU=Servers,DC=lab,DC=test", "Servers", "ou", owner=HELPDESK)
    snap = snapshot(objects=[computers, servers], principals={HELPDESK: "helpdesk"})
    assert only(snap, "AD-INF-007").objects == ["Computers: helpdesk", "Servers: helpdesk (owner)"]


def test_trust_tgt_delegation_is_an_inbound_property() -> None:
    snap = snapshot(trusts=[Trust("partner.test", 1, 2, 0x8 | 0x800)])
    assert only(snap, "AD-INF-006").objects == ["partner.test (forest, TGT delegation enabled)"]


def test_user_with_dc_primary_group() -> None:
    snap = snapshot(user("sneaky", primary_group=516))
    assert only(snap, "AD-PRIV-007").objects == [
        "sneaky (primary group Domain Controllers, but not a DC)"
    ]


def test_pre2k_counts_as_broad_for_templates() -> None:
    t = template(
        "Open",
        enrollee_supplies_subject=True,
        aces=[Ace("S-1-5-32-554", sd.CONTROL_ACCESS, sd.CERT_ENROLL)],
    )
    assert only(snapshot(templates=[t]), "AD-ADCS-001").objects == [
        "Open (enroll: Pre-Windows 2000 Compatible Access)"
    ]


def test_inheritable_aces_are_parsed_separately() -> None:
    raw = bytearray(ace_bytes(HELPDESK, sd.GENERIC_ALL, flags=sd.INHERIT_ONLY | 0x02))
    # an object ACE that only user objects inherit
    body = (
        struct.pack("<II", sd.CONTROL_ACCESS, 0x1 | 0x2)
        + uuid.UUID(sd.RESET_PASSWORD).bytes_le
        + uuid.UUID(sd.USER_CLASS).bytes_le
        + sid_bytes(HELPDESK)
    )
    raw += (
        struct.pack("<BBH", sd.ACCESS_ALLOWED_OBJECT, 0x02 | sd.INHERIT_ONLY, 4 + len(body)) + body
    )
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(raw), 2, 0) + bytes(raw)
    desc = sd.parse(struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + acl)
    assert desc.aces == []  # both are inherit-only
    assert desc.inheritable == [
        Ace(HELPDESK, sd.GENERIC_ALL),
        Ace(HELPDESK, sd.CONTROL_ACCESS, sd.RESET_PASSWORD, sd.USER_CLASS),
    ]


# --- control paths ---------------------------------------------------------------------


def test_dcsync_from_two_aces_is_a_path_through_the_domain_node() -> None:
    sync_group = DirObject(
        "CN=SyncSvc,DC=lab,DC=test",
        "SyncSvc",
        "group",
        sid=f"{DOMAIN_SID}-1300",
        members=["CN=bob,CN=Users,DC=lab,DC=test"],
    )
    head = domain_head(
        Ace(sync_group.sid, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
        Ace(sync_group.sid, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL),
    )
    snap = snapshot(
        user("bob", sid=f"{DOMAIN_SID}-1301"),
        objects=[head, sync_group],
        acls={"domain": head.aces},
    )
    assert only(snap, "AD-PATH-001").objects == ["SyncSvc -[DCSync]-> lab.test"]
    g = paths.build(snap)
    reached = paths.reachable(g, paths.identity_nodes(snap, "bob"))
    assert any(n in g.tier0 for n in reached)


def test_ou_control_reaches_nested_children_and_groups() -> None:
    corp = DirObject("OU=Corp,DC=lab,DC=test", "Corp", "ou", aces=[Ace(HELPDESK, sd.GENERIC_ALL)])
    svc_ou = DirObject("OU=Svc,OU=Corp,DC=lab,DC=test", "Svc", "ou")
    ops = DirObject(
        "CN=Ops,OU=Svc,OU=Corp,DC=lab,DC=test", "Ops", "group", sid=f"{DOMAIN_SID}-1400"
    )
    da = DirObject(
        "CN=Domain Admins,DC=lab,DC=test", "Domain Admins", "group", sid=DA, members=[ops.dn]
    )
    snap = snapshot(objects=[corp, svc_ou, ops, da], principals={HELPDESK: "helpdesk"})
    assert only(snap, "AD-PATH-001").objects == [
        "helpdesk -[full control]-> Corp -[contains]-> Ops -[member of]-> Domain Admins"
    ]


def test_inherited_reset_password_reaches_users_only() -> None:
    ou = DirObject(
        "OU=Staff,DC=lab,DC=test",
        "Staff",
        "ou",
        inheritable=[Ace(HELPDESK, sd.CONTROL_ACCESS, sd.RESET_PASSWORD, sd.USER_CLASS)],
    )
    victim = user("victim", sid=f"{DOMAIN_SID}-1600")
    victim.dn = "CN=victim,OU=Staff,DC=lab,DC=test"
    group = DirObject("CN=Grp,OU=Staff,DC=lab,DC=test", "Grp", "group", sid=f"{DOMAIN_SID}-1601")
    g = paths.build(snapshot(victim, objects=[ou, group], principals={HELPDESK: "helpdesk"}))
    out = dict(g.edges[f"sid:{HELPDESK}"])
    assert out[f"sid:{victim.sid}"] == "reset password (inherited)"
    assert f"sid:{group.sid}" not in out


def test_template_paths_for_named_enrollers_and_writers() -> None:
    vpn = f"{DOMAIN_SID}-1800"
    esc1 = template(
        "Vpn", enrollee_supplies_subject=True, aces=[Ace(vpn, sd.CONTROL_ACCESS, sd.CERT_ENROLL)]
    )
    plain = template("Plain", aces=[Ace(HELPDESK, sd.GENERIC_WRITE)])
    snap = snapshot(templates=[esc1, plain], principals={vpn: "VPN-Users", HELPDESK: "helpdesk"})
    assert set(only(snap, "AD-PATH-001").objects) == {
        "VPN-Users -[enroll (ESC1-3)]-> template Vpn",
        "helpdesk -[write template (ESC4)]-> template Plain",
    }


def test_direct_holder_listed_even_when_a_group_path_is_shorter() -> None:
    x = user("x", sid=f"{DOMAIN_SID}-2000")
    da = DirObject("CN=Domain Admins,DC=lab,DC=test", "Domain Admins", "group", sid=DA)
    owned = DirObject(
        "CN=G,DC=lab,DC=test",
        "G",
        "group",
        sid=f"{DOMAIN_SID}-2001",
        members=[x.dn],
        aces=[Ace(DA, sd.GENERIC_ALL)],
    )
    it = DirObject(
        "CN=IT,DC=lab,DC=test",
        "IT",
        "group",
        sid=f"{DOMAIN_SID}-2002",
        aces=[Ace(owned.sid, sd.GENERIC_ALL), Ace(x.sid, sd.GENERIC_ALL)],
    )
    da.members = [it.dn]
    snap = snapshot(x, objects=[da, owned, it])
    objects = set(only(snap, "AD-PATH-001").objects)
    assert "x -[full control]-> IT -[member of]-> Domain Admins" in objects


def test_blast_radius_of_tier0_and_hidden_admins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    admin = user("adm_bob", sid=f"{DOMAIN_SID}-1500")
    hidden = user("hidden", sid=f"{DOMAIN_SID}-1501", primary_group=512)
    snap_path = tmp_path / "s.json"
    snap_path.write_text(
        json.dumps(snapshot(admin, hidden, privileged={"Domain Admins": [admin.dn]}).to_json())
    )
    assert main(["blast-radius", str(snap_path), "adm_bob"]) == 2
    assert main(["blast-radius", str(snap_path), "hidden"]) == 2
    assert "primary group" in capsys.readouterr().out


def test_gmsa_not_counted_as_user() -> None:
    snap = snapshot(
        user("gmsa$", managed=True, sid=f"{DOMAIN_SID}-1700"), user("u", sid=f"{DOMAIN_SID}-1701")
    )
    g = paths.build(snap)
    assert paths.exposure(snap, g, {}) == (0, 1)
    assert f"sid:{DOMAIN_SID}-515" in paths.identity_nodes(snap, "gmsa$")


# --- collector and probes ------------------------------------------------------------------


def test_web_enrollment_probe_reports_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client

    class Broken:
        def __init__(self, *a: object, **k: object) -> None: ...
        def request(self, *a: object, **k: object) -> None:
            raise http.client.BadStatusLine("garbage")

        def close(self) -> None: ...

    monkeypatch.setattr(probes.http.client, "HTTPConnection", Broken)
    assert probes.web_enrollment_ntlm("h", "h", 80) == (None, "garbage")


# --- CLI, reports, invariants, accepted risks, fixes, redaction ---------------------------


def test_fix_script_targets_and_ids() -> None:
    snap = snapshot()
    fs = [
        Finding(
            "AD-PRIV-007",
            "t",
            Severity.HIGH,
            "d",
            "r",
            [
                "PC01$ (primary group Domain Controllers, but not a DC)",
                "bob (primary group Domain Admins)",
            ],
        ),
        Finding("AD-PRIV-009", "t", Severity.MEDIUM, "d", "r", ["PKI Admins"]),
        Finding("AD-DEL-003", "t", Severity.LOW, "d", "r", ["FS01$", "krbtgt"]),
        Finding("AD-ACL-001", "t", Severity.HIGH, "d", "r", ["Exchange Windows Permissions"]),
    ]
    script = render_fixes(fs, snap)
    assert "-LDAPFilter '(sAMAccountName=PC01$)') -Replace @{primaryGroupID=515}" in script
    assert "-LDAPFilter '(sAMAccountName=bob)') -Replace @{primaryGroupID=513}" in script
    assert "-Members 'PKI Admins'" in script
    assert "Set-ADComputer 'FS01' -PrincipalsAllowedToDelegateToAccount" in script
    assert "Set-ADUser 'krbtgt' -PrincipalsAllowedToDelegateToAccount" in script
    assert 'LAB\\Exchange Windows Permissions"' in script


def test_invariants_case_insensitive_and_transitive(tmp_path: Path) -> None:
    spec = tmp_path / "i.toml"
    spec.write_text(
        '[groups]\n"helpdesk team" = ["BOB"]\n"domain admins" = ["administrator"]\n'
        '[templates]\npublished = ["user"]\n'
    )
    admin = user("Administrator")
    bob, mallory = user("bob"), user("mallory")
    nested = DirObject("CN=HD-Temp,DC=lab,DC=test", "HD-Temp", "group", members=[mallory.dn])
    team = DirObject(
        "CN=Helpdesk Team,DC=lab,DC=test", "Helpdesk Team", "group", members=[bob.dn, nested.dn]
    )
    snap = snapshot(
        admin,
        bob,
        mallory,
        objects=[team, nested],
        privileged={"Domain Admins": [admin.dn]},
        templates=[template("User")],
    )
    found = {f.check_id: f.objects for f in invariants.evaluate(snap, invariants.load(spec))}
    assert found == {"AD-INV-001": ["helpdesk team: unexpected mallory"]}


def test_accept_is_case_insensitive_and_scoped_to_checks_that_ran() -> None:
    entries = [
        accept.Entry("AD-KRB-003", {"svc_backup"}, "r", NOW.date().replace(year=2030)),
        accept.Entry("AD-DEL-001", set(), "r", NOW.date().replace(year=2030)),
    ]
    snap = snapshot(user("SVC_Backup", spns=["HTTP/x"]))
    kept, accepted, notes = accept.apply(
        run_all(snap, ["AD-KRB-003"]), entries, NOW.date(), {"AD-KRB-003"}
    )
    assert kept == [] and accepted[0].objects == ["SVC_Backup"]
    assert notes == []


def test_baseline_snapshot_gets_the_same_invariants(tmp_path: Path) -> None:
    spec = tmp_path / "i.toml"
    spec.write_text("[settings]\nmin_pwd_length = 20\n")
    snap_path = tmp_path / "s.json"
    snap_path.write_text(json.dumps(snapshot().to_json()))
    args = ["analyze", str(snap_path), "--invariants", str(spec), "--fail-on", "low"]
    assert main(args) == 2  # the drift itself fails the gate...
    assert main([*args, "--baseline", str(snap_path)]) == 0  # ...but it is not new


def test_junit_and_sarif_include_invariant_findings() -> None:
    snap = snapshot()
    inv = Finding("AD-INV-003", "Domain settings differ", Severity.MEDIUM, "d", "r", ["x"])
    r = Report(snap, [inv])
    assert 'failures="1"' in render_junit(r, ["AD-KRB-001"])
    rules = json.loads(render_sarif(r))["runs"][0]["tool"]["driver"]["rules"]
    assert any(rule["id"] == "AD-INV-003" for rule in rules)


def test_redact_unicode_ca_templates_and_foreign_sids() -> None:
    gulsen = user("gülşen.yılmaz", sid_history=["S-1-5-21-44-55-66-1104"])
    rnd = DirObject("OU=R&D,DC=lab,DC=test", "R&D", "ou")
    snap = snapshot(
        gulsen,
        objects=[rnd],
        templates=[template("CorpVPN")],
        acls={"PKI:CA lab-DC01-CA": [Ace(DA, sd.GENERIC_ALL)]},
        ca_hosts=["DC01$"],
    )
    out = json.dumps(
        redact.redact(json.loads(json.dumps(snap.to_json())), b"k"), ensure_ascii=False
    )
    for secret in ("gülşen", "yılmaz", "R&D", "CorpVPN", "lab-DC01-CA", "S-1-5-21-44-55-66"):
        assert secret not in out, secret
    redacted = Snapshot.from_json(json.loads(out))
    assert {f.check_id for f in run_all(redacted)} == {f.check_id for f in run_all(snap)}
