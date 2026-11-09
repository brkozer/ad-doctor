"""Configuration Manager, AD FS, Cloud Sync, configuration ACLs, privileged leftovers, CA
certificates, display specifiers and dynamic objects."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest

from ad_doctor import collect, paths, redact, sd, x509
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector
from ad_doctor.model import (
    UAC,
    CaCertificate,
    DirObject,
    DisplaySpecifierCommand,
    Gmsa,
    SccmObject,
    Severity,
    Snapshot,
    computers_behind,
)
from ad_doctor.sd import Ace

from .test_acl_adcs import ace_bytes, descriptor
from .test_checks import NOW, computer, ids, only, snapshot, user

SID = "S-1-5-21-1-2-3"
HELPDESK = f"{SID}-1200"
SITE_SERVER = f"{SID}-1300"
OTHER = f"{SID}-1400"
GMSA_SID = f"{SID}-1500"
DOMAIN_USERS = f"{SID}-513"
FULL = sd.FULL_CONTROL
CONTAINER_DN = "CN=System Management,CN=System,DC=lab,DC=test"
OLD = NOW - timedelta(days=500)


def sccm_container(*aces: Ace, owner: str | None = f"{SID}-512") -> DirObject:
    return DirObject(CONTAINER_DN, "System Management", "container", owner=owner, aces=list(aces))


def sccm(*aces: Ace, **kw: Any) -> Snapshot:
    server = computer("SCCM01", sid=SITE_SERVER)
    return snapshot(
        server,
        sccm_container=sccm_container(Ace(SITE_SERVER, FULL), *aces),
        sccm_checked=True,
        principals={HELPDESK: "helpdesk", SITE_SERVER: "SCCM01$", OTHER: "other"},
        **kw,
    )


# --- Configuration Manager ------------------------------------------------------------


def test_footprint_names_site_server_site_and_management_point() -> None:
    objects = [
        SccmObject("CN=SMS-Site-P01,CN=System Management,DC=lab,DC=test", "site", "P01"),
        SccmObject(
            "CN=SMS-MP-P01,CN=System Management", "management point", "P01", "sccm01.lab.test"
        ),
    ]
    f = only(sccm(sccm_objects=objects), "AD-INF-022")
    assert f.severity is Severity.INFO
    assert f.objects == [
        "management point sccm01.lab.test (site P01)",
        "site P01",
        "site server SCCM01$",
    ]


def test_no_container_and_no_objects_is_quiet() -> None:
    assert not {"AD-INF-022", "AD-ACL-014"} & ids(run_all(snapshot(sccm_checked=True)))


def test_container_without_site_server_is_still_a_footprint() -> None:
    snap = snapshot(sccm_container=sccm_container(), sccm_checked=True)
    assert only(snap, "AD-INF-022").objects == [
        "System Management container, no site server identified"
    ]


def test_site_server_through_a_group() -> None:
    group = DirObject(f"CN=Sccm,{CONTAINER_DN}", "Sccm", "group", f"{SID}-1600",
                      members=[computer("SCCM02").dn])  # fmt: skip
    snap = snapshot(
        computer("SCCM02", sid=f"{SID}-1601"),
        sccm_container=sccm_container(Ace(group.sid, FULL)),
        sccm_checked=True,
        objects=[group],
    )
    assert [a.sam for a in snap.sccm_site_servers()] == ["SCCM02$"]
    assert "AD-ACL-014" not in ids(run_all(snap))


def test_group_that_also_holds_a_user_is_not_a_site_server_group() -> None:
    group = DirObject(f"CN=Sccm,{CONTAINER_DN}", "Sccm", "group", f"{SID}-1600",
                      members=[computer("SCCM02").dn, user("bob").dn])  # fmt: skip
    snap = snapshot(
        computer("SCCM02", sid=f"{SID}-1601"),
        user("bob"),
        sccm_container=sccm_container(Ace(group.sid, FULL)),
        sccm_checked=True,
        objects=[group],
        principals={group.sid: "Sccm"},
    )
    f = only(snap, "AD-ACL-014")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["System Management: Sccm (full control)"]


def test_broad_full_control_is_high_and_names_no_site_server() -> None:
    snap = sccm(Ace(DOMAIN_USERS, FULL))
    assert [a.sam for a in snap.sccm_site_servers()] == ["SCCM01$"]
    f = only(snap, "AD-ACL-014")
    assert f.severity is Severity.HIGH
    assert f.objects == ["System Management: Domain Users (full control)"]


def test_control_over_site_server_object_is_high() -> None:
    target = computer("SCCM01", sid=SITE_SERVER)
    server_object = DirObject(target.dn, "SCCM01$", "computer", SITE_SERVER, f"{SID}-512",
                              aces=[Ace(HELPDESK, sd.WRITE_DAC)])  # fmt: skip
    f = only(sccm(objects=[server_object]), "AD-ACL-014")
    assert f.severity is Severity.HIGH
    assert f.objects == ["SCCM01$: helpdesk (write/WriteDacl/WriteOwner)"]


def test_owner_of_site_server_is_reported() -> None:
    target = computer("SCCM01", sid=SITE_SERVER)
    server_object = DirObject(target.dn, "SCCM01$", "computer", SITE_SERVER, HELPDESK)
    assert only(sccm(objects=[server_object]), "AD-ACL-014").objects == [
        "SCCM01$: owned by helpdesk"
    ]


def test_container_acl_unread_is_not_judged() -> None:
    snap = sccm(Ace(DOMAIN_USERS, FULL))
    snap.sccm_checked = False
    assert "AD-ACL-014" not in ids(run_all(snap))


def test_site_server_is_tier0_in_the_graph() -> None:
    snap = sccm()
    g = paths.build(snap)
    assert f"sid:{SITE_SERVER}" in g.tier0 or any(SITE_SERVER in n for n in g.tier0)
    empty = snapshot()
    assert not any(SITE_SERVER in n for n in paths.build(empty).tier0)


def test_computers_behind_follows_nesting_and_stops_at_loops() -> None:
    a, b = f"CN=A,{CONTAINER_DN}", f"CN=B,{CONTAINER_DN}"
    pc = computer("PC", sid=f"{SID}-1700")
    groups = [
        DirObject(a, "A", "group", f"{SID}-1", members=[b]),
        DirObject(b, "B", "group", f"{SID}-2", members=[a, pc.dn]),
    ]
    assert computers_behind({f"{SID}-1"}, [pc], groups) == [pc]
    assert computers_behind(set(), [pc], groups) == []


# --- Entra Cloud Sync ------------------------------------------------------------------


def cloud_sync(*readers: str, **agent: Any) -> Snapshot:
    gmsa = computer("provAgentgMSA", sid=GMSA_SID)
    gmsa.is_computer = False
    gmsa.managed = True
    host = computer("AGENT01", sid=f"{SID}-1800", **agent)
    return snapshot(
        gmsa,
        host,
        gmsas=[Gmsa("provAgentgMSA$", gmsa.dn, list(readers), 30)],
        acls={"domain": [
            Ace(GMSA_SID, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
            Ace(GMSA_SID, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL),
        ]},
        principals={f"{SID}-1800": "AGENT01$", GMSA_SID: "provAgentgMSA$"},
    )  # fmt: skip


def test_dcsync_gmsa_reader_outside_tier0_is_medium() -> None:
    f = only(cloud_sync(f"{SID}-1800", laps=False), "AD-PRIV-016")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["provAgentgMSA$ readable by AGENT01$ (no LAPS)"]


def test_dcsync_gmsa_found_by_rights_not_by_name() -> None:
    snap = cloud_sync(f"{SID}-1800")
    snap.gmsas[0].name = "svc_custom$"
    assert only(snap, "AD-PRIV-016").objects[0].startswith("svc_custom$")


def test_gmsa_without_dcsync_is_quiet() -> None:
    snap = cloud_sync(f"{SID}-1800")
    snap.acls["domain"] = []
    assert "AD-PRIV-016" not in ids(run_all(snap))


def test_tier0_reader_is_quiet() -> None:
    assert "AD-PRIV-016" not in ids(run_all(cloud_sync(f"{SID}-512")))


def test_unreadable_reader_list_is_not_reported_as_passing() -> None:
    snap = cloud_sync()
    assert "AD-PRIV-016" not in ids(run_all(snap))
    domain_aces = snap.acls["domain"]
    notes = collect._dcsync_gmsa_notes(domain_aces, snap.gmsas, snap.accounts)
    assert notes and "AD-PRIV-016 not judged" in notes[0]
    assert "AD-PRIV-016 not judged" in collect._dcsync_gmsa_notes([], snap.gmsas, snap.accounts)[0]


def _connector(**kw: Any) -> Any:
    return user("MSOL_0a1b2c3d4e5f", sid=f"{SID}-1900", sync_host="SYNC01", **kw)


def test_connector_password_age_low_and_medium_with_dcsync() -> None:
    f = only(snapshot(_connector(pwd_last_set=OLD)), "AD-ACC-020")
    assert f.severity is Severity.LOW and f.objects == ["MSOL_0a1b2c3d4e5f"]
    aces = {"domain": [
        Ace(f"{SID}-1900", sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
        Ace(f"{SID}-1900", sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL),
    ]}  # fmt: skip
    assert only(snapshot(_connector(pwd_last_set=OLD), acls=aces), "AD-ACC-020").severity is (
        Severity.MEDIUM
    )


def test_recent_or_unknown_connector_password_is_quiet() -> None:
    assert "AD-ACC-020" not in ids(run_all(snapshot(_connector())))
    assert "AD-ACC-020" not in ids(run_all(snapshot(_connector(pwd_last_set=None))))


# --- AD FS DKM -------------------------------------------------------------------------


def dkm(*aces: Ace, **kw: Any) -> Snapshot:
    container = DirObject("CN=guid,CN=ADFS,DC=lab,DC=test", "guid", "container", aces=list(aces))
    return snapshot(dkm_containers=[container], dkm_checked=True, **kw)


def test_dkm_unknown_is_not_judged_not_clean() -> None:
    snap = snapshot(dkm_checked=False)
    assert "AD-ACL-011" not in ids(run_all(snap))


def test_dkm_expected_state_is_quiet() -> None:
    service = user("svc_adfs", sid=f"{SID}-1000")
    snap = dkm(Ace(f"{SID}-512", FULL), Ace(f"{SID}-1000", sd.GENERIC_READ | sd.WRITE_PROPERTY))
    snap.accounts.append(service)
    assert "AD-ACL-011" not in ids(run_all(snap))


def test_dkm_broad_reader_is_high() -> None:
    f = only(dkm(Ace(DOMAIN_USERS, sd.READ_PROPERTY)), "AD-ACL-011")
    assert f.severity is Severity.HIGH
    assert f.objects == ["guid: Domain Users"]


def test_dkm_second_account_is_medium_and_lists_both() -> None:
    snap = dkm(
        Ace(f"{SID}-1000", sd.GENERIC_READ),
        Ace(f"{SID}-1001", sd.READ_PROPERTY, sd.THUMBNAIL_PHOTO),
        principals={f"{SID}-1000": "svc_adfs", f"{SID}-1001": "reader"},
    )
    snap.accounts += [user("svc_adfs", sid=f"{SID}-1000"), user("reader", sid=f"{SID}-1001")]
    f = only(snap, "AD-ACL-011")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["guid: reader", "guid: svc_adfs"]


def test_dkm_group_alone_is_not_taken_for_the_service_account() -> None:
    snap = dkm(Ace(HELPDESK, sd.GENERIC_READ), principals={HELPDESK: "helpdesk"})
    assert only(snap, "AD-ACL-011").objects == ["guid: helpdesk"]


def test_dkm_right_on_another_attribute_does_not_count() -> None:
    snap = dkm(Ace(HELPDESK, sd.READ_PROPERTY, "00000000-0000-0000-0000-000000000001"))
    assert "AD-ACL-011" not in ids(run_all(snap))


class DkmCollector(Collector):
    def __init__(self, routes: list[dict[str, Any]] | None) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.routes = routes
        self.asked: list[list[str]] = []

    def attempt(
        self, base: str, flt: str, attrs: list[str], must_exist: bool = False, **kw: Any
    ) -> Any:
        self.asked.append(attrs)
        return self.routes


def test_dkm_never_asks_for_the_key() -> None:
    c = DkmCollector([])
    c._dkm("DC=lab,DC=test")
    assert not any("thumbnailphoto" in a.lower() for attrs in c.asked for a in attrs)


@pytest.mark.parametrize("routes", [None, []])
def test_dkm_refused_or_hidden_is_a_note(routes: list[dict[str, Any]] | None) -> None:
    c = DkmCollector(routes)
    assert c._dkm("DC=lab,DC=test") == ([], False)
    assert "AD-ACL-011 not judged" in c.notes[0]


def test_dkm_container_without_dacl_is_a_note() -> None:
    e = {"distinguishedname": ["CN=g,CN=ADFS,DC=lab,DC=test"], "name": [b"g"]}
    c = DkmCollector([e])
    assert c._dkm("DC=lab,DC=test") == ([], False)
    assert "AD-ACL-011 not judged" in c.notes[0]


# --- Configuration ACLs and OUs ---------------------------------------------------------


def test_config_acl_write_is_high() -> None:
    snap = snapshot(
        config_acls={
            "Schema": [Ace(HELPDESK, sd.WRITE_DAC)],
            "Sites": [Ace(HELPDESK, sd.CREATE_CHILD)],
            "Configuration": [Ace(HELPDESK, sd.CONTROL_ACCESS)],
        },
        config_acls_checked=True,
        principals={HELPDESK: "helpdesk"},
    )
    f = only(snap, "AD-ACL-012")
    assert f.severity is Severity.HIGH
    assert f.objects == [
        "Configuration: helpdesk (all extended rights)",
        "Schema: helpdesk (write/WriteDacl/WriteOwner)",
        "Sites: helpdesk (create child objects)",
    ]


def test_config_acl_default_shape_is_quiet() -> None:
    snap = snapshot(
        config_acls={
            "Schema": [
                Ace("S-1-5-11", 0x20094),
                Ace(f"{SID}-518", FULL),
                Ace("S-1-5-9", sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
            ],
            "Partitions": [Ace("S-1-5-11", sd.READ_PROPERTY, sd.PUBLIC_INFORMATION_SET)],
        },
        config_acls_checked=True,
    )
    assert "AD-ACL-012" not in ids(run_all(snap))


def test_config_acl_unread_is_quiet_and_noted() -> None:
    class Stub(Collector):
        def _dacl(self, dn: str) -> list[Ace]:
            return []

    c = Stub(None)  # type: ignore[arg-type]
    assert c._config_acls({}, "CN=Configuration,DC=lab,DC=test") == {}
    assert "AD-ACL-012 not judged" in c.notes[0]
    assert "AD-ACL-012" not in ids(run_all(snapshot(config_acls_checked=False)))


def ou(*inheritable: Ace, kind: str = "ou") -> DirObject:
    return DirObject("OU=Staff,DC=lab,DC=test", "Staff", kind, inheritable=list(inheritable))


def run_ou(*aces: Ace, **kw: Any) -> Snapshot:
    return snapshot(objects=[ou(*aces)], ace_inheritance_checked=True,
                    principals={HELPDESK: "helpdesk"}, **kw)  # fmt: skip


def test_broad_reset_password_on_ou_is_high() -> None:
    f = only(run_ou(Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, sd.RESET_PASSWORD)), "AD-ACL-013")
    assert f.severity is Severity.HIGH
    assert f.objects == ["Staff: Domain Users (reset password)"]


def test_broad_full_control_on_container_is_high() -> None:
    snap = snapshot(objects=[ou(Ace("S-1-5-11", FULL), kind="container")],
                    ace_inheritance_checked=True)  # fmt: skip
    assert only(snap, "AD-ACL-013").severity is Severity.HIGH


def test_named_all_extended_rights_is_low() -> None:
    f = only(run_ou(Ace(HELPDESK, sd.CONTROL_ACCESS)), "AD-ACL-013")
    assert f.severity is Severity.LOW
    assert f.objects == ["Staff: helpdesk (all extended rights)"]


@pytest.mark.parametrize(
    "ace",
    [
        Ace(HELPDESK, sd.CONTROL_ACCESS, sd.RESET_PASSWORD),  # ordinary delegation
        Ace(HELPDESK, FULL),  # ordinary OU delegation
        Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, "a1e9912c-f0f7-4a6f-a7d3-c58c09f99668"),  # other right
        Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, None, sd.GROUP_CLASS),  # groups only
        Ace(f"{SID}-512", FULL),  # tier 0
        Ace("S-1-5-32-548", FULL),  # Account Operators
        Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, sd.RESET_PASSWORD, None, True),  # inherited copy
    ],
)
def test_ou_rights_that_stay_quiet(ace: Ace) -> None:
    assert "AD-ACL-013" not in ids(run_all(run_ou(ace)))


def test_ou_rights_not_run_without_inheritance_data() -> None:
    snap = snapshot(objects=[ou(Ace(DOMAIN_USERS, FULL))], ace_inheritance_checked=False)
    assert "AD-ACL-013" not in ids(run_all(snap))


# --- Privileged leftovers ---------------------------------------------------------------


def _admin(**kw: Any) -> Any:
    return user("Administrator", sid=f"{SID}-500", last_logon=NOW, **kw)


def test_builtin_admin_used_recently() -> None:
    f = only(snapshot(_admin()), "AD-ACC-018")
    assert f.severity is Severity.LOW
    assert f.objects == ["Administrator"]


def test_renamed_builtin_admin_is_found_by_rid() -> None:
    a = user("root", sid=f"{SID}-500", last_logon=NOW)
    assert only(snapshot(a), "AD-ACC-018").objects == ["root"]


def test_builtin_admin_quiet_when_old_never_or_disabled() -> None:
    old = user("Administrator", sid=f"{SID}-500", last_logon=NOW - timedelta(days=31))
    never = user("Administrator", sid=f"{SID}-500", last_logon=None)
    off = user("Administrator", 0x202, sid=f"{SID}-500", last_logon=NOW)
    for a in (old, never, off):
        assert "AD-ACC-018" not in ids(run_all(snapshot(a)))


def test_smart_card_old_hash_low_and_medium() -> None:
    a = user("sc", 0x200 | UAC.SMARTCARD_REQUIRED, sid=f"{SID}-2000", pwd_last_set=OLD)
    assert only(snapshot(a), "AD-ACC-019").severity is Severity.LOW
    snap = snapshot(a, privileged={"Domain Admins": [a.dn]})
    assert only(snap, "AD-ACC-019").severity is Severity.MEDIUM


def test_smart_card_recent_unknown_and_no_flag_are_quiet() -> None:
    recent = user("sc", 0x200 | UAC.SMARTCARD_REQUIRED)
    unknown = user("sc", 0x200 | UAC.SMARTCARD_REQUIRED, pwd_last_set=None)
    plain = user("sc", pwd_last_set=OLD)
    for a in (recent, unknown, plain):
        assert "AD-ACC-019" not in ids(run_all(snapshot(a)))


def test_mail_on_tier0_account() -> None:
    a = user("admin1", has_mail=True)
    snap = snapshot(a, privileged={"Domain Admins": [a.dn]}, mail_checked=True)
    f = only(snap, "AD-PRIV-017")
    assert f.severity is Severity.LOW and f.objects == ["admin1"]


def test_mail_quiet_for_ordinary_users_and_when_not_judged() -> None:
    a = user("alice", has_mail=True)
    assert "AD-PRIV-017" not in ids(run_all(snapshot(a, mail_checked=True)))
    b = user("admin1", has_mail=True)
    snap = snapshot(b, privileged={"Domain Admins": [b.dn]}, mail_checked=False)
    assert "AD-PRIV-017" not in ids(run_all(snap))


def _group(name: str, sid: str, *members: str) -> DirObject:
    return DirObject(f"CN={name},DC=lab,DC=test", name, "group", sid, members=list(members))


def test_loop_with_tier0_group_is_low() -> None:
    da_dn, b_dn = "CN=DA,DC=lab,DC=test", "CN=B,DC=lab,DC=test"
    objects = [_group("DA", f"{SID}-512", b_dn), _group("B", f"{SID}-3000", da_dn)]
    f = only(snapshot(objects=objects), "AD-PRIV-018")
    assert f.severity is Severity.LOW
    assert f.objects == ["B <-> DA"]


def test_loop_through_three_groups_is_info() -> None:
    a, b, c = (f"CN={n},DC=lab,DC=test" for n in "ABC")
    objects = [
        _group("A", f"{SID}-1", b),
        _group("B", f"{SID}-2", c),
        _group("C", f"{SID}-3", a),
        _group("D", f"{SID}-4", a),  # points into the loop, is not in it
    ]
    f = only(snapshot(objects=objects), "AD-PRIV-018")
    assert f.severity is Severity.INFO
    assert f.objects == ["A <-> B <-> C"]


def test_nesting_without_a_loop_is_quiet() -> None:
    b = "CN=B,DC=lab,DC=test"
    objects = [_group("A", f"{SID}-1", b), _group("B", f"{SID}-2", user("x").dn)]
    assert "AD-PRIV-018" not in ids(run_all(snapshot(objects=objects)))


def test_two_separate_loops_and_deep_chain() -> None:
    a, b, c, d = (f"CN={n},DC=lab,DC=test" for n in "ABCD")
    objects = [_group("A", "s1", b), _group("B", "s2", a)]
    objects += [_group("C", "s3", d), _group("D", "s4", c)]
    assert len(only(snapshot(objects=objects), "AD-PRIV-018").objects) == 2
    chain = [
        _group(f"G{i}", f"s{i}", f"CN=G{i + 1},DC=lab,DC=test") for i in range(3000)
    ]  # no recursion limit
    assert "AD-PRIV-018" not in ids(run_all(snapshot(objects=chain)))


# --- CA certificates -------------------------------------------------------------------


def _der(tag: int, body: bytes) -> bytes:
    size = len(body)
    if size < 0x80:
        return bytes([tag, size]) + body
    data = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(data)]) + data + body


def _oid(text: str) -> bytes:
    parts = [int(p) for p in text.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | p & 0x7F)
            p >>= 7
        out += bytes(reversed(chunk))
    return _der(0x06, bytes(out))


def _name(cn: str) -> bytes:
    pair = _der(0x30, _oid("2.5.4.3") + _der(0x0C, cn.encode()))
    return _der(0x30, _der(0x31, pair))


def _cert(
    bits: int = 2048,
    sig: str = "1.2.840.113549.1.1.11",
    subject: str = "CA1",
    issuer: str | None = None,
    not_after: bytes = b"301231235959Z",
    params: bytes = _der(0x05, b""),
) -> bytes:
    modulus = _der(0x02, b"\x00" + b"\xff" * (bits // 8))
    rsa_key = _der(0x30, modulus + _der(0x02, b"\x01\x00\x01"))
    key = _der(
        0x30,
        _der(0x30, _oid("1.2.840.113549.1.1.1") + _der(0x05, b"")) + _der(0x03, b"\x00" + rsa_key),
    )
    algorithm = _der(0x30, _oid(sig) + params)
    tbs = _der(
        0x30,
        _der(0xA0, _der(0x02, b"\x02"))
        + _der(0x02, b"\x01")
        + algorithm
        + _name(issuer or subject)
        + _der(0x30, _der(0x17, b"200101000000Z") + _der(0x17, not_after))
        + _name(subject)
        + key,
    )
    return _der(0x30, tbs + algorithm + _der(0x03, b"\x00\x01"))


def test_x509_parser_reads_the_fields() -> None:
    c = x509.parse(_cert(2048, subject="Corp Root"))
    assert c.common_name == "Corp Root"
    assert c.key_type == "rsa" and c.key_bits == 2048
    assert c.signature_hash == "sha256" and c.self_signed
    assert c.not_after is not None and c.not_after.year == 2030


def test_x509_parser_rsa_pss_default_is_sha1_and_named_hash_is_read() -> None:
    pss = "1.2.840.113549.1.1.10"
    assert x509.parse(_cert(sig=pss, params=_der(0x30, b""))).signature_hash == "sha1"
    sha256 = _der(0x30, _oid("2.16.840.1.101.3.4.2.1") + _der(0x05, b""))
    params = _der(0x30, _der(0xA0, sha256))
    assert x509.parse(_cert(sig="1.2.840.113549.1.1.10", params=params)).signature_hash == "sha256"


@pytest.mark.parametrize("bad", [b"", b"\x30\x03\x01", b"not a certificate at all"])
def test_x509_parser_refuses_malformed_input(bad: bytes) -> None:
    with pytest.raises((ValueError, IndexError)):
        x509.parse(bad)


def test_unparsed_cert_comes_back_unjudged() -> None:
    c = collect._ca_certificate(b"garbage", "AIA object")
    assert c.name == "AIA object" and not c.parsed


def cert(**kw: Any) -> CaCertificate:
    base: dict[str, Any] = {
        "name": "CA1",
        "stores": ["ntauth"],
        "parsed": True,
        "key_type": "rsa",
        "key_bits": 2048,
        "signature_hash": "sha256",
        "self_signed": False,
    }
    return CaCertificate(**{**base, **kw})


def run_ca(*certs: CaCertificate) -> Snapshot:
    return snapshot(ca_certificates=list(certs), ca_certificates_checked=True)


def test_short_key_is_medium_very_short_is_high() -> None:
    f = only(run_ca(cert(key_bits=1024)), "AD-ADCS-021")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["CA1 (ntauth): RSA key of 1024 bits"]
    assert only(run_ca(cert(key_bits=512)), "AD-ADCS-021").severity is Severity.HIGH


def test_sha1_intermediate_is_medium_md5_is_high() -> None:
    assert only(run_ca(cert(signature_hash="sha1")), "AD-ADCS-021").severity is Severity.MEDIUM
    assert only(run_ca(cert(signature_hash="md5")), "AD-ADCS-021").severity is Severity.HIGH


def test_self_signed_root_is_judged_on_its_key_only() -> None:
    assert "AD-ADCS-021" not in ids(run_all(run_ca(cert(signature_hash="sha1", self_signed=True))))
    assert "AD-ADCS-021" in ids(run_all(run_ca(cert(key_bits=1024, self_signed=True))))


def test_strong_expired_ec_and_unparsed_are_quiet() -> None:
    expired = cert(key_bits=1024, not_after=NOW - timedelta(days=1))
    for c in (cert(), expired, cert(key_type="ec", key_bits=256), CaCertificate("x", parsed=False)):
        assert "AD-ADCS-021" not in ids(run_all(run_ca(c)))


# --- Display specifiers, dynamic objects ------------------------------------------------


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("1,{4A2C0E60-5E2D-11D1-AB22-00C04FC2D4EE}", None),
        ("2, {4A2C0E60-5E2D-11D1-AB22-00C04FC2D4EE},extra", None),
        ("4,Manage...,RsAdmin.msc", "RsAdmin.msc"),
        (r"5,&Tool,\\evil\share\x.exe", r"\\evil\share\x.exe"),
        ("6,Help,https://evil.example/a", "https://evil.example/a"),
    ],
)
def test_display_command_forms(value: str, want: str | None) -> None:
    assert collect.display_command(value) == want


@pytest.mark.parametrize(
    "command",
    [r"\\evil\x.exe", "//evil/x.exe", "http://evil/x", "https://evil/x", r'"\\evil\x"'],
)
def test_remote_commands_are_recognised(command: str) -> None:
    assert collect.REMOTE_COMMAND.match(command)


@pytest.mark.parametrize("command", ["RsAdmin.msc", r"C:\Tools\a.exe", "notepad.exe"])
def test_local_commands_are_not_remote(command: str) -> None:
    assert not collect.REMOTE_COMMAND.match(command)


def test_remote_display_specifier_is_medium() -> None:
    entry = DisplaySpecifierCommand(
        "CN=user-Display,CN=409,CN=DisplaySpecifiers", "adminContextMenu", r"\\evil\x.exe"
    )
    f = only(snapshot(display_specifiers=[entry], display_specifiers_checked=True), "AD-INF-023")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [r"user-Display (adminContextMenu): \\evil\x.exe"]


def test_no_display_commands_is_quiet() -> None:
    assert "AD-INF-023" not in ids(run_all(snapshot(display_specifiers_checked=True)))


def _dynamic(*dns: str, **kw: Any) -> Snapshot:
    defaults = {"dynamic_ttl_default": 86400, "dynamic_ttl_min": 900}
    return snapshot(dynamic_objects=list(dns), dynamic_objects_checked=True, **{**defaults, **kw})


def test_dynamic_object_low() -> None:
    f = only(_dynamic("CN=temp,DC=lab,DC=test"), "AD-INF-024")
    assert f.severity is Severity.LOW and f.objects == ["CN=temp,DC=lab,DC=test"]


def test_dynamic_tier0_object_is_high() -> None:
    a = user("temp")
    snap = _dynamic(a.dn, privileged={"Domain Admins": [a.dn]})
    assert only(snap, "AD-INF-024").severity is Severity.HIGH


def test_lowered_ttl_is_reported() -> None:
    f = only(_dynamic(dynamic_ttl_min=1, dynamic_ttl_default=3600), "AD-INF-024")
    assert f.objects == [
        "DynamicObjectDefaultTTL is 3600 seconds (default 86400)",
        "DynamicObjectMinTTL is 1 seconds (default 900)",
    ]


def test_default_ttl_no_objects_and_unknown_ttl_are_quiet() -> None:
    assert "AD-INF-024" not in ids(run_all(_dynamic()))
    unknown = _dynamic(dynamic_ttl_min=None, dynamic_ttl_default=None)
    assert "AD-INF-024" not in ids(run_all(unknown))
    assert "AD-INF-024" not in ids(run_all(snapshot(dynamic_objects=["CN=x"])))


class TtlCollector(Collector):
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.entries = entries

    def optional(self, base: str, flt: str, attrs: list[str], **kw: Any) -> list[dict[str, Any]]:
        return self.entries


def test_ttl_settings_are_read_and_unknown_is_a_note() -> None:
    values = [b"DisableVLVSupport=0", b"DynamicObjectDefaultTTL=86400", b"DynamicObjectMinTTL=900"]
    c = TtlCollector([{"msds-other-settings": values}])
    assert c._dynamic_ttl("CN=Configuration") == (86400, 900)
    assert c.notes == []
    c = TtlCollector([{}])
    assert c._dynamic_ttl("CN=Configuration") == (None, None)
    assert "AD-INF-024" in c.notes[0]


# --- Round trip, older snapshots, redaction ----------------------------------------------


def full_snapshot() -> Snapshot:
    a = user("admin1", has_mail=True)
    snap = sccm(
        Ace(DOMAIN_USERS, FULL),
        sccm_objects=[SccmObject("CN=SMS-Site-P01,CN=System Management", "site", "P01"),
                      SccmObject("CN=SMS-MP,CN=System Management", "management point", "P01",
                                 "sccm01.secretcorp.test")],
        privileged={"Domain Admins": [a.dn]},
        mail_checked=True,
        config_acls={"Schema": [Ace(HELPDESK, sd.WRITE_DAC)]},
        config_acls_checked=True,
        ca_certificates=[cert(name="Secret CA", key_bits=1024, not_after=NOW + timedelta(days=1))],
        ca_certificates_checked=True,
        display_specifiers=[DisplaySpecifierCommand("CN=u,CN=409", "adminContextMenu",
                                                     r"\\files.secretcorp.test\tool.exe")],
        display_specifiers_checked=True,
        dynamic_objects=["CN=Temp Secret,DC=lab,DC=test"],
        dynamic_ttl_default=86400,
        dynamic_ttl_min=900,
        dynamic_objects_checked=True,
        dkm_containers=[DirObject("CN=adfsguid,CN=ADFS", "adfsguid", "container",
                                  aces=[Ace(DOMAIN_USERS, sd.GENERIC_READ)])],
        dkm_checked=True,
    )  # fmt: skip
    snap.accounts.append(a)
    return snap


def test_new_fields_survive_a_round_trip() -> None:
    snap = full_snapshot()
    back = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert back == snap


NEW_KEYS = (
    "sccm_container", "sccm_objects", "sccm_checked", "dkm_containers", "dkm_checked",
    "config_acls", "config_acls_checked", "mail_checked", "ca_certificates",
    "ca_certificates_checked", "display_specifiers", "display_specifiers_checked",
    "dynamic_objects", "dynamic_ttl_default", "dynamic_ttl_min", "dynamic_objects_checked",
    "ace_inheritance_checked",
)  # fmt: skip
NEW_CHECKS = (
    "AD-INF-022", "AD-ACL-014", "AD-ACL-011", "AD-ACL-012", "AD-ACL-013", "AD-PRIV-017",
    "AD-ADCS-021", "AD-INF-023", "AD-INF-024",
)  # fmt: skip


def test_older_snapshot_loads_and_says_what_was_not_evaluated() -> None:
    data = json.loads(json.dumps(full_snapshot().to_json()))
    for key in NEW_KEYS:
        del data[key]
    for a in data["accounts"]:
        del a["has_mail"]
    loaded = Snapshot.from_json(data)
    text = " ".join(loaded.notes)
    for check_id in NEW_CHECKS:
        assert check_id in text, check_id
    assert not set(NEW_CHECKS) & ids(run_all(loaded))


def test_redaction_covers_the_new_names_and_keeps_the_findings() -> None:
    snap = full_snapshot()
    before = {f.check_id for f in run_all(snap)}
    out = redact.redact(json.loads(json.dumps(snap.to_json())), b"k")
    text = json.dumps(out)
    for secret in ("sccm01", "secretcorp", "P01", "Secret CA", "Temp Secret", "adfsguid", SID):
        assert secret not in text, secret
    # vocabulary the checks compare stays
    assert out["config_acls"].keys() == {"Schema"}
    assert out["ca_certificates"][0]["stores"] == ["ntauth"]
    assert out["display_specifiers"][0]["attribute"] == "adminContextMenu"
    back = Snapshot.from_json(out)
    assert {f.check_id for f in run_all(back)} == before


# --- Collector paths the lab cannot reach -------------------------------------------------


class Routes(Collector):
    """attempt(), search() and optional() answered from a list of responses, in order;
    a None response stands for a refused search."""

    def __init__(self, *responses: Any) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.responses = list(responses)

    def attempt(
        self, base: str, flt: str, attrs: list[str], must_exist: bool = False, **kw: Any
    ) -> Any:
        return self.responses.pop(0)


CONTAINER_ENTRY = {
    "distinguishedname": [CONTAINER_DN],
    "name": [b"System Management"],
    "ntsecuritydescriptor": [descriptor(ace_bytes(SITE_SERVER, FULL))],
}
MP_ENTRY = {
    "distinguishedname": [f"CN=SMS-MP-P01,{CONTAINER_DN}"],
    "objectclass": [b"top", b"mSSMSManagementPoint"],
    "mssmssitecode": [b"P01"],
    "dnshostname": [b"sccm01.lab.test"],
}
SITE_ENTRY = {
    "distinguishedname": [f"CN=SMS-Site-P01,{CONTAINER_DN}"],
    "objectclass": [b"top", b"mSSMSSite"],
    "mssmssitecode": [b"P01"],
}


def test_sccm_collection_reads_the_container_and_its_objects() -> None:
    c = Routes([CONTAINER_ENTRY], [MP_ENTRY, SITE_ENTRY])
    container, found, checked = c._sccm("DC=lab,DC=test")
    assert checked and container is not None
    assert [a.sid for a in container.aces] == [SITE_SERVER]
    assert found == [
        SccmObject(MP_ENTRY["distinguishedname"][0], "management point", "P01", "sccm01.lab.test"),
        SccmObject(SITE_ENTRY["distinguishedname"][0], "site", "P01", ""),
    ]


def test_sccm_absent_is_checked_and_empty() -> None:
    assert Routes([], [])._sccm("DC=lab,DC=test") == (None, [], True)


@pytest.mark.parametrize("responses", [(None, []), ([CONTAINER_ENTRY], None)])
def test_sccm_refused_is_a_note_and_not_clean(responses: tuple[Any, Any]) -> None:
    c = Routes(*responses)
    assert c._sccm("DC=lab,DC=test") == (None, [], False)
    assert "not judged" in c.notes[0]


def test_sccm_container_without_dacl_is_not_checked() -> None:
    bare = {"distinguishedname": [CONTAINER_DN], "name": [b"System Management"]}
    c = Routes([bare], [])
    container, _found, checked = c._sccm("DC=lab,DC=test")
    assert container is not None and not checked
    assert "AD-ACL-014 not judged" in c.notes[0]


def test_host_objects_are_read_for_site_servers_and_sync_agents() -> None:
    server = computer("SCCM01", sid=SITE_SERVER)
    agent = computer("AGENT01", sid=f"{SID}-1800")
    gmsa = computer("prov", sid=GMSA_SID)
    read: list[str] = []

    class Stub(Collector):
        def _base(self, dn: str, attrs: list[str]) -> list[dict[str, Any]]:
            read.append(dn)
            return [{"distinguishedname": [dn], "name": [b"x"]}]

    c = Stub(None)  # type: ignore[arg-type]
    objects = c._host_objects(
        [server, agent, gmsa],
        [],
        [Gmsa("prov$", gmsa.dn, [f"{SID}-1800"], 30)],
        sccm_container(Ace(SITE_SERVER, FULL)),
        {GMSA_SID},
    )
    assert sorted(read) == sorted([server.dn, agent.dn])
    assert all(o.kind == "computer" for o in objects)


def test_host_objects_skip_a_gmsa_without_dcsync() -> None:
    gmsa = computer("prov", sid=GMSA_SID)
    agent = computer("AGENT01", sid=f"{SID}-1800")

    class Stub(Collector):
        def _base(self, dn: str, attrs: list[str]) -> list[dict[str, Any]]:
            raise AssertionError(dn)

    c = Stub(None)  # type: ignore[arg-type]
    gmsas = [Gmsa("prov$", gmsa.dn, [f"{SID}-1800"], 30)]
    assert c._host_objects([gmsa, agent], [], gmsas, None, set()) == []


def test_ca_certificates_are_deduplicated_across_stores() -> None:
    entry = {"name": [b"object"], "cacertificate": [_cert(subject="Lab CA")]}
    c = Routes([entry], [entry], [], [])
    certs, checked = c._ca_certificates("CN=Public Key Services")
    assert checked and len(certs) == 1
    assert certs[0].name == "Lab CA" and certs[0].stores == ["enrollment", "root"]


def test_ca_store_refused_and_bad_certificate_are_notes() -> None:
    entry = {"name": [b"bad"], "cacertificate": [b"garbage"]}
    c = Routes(None, [entry], [], [])
    certs, checked = c._ca_certificates("CN=Public Key Services")
    assert not checked and not certs[0].parsed
    assert sum("AD-ADCS-021" in n for n in c.notes) == 2


def test_display_specifiers_keep_only_remote_commands() -> None:
    entry = {
        "distinguishedname": ["CN=user-Display,CN=409,CN=DisplaySpecifiers"],
        "admincontextmenu": [
            b"1,{4A2C0E60-5E2D-11D1-AB22-00C04FC2D4EE}",
            b"2,Manage,RsAdmin.msc",
            b"3,Tool,\\\\evil\\x.exe",
        ],
    }
    found, checked = Routes([entry])._display_specifiers("CN=Configuration")
    assert checked
    assert found == [DisplaySpecifierCommand(entry["distinguishedname"][0], "adminContextMenu",
                                             "\\\\evil\\x.exe")]  # fmt: skip


def test_display_specifiers_refused_is_a_note() -> None:
    c = Routes(None)
    assert c._display_specifiers("CN=Configuration") == ([], False)
    assert "AD-INF-023" in c.notes[0]


def test_dynamic_objects_from_both_partitions_and_refusal_is_a_note() -> None:
    entry = {"distinguishedname": ["CN=t,DC=lab"]}
    assert Routes([entry], [])._dynamic_objects("DC=lab", "CN=Config") == (["CN=t,DC=lab"], True)
    c = Routes([], None)
    assert c._dynamic_objects("DC=lab", "CN=Config") == ([], False)
    assert "AD-INF-024" in c.notes[0]
