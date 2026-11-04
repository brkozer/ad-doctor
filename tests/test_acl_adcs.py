from __future__ import annotations

import struct
import uuid

from ad_doctor import sd
from ad_doctor.checks import run_all
from ad_doctor.model import CertTemplate, GppPassword
from ad_doctor.sd import Ace
from ad_doctor.sysvol import scan_xml

from .test_checks import only, snapshot

DOMAIN_SID = "S-1-5-21-1-2-3"
DOMAIN_USERS = f"{DOMAIN_SID}-513"
DOMAIN_ADMINS = f"{DOMAIN_SID}-512"
HELPDESK = f"{DOMAIN_SID}-1105"
AUTH_USERS = "S-1-5-11"


def sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    subs = [int(x) for x in parts[3:]]
    return (
        bytes([int(parts[1]), len(subs)])
        + int(parts[2]).to_bytes(6, "big")
        + struct.pack(f"<{len(subs)}I", *subs)
    )


def ace_bytes(sid: str, mask: int, object_type: str | None = None, flags: int = 0) -> bytes:
    if object_type is None:
        body = struct.pack("<I", mask) + sid_bytes(sid)
        ace_type = sd.ACCESS_ALLOWED
    else:
        body = (
            struct.pack("<II", mask, sd.ACE_OBJECT_TYPE_PRESENT)
            + uuid.UUID(object_type).bytes_le
            + sid_bytes(sid)
        )
        ace_type = sd.ACCESS_ALLOWED_OBJECT
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


def descriptor(*aces: bytes) -> bytes:
    acl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(acl_body), len(aces), 0) + acl_body
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)
    return header + acl


def test_parse_dacl_reads_plain_and_object_aces() -> None:
    raw = descriptor(
        ace_bytes(DOMAIN_ADMINS, sd.GENERIC_ALL),
        ace_bytes(DOMAIN_USERS, sd.CONTROL_ACCESS, sd.CERT_ENROLL),
        ace_bytes(HELPDESK, sd.WRITE_DAC, flags=sd.INHERIT_ONLY),
    )
    aces = sd.parse_dacl(raw)
    assert aces == [
        Ace(DOMAIN_ADMINS, sd.GENERIC_ALL),
        Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, sd.CERT_ENROLL),
    ]
    assert aces[1].extended_right(sd.CERT_ENROLL)
    assert not aces[1].extended_right(sd.DS_REPL_GET_CHANGES)
    assert not aces[1].takeover


def test_takeover_rights() -> None:
    assert Ace(HELPDESK, sd.WRITE_OWNER).takeover
    assert Ace(HELPDESK, sd.WRITE_PROPERTY).takeover
    # WriteProperty on a single attribute is not a takeover
    assert not Ace(HELPDESK, sd.WRITE_PROPERTY, "bf967a68-0de6-11d0-a285-00aa003049e2").takeover


def template(name: str = "VulnUser", **kw: object) -> CertTemplate:
    values: dict[str, object] = {
        "name": name,
        "published": True,
        "enrollee_supplies_subject": False,
        "manager_approval": False,
        "authorized_signatures": 0,
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "aces": [Ace(DOMAIN_USERS, sd.CONTROL_ACCESS, sd.CERT_ENROLL)],
    }
    values.update(kw)
    return CertTemplate(**values)  # type: ignore[arg-type]


def test_esc1() -> None:
    snap = snapshot(templates=[template(enrollee_supplies_subject=True)])
    f = only(snap, "AD-ADCS-001")
    assert f.objects == ["VulnUser (enroll: Domain Users)"]


def test_esc1_needs_publication_and_no_approval() -> None:
    for kw in ({"published": False}, {"manager_approval": True}, {"authorized_signatures": 1}):
        snap = snapshot(templates=[template(enrollee_supplies_subject=True, **kw)])
        assert run_all(snap) == []


def test_esc1_ignores_admin_only_enrollment() -> None:
    t = template(
        enrollee_supplies_subject=True,
        aces=[Ace(DOMAIN_ADMINS, sd.CONTROL_ACCESS, sd.CERT_ENROLL)],
    )
    assert run_all(snapshot(templates=[t])) == []


def test_esc2_no_eku() -> None:
    assert only(snapshot(templates=[template(ekus=[])]), "AD-ADCS-002")


def test_esc3_request_agent() -> None:
    t = template(ekus=["1.3.6.1.4.1.311.20.2.1"])
    assert only(snapshot(templates=[t]), "AD-ADCS-003")


def test_esc4_write_on_unpublished_template() -> None:
    t = template(published=False, aces=[Ace(AUTH_USERS, sd.GENERIC_WRITE)])
    assert only(snapshot(templates=[t]), "AD-ADCS-004").objects == [
        "VulnUser (Authenticated Users)"
    ]


def test_dcsync_needs_both_rights_and_skips_tier0() -> None:
    aces = [
        Ace(HELPDESK, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
        Ace(HELPDESK, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL),
        Ace(f"{DOMAIN_SID}-1106", sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
        Ace("S-1-5-32-544", sd.CONTROL_ACCESS),
    ]
    snap = snapshot(acls={"domain": aces}, principals={HELPDESK: "svc_sync"})
    assert only(snap, "AD-ACL-001").objects == ["svc_sync"]


def test_adminsdholder_and_domain_takeover() -> None:
    snap = snapshot(
        acls={
            "AdminSDHolder": [Ace(DOMAIN_ADMINS, sd.GENERIC_ALL), Ace(HELPDESK, sd.GENERIC_ALL)],
            "domain": [Ace(DOMAIN_USERS, sd.WRITE_OWNER), Ace("S-1-5-18", sd.FULL_CONTROL)],
        },
        principals={HELPDESK: "helpdesk"},
    )
    assert only(snap, "AD-ACL-002").objects == ["helpdesk"]
    assert only(snap, "AD-ACL-003").objects == ["Domain Users"]


def test_gpp_finding() -> None:
    snap = snapshot(gpp_passwords=[GppPassword(r"Policies\{X}\Groups.xml", "localadmin")])
    assert only(snap, "AD-GPP-001").objects == [r"Policies\{X}\Groups.xml (localadmin)"]


def test_scan_xml_reports_accounts_not_secrets() -> None:
    xml = (
        b'<Groups><User name="a">'
        b'<Properties newName="" cpassword="abc" userName="localadmin"/></User>'
        b'<User name="b"><Properties userName="other" cpassword=""/></User></Groups>'
    )
    assert scan_xml(xml) == ["localadmin"]
