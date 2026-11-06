"""Regressions from the round 5 review: CA registry robustness, ESC7 scope, GPO local
group scope, injection into the fixes script and Markdown, and redaction."""

from __future__ import annotations

import json
import struct
from dataclasses import replace

from ad_doctor import gpo_scope, probes, sd, winreg
from ad_doctor.checks import run_all
from ad_doctor.fixes import render_fixes
from ad_doctor.model import CaConfig, Probes, Severity, Snapshot, Trust
from ad_doctor.redact import redact
from ad_doctor.report import Report, render_markdown

from .test_acl_adcs import HELPDESK, sid_bytes
from .test_checks import only
from .test_gpo_local import (
    ADMINS,
    AU,
    DOMAIN_USERS,
    GUID_A,
    HEAD,
    LAB,
    RDU,
    SERVER_ADMINS,
    _tier0_lab,
    entry,
    gpo,
    gsnap,
    host,
    link,
    reached,
)
from .test_round5 import CA_HOST, POLICY, FakeRegistry, FakeTransport, _pdu, _snap, _tree, ca

CLEAN = {
    "interface_flags": 0x641,
    "edit_flags": 0x11014E,
    "disabled_extensions": [],
    "owner": "S-1-5-32-544",
    "policy_module": POLICY,
}


def clean_ca(**kw: object) -> CaConfig:
    return ca(**{**CLEAN, **kw})


def ca_sd(owner: str, *aces: tuple[int, str, int]) -> bytes:
    body = b""
    for ace_type, sid, mask in aces:
        raw = sid_bytes(sid)
        body += struct.pack("<BBHI", ace_type, 0, 8 + len(raw), mask) + raw
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(body), len(aces), 0) + body
    own = sid_bytes(owner)
    return struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(own)) + own + acl


def ids(snap: Snapshot) -> set[str]:
    return {f.check_id for f in run_all(snap)}


# --- the CA's registry -------------------------------------------------------------------


def test_truncated_ca_security_descriptor_is_an_error_not_a_crash() -> None:
    tree = _tree()
    bad = struct.pack("<BBHIIII", 1, 0, 0x8004, 0xFFFF, 0, 0, 20) + b"\0" * 8
    tree[f"{probes.CA_CONFIGURATION}\\adlab-CA"]["Security"] = bad
    cfg = probes.read_ca_config(FakeRegistry(tree), CA_HOST, "adlab-CA")
    assert cfg.error == "CA security descriptor of adlab-CA not parseable"
    f = only(_snap(cfg), "AD-ADCS-016")
    assert f.objects == [f"{CA_HOST}: CA security descriptor of adlab-CA not parseable"]


def test_absent_ca_values_are_unknown_not_clean() -> None:
    tree = _tree()
    ca_key = f"{probes.CA_CONFIGURATION}\\adlab-CA"
    del tree[ca_key]["InterfaceFlags"], tree[ca_key]["Security"]
    del tree[f"{ca_key}\\PolicyModules\\{POLICY}"]["EditFlags"]
    cfg = probes.read_ca_config(FakeRegistry(tree), CA_HOST, "adlab-CA")
    assert cfg.error is None
    f = only(_snap(cfg), "AD-ADCS-016")
    assert f.objects == [
        f"{CA_HOST}: InterfaceFlags, security descriptor, EditFlags absent or empty; "
        "ESC11, ESC7, ESC6 not judged",
    ]
    assert "AD-ADCS-016" not in ids(_snap(clean_ca()))


def test_third_party_module_names_only_the_checks_it_affects() -> None:
    f = only(_snap(clean_ca(policy_module="Acme.Policy", edit_flags=None)), "AD-ADCS-016")
    assert f.objects == [
        f"{CA_HOST}: policy module Acme.Policy is not Microsoft's; ESC6 and ESC16 not judged"
    ]
    assert "each line names the checks affected" in f.detail


def test_ca_deny_aces_remove_rights() -> None:
    everyone = "S-1-1-0"
    owner, aces = sd.parse_ca(
        ca_sd(
            "S-1-5-32-544",
            (sd.ACCESS_DENIED, everyone, sd.CA_MANAGE | sd.CA_OFFICER),
            (sd.ACCESS_ALLOWED, everyone, sd.CA_MANAGE | sd.CA_OFFICER),
            (sd.ACCESS_DENIED, HELPDESK, sd.CA_MANAGE),
            (sd.ACCESS_ALLOWED, HELPDESK, sd.CA_MANAGE | sd.CA_OFFICER | 0x200),
        )
    )
    assert owner == "S-1-5-32-544"
    # Everyone is denied both rights by an earlier ACE; helpdesk keeps what was not denied
    assert aces == [sd.Ace(HELPDESK, 0x200)]
    # an allow that comes before the deny still grants (Windows reads the DACL in order)
    _, aces = sd.parse_ca(
        ca_sd(
            "S-1-5-32-544",
            (sd.ACCESS_ALLOWED, HELPDESK, sd.CA_OFFICER),
            (sd.ACCESS_DENIED, HELPDESK, sd.CA_OFFICER),
        )
    )
    assert aces == [sd.Ace(HELPDESK, sd.CA_OFFICER)]


def test_esc6_and_esc16_texts_follow_kb5014754() -> None:
    snap = _snap(clean_ca(edit_flags=0x15014E, disabled_extensions=[sd.SZOID_NTDS_CA_SECURITY_EXT]))
    for cid in ("AD-ADCS-012", "AD-ADCS-015", "AD-CHAIN-004"):
        f = only(snap, cid)
        assert "StrongCertificateBindingEnforcement=2" not in f.detail + f.remediation, cid
    assert "current updates" in only(snap, "AD-ADCS-012").remediation
    assert "September 2025" in only(snap, "AD-ADCS-015").detail


def test_chain_esc6_esc16_drops_a_level_when_requests_wait_for_a_manager() -> None:
    snap = _snap(
        clean_ca(
            edit_flags=0x15014E,
            disabled_extensions=[sd.SZOID_NTDS_CA_SECURITY_EXT],
            request_disposition=0x101,
        )
    )
    assert only(snap, "AD-CHAIN-004").severity == Severity.MEDIUM


def test_bind_takes_the_fragment_size_from_the_servers_receive_size() -> None:
    body = struct.pack("<HHI", 4280, 2048, 0)
    body += struct.pack("<H", 0) + b"\0\0"
    body += struct.pack("<BxxxHHx", 1, 0, 0) + b"\0" * 19
    ack = _pdu(winreg.PTYPE_BIND_ACK, 3, 1, body)

    class Small(FakeTransport):
        def write(self, data: bytes) -> None:
            super().write(data)
            if data[2] == winreg.PTYPE_BIND:
                self._pending = ack

    client = winreg.RpcClient(Small([]))
    client.bind()
    assert client.max_xmit == 2048


# --- ESC7 and the CA's own domain --------------------------------------------------------

CHILD_DA = "S-1-5-21-111-222-333-512"


def test_esc7_accepts_admins_of_other_forest_domains() -> None:
    aces = [sd.Ace(CHILD_DA, sd.CA_MANAGE | sd.CA_OFFICER)]
    # the child domain is known from its trust object
    child = Trust("child.lab.test", 3, 2, 0x20, sid="S-1-5-21-111-222-333")
    assert "AD-ADCS-013" not in ids(_snap(clean_ca(aces=aces), trusts=[child]))
    # no trust object (a sibling domain), but the CA lives in another domain
    other = clean_ca(aces=aces, host="ca01.child.lab.test")
    assert "AD-ADCS-013" not in ids(_snap(other))
    # a foreign forest's admins on a CA of this domain are still reported
    external = Trust("other.example", 3, 2, 0x8, sid="S-1-5-21-111-222-333")
    f = only(_snap(clean_ca(aces=aces), trusts=[external]), "AD-ADCS-013")
    assert f.severity == Severity.HIGH


# --- GPO local groups --------------------------------------------------------------------


def test_interactive_in_administrators_is_broad() -> None:
    snap = gsnap(
        host("WS01"),
        gpos=[gpo("X", GUID_A, link(LAB))],
        entries=[entry(GUID_A, ADMINS, gpo_scope.INTERACTIVE)],
    )
    assert only(snap, "AD-GPO-005").objects == ["X: Interactive -> Administrators on WS01$"]


def test_ou_name_ending_in_a_backslash_keeps_the_domain_links() -> None:
    ou = "OU=Lab\\\\,DC=lab,DC=test"  # an OU named "Lab\"
    assert gpo_scope.containers(f"CN=WS01,{ou}", HEAD) == [ou.lower(), HEAD.lower()]
    assert gpo_scope.containers("CN=WS01,OU=a\\,b,DC=lab,DC=test", HEAD) == [
        "ou=a\\,b,dc=lab,dc=test",
        HEAD.lower(),
    ]
    snap = gsnap(
        host("WS01", ou=ou),
        gpos=[gpo("AtDomain", GUID_A, link(HEAD, "domain"))],
        entries=[entry(GUID_A, ADMINS, DOMAIN_USERS)],
    )
    assert reached(snap) == {("AtDomain", "WS01$")}


def test_item_level_targeting_alone_still_reports() -> None:
    snap = gsnap(
        host("WS02"),
        gpos=[gpo("LabRdp", GUID_A, link(LAB))],
        entries=[entry(GUID_A, ADMINS, DOMAIN_USERS, "gpp", filtered=True)],
    )
    f = only(snap, "AD-GPO-005")
    assert f.objects == [
        "LabRdp: Domain Users -> Administrators on WS02$ [item-level targeting not evaluated]"
    ]


def test_unresolved_remote_logon_holder_keeps_the_grant() -> None:
    from ad_doctor.model import GpoSettings

    settings = {
        GUID_A: GpoSettings(privileges={"SeRemoteInteractiveLogonRight": ["LAB\\LabServerAdmins"]})
    }
    snap = gsnap(
        host("WS01"),
        gpos=[gpo("X", GUID_A, link(LAB))],
        entries=[entry(GUID_A, RDU, AU)],
        gpo_settings=settings,
    )
    [grant] = gpo_scope.grants(snap)
    assert grant.effective
    assert gpo_scope.UNRESOLVED_LOGON in grant.caveats
    # resolved to the member's SID (what the collector now does), it is certain
    settings[GUID_A].privileges["SeRemoteInteractiveLogonRight"] = [SERVER_ADMINS]
    snap = gsnap(
        host("WS01"),
        gpos=[gpo("X", GUID_A, link(LAB))],
        entries=[entry(GUID_A, RDU, SERVER_ADMINS)],
        gpo_settings=settings,
    )
    [grant] = gpo_scope.grants(snap)
    assert grant.effective and not grant.caveats


# --- injection into generated text -------------------------------------------------------

EVIL = "Evil\nRemove-ADUser alice -Confirm:$false #`|\r\n" + chr(0x2028) + "x"


def _hostile() -> Snapshot:
    snap = gsnap(
        host("WS01"),
        gpos=[gpo(EVIL, GUID_A, link(LAB))],
        entries=[entry(GUID_A, ADMINS, DOMAIN_USERS)],
    )
    cfg = clean_ca(name="CA\nStop-Computer -Force", edit_flags=0x15014E)
    return replace(snap, probes=Probes(ca_configs=[cfg]))


def test_fixes_script_never_breaks_out_of_a_comment() -> None:
    snap = _hostile()
    findings = run_all(snap)
    assert {"AD-GPO-005", "AD-ADCS-012"} <= {f.check_id for f in findings}
    script = render_fixes(findings, snap)
    for line in script.splitlines():
        assert not line or line.startswith("#") or line.endswith("-WhatIf"), line
    assert "Evil\\x0aRemove-ADUser" in script
    assert "CA\\x0aStop-Computer" in script


def test_markdown_objects_stay_in_their_code_span() -> None:
    snap = _hostile()
    md = render_markdown(Report(snap, run_all(snap)))
    for line in md.splitlines():
        assert not line.startswith(("Remove-ADUser", "Stop-Computer", "x")), line
    assert "- ``Evil Remove-ADUser alice -Confirm:$false #`|" in md


# --- redaction ---------------------------------------------------------------------------

KEY = b"k" * 32


def test_redaction_covers_sites_policy_modules_and_ipv6() -> None:
    dc_dn = "CN=DC02,OU=Domain Controllers,DC=lab,DC=test"
    site = "CN=HQ-Istanbul-Site,CN=Sites,CN=Configuration,DC=lab,DC=test"
    cfg = clean_ca(
        policy_module="AcmeVendor.SecretPolicy",
        error="SMB failed: connect to 10.20.30.40 / fe80::1234:5678%eth0 and 2001:db8::1",
    )
    snap = replace(_snap(cfg), dc_sites={dc_dn.lower(): site})
    out = json.dumps(redact(snap.to_json(), KEY))
    for leak in ("HQ-Istanbul-Site", "AcmeVendor", "10.20.30.40", "fe80::1234", "2001:db8"):
        assert leak not in out, leak


def test_redaction_keeps_every_finding() -> None:
    """The same checks at the same severities before and after redaction."""
    ext = [sd.SZOID_NTDS_CA_SECURITY_EXT]
    snap = _tier0_lab(
        probes=Probes(ca_configs=[clean_ca(edit_flags=0x15014E, disabled_extensions=ext)])
    )
    ca01 = next(a for a in snap.accounts if a.sam == "CA01$")
    # the CA host controls its own CA object: expected, before and after redaction
    snap.acls["PKI:CA lab-CA"] = [sd.Ace(ca01.sid, sd.GENERIC_ALL)]
    snap.principals[ca01.sid] = "CA01$"
    back = Snapshot.from_json(redact(snap.to_json(), KEY))
    assert back.probes.ca_configs[0].disabled_extensions == ext
    before = {(f.check_id, f.severity, len(f.objects)) for f in run_all(snap)}
    after = {(f.check_id, f.severity, len(f.objects)) for f in run_all(back)}
    assert {"AD-ADCS-015", "AD-CHAIN-004", "AD-GPO-006"} <= {c for c, _, _ in before}
    assert "AD-ADCS-005" not in {c for c, _, _ in before}
    assert before == after


def test_computer_name_and_sam_share_a_token() -> None:
    from ad_doctor.redact import Redactor

    r = Redactor(KEY)
    assert r.token("ENTRA01$") == r.token("ENTRA01") + "$"
