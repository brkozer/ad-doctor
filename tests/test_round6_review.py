"""Regression tests for the review of the round 6 checks."""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest
from ldap3.core.exceptions import LDAPBusyResult
from smbprotocol.exceptions import SMBOSError
from smbprotocol.header import NtStatus

from ad_doctor import catalog, collect, fixes, gpo_scope, probes, redact, sd, sysvol, winreg
from ad_doctor.checks import run_all
from ad_doctor.collect import mark_rogue_dcs
from ad_doctor.model import DirObject, GpoSettings, Probes, Severity, Snapshot
from ad_doctor.report import Report, render_junit

from .test_checks import computer, ids, only, snapshot, user
from .test_round5 import CA_HOST, FakeRegistry, _snap, _tree
from .test_round6 import HEAD, SID, URL, gpo, ntlm_snapshot, snapshot_entries
from .test_round6_data import (
    CONFIG,
    CROSSREFS,
    CUTOVER,
    DC_UAC,
    DOMAIN,
    HIDDEN,
    LISTED,
    OLD,
    SPN,
    Recorder,
    admins,
    audit_ca,
    builtin_admins,
    channel_snapshot,
    compare,
)

ROOT = Path(__file__).resolve().parent.parent
AUTH_USERS_FSP = f"CN=S-1-5-11,CN=ForeignSecurityPrincipals,{HEAD}"


# --- AD-CHAIN-003: a deny next to anything that could change it ---------------------------


def test_a_deny_next_to_an_unread_gpo_is_unknown() -> None:
    snap = ntlm_snapshot(2)
    snap.gpos.append(gpo("Other", "{C}"))
    state = gpo_scope.dc_outgoing_ntlm(snap)
    assert state.denied is None
    assert "Hardening" in state.detail and "Other" in state.detail
    f = only(snap, "AD-CHAIN-003")
    assert f.severity is Severity.MEDIUM and "unknown" in f.detail


def test_a_gpo_read_as_empty_does_not_stop_a_deny() -> None:
    snap = ntlm_snapshot(2)
    snap.gpos.append(gpo("Other", "{C}"))
    snap.gpo_settings["{C}"] = GpoSettings()
    assert gpo_scope.dc_outgoing_ntlm(snap).denied is True


def test_an_exception_list_keeps_the_deny_unknown() -> None:
    snap = ntlm_snapshot(2)
    snap.gpo_settings["{A}"].ntlm_exceptions = ["*.lab.test"]
    state = gpo_scope.dc_outgoing_ntlm(snap)
    assert state.denied is None
    assert "denied with exceptions: *.lab.test" in state.detail
    probed = Probes(web_enrollment_ntlm=[URL], spooler_on_dc=True)
    snap = ntlm_snapshot(2, probes=probed)
    snap.gpo_settings["{A}"].ntlm_exceptions = ["*.lab.test"]
    assert only(snap, "AD-CHAIN-003").severity is Severity.HIGH


def test_a_long_exception_list_is_cut() -> None:
    snap = ntlm_snapshot(2)
    snap.gpo_settings["{A}"].ntlm_exceptions = [f"h{i}" for i in range(8)]
    assert "(+3 more)" in gpo_scope.dc_outgoing_ntlm(snap).detail


def test_exception_servers_are_parsed() -> None:
    key = rf"{sysvol.LSA}\MSV1_0\ClientAllowedNTLMServers"
    text = f"[Registry Values]\n{key}=7,*.lab.test,relay01\n"
    assert sysvol.parse_gpttmpl(text).ntlm_exceptions == ["*.lab.test", "relay01"]
    assert sysvol.parse_gpttmpl(f"[Registry Values]\n{key}=7,\n").ntlm_exceptions == []


def test_exception_servers_are_redacted() -> None:
    snap = ntlm_snapshot(2)
    snap.gpo_settings["{A}"].ntlm_exceptions = ["relay01.hidden.example"]
    out = json.dumps(redact.redact(json.loads(json.dumps(snap.to_json())), b"k"))
    assert "relay01" not in out and "hidden" not in out


def scan_templates(monkeypatch: pytest.MonkeyPatch, status: int) -> sysvol.SysvolResult:
    def fail(path: str, port: int) -> bytes:
        raise SMBOSError(status, path)

    def no_walk(*a: Any, **k: Any) -> None:
        raise OSError("no tree")

    monkeypatch.setattr(sysvol.smbclient, "register_session", lambda *a, **k: None)
    monkeypatch.setattr(sysvol.smbclient, "walk", no_walk)
    monkeypatch.setattr(sysvol.smbclient, "reset_connection_cache", lambda: None)
    monkeypatch.setattr(sysvol, "_read", fail)
    return sysvol.scan("dc", "lab.test", "u", "p", ["{A}"])


def test_a_gpo_without_a_template_counts_as_read(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan_templates(monkeypatch, NtStatus.STATUS_OBJECT_PATH_NOT_FOUND)
    assert result.gpo_settings == {"{A}": GpoSettings()}
    assert result.unreadable == []


def test_a_failed_template_read_stays_unread(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan_templates(monkeypatch, NtStatus.STATUS_ACCESS_DENIED)
    assert result.gpo_settings == {}
    assert len(result.unreadable) == 1


def test_a_denied_chain_stays_medium_with_a_spooler() -> None:
    probed = Probes(web_enrollment_ntlm=[URL], spooler_on_dc=True)
    f = only(ntlm_snapshot(2, probes=probed), "AD-CHAIN-003")
    assert f.severity is Severity.MEDIUM and "Kerberos" in f.detail


# --- AD-ADCS-018: absent against unreadable -----------------------------------------------


def test_an_absent_filter_is_a_finding_not_a_gap() -> None:
    cfg = probes.read_ca_config(FakeRegistry(_tree()), CA_HOST, "adlab-CA")
    assert cfg.audit_absent and cfg.audit_filter is None
    snap = _snap(audit_ca(None, audit_absent=True))
    f = only(snap, "AD-ADCS-018")
    assert f.severity is Severity.MEDIUM
    assert f.objects[0].startswith("adlab-CA: AuditFilter not set, off: start and stop")
    assert f.key(f.objects[0]) == "adlab-CA"
    assert "AD-ADCS-016" not in ids(run_all(snap))


def test_a_failed_filter_read_stays_a_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = FakeRegistry(_tree())
    original = reg.query_value

    def query(key: bytes, name: str) -> winreg.RegValue | None:
        if name == "AuditFilter":
            raise winreg.RegistryError("denied", 5)
        return original(key, name)

    monkeypatch.setattr(reg, "query_value", query)
    cfg = probes.read_ca_config(reg, CA_HOST, "adlab-CA")
    assert cfg.audit_checked and not cfg.audit_absent and cfg.audit_filter is None


# --- AD-GPO-008: what a listed group holds ------------------------------------------------


def group_snapshot(*members: str, **kw: object) -> Snapshot:
    allow = DirObject(f"CN=Allow,{HEAD}", "Allow", "group", sid=LISTED, members=list(members))
    extra: list[DirObject] = list(kw.pop("objects", []))  # type: ignore[call-overload]
    accounts = kw.pop("accounts", [])
    return channel_snapshot(
        f"O:BAG:BAD:(A;;RC;;;{LISTED})",
        *accounts,  # type: ignore[misc]
        objects=[allow, *extra],
        **kw,
    )


def test_a_foreign_broad_member_makes_a_group_severe() -> None:
    f = only(group_snapshot(AUTH_USERS_FSP), "AD-GPO-008")
    assert f.severity is Severity.HIGH


def test_a_nested_broad_group_makes_a_group_severe() -> None:
    computers = DirObject(
        f"CN=Domain Computers,{HEAD}", "Domain Computers", "group", sid=f"{SID}-515"
    )
    f = only(group_snapshot(computers.dn, objects=[computers]), "AD-GPO-008")
    assert f.severity is Severity.HIGH


def test_an_ordinary_member_stays_medium() -> None:
    plain = user("plain", sid=f"{SID}-3000")
    f = only(group_snapshot(plain.dn, accounts=[plain]), "AD-GPO-008")
    assert f.severity is Severity.MEDIUM


def test_a_listed_exchange_server_is_high() -> None:
    server = computer("EX01", sid=f"{SID}-3001")
    trusted = DirObject(
        f"CN=Exchange Trusted Subsystem,{HEAD}",
        "Exchange Trusted Subsystem",
        "group",
        sid=f"{SID}-3002",
        members=[server.dn],
    )
    snap = channel_snapshot(
        f"O:BAG:BAD:(A;;RC;;;{SID}-3001)", server, objects=[trusted], principals={}
    )
    assert only(snap, "AD-GPO-008").severity is Severity.HIGH


def test_a_listed_ca_host_through_a_group_is_high() -> None:
    server = computer("CA01", sid=f"{SID}-3001")
    snap = group_snapshot(server.dn, accounts=[server], ca_hosts=["CA01$", "CA01"])
    assert only(snap, "AD-GPO-008").severity is Severity.HIGH


# --- SDDL aliases -------------------------------------------------------------------------


def test_ro_is_the_forest_wide_group() -> None:
    allow, _ = sd.sddl_trustees("O:BAG:BAD:(A;;RC;;;RO)", SID, "S-1-5-21-9-9-9")
    assert allow == ["S-1-5-21-9-9-9-498"]


@pytest.mark.parametrize(
    ("alias", "sid"),
    [
        ("MU", "S-1-5-32-558"),
        ("LU", "S-1-5-32-559"),
        ("IS", "S-1-5-32-568"),
        ("CY", "S-1-5-32-569"),
        ("ER", "S-1-5-32-573"),
        ("CD", "S-1-5-32-574"),
        ("RA", "S-1-5-32-575"),
        ("ES", "S-1-5-32-576"),
        ("MS", "S-1-5-32-577"),
        ("HA", "S-1-5-32-578"),
        ("AA", "S-1-5-32-579"),
        ("RM", "S-1-5-32-580"),
        ("OW", "S-1-3-4"),
        ("AC", "S-1-15-2-1"),
    ],
)
def test_documented_aliases_are_known(alias: str, sid: str) -> None:
    assert sd.sddl_trustees(f"O:BAG:BAD:(A;;RC;;;{alias})", SID)[0] == [sid]


def test_a_new_alias_no_longer_hides_a_listed_dc() -> None:
    f = only(channel_snapshot("O:BAG:BAD:(A;;RC;;;DD)(A;;RC;;;MU)"), "AD-GPO-008")
    assert f.severity is Severity.HIGH


# --- AD-KRB-005 ---------------------------------------------------------------------------


def test_the_fix_never_sets_aes_only_on_a_suspect_password() -> None:
    snap = snapshot(user("svc_web", spns=SPN, enc_types=4, pwd_last_set=OLD), aes_cutover=CUTOVER)
    (line,) = fixes.snippet(only(snap, "AD-KRB-005"), snap)
    assert line.startswith("# svc_web:") and "reset the password first" in line


def test_a_password_that_must_change_has_no_known_age() -> None:
    snap = snapshot(
        user(
            "svc_must", spns=SPN, enc_types=0x18, pwd_last_set=None, when_created=OLD,
            pwd_must_change=True,
        ),
        aes_cutover=CUTOVER,
    )  # fmt: skip
    assert "AD-KRB-005" not in ids(run_all(snap))


def test_whencreated_is_used_when_pwdlastset_was_not_read() -> None:
    snap = snapshot(
        user("svc_x", spns=SPN, enc_types=0x18, pwd_last_set=None, when_created=OLD),
        aes_cutover=CUTOVER,
    )
    assert only(snap, "AD-KRB-005").severity is Severity.MEDIUM


def test_pwdlastset_zero_and_absent_are_told_apart() -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    base: dict[str, list[Any]] = {
        "distinguishedname": [f"CN=a,{HEAD}"],
        "samaccountname": [b"a"],
        "objectclass": [b"user"],
    }
    assert c._account({**base, "pwdlastset": [b"0"]}).pwd_must_change
    assert not c._account(base).pwd_must_change


def test_computers_with_no_value_share_one_line() -> None:
    names = [f"H{i:02}" for i in range(7)]
    f = only(snapshot(*(computer(n, spns=SPN) for n in names)), "AD-KRB-005")
    assert f.severity is Severity.LOW
    assert len(f.objects) == 1
    assert f.objects[0].startswith("7 computer(s) with an SPN: no value set")
    assert "H00$" in f.objects[0] and "H05$" not in f.objects[0]
    # the identity holds when the count moves
    other = only(snapshot(*(computer(n, spns=SPN) for n in names[:3])), "AD-KRB-005")
    assert f.key(f.objects[0]) == other.key(other.objects[0])


def test_a_user_row_stays_visible_next_to_many_computers() -> None:
    f = only(
        snapshot(user("svc_a", spns=SPN), *(computer(f"H{i}", spns=SPN) for i in range(50))),
        "AD-KRB-005",
    )
    assert "svc_a: no value set, the domain default applies" in f.objects
    assert len(f.objects) == 2


def test_a_computer_with_an_explicit_rc4_value_keeps_its_own_row() -> None:
    f = only(snapshot(computer("NAS01", spns=SPN, enc_types=4)), "AD-KRB-005")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["NAS01$: no AES in msDS-SupportedEncryptionTypes (0x4)"]


# --- AD-INF-007 ---------------------------------------------------------------------------


def dmsa_link() -> Any:
    admin = f"CN=adm,{HEAD}"
    return admin, user("dm$", preceded_by=admin, managed=True)


def test_a_visible_link_is_never_called_invisible() -> None:
    admin, dm = dmsa_link()
    data = snapshot(dm, privileged={"Domain Admins": [admin]}).to_json()
    data["dmsa_visible"] = False
    f = only(Snapshot.from_json(data), "AD-INF-007")
    assert "No dMSA was visible" not in f.detail


def test_an_older_snapshot_does_not_claim_anything_about_dmsas() -> None:
    admin, dm = dmsa_link()
    data = json.loads(json.dumps(snapshot(dm, privileged={"Domain Admins": [admin]}).to_json()))
    del data["dmsa_visible"]
    snap = Snapshot.from_json(data)
    assert "No dMSA was visible" not in only(snap, "AD-INF-007").detail
    assert any("dMSA was visible is not recorded" in n for n in snap.notes)


# --- AD-PRIV-012 --------------------------------------------------------------------------


def test_an_empty_main_group_gets_a_note() -> None:
    _, c = compare()
    assert any(n.startswith("Domain Admins: member attribute empty or unreadable") for n in c.notes)
    assert any(n.startswith("Administrators: member") for n in c.notes)


def test_a_filled_group_gets_no_such_note() -> None:
    c = Recorder({"crossref": CROSSREFS})
    known = user("adm")
    c._unreadable_members(
        DOMAIN, CONFIG, SID, [known], [admins(known.dn), builtin_admins(known.dn)]
    )
    assert not any("member attribute" in n for n in c.notes)


class BusyRecorder(Recorder):
    def search(self, base: str, *a: Any, **k: Any) -> list[dict[str, Any]]:
        if base == HIDDEN:
            raise LDAPBusyResult(description="busy")
        return super().search(base, *a, **k)  # type: ignore[no-any-return]


def test_an_ldap_error_leaves_no_dn_in_the_notes() -> None:
    c = BusyRecorder({"crossref": CROSSREFS})
    found = c._unreadable_members(DOMAIN, CONFIG, SID, [], [admins(HIDDEN), builtin_admins()])
    assert found == []
    assert "1 member value(s) of Domain Admins not judged by AD-PRIV-012: busy" in c.notes
    assert not any(HIDDEN in n or "CN=" in n for n in c.notes)


# --- AD-INF-014 ---------------------------------------------------------------------------


def test_an_unreadable_server_reference_stops_the_judgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = snapshot_entries(True)
    site = entries[0]["distinguishedname"][0].split(",", 2)[2]
    entries.append(
        {
            "distinguishedname": [f"CN=DC02,CN=Servers,CN=X,{site}"],
            "objectclass": [b"server"],
        }
    )
    entries.append(
        {
            "distinguishedname": [f"CN=NTDS Settings,CN=DC02,CN=Servers,CN=X,{site}"],
            "objectclass": [b"nTDSDSA"],
        }
    )
    c = collect.Collector(None)  # type: ignore[arg-type]
    monkeypatch.setattr(c, "optional", lambda *a, **k: entries)
    assert c._registered_dcs("CN=Configuration") is None
    assert any("1 nTDSDSA" in n and "not judged" in n for n in c.notes)


def test_a_hidden_ntdsdsa_does_not_make_a_rogue(monkeypatch: pytest.MonkeyPatch) -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    monkeypatch.setattr(c, "optional", lambda *a, **k: snapshot_entries(True))
    registered = c._registered_dcs("CN=Configuration")
    assert registered is not None
    dc = computer("OLD", DC_UAC)
    dc.dn = f"CN=OLD,OU=Domain Controllers,{HEAD}"
    mark_rogue_dcs([dc], registered)
    assert not dc.rogue_dc
    assert any("1 server object(s) without a visible nTDSDSA" in n for n in c.notes)


# --- robustness ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["garbage", "0000-00-00T00:00:00Z"])
def test_a_broken_metadata_time_is_not_readable(value: str) -> None:
    block = (
        "<DS_REPL_ATTR_META_DATA><pszAttributeName>unicodePwd</pszAttributeName>"
        f"<ftimeLastOriginatingChange>{value}</ftimeLastOriginatingChange>"
        "</DS_REPL_ATTR_META_DATA>"
    )
    assert collect._meta_time(block, "unicodePwd") is None


def test_junit_stays_well_formed_with_control_characters() -> None:
    sddl = "O:BAG:BAD:(A;;RC;;;\x01)"
    snap = channel_snapshot(sddl)
    r = Report(snap, run_all(snap))
    root = ElementTree.fromstring(render_junit(r, ["AD-GPO-008"]))
    failure = root.find("testcase/failure")
    assert failure is not None and "\\x01" in (failure.text or "")


def test_no_ca_registry_note_names_the_audit_filter() -> None:
    c = collect.Collector(None)  # type: ignore[arg-type]
    c.target = collect.Target(host="dc", ca_registry=False)
    c.ca_dns_hosts = ["ca.lab.test"]
    assert c._ca_configs("dc") == []
    assert any("audit filter" in n for n in c.notes)


# --- docs ---------------------------------------------------------------------------------


def test_readme_severities_match_the_catalog() -> None:
    cat = catalog.load()
    rows = re.findall(
        r"^\|[^|]*\| (AD-[A-Z]+-\d+) \|.*\| ([a-z/]+) \|$",
        (ROOT / "README.md").read_text(encoding="utf8"),
        re.M,
    )
    assert len(rows) == len(cat) - sum(1 for k in cat if k.startswith("AD-INV-"))
    wrong = [cid for cid, grades in rows if set(grades.split("/")) != set(cat[cid].severities)]
    assert wrong == []


def test_old_password_margin_still_applies_to_a_read_time() -> None:
    near = CUTOVER - timedelta(minutes=30)
    snap = snapshot(user("svc_a", spns=SPN, enc_types=0x18, pwd_last_set=near), aes_cutover=CUTOVER)
    assert "AD-KRB-005" not in ids(run_all(snap))
