"""audit.csv and Preferences Registry.xml, and the checks built on them."""

from __future__ import annotations

import json
import random
from dataclasses import replace
from typing import Any

import pytest
from smbprotocol.exceptions import SMBOSError
from smbprotocol.header import NtStatus

from ad_doctor import auditpol, gpo_scope, redact, regpol, sysvol
from ad_doctor.checks import run_all
from ad_doctor.collect import _policy_file_notes
from ad_doctor.gpo_scope import CSE_AUDIT, CSE_GPP_REGISTRY, CSE_REGISTRY, CSE_SECURITY
from ad_doctor.model import (
    Finding,
    Gpo,
    GpoAutologon,
    GpoSettings,
    RegistryEntry,
    Severity,
    Snapshot,
)

from .test_gpo_local import DC_OU, LAB, dc
from .test_registry_policy import dword, member, pol, snap_of, sz
from .test_registry_policy import gpo as registry_gpo

GUID = "{A0000000-0000-0000-0000-000000000000}"
SECRET = "hunter2-do-not-keep"
HEADER = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,"
HEADER += "Exclusion Setting,Setting Value\r\n"
LOGON = next(s for s in auditpol.RECOMMENDED if s.name == "Logon")
PROCESS = next(s for s in auditpol.RECOMMENDED if s.name == "Process Creation")
AUDIT = "AD-GPO-013"
AUTOLOGON = "AD-GPO-014"
NTLM = "AD-GPO-015"
ENCTYPES = "AD-GPO-016"
ESC10 = "AD-ADCS-020"
NEW = {AUDIT, AUTOLOGON, NTLM, ENCTYPES, ESC10}
WINLOGON = regpol.WINLOGON_KEY


def row(sub: auditpol.Subcategory, value: int, target: str = "System") -> str:
    return f",{target},{sub.name},{sub.guid.upper()},x,,{value}\r\n"


def item(key: str, name: str, value: str, kind: str = "REG_DWORD", **attrs: str) -> str:
    outer = attrs.pop("outer", "")
    action = attrs.pop("action", "U")
    hive = attrs.pop("hive", "HKEY_LOCAL_MACHINE")
    filters = attrs.pop("filters", "")
    return (
        f'<Registry clsid="{{9CD4B2F4}}" name="{name}" {outer}>'
        f'<Properties action="{action}" hive="{hive}" key="{key}" name="{name}" '
        f'type="{kind}" value="{value}" {" ".join(f'{k}="{v}"' for k, v in attrs.items())}/>'
        f"{filters}</Registry>"
    )


def xml(*items: str) -> bytes:
    prolog = '<?xml version="1.0" encoding="utf-8"?>'
    return f"{prolog}<RegistrySettings>{''.join(items)}</RegistrySettings>".encode()


# --- audit.csv --------------------------------------------------------------------------------


def test_audit_keeps_the_settings_read() -> None:
    text = HEADER + row(LOGON, 3)
    assert auditpol.parse(text) == [RegistryEntry(auditpol.KEY, LOGON.guid, "set", 4, 3)]


def test_audit_skips_others_and_options() -> None:
    other = ",System,Registry,{0CCE921E-69AE-11D9-BED3-505054503030},x,,1\r\n"
    option = ",,Option:CrashOnAuditFail,,Disabled,,0\r\n"
    sacl = ",,FileGlobalSacl,,,,S:(AU;SA;FA;;;WD)\r\n"
    user = row(LOGON, 3, "S-1-5-21-1-2-3-500")
    assert auditpol.parse(HEADER + other + option + sacl + user) == []


def test_audit_empty_and_header_only_set_nothing() -> None:
    assert auditpol.parse("") == []
    assert auditpol.parse(HEADER) == []


@pytest.mark.parametrize(
    "bad",
    [
        "not,a,header\r\n" + row(LOGON, 3),
        HEADER + ",System,Logon\r\n",
        HEADER + ",System,Logon,{bad-guid},x,,3\r\n",
        HEADER + row(LOGON, 9),
        HEADER + ",System,Logon," + LOGON.guid + ",x,,abc\r\n",
    ],
)
def test_audit_malformed_raises(bad: str) -> None:
    with pytest.raises(auditpol.MalformedAudit):
        auditpol.parse(bad)


def test_audit_random_text_never_escapes() -> None:
    rng = random.Random(1)
    for _ in range(300):
        junk = "".join(rng.choice(',"\r\n\0abc{}-') for _ in range(rng.randrange(200)))
        with pytest.raises(auditpol.MalformedAudit):
            auditpol.parse(HEADER.replace("Machine", "X") + junk)


# --- Registry.xml -----------------------------------------------------------------------------


def test_xml_keeps_watched_values_in_hex() -> None:
    data = xml(item(regpol.SCHANNEL_KEY, regpol.CERT_MAPPING, "0000001F"))
    entries = sysvol.parse_registry_xml(data).entries
    assert entries == [
        RegistryEntry(regpol.SCHANNEL_KEY, regpol.CERT_MAPPING, "set", regpol.REG_DWORD, 0x1F)
    ]


def test_xml_actions_case_and_other_values() -> None:
    data = xml(
        item(regpol.KDC_KEY.upper(), regpol.STRONG_MAPPING.lower(), "00000001", action="C"),
        item(regpol.KDC_KEY, regpol.STRONG_MAPPING, "", action="D"),
        item(regpol.KDC_KEY, "Whatever", "00000001"),
        item(regpol.KDC_KEY, regpol.STRONG_MAPPING, "00000000", hive="HKEY_CURRENT_USER"),
    )
    entries = sysvol.parse_registry_xml(data).entries
    assert [(e.action, e.data) for e in entries] == [("soft", 1), ("delete", None)]


def test_xml_disabled_and_filtered_items_and_collections() -> None:
    plain = item(regpol.KDC_KEY, regpol.STRONG_MAPPING, "00000000", outer='disabled="1"')
    targeted = item(
        regpol.KDC_KEY,
        regpol.DEFAULT_ENCTYPES,
        "00000004",
        filters='<Filters><FilterComputer name="X"/></Filters>',
    )
    data = xml(plain, f'<Collection name="c" disabled="1">{plain}</Collection>', targeted)
    (entry,) = sysvol.parse_registry_xml(data).entries
    assert entry.name == regpol.DEFAULT_ENCTYPES and entry.filtered


def test_xml_bad_number_is_not_a_guess() -> None:
    (entry,) = sysvol.parse_registry_xml(
        xml(item(regpol.KDC_KEY, regpol.STRONG_MAPPING, "zzzz"))
    ).entries
    assert entry.data is None


def test_xml_password_is_the_fact_only() -> None:
    data = xml(
        item(WINLOGON, "DefaultPassword", SECRET, kind="REG_SZ"),
        item(WINLOGON, "AutoAdminLogon", "1", kind="REG_SZ"),
    )
    parsed = sysvol.parse_registry_xml(data)
    assert parsed.autologon.password and parsed.autologon.auto_on
    assert SECRET not in repr(parsed)
    assert parsed.secrets == [(WINLOGON, "DefaultPassword")]


@pytest.mark.parametrize("empty", ["", "  ", "%AUTOPW%"])
def test_xml_empty_or_variable_password_is_none(empty: str) -> None:
    data = xml(item(WINLOGON, "DefaultPassword", empty, kind="REG_SZ"))
    assert not sysvol.parse_registry_xml(data).autologon.password


def test_xml_password_in_a_disabled_item_still_counts() -> None:
    data = xml(
        item(WINLOGON, "DefaultPassword", SECRET, kind="REG_SZ", outer='disabled="1"'),
        item(WINLOGON, "AutoAdminLogon", "1", kind="REG_SZ", outer='disabled="1"'),
    )
    found = sysvol.parse_registry_xml(data).autologon
    assert found.password and not found.auto_on


@pytest.mark.parametrize(
    "bad",
    [
        b"not xml",
        b"<RegistrySettings>",
        b'<!DOCTYPE x [<!ENTITY a "b">]><RegistrySettings/>',
        b"<RegistrySettings>"
        + b"<Collection>" * 200
        + b"</Collection>" * 200
        + b"</RegistrySettings>",
    ],
)
def test_xml_malformed_raises(bad: bytes) -> None:
    with pytest.raises(sysvol.MalformedXml):
        sysvol.parse_registry_xml(bad)


def test_xml_very_deep_nesting_is_refused_without_a_crash() -> None:
    count = 90_000
    bomb = b"<a>" + b"<Collection>" * count + b"</Collection>" * count + b"</a>"
    with pytest.raises(sysvol.MalformedXml):
        sysvol.parse_registry_xml(bomb)


def test_xml_random_bytes_never_escape_as_another_exception() -> None:
    rng = random.Random(2)
    start = b'<RegistrySettings><Registry name="a"><Properties '
    for _ in range(300):
        junk = bytes(rng.randrange(256) for _ in range(rng.randrange(120)))
        with pytest.raises(sysvol.MalformedXml):
            sysvol.parse_registry_xml(start + junk)


def test_registry_pol_password_is_recorded_as_a_fact() -> None:
    parsed = regpol.parse(
        pol(sz(WINLOGON, "DefaultPassword", SECRET), dword(WINLOGON, "AutoAdminLogon", 1))
    )
    assert parsed.autologon.password and parsed.autologon.auto_on
    assert SECRET not in repr(parsed)


# --- reading from SYSVOL ----------------------------------------------------------------------


def scan(monkeypatch: pytest.MonkeyPatch, reader: Any) -> sysvol.SysvolResult:
    monkeypatch.setattr(sysvol.smbclient, "register_session", lambda *a, **k: None)
    monkeypatch.setattr(sysvol.smbclient, "walk", lambda *a, **k: iter(()))
    monkeypatch.setattr(sysvol.smbclient, "reset_connection_cache", lambda: None)
    monkeypatch.setattr(sysvol, "_read", reader)
    return sysvol.scan("dc", "lab.test", "u", "p", [GUID])


def by_file(audit: Any = None, registry_xml: Any = None) -> Any:
    def read(path: str, port: int) -> bytes:
        content = audit if "audit.csv" in path else registry_xml if "Registry.xml" in path else None
        if content is None:
            raise SMBOSError(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, path)
        if isinstance(content, int):
            raise SMBOSError(content, path)
        return content  # type: ignore[no-any-return]

    return read


def test_scan_reads_both_files(monkeypatch: pytest.MonkeyPatch) -> None:
    data = xml(item(WINLOGON, "DefaultPassword", SECRET, kind="REG_SZ"))
    result = scan(monkeypatch, by_file((HEADER + row(LOGON, 3)).encode(), data))
    assert [e.name for e in result.audit[GUID]] == [LOGON.guid]
    assert result.preferences[GUID] == []
    assert result.autologon[0].password and result.autologon[0].source == "xml"
    assert SECRET not in json.dumps([result.notes, repr(result.autologon)])


def test_scan_missing_files_count_as_read(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, by_file())
    assert result.audit == {GUID: []} and result.preferences == {GUID: []}


def test_scan_denied_files_stay_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    denied = NtStatus.STATUS_ACCESS_DENIED
    result = scan(monkeypatch, by_file(denied, denied))
    assert result.audit == {} and result.preferences == {}
    assert len(result.policy_unread) == 2


def test_scan_malformed_files_are_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, by_file(b"junk", b"junk"))
    assert result.audit == {} and result.preferences == {}
    assert sum("not evaluated" in n for n in result.notes) == 2


def test_scan_oversized_files_are_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    big = b"x" * sysvol.MAX_FILE
    result = scan(monkeypatch, by_file(big, big))
    assert result.audit == {} and result.preferences == {}
    assert sum("over" in n and "not evaluated" in n for n in result.notes) == 2


def test_gpttmpl_reads_the_basic_audit_section() -> None:
    settings = sysvol.parse_gpttmpl("[Event Audit]\nAuditLogonEvents = 3\nAuditOther = 1\n")
    assert settings.audit_categories == ["AuditLogonEvents"]


# --- precedence -------------------------------------------------------------------------------


def snapped(
    made: list[tuple[Gpo, list[RegistryEntry] | None]],
    audit: dict[str, list[RegistryEntry]] | None = None,
    prefs: dict[str, list[RegistryEntry]] | None = None,
    **kw: Any,
) -> Snapshot:
    snap = snap_of(made, **kw)
    known = {g.guid for g in snap.gpos}
    return replace(
        snap,
        gpo_audit={g: (audit or {}).get(g, []) for g in known if audit is None or g in audit},
        gpo_preferences={g: (prefs or {}).get(g, []) for g in known if prefs is None or g in prefs},
        policy_files_collected=True,
    )


def gpo(
    name: str,
    entries: list[RegistryEntry] | None,
    placed: list[tuple[str, int, bool, bool]],
    machine_extensions: list[str],
) -> tuple[Gpo, list[RegistryEntry] | None]:
    made, kept = registry_gpo(name, entries, placed)
    return replace(made, machine_extensions=machine_extensions), kept


def audited(*cses: str) -> Any:
    return {"machine_extensions": [CSE_AUDIT, CSE_GPP_REGISTRY, CSE_REGISTRY, *cses]}


def audit_entry(value: int, sub: auditpol.Subcategory = LOGON) -> RegistryEntry:
    return RegistryEntry(auditpol.KEY, sub.guid, "set", 4, value)


def run(snap: Snapshot, check: str) -> Finding | None:
    return next((f for f in run_all(snap) if f.check_id == check), None)


def all_on(*skip: auditpol.Subcategory) -> list[RegistryEntry]:
    return [audit_entry(s.wanted, s) for s in auditpol.RECOMMENDED if s not in skip]


def audit_snap(entries: list[RegistryEntry], **kw: Any) -> Snapshot:
    made = [gpo("Audit", [], [(DC_OU, 0, False, True)], **audited())]
    guid = made[0][0].guid
    return snapped(made, audit={guid: entries}, prefs={guid: []}, accounts=[dc()], **kw)


def test_audit_all_recommended_is_silent() -> None:
    assert run(audit_snap(all_on()), AUDIT) is None


def test_audit_none_is_medium() -> None:
    entries = [*all_on(LOGON), audit_entry(auditpol.NONE)]
    found = run(audit_snap(entries), AUDIT)
    assert found is not None and found.severity is Severity.MEDIUM
    assert "set to no auditing: Logon by Audit" in found.objects[0]


def test_audit_one_direction_is_low_and_names_it() -> None:
    entries = [*all_on(LOGON), audit_entry(auditpol.SUCCESS)]
    found = run(audit_snap(entries), AUDIT)
    assert found is not None and found.severity is Severity.LOW
    assert "Logon without failure" in found.objects[0]


def test_audit_more_than_wanted_is_fine() -> None:
    entries = [*all_on(PROCESS), audit_entry(auditpol.BOTH, PROCESS)]
    assert run(audit_snap(entries), AUDIT) is None


def test_audit_zero_is_info_and_says_why() -> None:
    found = run(audit_snap([*all_on(LOGON), audit_entry(auditpol.NOT_CHANGED)]), AUDIT)
    assert found is not None and found.severity is Severity.INFO
    assert "not judged" in found.objects[0]


def test_audit_nothing_set_is_info_and_unknown() -> None:
    found = run(audit_snap([]), AUDIT)
    assert found is not None and found.severity is Severity.INFO
    assert "no GPO sets any of the 17" in found.objects[0]
    assert "does not say what the computer really does" in found.detail


def test_audit_only_basic_policy_is_info() -> None:
    made = [gpo("Basic", [], [(DC_OU, 0, False, True)], **audited(CSE_SECURITY))]
    guid = made[0][0].guid
    snap = snapped(made, audit={guid: all_on(LOGON)}, prefs={guid: []}, accounts=[dc()])
    snap.gpo_settings[guid] = GpoSettings(audit_categories=["AuditLogonEvents"])
    found = run(snap, AUDIT)
    assert found is not None and found.severity is Severity.INFO
    assert "basic audit policy" in found.objects[0] and "Logon" in found.objects[0]


def test_audit_later_gpo_overrides_per_subcategory() -> None:
    low = gpo("Low", [], [(DC_OU, 1, False, True)], **audited())
    high = gpo("High", [], [(DC_OU, 0, False, True)], **audited())
    audit = {low[0].guid: all_on(), high[0].guid: [audit_entry(auditpol.NONE)]}
    prefs = {low[0].guid: [], high[0].guid: []}
    found = run(snapped([low, high], audit=audit, prefs=prefs, accounts=[dc()]), AUDIT)
    # gPLink index 1 is applied last, so Low wins for Logon and every other subcategory
    assert found is None
    audit = {low[0].guid: [audit_entry(auditpol.NONE)], high[0].guid: all_on()}
    found = run(snapped([low, high], audit=audit, prefs=prefs, accounts=[dc()]), AUDIT)
    assert found is not None and found.severity is Severity.MEDIUM


def test_audit_unreadable_file_leaves_it_undecided() -> None:
    made = [gpo("Broken", [], [(DC_OU, 0, False, True)], **audited())]
    guid = made[0][0].guid
    found = run(snapped(made, audit={}, prefs={guid: []}, accounts=[dc()]), AUDIT)
    assert found is not None and found.severity is Severity.INFO
    assert "audit.csv of Broken not readable" in found.objects[0]


def test_audit_gpo_without_the_extension_is_not_applied() -> None:
    made = [gpo("NoCse", [], [(DC_OU, 0, False, True)], machine_extensions=[CSE_REGISTRY])]
    guid = made[0][0].guid
    found = run(snapped(made, audit={guid: all_on()}, prefs={guid: []}, accounts=[dc()]), AUDIT)
    assert found is not None and "no GPO sets any" in found.objects[0]


def test_audit_applies_to_domain_controllers_only() -> None:
    made = [gpo("Audit", [], [(LAB, 0, False, True)], **audited())]
    guid = made[0][0].guid
    snap = snapped(made, audit={guid: []}, prefs={guid: []}, accounts=[member()])
    assert run(snap, AUDIT) is None


def test_old_snapshot_is_not_evaluated() -> None:
    data = audit_snap([]).to_json()
    for key in ("policy_files_collected", "gpo_audit", "gpo_preferences", "gpo_autologon"):
        data.pop(key)
    back = Snapshot.from_json(data)
    assert not (NEW & {f.check_id for f in run_all(back)})
    assert any("audit.csv and Registry.xml" in n for n in back.notes)


def test_redaction_keeps_the_new_findings() -> None:
    snap = audit_snap([audit_entry(auditpol.NONE)])
    before = {f.check_id: f.severity for f in run_all(snap) if f.check_id in NEW}
    redacted = redact.redact(snap.to_json(), b"k")
    back = Snapshot.from_json(redacted)
    assert {f.check_id: f.severity for f in run_all(back) if f.check_id in NEW} == before


def test_redaction_keeps_basic_audit_categories() -> None:
    made = [gpo("Basic", [], [(DC_OU, 0, False, True)], **audited(CSE_SECURITY))]
    guid = made[0][0].guid
    snap = snapped(made, audit={guid: []}, prefs={guid: []}, accounts=[dc()])
    snap.gpo_settings[guid] = GpoSettings(audit_categories=["AuditLogonEvents"])
    back = Snapshot.from_json(redact.redact(snap.to_json(), b"k"))
    (settings,) = back.gpo_settings.values()
    assert settings.audit_categories == ["AuditLogonEvents"]


# --- autologon --------------------------------------------------------------------------------


def autologon(*records: GpoAutologon) -> Snapshot:
    made = [gpo("Kiosk", [], [(LAB, 0, False, True)], **audited())]
    return replace(
        snapped(
            made, audit={made[0][0].guid: []}, prefs={made[0][0].guid: []}, accounts=[member()]
        ),
        gpo_autologon=[replace(r, gpo=made[0][0].guid.upper()) for r in records],
    )


def test_autologon_with_password_is_high() -> None:
    found = run(autologon(GpoAutologon("", "file", "xml", True, True)), AUTOLOGON)
    assert found is not None and found.severity is Severity.HIGH
    assert found.objects == [
        "Kiosk (file): DefaultPassword stored in the file; AutoAdminLogon is 1"
    ]


def test_password_without_autologon_is_still_high() -> None:
    found = run(autologon(GpoAutologon("", "file", "pol", True, False)), AUTOLOGON)
    assert found is not None and found.severity is Severity.HIGH
    assert "AutoAdminLogon not set" in found.objects[0]


def test_autologon_without_password_is_info() -> None:
    found = run(autologon(GpoAutologon("", "file", "pol", False, True)), AUTOLOGON)
    assert found is not None and found.severity is Severity.INFO


def test_no_autologon_is_silent() -> None:
    assert run(autologon(), AUTOLOGON) is None


# --- ESC10, BlockNtlmv1SSO, encryption types --------------------------------------------------


def policy(
    where: str, pol_entries: list[RegistryEntry], xml_entries: list[RegistryEntry]
) -> Snapshot:
    made = [gpo("Hardening", pol_entries, [(where, 0, False, True)], **audited())]
    guid = made[0][0].guid
    accounts = [dc()] if where == DC_OU else [member()]
    return snapped(made, audit={guid: []}, prefs={guid: xml_entries}, accounts=accounts)


def entry(key: str, name: str, value: Any, action: str = "set", **kw: Any) -> RegistryEntry:
    return RegistryEntry(key, name, action, 4, value, **kw)


def mapping(value: Any, **kw: Any) -> RegistryEntry:
    return entry(regpol.SCHANNEL_KEY, regpol.CERT_MAPPING, value, **kw)


def binding(value: Any, **kw: Any) -> RegistryEntry:
    return entry(regpol.KDC_KEY, regpol.STRONG_MAPPING, value, **kw)


def test_esc10_absent_is_unknown_and_says_so() -> None:
    found = run(policy(DC_OU, [], []), ESC10)
    assert found is not None and found.severity is Severity.INFO
    assert (
        "no GPO sets CertificateMappingMethods or StrongCertificateBindingEnforcement"
        in found.objects[0]
    )
    assert "commonly set locally" in found.detail


@pytest.mark.parametrize("value", [0, 1])
def test_esc10_weak_binding_is_medium(value: int) -> None:
    found = run(policy(DC_OU, [mapping(0x18), binding(value)], []), ESC10)
    assert found is not None and found.severity is Severity.MEDIUM
    assert "StrongCertificateBindingEnforcement set to" in found.objects[0]


@pytest.mark.parametrize(("value", "label"), [(0x4, "UPN"), (0x1F, "UPN, subject/issuer, issuer")])
def test_esc10_weak_mapping_from_xml_is_medium(value: int, label: str) -> None:
    found = run(policy(DC_OU, [], [mapping(value), binding(2)]), ESC10)
    assert found is not None and found.severity is Severity.MEDIUM
    assert f"allows {label} mapping" in found.objects[0]


def test_esc10_strong_settings_are_silent() -> None:
    assert run(policy(DC_OU, [mapping(0x18), binding(2)], []), ESC10) is None


def test_esc10_xml_wins_over_registry_pol() -> None:
    assert (
        run(policy(DC_OU, [mapping(0x1F), binding(0)], [mapping(0x18), binding(2)]), ESC10) is None
    )
    found = run(policy(DC_OU, [mapping(0x18), binding(2)], [binding(1)]), ESC10)
    assert found is not None and found.severity is Severity.MEDIUM


def test_esc10_xml_delete_leaves_it_unknown() -> None:
    deleted = entry(regpol.KDC_KEY, regpol.STRONG_MAPPING, None, action="delete")
    found = run(policy(DC_OU, [mapping(0x18), binding(0)], [deleted]), ESC10)
    assert found is not None and found.severity is Severity.INFO
    assert "no GPO sets StrongCertificateBindingEnforcement" in found.objects[0]


def test_esc10_create_item_does_not_overwrite_a_value() -> None:
    created = entry(regpol.KDC_KEY, regpol.STRONG_MAPPING, 0, action="soft")
    assert run(policy(DC_OU, [mapping(0x18), binding(2)], [created]), ESC10) is None


def test_esc10_targeted_item_is_undecided() -> None:
    found = run(policy(DC_OU, [mapping(0x18), binding(2)], [binding(0, filtered=True)]), ESC10)
    assert found is not None and found.severity is Severity.INFO
    assert gpo_scope.ILT_CAVEAT in found.objects[0]


def test_esc10_unrecognised_is_info() -> None:
    found = run(policy(DC_OU, [mapping("x"), binding(7)], []), ESC10)
    assert found is not None and found.severity is Severity.INFO


def test_esc10_ignores_member_servers() -> None:
    assert run(policy(LAB, [mapping(0x1F)], []), ESC10) is None


def test_esc10_unreadable_xml_is_undecided() -> None:
    made = [gpo("Broken", [], [(DC_OU, 0, False, True)], **audited())]
    guid = made[0][0].guid
    found = run(snapped(made, audit={guid: []}, prefs={}, accounts=[dc()]), ESC10)
    assert found is not None and found.severity is Severity.INFO
    assert "Registry.xml of Broken not readable" in found.objects[0]


def sso(value: Any, **kw: Any) -> RegistryEntry:
    return entry(regpol.MSV1_0_KEY, regpol.BLOCK_NTLMV1_SSO, value, **kw)


def test_sso_zero_is_low() -> None:
    found = run(policy(LAB, [sso(0)], []), NTLM)
    assert found is not None and found.severity is Severity.LOW


def test_sso_enforced_or_absent_is_silent() -> None:
    assert run(policy(LAB, [sso(1)], []), NTLM) is None
    assert run(policy(LAB, [], []), NTLM) is None


def test_sso_undecided_is_info() -> None:
    found = run(policy(LAB, [], [sso(0, filtered=True)]), NTLM)
    assert found is not None and found.severity is Severity.INFO


def test_sso_unrecognised_is_info() -> None:
    found = run(policy(LAB, [sso("x")], []), NTLM)
    assert found is not None and found.severity is Severity.INFO


def enc(value: Any, **kw: Any) -> RegistryEntry:
    return entry(regpol.KDC_KEY, regpol.DEFAULT_ENCTYPES, value, **kw)


@pytest.mark.parametrize(
    ("value", "severity"), [(0x27, Severity.MEDIUM), (0x3C, Severity.LOW), (0x4, Severity.LOW)]
)
def test_enctypes_weak(value: int, severity: Severity) -> None:
    found = run(policy(DC_OU, [enc(value)], []), ENCTYPES)
    assert found is not None and found.severity is severity


@pytest.mark.parametrize("value", [0x38, 0x18])
def test_enctypes_aes_is_silent(value: int) -> None:
    assert run(policy(DC_OU, [enc(value)], []), ENCTYPES) is None


def test_enctypes_absent_is_silent() -> None:
    assert run(policy(DC_OU, [], []), ENCTYPES) is None


def test_enctypes_only_on_domain_controllers() -> None:
    assert run(policy(LAB, [enc(0x27)], []), ENCTYPES) is None


def test_enctypes_undecided_and_unrecognised_are_info() -> None:
    found = run(policy(DC_OU, [], [enc(0x27, filtered=True)]), ENCTYPES)
    assert found is not None and found.severity is Severity.INFO
    found = run(policy(DC_OU, [enc("x")], []), ENCTYPES)
    assert found is not None and found.severity is Severity.INFO


def test_notes_name_the_checks() -> None:
    made = [gpo("Unread", [], [(LAB, 0, False, True)], **audited())]
    snap: Snapshot = snapped(made, audit={}, prefs={}, accounts=[member()])
    notes = " ".join(_policy_file_notes(snap, ["x (SMBOSError)"]))
    assert "Unread" in notes and ESC10 in notes and "x (SMBOSError)" in notes
    notes = " ".join(_policy_file_notes(replace(snap, policy_files_collected=False), []))
    assert "not judged" in notes
