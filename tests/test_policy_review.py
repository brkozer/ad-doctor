"""Regression tests for the review of the registry policy parser, its checks and redaction."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from ad_doctor import redact, regpol, sysvol
from ad_doctor.checks import run_all
from ad_doctor.gpo_scope import CSE_SECURITY, RegistryView
from ad_doctor.model import CaConfig, Finding, GpoSettings, RegistryEntry, Severity, Snapshot
from ad_doctor.sysvol import SysvolResult

from .test_acl_adcs import template
from .test_gpo_local import DC_OU, HEAD, LAB, dc
from .test_policy_files import audited, binding, item, mapping, policy, snapped, xml
from .test_policy_files import gpo as policy_gpo
from .test_policy_files import run as run_check
from .test_registry_policy import (
    GOOD_HARDENING,
    dword,
    gpo,
    instruction,
    member,
    pol,
    snap_of,
    sz,
    text16,
)

CANARY = "CANARY"
WSUS = "AD-GPO-010"
UNC = "AD-GPO-012"
ESC10 = "AD-ADCS-020"
AUDIT = "AD-GPO-013"
MODULES = regpol.MODULE_NAMES_KEY
WINLOGON = regpol.WINLOGON_KEY
PARENT = r"Software\Policies\Microsoft\Windows\NetworkProvider"
SYSVOL = r"\\*\SYSVOL"
NETLOGON = r"\\*\NETLOGON"


def opener(key: str) -> bytes:
    return b"[\0" + text16(key)


def run(snap: Snapshot, check_id: str) -> Finding | None:
    return next((f for f in run_all(snap) if f.check_id == check_id), None)


def redacted(snap: Snapshot, **extra: Any) -> dict[str, Any]:
    data = json.loads(json.dumps(snap.to_json()))
    data.update(extra)
    result: dict[str, Any] = redact.redact(data, b"key")
    return result


def wsus_on(server: Any) -> list[RegistryEntry]:
    kind = regpol.REG_MULTI_SZ if isinstance(server, list) else regpol.REG_SZ
    return [
        RegistryEntry(regpol.WSUS_KEY, regpol.WSUS_SERVER, "set", kind, server),
        RegistryEntry(regpol.WSUS_AU_KEY, regpol.WSUS_USE, "set", 4, 1),
    ]


def with_gpo(entries: list[RegistryEntry], computer: Any = None, **kw: Any) -> Snapshot:
    made = [gpo("Baseline", entries, [(LAB, 0, False, True)])]
    return snap_of(made, accounts=[computer or member()], **kw)


# --- bounded memory ---------------------------------------------------------------------------


def retained(parsed: regpol.Parsed) -> int:
    return sum(len(e.key) + len(e.name) for e in parsed.entries)


def test_delete_keys_retains_no_more_than_the_file_holds() -> None:
    padded = "\\" * (regpol.MAX_NAME - len("Software")) + "Software"
    targets = ";".join(["Policies"] * 4000)
    data = pol(instruction(padded, "**DeleteKeys", regpol.REG_SZ, text16(targets)))
    parsed = regpol.parse(data)
    assert [(e.key, e.action) for e in parsed.entries] == [("software\\policies", "delete_key")]
    assert retained(parsed) <= len(data)


@pytest.mark.parametrize(
    "records",
    [
        lambda: [instruction("\\" * 100000 + "Software", "**DeleteKeys", 1, text16("Policies"))],
        lambda: [instruction("Software", "**DeleteKeys", 1, text16("\\" * 100000 + "Policies"))],
        lambda: [instruction("Software", "**DeleteValues", 1, text16("x" * 2000))],
        lambda: [sz(regpol.MODULE_NAMES_KEY, "m" * 2000, "x")],
        lambda: [opener("k" * 2000) + b"]\0"],
    ],
    ids=["key", "delete-target", "value-target", "value-name", "key-only"],
)
def test_names_over_the_limit_make_the_file_malformed(records: Any) -> None:
    with pytest.raises(regpol.MalformedPol, match="registry name"):
        regpol.parse(pol(*records()))


def test_the_longest_name_allowed_still_parses() -> None:
    name = rf"\\{'h' * (regpol.MAX_NAME - 10)}\SYSVOL"
    assert len(name) <= regpol.MAX_NAME
    entries = regpol.parse(pol(sz(regpol.HARDENED_KEY, name, GOOD_HARDENING))).entries
    assert [e.name for e in entries] == [name]


@pytest.mark.parametrize("attrs", [("k" * 2000, "n"), ("k", "n" * 2000)], ids=["key", "name"])
def test_registry_xml_names_are_bounded_too(attrs: tuple[str, str]) -> None:
    with pytest.raises(regpol.MalformedPol, match="registry name"):
        sysvol.parse_registry_xml(xml(item(attrs[0], attrs[1], "1")))


def test_a_file_with_a_name_over_the_limit_is_a_note_and_stays_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = pol(sz(regpol.LLMNR_KEY, "n" * 2000, "x"))
    monkeypatch.setattr(sysvol, "_read", lambda _path, _port: body)
    result = SysvolResult()
    sysvol._read_registry(result, r"\\h\SYSVOL\d", "{G}", 445)
    assert "{G}" not in result.registry
    assert "not a valid Registry.pol" in " ".join(result.notes)


def test_a_registry_xml_with_a_name_over_the_limit_is_a_note_and_stays_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = xml(item("k" * 2000, "n", "1"))
    monkeypatch.setattr(sysvol, "_read", lambda _path, _port: body)
    result = SysvolResult()
    sysvol._read_preferences(result, r"\\h\SYSVOL\d", "{G}", 445)
    assert "{G}" not in result.preferences
    assert "not valid Registry.xml" in " ".join(result.notes)


# --- credentials in a WSUS URL ----------------------------------------------------------------


URLS = [
    ("http://svc:CANARY@wsus:8530", "http://wsus:8530"),
    (" http://svc:CANARY@wsus:8530", "http://wsus:8530"),
    ("http://svc:CAN/ARY@wsus:8530", "http://wsus:8530"),
    ("http://svc:CAN@ARY@wsus:8530", "http://wsus:8530"),
    ("svc:CANARY@wsus:8530", "wsus:8530"),
    ("http://wsus:8530", "http://wsus:8530"),
]


@pytest.mark.parametrize(("url", "stored"), URLS)
def test_registry_pol_keeps_no_credentials(url: str, stored: str) -> None:
    entries = regpol.parse(pol(sz(regpol.WSUS_KEY, regpol.WSUS_SERVER, url))).entries
    assert [e.data for e in entries] == [stored]


def test_registry_pol_multi_string_keeps_no_credentials() -> None:
    payload = "http://svc:CANARY@wsus:8530\0\0".encode("utf-16-le")
    record = instruction(regpol.WSUS_KEY, regpol.WSUS_SERVER, regpol.REG_MULTI_SZ, payload)
    assert regpol.parse(pol(record)).entries[0].data == ["http://wsus:8530"]


@pytest.mark.parametrize(("url", "stored"), URLS)
def test_registry_xml_keeps_no_credentials(url: str, stored: str) -> None:
    body = xml(item(regpol.WSUS_KEY, regpol.WSUS_SERVER, url, "REG_SZ"))
    assert [e.data for e in sysvol.parse_registry_xml(body).entries] == [stored]


def test_the_finding_shows_no_password() -> None:
    entries = regpol.parse(
        pol(
            sz(regpol.WSUS_KEY, regpol.WSUS_SERVER, " http://svc:CAN/ARY@wsus:8530"),
            dword(regpol.WSUS_AU_KEY, regpol.WSUS_USE, 1),
        )
    ).entries
    found = run(with_gpo(entries), WSUS)
    assert found is not None and "http://wsus:8530" in found.objects[0]
    assert "ARY" not in " ".join(found.objects)


# --- redaction --------------------------------------------------------------------------------


def test_registry_xml_module_data_is_blank_like_registry_pol() -> None:
    body = xml(item(MODULES, "AcmeInternal.Tools", "AcmeInternal.Tools", "REG_SZ"))
    assert [e.data for e in sysvol.parse_registry_xml(body).entries] == [""]


def test_redaction_blanks_module_data_a_snapshot_already_holds() -> None:
    entry = RegistryEntry(MODULES, "AcmeInternal.Tools", "set", 1, "AcmeInternal.Tools")
    out = redacted(with_gpo([entry]))
    assert "acmeinternal" not in json.dumps(out["gpo_registry"]).lower()


def test_redaction_hides_a_wsus_server_in_a_multi_string() -> None:
    out = redacted(with_gpo(wsus_on(["http://wsus01.acme.example:8530"])))
    dumped = json.dumps(out["gpo_registry"]).lower()
    assert "wsus01" not in dumped and "acme" not in dumped
    assert '"http://' in dumped


def test_redaction_hides_a_wsus_server_without_a_scheme() -> None:
    out = redacted(with_gpo(wsus_on("wsus01.acme.example:8530")))
    dumped = json.dumps(out["gpo_registry"]).lower()
    assert "wsus01" not in dumped and "acme" not in dumped


@pytest.mark.parametrize("hive", ["pol", "xml"])
def test_redaction_hides_the_location_in_a_password_note(hive: str) -> None:
    key, name = r"Software\NorthwindAgent\HamburgPlant", "ServicePassword"
    parsed = (
        regpol.parse(pol(sz(key, name, "Sup3rSecretVal")))
        if hive == "pol"
        else sysvol.parse_registry_xml(xml(item(key, name, "Sup3rSecretVal", "REG_SZ")))
    )
    result = SysvolResult()
    sysvol._keep_facts(result, "{G}", r"Policies\{G}\Machine\Registry.pol", hive, parsed)
    assert result.notes == [
        r"Policies\{G}\Machine\Registry.pol: holds a value named like a password: "
        r"Software\NorthwindAgent\HamburgPlant\ServicePassword"
    ]
    assert "Sup3rSecretVal" not in result.notes[0]
    out = redacted(with_gpo([]), notes=result.notes)
    note = " ".join(out["notes"])
    assert regpol.SECRET_NOTE in note
    for word in ("NorthwindAgent", "HamburgPlant", "ServicePassword"):
        assert word not in note


def test_redaction_keeps_winlogons_default_password_note() -> None:
    note = f"p: holds a value named like a password: {WINLOGON}\\DefaultPassword"
    other = f"p: holds a value named like a password: {WINLOGON}\\AcmeSitePwd"
    out = redacted(with_gpo([]), notes=[note, other])
    assert out["notes"][0] == note
    assert "AcmeSitePwd" not in out["notes"][1]


def test_redaction_leaves_other_notes_alone() -> None:
    out = redacted(with_gpo([]), notes=["a note"])
    assert out["notes"] == ["a note"]


def test_redaction_learns_the_labels_of_a_wildcard_host() -> None:
    name = r"\\*.tokyo-branch.acmeinternal.net\SYSVOL"
    entry = RegistryEntry(regpol.HARDENED_KEY, name, "set", 1, GOOD_HARDENING)
    dumped = json.dumps(redacted(with_gpo([entry]))["gpo_registry"]).lower()
    assert "tokyo" not in dumped and "acmeinternal" not in dumped
    assert "\\\\\\\\*." in dumped  # the wildcard itself is no name


def test_redaction_keeps_a_bare_wildcard_host() -> None:
    entry = RegistryEntry(regpol.HARDENED_KEY, SYSVOL, "set", 1, GOOD_HARDENING)
    entries = redacted(with_gpo([entry]))["gpo_registry"]
    assert next(iter(entries.values()))[0]["name"] == SYSVOL


@pytest.mark.parametrize("os_name", ["Hyper-V Server 2019", "Windows Server 2016 Standard"])
def test_redaction_keeps_the_words_the_os_test_reads(os_name: str) -> None:
    computer = replace(member(), os=os_name, dns_host="server.hyper-v.lab.test")
    snap = with_gpo([], computer=computer)
    before = run(snap, UNC)
    after = run(Snapshot.from_json(redacted(snap)), UNC)
    assert before is not None and after is not None and before.severity is after.severity
    assert before.severity is Severity.INFO


# --- instructions with missing or empty fields ------------------------------------------------


TYPE = (4).to_bytes(4, "little")
SIZE = (4).to_bytes(4, "little")
KEY = regpol.LLMNR_KEY
NAME = regpol.LLMNR_VALUE
NEXT = dword(regpol.KDC_KEY, regpol.STRONG_MAPPING, 2)


@pytest.mark.parametrize(
    "body",
    [
        opener(KEY) + b"]\0",
        opener(KEY) + b";\0" + text16(NAME) + b"]\0",
        opener(KEY) + b";\0" + text16(NAME) + b";\0" + TYPE + b"]\0",
        opener(KEY) + b";\0" + text16(NAME) + b";\0" + TYPE + b";\0" + SIZE + b"]\0",
    ],
    ids=["key", "value", "type", "size"],
)
def test_an_instruction_may_stop_early_and_only_creates_the_key(body: bytes) -> None:
    entries = regpol.parse(pol(body, NEXT)).entries
    assert [e.name for e in entries] == [regpol.STRONG_MAPPING]


@pytest.mark.parametrize(
    "record",
    [
        instruction(KEY, NAME, regpol.REG_DWORD, b""),
        instruction(KEY, NAME, 0, (0).to_bytes(4, "little")),
        instruction(KEY, f"**soft.{NAME}", regpol.REG_DWORD, b""),
        instruction(MODULES, "", regpol.REG_SZ, text16("x")),
    ],
    ids=["size", "type", "soft", "value"],
)
def test_an_empty_field_sets_no_value(record: bytes) -> None:
    assert regpol.parse(pol(record)).entries == []


@pytest.mark.parametrize("marker", [f"**del.{NAME}", "**delvals."])
def test_markers_with_no_data_still_act(marker: str) -> None:
    entries = regpol.parse(pol(instruction(KEY, marker, regpol.REG_SZ, b""))).entries
    assert [e.action for e in entries] == ["delete" if "del." in marker else "delete_all"]


def test_a_truncated_instruction_is_still_malformed() -> None:
    with pytest.raises(regpol.MalformedPol):
        regpol.parse(pol(opener(KEY) + b";\0" + text16(NAME) + b";\0" + TYPE))


def test_an_empty_instruction_leaves_an_earlier_gpos_value() -> None:
    baseline = regpol.parse(pol(dword(KEY, NAME, 0))).entries
    keyed = regpol.parse(pol(instruction(KEY, NAME, regpol.REG_DWORD, b""))).entries
    made = [
        gpo("Baseline", baseline, [(LAB, 0, False, True)]),
        gpo("Key only", keyed, [(LAB, 1, False, True)]),
    ]
    assert run(snap_of(made, accounts=[member()]), "AD-GPO-009") is None


# --- ESC10 without certificate infrastructure -------------------------------------------------


def no_ca(pol_entries: list[RegistryEntry]) -> Snapshot:
    return replace(policy(DC_OU, pol_entries, []), templates=[], ca_hosts=[], enrollment_urls=[])


def test_esc10_counts_a_ca_probe_as_a_ca() -> None:
    snap = no_ca([mapping(0x4), binding(2)])
    probes = replace(snap.probes, ca_configs=[CaConfig(name="CA", host="ca01.lab.test")])
    found = run_check(replace(snap, probes=probes), ESC10)
    assert found is not None and found.severity is Severity.MEDIUM


def test_esc10_says_nothing_unknown_where_no_ca_was_seen() -> None:
    assert run_check(no_ca([]), ESC10) is None
    assert run_check(no_ca([mapping("x"), binding(7)]), ESC10) is None


def test_esc10_strong_values_are_silent_where_no_ca_was_seen() -> None:
    assert run_check(no_ca([mapping(0x18), binding(2)]), ESC10) is None


def test_esc10_weak_value_is_info_and_says_no_ca_was_seen() -> None:
    found = run_check(no_ca([mapping(0x4), binding(2)]), ESC10)
    assert found is not None and found.severity is Severity.INFO
    assert "allows UPN mapping" in found.objects[0]
    assert "no enterprise CA or certificate template" in found.objects[0]
    assert "NTAuth" in found.detail


@pytest.mark.parametrize(
    "seen",
    [
        {"ca_hosts": ["CA01"]},
        {"enrollment_urls": ["https://ca01.lab.test/certsrv/"]},
        {"templates": [template("User")]},
    ],
    ids=["host", "url", "template"],
)
def test_esc10_counts_any_sign_of_a_ca(seen: Any) -> None:
    found = run_check(replace(no_ca([mapping(0x4), binding(2)]), **seen), ESC10)
    assert found is not None and found.severity is Severity.MEDIUM
    assert "no enterprise CA" not in found.objects[0]
    unknown = run_check(replace(no_ca([]), **seen), ESC10)
    assert unknown is not None and unknown.severity is Severity.INFO


# --- the Windows default for hardened paths ---------------------------------------------------


GOOD_PATHS = [
    RegistryEntry(regpol.HARDENED_KEY, SYSVOL, "set", 1, GOOD_HARDENING),
    RegistryEntry(regpol.HARDENED_KEY, NETLOGON, "set", 1, GOOD_HARDENING),
]


@pytest.mark.parametrize(
    "os_name",
    [
        "Windows Storage Server 2008 R2 Standard",
        "Windows Web Server 2008 R2",
        "Windows Small Business Server 2011 Standard",
        "Windows Embedded Standard",
        "Windows 2000 Server",
        "Windows Thin PC",
        "Windows 98",
        "Windows Server\u00ae 2008 Standard",
        "Hyper-V Server 2012 R2",
    ],
)
def test_a_name_not_known_to_be_new_gets_no_default(os_name: str) -> None:
    found = run(with_gpo([], computer=replace(member(), os=os_name)), UNC)
    assert found is not None and found.severity is Severity.MEDIUM
    assert "harden it by default" not in found.objects[0]
    assert "no default can be assumed" in found.objects[0]


@pytest.mark.parametrize(
    "os_name",
    [
        "Windows 10 Enterprise",
        "Windows 11 Pro",
        "Windows Server 2016 Standard",
        "Windows Server\u00ae 2019 Datacenter",
        "Windows Server 2025 Standard Evaluation",
        "Windows Storage Server 2016 Standard",
        "Windows Server Datacenter",
        "Hyper-V Server 2019",
    ],
)
def test_a_name_known_to_be_new_gets_the_default(os_name: str) -> None:
    found = run(with_gpo([], computer=replace(member(), os=os_name)), UNC)
    assert found is not None and found.severity is Severity.INFO
    assert "harden it by default" in found.objects[0]


def test_a_dc_with_no_recorded_version_is_unknown() -> None:
    computer = replace(dc(), os=None)
    made = [gpo("Baseline", [], [(DC_OU, 0, False, True)])]
    found = run(snap_of(made, accounts=[computer]), UNC)
    assert found is not None and found.severity is Severity.INFO
    assert "version is not recorded" in found.objects[0]
    assert "harden it by default" not in found.objects[0]


@pytest.mark.parametrize("os_name", ["Hyper-V Server 2012 R2", "Hyper-V Server 2019"])
def test_hyper_v_server_processes_group_policy(os_name: str) -> None:
    computer = replace(member(), os=os_name)
    snap = with_gpo([], computer=computer)
    assert [a.sam for a in RegistryView(snap).targets()] == [computer.sam]


def test_appliances_stay_out_of_the_targets() -> None:
    computer = replace(member(), os="Data ONTAP")
    assert RegistryView(with_gpo([], computer=computer)).targets() == []


# --- trailing backslash on a hardened path ----------------------------------------------------


def test_trailing_backslash_counts_as_the_wildcard_path() -> None:
    entries = [
        RegistryEntry(regpol.HARDENED_KEY, SYSVOL + "\\", "set", 1, GOOD_HARDENING),
        RegistryEntry(regpol.HARDENED_KEY, NETLOGON + "\\", "set", 1, GOOD_HARDENING),
    ]
    old = replace(member(), os="Windows Server 2008 R2 Standard")
    assert run(with_gpo(entries, computer=old), UNC) is None


def test_a_weak_value_with_a_trailing_backslash_is_still_weak() -> None:
    weak = "RequireMutualAuthentication=0"
    entries = [
        *GOOD_PATHS,
        RegistryEntry(regpol.HARDENED_KEY, SYSVOL + "\\", "set", 1, weak),
    ]
    found = run(with_gpo(entries), UNC)
    assert found is not None and found.severity is Severity.MEDIUM


def test_a_delete_with_a_trailing_backslash_removes_the_value() -> None:
    entries = [
        *GOOD_PATHS,
        RegistryEntry(regpol.HARDENED_KEY, SYSVOL + "\\", "delete"),
    ]
    found = run(with_gpo(entries), UNC)
    assert found is not None and "SYSVOL: no GPO sets it" in found.objects[0]


# --- basic audit policy -----------------------------------------------------------------------


def parsed_audit(*lines: str) -> GpoSettings:
    return sysvol.parse_gpttmpl("[Event Audit]\n" + "\n".join(lines))


def test_gpttmpl_tells_no_auditing_from_auditing() -> None:
    settings = parsed_audit("AuditLogonEvents = 0", "AuditSystemEvents = 3", "AuditDSAccess = x")
    assert settings.audit_categories == ["AuditSystemEvents"]
    assert settings.audit_off == ["AuditLogonEvents"]


def audits(value: str) -> GpoSettings:
    return parsed_audit(f"AuditLogonEvents = {value}")


def audit_row(snap: Snapshot) -> str:
    found = run_check(snap, AUDIT)
    assert found is not None
    return found.objects[0]


def with_basic(*settings: GpoSettings, filter_last: str | None = None) -> Snapshot:
    """One GPO per setting, each applied after the one before: the domain head, then the OU."""
    places = [DC_OU] if len(settings) == 1 else [HEAD, DC_OU]
    made = [
        policy_gpo(f"Audit {n}", [], [(place, 0, False, True)], **audited(CSE_SECURITY))
        for n, place in enumerate(places)
    ]
    guids = [g.guid for g, _ in made]
    snap = snapped(
        made,
        audit={guid: [] for guid in guids},
        prefs={guid: [] for guid in guids},
        accounts=[dc()],
    )
    last = replace(snap.gpos[-1], wmi_filter=filter_last)
    return replace(
        snap, gpos=[*snap.gpos[:-1], last], gpo_settings=dict(zip(guids, settings, strict=True))
    )


def test_zero_is_not_reported_as_coverage() -> None:
    row = audit_row(with_basic(parsed_audit("AuditLogonEvents = 0")))
    assert "only basic audit policy covers" not in row
    assert "basic audit policy sets no auditing for these: Logoff, Logon, Special Logon" in row


def test_a_category_that_audits_is_still_coverage() -> None:
    row = audit_row(with_basic(parsed_audit("AuditLogonEvents = 3")))
    assert "only basic audit policy covers these" in row and "Logon" in row


def test_a_later_gpo_setting_zero_wins() -> None:
    row = audit_row(with_basic(audits("3"), audits("0")))
    assert "only basic audit policy covers" not in row
    assert "sets no auditing for these" in row


def test_a_later_gpo_that_audits_wins_over_zero() -> None:
    row = audit_row(with_basic(audits("0"), audits("3")))
    assert "only basic audit policy covers these" in row
    assert "sets no auditing" not in row


def test_a_gpo_that_may_not_apply_takes_no_coverage_away() -> None:
    row = audit_row(with_basic(audits("3"), audits("0"), filter_last="Filter"))
    assert "only basic audit policy covers these" in row
