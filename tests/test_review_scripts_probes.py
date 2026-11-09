"""Review findings on the script audit, the probe notes, redaction and the scorecard."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest
from smbprotocol.exceptions import SMBOSError
from smbprotocol.header import NtStatus

from ad_doctor import collect, probes, redact, regpol, sysvol, views, x509
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector, Target, _ca_certificate
from ad_doctor.coverage import CHECK_IN_NOTE
from ad_doctor.gpo_scope import CSE_REGISTRY, CSE_SCRIPTS, script_reach
from ad_doctor.model import (
    DisplaySpecifierCommand,
    GpoScript,
    RegistryEntry,
    Severity,
    Snapshot,
    UnreadableMember,
)
from ad_doctor.sd import Ace

from .test_checks import only, snapshot, user
from .test_gpo_local import DC_OU, DOM, GUID_A, GUID_B, HELPDESK, LAB, dc, gpo, gsnap, host, link
from .test_gpo_scripts import (
    AU,
    FOLDER,
    INI,
    WRITE,
    acl,
    findings,
    remote,
    scripts_snap,
    startup,
)

SECRET = "S3cretArg!"
TARGET = r"\\fs01\it\deploy.ps1"


def targets(command: str, arguments: str = "") -> list[tuple[str, str]]:
    return sysvol._run_targets(command, arguments)


# --- what a command line runs ------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "arguments"),
    [
        ("powershell.exe", r"-File C:\Tools\inventory.ps1 -LogPath \\ws03\logs\inv.log"),
        ("pwsh", r"-f C:\Tools\inventory.ps1 \\ws03\logs\inv.log"),
        ("powershell", r"-NoProfile -Command C:\Tools\x.ps1 -Log \\ws03\logs\x.log"),
        ("powershell", r"-ExecutionPolicy Bypass C:\Tools\x.ps1 \\ws03\logs\x.log"),
        ("cmd.exe", r"/c C:\Tools\a.bat > \\ws03\logs\a.log"),
        ("cmd.exe", r"/d /s /c a.bat \\ws03\data\in.csv"),
        ("wscript.exe", r"//B C:\Tools\a.vbs \\ws03\data\in.csv"),
        ("cscript", r"//Nologo a.vbs /log:\\ws03\logs\a.log"),
        ("mshta", r"C:\Tools\a.hta \\ws03\data\in.csv"),
        ("msiexec.exe", r"/i C:\Tools\a.msi /l*v \\ws03\logs\a.log"),
        ("msiexec", r"/qn /iC:\Tools\a.msi /log \\ws03\logs\a.log"),
        ("regsvr32", r"/s C:\Tools\a.dll \\ws03\data\in.csv"),
        ("rundll32", r"shell32.dll,Control_RunDLL \\ws03\data\a.cpl"),
        ("cmd", "/c echo hello"),
        ("powershell", "-EncodedCommand AAAA"),
    ],
)
def test_an_argument_that_is_not_run_is_not_followed(command: str, arguments: str) -> None:
    assert targets(command, arguments) == []


@pytest.mark.parametrize(
    ("command", "arguments", "path"),
    [
        ("powershell.exe", r"-File \\fs\s\a.ps1 -Log \\ws03\l\a.log", r"\\fs\s\a.ps1"),
        ("powershell", r'-file:"\\fs\my share\a.ps1"', r"\\fs\my share\a.ps1"),
        ("pwsh", r"-NoLogo -ep Bypass \\fs\s\a.ps1", r"\\fs\s\a.ps1"),
        ("powershell", r"""-Command "& '\\fs\s\a b.ps1' -P x" """, r"\\fs\s\a b.ps1"),
        ("powershell", r'-c "& \"\\fs\s\a b.ps1\" -P x"', r"\\fs\s\a b.ps1"),
        ("powershell", r'-Command ". \\fs\s\a.ps1"', r"\\fs\s\a.ps1"),
        ("cmd.exe", r"/c \\fs\s\a.bat", r"\\fs\s\a.bat"),
        ("cmd.exe", r'/s /c ""\\fs\my s\a.bat" x"', r"\\fs\my s\a.bat"),
        ("cmd", r'/c"\\fs\s\a.bat"', r"\\fs\s\a.bat"),
        ("cmd", r"/K call \\fs\s\a.bat", r"\\fs\s\a.bat"),
        ("cmd", r"/c C:\a.bat & \\fs\s\b.bat", r"\\fs\s\b.bat"),
        ("cmd", r"/c powershell -File \\fs\s\a.ps1", r"\\fs\s\a.ps1"),
        ("wscript", r"//B //Nologo \\fs\s\a.vbs C:\x", r"\\fs\s\a.vbs"),
        ("mshta.exe", r"\\fs\s\a.hta", r"\\fs\s\a.hta"),
        ("msiexec", r"/qn /i \\fs\s\a.msi /l*v C:\x.log", r"\\fs\s\a.msi"),
        ("msiexec", r'/package"\\fs\s\a b.msi"', r"\\fs\s\a b.msi"),
        ("regsvr32", r"/s /n /i:\\fs\s\a.sct scrobj.dll", r"\\fs\s\a.sct"),
        ("rundll32", r"\\fs\s\a.dll,Entry C:\x", r"\\fs\s\a.dll"),
        ("cmd", r"/c %LOGONSERVER%\netlogon\a.bat x", r"%LOGONSERVER%\netlogon\a.bat"),
        (r"C:\Program Files\PowerShell\7\pwsh.exe", r"-File \\fs\s\a.ps1", r"\\fs\s\a.ps1"),
    ],
)
def test_what_an_interpreter_runs_is_followed(command: str, arguments: str, path: str) -> None:
    assert targets(command, arguments) == [(path, "")]


@pytest.mark.parametrize(
    ("command", "arguments"),
    [
        ("powershell", r"-Command Copy-Item \\fs\s\a.exe C:\t"),
        ("powershell", r'-Command "Start-Process \\fs\s\a.exe -ArgumentList x"'),
        ("cmd", r"/c copy \\fs\s\a.exe C:\t"),
        ("cmd", r"\\fs\s\a.exe"),
        ("msiexec", r"/l*v \\fs\s\a.exe"),
    ],
)
def test_a_line_that_does_not_say_what_runs_is_not_judged(command: str, arguments: str) -> None:
    assert targets(command, arguments) == [(r"\\fs\s\a.exe", sysvol.UNCLEAR)]


def test_a_shell_line_ends_the_file_at_the_first_space() -> None:
    assert targets("cmd", r"/c \\fs\s\a admin pw.bat") == [(r"\\fs\s\a", "")]


def test_a_redirection_is_not_a_path_to_judge() -> None:
    assert targets("cmd", r"/c echo x > \\ws03\logs\a.log") == []


def test_nesting_is_bounded() -> None:
    line = "cmd /c " * 20_000 + r"\\fs\s\a.bat"
    assert targets(line) == [(r"\\fs\s\a.bat", sysvol.UNCLEAR)]


def test_unclear_path_is_an_info_row_and_stays_out_of_the_graph() -> None:
    script = startup(path=r"\\app01\s\a.exe", location="unclear", target="")
    f = only(scripts_snap(script=script), "AD-GPO-018")
    assert f.severity == Severity.INFO and "not judged" in f.objects[0]


def test_scheduled_task_log_argument_gives_no_host_row() -> None:
    body = (
        "<ScheduledTasks><TaskV2><Properties action='U'><Task><Actions><Exec>"
        "<Command>powershell.exe</Command>"
        r"<Arguments>-File C:\Tools\inventory.ps1 -LogPath \\ws03\logs\inv.log</Arguments>"
        "</Exec></Actions></Task></Properties></TaskV2></ScheduledTasks>"
    )
    assert sysvol.parse_scheduled_tasks(body.encode(), GUID_A, "computer", "c") == []


# --- arguments are never kept ------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "arguments"),
    [
        ("powershell.exe", rf'-NoProfile -Command "{TARGET} -User svc -Password {SECRET}"'),
        ("powershell.exe", rf'-File "{TARGET} -Password {SECRET}"'),
        ("cmd.exe", rf'/c "{TARGET} admin {SECRET}"'),
        (rf"{TARGET} admin {SECRET}", ""),
        (rf'"{TARGET}" admin {SECRET}', ""),
        (rf'"{TARGET} admin {SECRET}"', ""),
        (rf"powershell -File {TARGET} -P {SECRET}", ""),
    ],
)
def test_a_password_in_a_command_line_is_cut_off(command: str, arguments: str) -> None:
    assert targets(command, arguments) == [(TARGET, "")]


def test_a_name_with_spaces_ends_at_its_extension() -> None:
    assert targets(rf"\\fs01\Group Scripts\my run.bat admin {SECRET}") == [
        (r"\\fs01\Group Scripts\my run.bat", "")
    ]
    assert targets(rf"\\fs01\it\tool -u admin -p {SECRET}.bat") == [(r"\\fs01\it\tool", "")]


def test_password_stays_out_of_the_script_the_finding_and_the_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = (
        f'[Startup]\n0CmdLine=cmd.exe\n0Parameters=/c "\\\\app01\\it\\map.bat admin {SECRET}"\n'
        f"1CmdLine=run.bat admin {SECRET}\n"
        f"2CmdLine=\\\\lab.test\\netlogon\\gone.bat admin {SECRET}\n"
    )
    found = sysvol.parse_scripts_ini(text, GUID_A, "computer", INI, "scripts.ini")
    assert [x.path for x in found] == [
        r"\\app01\it\map.bat",
        "run.bat",
        r"\\lab.test\netlogon\gone.bat",
    ]
    assert found[1].target == rf"{FOLDER}\Machine\Scripts\Startup\run.bat"
    assert SECRET not in json.dumps([x.__dict__ for x in found])

    def missing(path: str, port: int, directory: bool) -> bytes:
        raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)

    monkeypatch.setattr(sysvol, "_descriptor", missing)
    result = sysvol.SysvolResult()
    sysvol._read_run_files(
        result, r"\\h\SYSVOL\lab.test", 445, [found[2]], [], "lab.test", {"lab.test"}
    )
    assert result.notes and SECRET not in " ".join(result.notes)
    place = sysvol.place(found[0], "lab.test", {"lab.test"})
    assert place and found[0].host == "app01"
    f = only(scripts_snap(script=found[0], ou=DC_OU), "AD-GPO-018")
    assert SECRET not in json.dumps(f.objects)


# --- WMI filters -------------------------------------------------------------------------


def filtered_gpo(snap: Snapshot) -> Snapshot:
    snap.gpos[0].wmi_filter = "only-workstations"
    return snap


def test_wmi_filter_caps_a_writer_and_says_so() -> None:
    writer = acl(INI, Ace(HELPDESK, WRITE))
    plain = only(scripts_snap(writer, ou=DC_OU), "AD-GPO-017")
    capped = only(filtered_gpo(scripts_snap(writer, ou=DC_OU)), "AD-GPO-017")
    assert plain.severity == Severity.HIGH and capped.severity == Severity.MEDIUM
    assert "WMI filter not evaluated" in capped.objects[0]
    broad = only(filtered_gpo(scripts_snap(acl(INI, Ace(AU, WRITE)))), "AD-GPO-017")
    assert broad.severity == Severity.MEDIUM


def test_wmi_filter_caps_a_host_and_says_so() -> None:
    plain = only(scripts_snap(script=remote(), ou=DC_OU), "AD-GPO-018")
    capped = only(filtered_gpo(scripts_snap(script=remote(), ou=DC_OU)), "AD-GPO-018")
    assert plain.severity == Severity.HIGH and capped.severity == Severity.MEDIUM
    assert "WMI filter not evaluated" in capped.objects[0]


def test_script_reach_carries_the_wmi_filter() -> None:
    snap = filtered_gpo(scripts_snap())
    assert script_reach(snap, set())[(GUID_A, "computer")].wmi
    assert not script_reach(scripts_snap(), set())[(GUID_A, "computer")].wmi


# --- loopback ----------------------------------------------------------------------------


USER_FOLDER = rf"{FOLDER}\User\Scripts"
USER_INI = rf"{USER_FOLDER}\scripts.ini"
LOGON = rf"{USER_FOLDER}\Logon\go.bat"


def logon(**kw: Any) -> GpoScript:
    fields: dict[str, Any] = {
        "side": "user", "phase": "logon", "config": USER_INI, "target": LOGON, "run_as": "user",
    }  # fmt: skip
    fields.update(kw)
    return startup(**fields)


def loopback_snap(*aces: Ace, mode: int | None, collected: bool = True, **kw: Any) -> Snapshot:
    """A logon script in a GPO linked to an OU with computers and no users."""
    runner = gpo(
        "Runner", GUID_A, link(DC_OU), machine_extensions=[CSE_SCRIPTS, CSE_REGISTRY],
        user_version=1, user_extensions=[CSE_SCRIPTS],
    )  # fmt: skip
    values = [
        RegistryEntry(regpol.LOOPBACK_KEY, regpol.LOOPBACK_VALUE, "set", regpol.REG_DWORD, mode)
    ]
    file_acls = [
        acl(USER_INI, Ace("S-1-5-32-544", 0xD0046)),
        acl(LOGON, *aces or (Ace("S-1-5-32-544", 0xD0046),)),
    ]
    return gsnap(
        dc("DC02"),
        gpos=[runner],
        entries=[],
        gpo_scripts=[kw.pop("script", logon())],
        sysvol_acls=file_acls,
        gpo_scripts_checked=True,
        gpo_registry={GUID_A: values if mode is not None else []},
        gpo_preferences={GUID_A: []},
        registry_policy_collected=True,
        policy_files_collected=True,
        loopback_collected=collected,
        principals={HELPDESK: "helpdesk"},
        **kw,
    )


def test_loopback_on_reaches_the_computers_at_the_full_grade() -> None:
    f = only(loopback_snap(Ace(AU, WRITE), mode=1), "AD-GPO-017")
    assert f.severity == Severity.HIGH and "through loopback" in f.objects[0]
    assert (
        script_reach(loopback_snap(mode=2), {f"cn=dc02,{DC_OU}".lower()})[(GUID_A, "user")].loopback
        == "on"
    )


def test_loopback_off_is_a_gpo_that_reaches_nobody() -> None:
    assert findings(loopback_snap(Ace(AU, WRITE), mode=None), "AD-GPO-017") is None


def test_loopback_that_was_not_collected_is_not_clean() -> None:
    f = only(loopback_snap(Ace(AU, WRITE), mode=None, collected=False), "AD-GPO-017")
    assert f.severity == Severity.MEDIUM and "loopback not evaluated" in f.objects[0]
    named = only(loopback_snap(Ace(HELPDESK, WRITE), mode=None, collected=False), "AD-GPO-017")
    assert named.severity == Severity.LOW


def test_loopback_from_an_unread_registry_pol_is_not_clean() -> None:
    snap = loopback_snap(Ace(AU, WRITE), mode=None)
    del snap.gpo_registry[GUID_A]
    assert "loopback not evaluated" in only(snap, "AD-GPO-017").objects[0]


def test_host_row_when_loopback_is_not_known_is_info() -> None:
    script = remote(side="user", phase="logon", config=USER_INI, run_as="user")
    snap = loopback_snap(mode=None, collected=False, script=script)
    snap.accounts.append(host("APP01"))
    f = only(snap, "AD-GPO-018")
    assert f.severity == Severity.INFO and "not judged" in f.objects[0]


def test_loopback_value_is_kept_from_registry_pol() -> None:
    assert regpol.watched(regpol.LOOPBACK_KEY, regpol.LOOPBACK_VALUE)


def test_a_gpo_that_reaches_users_is_not_a_loopback_case() -> None:
    snap = loopback_snap(mode=1)
    snap.gpos[0].links = [link(LAB)]
    snap.accounts.append(replace(user("bob", sid=f"{DOM}-3000"), dn=f"CN=bob,{LAB}"))
    assert script_reach(snap, set())[(GUID_A, "user")].loopback == ""


# --- NetBIOS -----------------------------------------------------------------------------


def test_real_netbios_name_is_netlogon(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, set[str]] = {}

    def run_files(_r: Any, _b: str, _p: int, _f: Any, _n: Any, _d: str, hosts: set[str]) -> None:
        calls["hosts"] = hosts

    monkeypatch.setattr(sysvol.smbclient, "register_session", lambda *a, **k: None)
    monkeypatch.setattr(sysvol.smbclient, "walk", lambda *a, **k: iter(()))
    monkeypatch.setattr(sysvol.smbclient, "reset_connection_cache", lambda: None)
    monkeypatch.setattr(sysvol, "_read", lambda *a: b"")
    monkeypatch.setattr(sysvol, "_read_run_files", run_files)
    sysvol.scan("dc", "ad.corp.example", "u", "p", [], netbios="CORP")
    assert calls["hosts"] == {"ad.corp.example", "corp"}
    script = startup(path=r"\\CORP\NETLOGON\logon.bat", location="", target="")
    assert sysvol.place(script, "ad.corp.example", calls["hosts"])
    assert (script.location, script.target) == ("sysvol", r"scripts\logon.bat")
    wrong = startup(path=r"\\ad\share\x.bat", location="", target="")
    sysvol.place(wrong, "ad.corp.example", calls["hosts"])
    assert (wrong.location, wrong.host) == ("host", "ad")


def test_collector_passes_the_crossref_name(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def scan(*args: Any) -> sysvol.SysvolResult:
        seen["netbios"] = args[8]
        return sysvol.SysvolResult()

    monkeypatch.setattr(sysvol, "scan", scan)
    c = collector()
    monkeypatch.setattr(
        c,
        "optional",
        lambda *_: [{"attributes": {"nETBIOSName": ["CORP"]}, "netbiosname": ["CORP"]}],
    )
    c._sysvol("ad.corp.example", [], [], "DC=ad,DC=corp,DC=example", "CN=Configuration,DC=x")
    assert seen["netbios"] == "CORP"
    monkeypatch.setattr(c, "optional", lambda *_: [])
    c._sysvol("ad.corp.example", [], [], "DC=ad,DC=corp,DC=example", "CN=Configuration,DC=x")
    assert seen["netbios"] == "ad"


# --- certificates ------------------------------------------------------------------------


def der_len(size: int) -> bytes:
    if size < 128:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, *parts: bytes) -> bytes:
    body = b"".join(parts)
    return bytes([tag]) + der_len(len(body)) + body


def oid_bytes(dotted: str) -> bytes:
    a, b, *rest = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * a + b])
    for arc in rest:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return der(x509.OID, bytes(out))


def name(cn: str) -> bytes:
    pair = der(x509.SEQUENCE, oid_bytes(x509.COMMON_NAME), der(0x0C, cn.encode()))
    return der(x509.SEQUENCE, der(x509.SET, pair))


def certificate(signature_oid: str, issuer: str = "root") -> bytes:
    algorithm = der(x509.SEQUENCE, oid_bytes(signature_oid))
    validity = der(
        x509.SEQUENCE, der(x509.UTC_TIME, b"200101000000Z"), der(x509.UTC_TIME, b"500101000000Z")
    )
    modulus = der(x509.INTEGER, b"\x00" + b"\xff" * 256)
    key = der(x509.SEQUENCE, modulus, der(x509.INTEGER, b"\x01\x00\x01"))
    info = der(
        x509.SEQUENCE,
        der(x509.SEQUENCE, oid_bytes(x509.RSA)),
        der(x509.BIT_STRING, b"\x00" + key),
    )
    tbs = der(
        x509.SEQUENCE,
        der(x509.INTEGER, b"\x01"),
        algorithm,
        name(issuer),
        validity,
        name("sub"),
        info,
    )
    return der(x509.SEQUENCE, tbs, algorithm, der(x509.BIT_STRING, b"\x00\x00"))


@pytest.mark.parametrize(
    ("oid", "expected"),
    [
        ("1.3.14.3.2.27", "sha1"),
        ("1.3.14.3.2.2", "md4"),
        ("1.2.840.10045.4.3.1", "sha224"),
        ("2.16.840.1.101.3.4.3.1", "sha224"),
    ],
)
def test_more_signature_algorithms_are_named(oid: str, expected: str) -> None:
    assert x509.parse(certificate(oid)).signature_hash == expected


def test_dsa_with_sha1_is_reported() -> None:
    cert = _ca_certificate(certificate("1.3.14.3.2.27"), "sub-ca")
    cert.stores.append("NTAuth")
    f = only(
        snapshot(user("bob"), ca_certificates=[cert], ca_certificates_checked=True), "AD-ADCS-021"
    )
    assert f.severity == Severity.MEDIUM and "SHA1" in f.objects[0]


def certificate_notes(monkeypatch: pytest.MonkeyPatch, der_bytes: bytes) -> list[str]:
    c = collector()
    entry = {"cacertificate": [der_bytes], "name": ["sub-ca"]}
    monkeypatch.setattr(c, "attempt", lambda *_, **__: [entry])
    c._ca_certificates("CN=Public Key Services,CN=Configuration,DC=x")
    return c.notes


def test_a_signature_it_cannot_name_is_in_the_note(monkeypatch: pytest.MonkeyPatch) -> None:
    notes = certificate_notes(monkeypatch, certificate("1.2.3.4.5"))
    assert any("not understood" in n and "AD-ADCS-021" in n for n in notes)


def test_a_known_signature_and_an_unknown_one_on_a_root_are_not_in_the_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not certificate_notes(monkeypatch, certificate("1.2.840.113549.1.1.11"))
    assert not certificate_notes(monkeypatch, certificate("1.2.3.4.5", issuer="sub"))


# --- notes that name the check ------------------------------------------------------------


def collector(**kw: Any) -> Collector:
    c = Collector.__new__(Collector)
    c.target = Target(host="dc01", user="LAB\\u", password="p", **kw)
    c.notes = []
    return c


def test_tier0_member_notes_name_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "smb_signing", lambda *_: (None, "timed out"))
    s = gsnap(
        host("CA01", dns_host="ca01.lab.test", rid=2100),
        host("CA02", rid=2102),
        dc("DC01"),
        gpos=[],
        entries=[],
        ca_hosts=["CA01$", "CA02$"],
    )
    c = collector()
    c._probe_tier0_members(s)
    assert len(c.notes) == 2
    assert all(CHECK_IN_NOTE.findall(n) == ["AD-INF-025"] for n in c.notes)


def test_probe_pack_note_names_each_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "webclient", lambda *_: None)
    monkeypatch.setattr(probes, "smb1_enabled", lambda *_: None)
    monkeypatch.setattr(
        probes,
        "ldaps_tls_versions",
        lambda *_: {"tls10": None, "tls11": False, "tls12": True, "tls13": False},
    )
    c = collector()
    c._probe_dc_pack(collect.DcProbe("DC1"), "dc1", True)
    assert CHECK_IN_NOTE.findall(c.notes[0]) == ["AD-INF-026", "AD-INF-027", "AD-INF-028"]


def scan_with(
    monkeypatch: pytest.MonkeyPatch, name: str, reader: Any
) -> tuple[sysvol.SysvolResult, str]:
    tree = rf"\\dc\SYSVOL\lab.test\{FOLDER}\Machine\Scripts"
    if name == "ScheduledTasks.xml":
        tree = rf"\\dc\SYSVOL\lab.test\{FOLDER}\Machine\Preferences\ScheduledTasks"

    def walk(root: str, **_: Any) -> list[tuple[str, list[str], list[str]]]:
        return [(tree, [], [name])] if root.endswith("Policies") else []

    monkeypatch.setattr(sysvol.smbclient, "register_session", lambda *a, **k: None)
    monkeypatch.setattr(sysvol.smbclient, "walk", walk)
    monkeypatch.setattr(sysvol.smbclient, "reset_connection_cache", lambda: None)
    monkeypatch.setattr(sysvol, "_read", reader)
    return sysvol.scan("dc", "lab.test", "u", "p", [GUID_A]), name


def test_unreadable_run_config_names_both_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(path: str, port: int) -> bytes:
        if path.endswith("scripts.ini"):
            raise PermissionError(path)
        raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)

    result, _ = scan_with(monkeypatch, "scripts.ini", deny)
    assert result.scanned
    assert [CHECK_IN_NOTE.findall(n) for n in result.notes] == [["AD-GPO-017", "AD-GPO-018"]]
    assert "scripts.ini" in result.notes[0]


def test_unreadable_file_of_an_unknown_gpo_says_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(path: str, port: int) -> bytes:
        if path.endswith("scripts.ini"):
            raise PermissionError(path)
        raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)

    tree = r"\\dc\SYSVOL\lab.test\Policies" + "\\" + GUID_B + r"\Machine\Scripts"
    monkeypatch.setattr(sysvol.smbclient, "register_session", lambda *a, **k: None)
    monkeypatch.setattr(
        sysvol.smbclient,
        "walk",
        lambda root, **_: [(tree, [], ["scripts.ini"])] if root.endswith("Policies") else [],
    )
    monkeypatch.setattr(sysvol.smbclient, "reset_connection_cache", lambda: None)
    monkeypatch.setattr(sysvol, "_read", deny)
    result = sysvol.scan("dc", "lab.test", "u", "p", [GUID_A])
    assert result.unreadable and not result.notes


def test_malformed_tasks_name_both_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(path: str, port: int) -> bytes:
        if path.endswith("ScheduledTasks.xml"):
            return b"<ScheduledTasks><oops>"
        raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)

    result, _ = scan_with(monkeypatch, "ScheduledTasks.xml", broken)
    assert [CHECK_IN_NOTE.findall(n) for n in result.notes] == [["AD-GPO-017", "AD-GPO-018"]]


# --- redaction -----------------------------------------------------------------------------


def severities(snap: Snapshot) -> dict[str, tuple[Severity, int]]:
    return {f.check_id: (f.severity, len(f.objects)) for f in run_all(snap)}


@pytest.mark.parametrize("address", ["10.1.2.3", "192.168.5.32"])
def test_address_host_keeps_sids_and_findings(address: str) -> None:
    script = startup(
        path=rf"\\{address}\share\2024\x.bat", location="host", host=address, target="",
    )  # fmt: skip
    s = scripts_snap(acl(INI, Ace(AU, WRITE)), script=script)
    data = json.loads(json.dumps(s.to_json()))
    out = redact.redact(data, b"k")
    text = json.dumps(out)
    assert "S-1-5-11" in text and "S-1-5-32-544" in text and address not in text
    back = Snapshot.from_json(out)
    assert severities(back) == severities(s)


def test_other_host_fields_learn_no_digits() -> None:
    snap_data: dict[str, Any] = {
        "domain": "lab.test",
        "accounts": [],
        "sccm_objects": [{"dn": "CN=x", "site_code": "ABC", "host": "10.1.2.3"}],
        "probes": {"patch_levels": [{"name": "10.9.8.7"}], "dcs": [{"name": "10.5.6.7"}]},
    }
    r = redact.Redactor(b"k")
    r.collect(snap_data)
    assert not any(w.replace(".", "").isdigit() for w in r.names)


def test_a_custom_class_name_in_a_display_specifier_is_replaced() -> None:
    dn = "CN=acmeHrPerson-Display,CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=lab,DC=test"
    s = replace(
        snapshot(user("bob")),
        display_specifiers=[DisplaySpecifierCommand(dn, "adminContextMenu", r"1,x,\\a\b.exe")],
        display_specifiers_checked=True,
    )
    out = redact.redact(json.loads(json.dumps(s.to_json())), b"k")
    assert "acmeHrPerson" not in json.dumps(out)
    assert ",CN=409,CN=DisplaySpecifiers," in out["display_specifiers"][0]["dn"]
    f = only(Snapshot.from_json(out), "AD-INF-023")
    assert f is not None and "acmeHrPerson" not in f.objects[0]


# --- scorecard ------------------------------------------------------------------------------


def card(s: Snapshot) -> dict[str, Any]:
    return views.tier0_scorecard(s, run_all(s))


def test_scorecard_shows_unreadable_members() -> None:
    hidden = UnreadableMember("CN=x,DC=lab,DC=test", "Domain Admins", "no search returned it")
    s = replace(
        snapshot(user("bob")),
        unreadable_members=[hidden] * 4,
        tier0_members_checked=True,
    )
    result = card(s)
    assert result["members_not_readable"] == 4
    assert json.loads(views.render_scorecard(result, "json"))["members_not_readable"] == 4
    line = next(
        x for x in views.render_scorecard(result, "text").splitlines() if "not readable" in x
    )
    assert line.split()[-1] == "4"


def test_scorecard_says_when_the_count_cannot_be_told() -> None:
    s = replace(snapshot(user("bob")), tier0_members_checked=False)
    assert card(s)["members_not_readable"] is None
    assert "not known" in views.render_scorecard(card(s), "text")


def test_scorecard_lists_not_judged_checks() -> None:
    s = replace(
        snapshot(user("bob")),
        tier0_members_checked=True,
        notes=["AD-PRIV-012 not judged", "a note about nothing"],
    )
    assert card(s)["checks_not_judged"] == ["AD-PRIV-012"]
