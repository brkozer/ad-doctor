"""Patch level, Certighost, fix preflight, multi-domain rollup and the two views."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ad_doctor import patches, probes, redact, rollup, views, winreg
from ad_doctor.checks import run_all
from ad_doctor.cli import main
from ad_doctor.collect import Collector, Target
from ad_doctor.fixes import FIXES, PREFLIGHT, render_preflight
from ad_doctor.model import (
    UAC,
    CaConfig,
    Finding,
    HostPatch,
    Probes,
    Severity,
    Snapshot,
)

from .test_checks import only, snapshot, user

CHASE = 0x11014E
NO_CHASE = CHASE & ~0x100000
# below every DC fix in the table for 20348, and above all of them
OLD = HostPatch("DC01.lab.test", ["dc"], 20348, 2000)
NEW = HostPatch("DC01.lab.test", ["dc"], 20348, 9000)
CA_OLD = HostPatch("CA01.lab.test", ["ca"], 20348, 5000)
CA_NEW = HostPatch("CA01.lab.test", ["ca"], 20348, 5386)


def ids(findings: list[Finding]) -> set[str]:
    return {f.check_id for f in findings}


def snap_with(*hosts: HostPatch, cas: list[CaConfig] | None = None) -> Snapshot:
    return replace(
        snapshot(),
        probes=Probes(patch_levels=list(hosts), patch_checked=True, ca_configs=cas or []),
    )


def ca(edit_flags: int | None = CHASE) -> CaConfig:
    return CaConfig("LAB-CA", "CA01.lab.test", edit_flags=edit_flags)


def test_table_is_dated_and_shaped() -> None:
    t = patches.table()
    assert t.updated == datetime(2026, 11, 9, tzinfo=UTC).date()
    assert len({c.id for c in t.cves}) == len(t.cves) == 6
    for c in t.cves:
        assert c.url == f"https://msrc.microsoft.com/update-guide/vulnerability/{c.id}"
        assert set(c.roles) <= {"dc", "ca"} and c.fixed
        assert set(c.fixed) <= {14393, 17763, 20348, 25398, 26100}
        assert all(v > 0 for v in c.fixed.values())


def test_dc_below_fix_fires_medium() -> None:
    f = only(snap_with(OLD), "AD-INF-029")
    assert f.severity is Severity.MEDIUM
    assert len(f.objects) == 1 and f.objects[0].startswith("DC01.lab.test (at 10.0.20348.2000")
    # hotpatch build is the threshold for this release
    assert "CVE-2025-33073 from 10.0.20348.3745" in f.objects[0]
    # build not in that CVE's list is not claimed
    assert "CVE-2025-53779" not in f.objects[0]
    assert f.key(f.objects[0]) == "DC01.lab.test"
    assert "does not test" in f.detail and f.data["confidence"] == "version only"


@pytest.mark.parametrize(
    "host",
    [
        NEW,
        HostPatch("DC01.lab.test", ["dc"], 20348, 5386),  # all DC fixes present
        HostPatch("DC01.lab.test", ["dc"], 20348, None, "denied"),  # unreadable
        HostPatch("DC01.lab.test", ["dc"], None, None, "denied"),
        HostPatch("DC01.lab.test", ["dc"], 9600, 21000),  # not in the table
        HostPatch("CA01.lab.test", ["ca"], 20348, 100),  # not a DC
    ],
)
def test_dc_stays_quiet(host: HostPatch) -> None:
    assert "AD-INF-029" not in ids(run_all(snap_with(host)))


def test_certighost_grades() -> None:
    f = only(snap_with(CA_OLD, cas=[ca()]), "AD-ADCS-022")
    assert f.severity is Severity.MEDIUM and "EDITF_ENABLECHASECLIENTDC set" in f.objects[0]
    f = only(snap_with(CA_OLD, cas=[ca(NO_CHASE)]), "AD-ADCS-022")
    assert f.severity is Severity.LOW and "EDITF_ENABLECHASECLIENTDC off" in f.objects[0]


@pytest.mark.parametrize(
    ("host", "cfg"),
    [
        (CA_NEW, ca()),  # at the fixed build
        (CA_OLD, ca(None)),  # flags unknown
        (HostPatch("CA01.lab.test", ["ca"], 25398, 1), ca()),  # no row for this build
        (HostPatch("CA01.lab.test", ["ca"], None, None, "denied"), ca()),
        (HostPatch("OTHER.lab.test", ["ca"], 20348, 5000), ca()),  # no matching config
    ],
)
def test_certighost_stays_quiet(host: HostPatch, cfg: CaConfig) -> None:
    assert "AD-ADCS-022" not in ids(run_all(snap_with(host, cas=[cfg])))


def test_notes_report_unknowns() -> None:
    s = snap_with(
        HostPatch("OLD.lab.test", ["dc"], 9600, 21000),
        CA_OLD,
        cas=[ca(None)],
    )
    text = "\n".join(patches.notes(s))
    assert "build 9600 is not in the patch table: AD-INF-029 did not judge it" in text
    assert "EditFlags could not be read: AD-ADCS-022 did not judge it" in text


def test_notes_report_a_stale_table() -> None:
    t = patches.table()
    fresh = replace(snap_with(), collected_at=datetime(2026, 11, 20, tzinfo=UTC))
    assert not [n for n in patches.notes(fresh, t) if "patch table" in n]
    old = replace(
        snap_with(),
        collected_at=datetime(2026, 11, 9, tzinfo=UTC) + timedelta(days=t.stale_after_days + 1),
    )
    note = next(n for n in patches.notes(old, t) if "patch table" in n)
    assert f"{t.stale_after_days + 1} days older" in note and "AD-INF-029" in note


def test_no_patch_data_means_no_notes_and_no_finding() -> None:
    s = replace(snapshot(), probes=Probes())
    assert patches.notes(s) == []
    assert not {"AD-INF-029", "AD-ADCS-022"} & ids(run_all(s))


def test_old_snapshot_reports_not_evaluated() -> None:
    data = snap_with(OLD).to_json()
    del data["probes"]["patch_levels"], data["probes"]["patch_checked"]
    back = Snapshot.from_json(data)
    assert not back.probes.patch_checked and not back.probes.patch_levels
    assert any("AD-INF-029 and AD-ADCS-022" in n and "not evaluated" in n for n in back.notes)


def test_new_field_round_trip_and_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    s = snap_with(replace(OLD, name="DC01.secretdomain.test"))
    back = Snapshot.from_json(s.to_json())
    assert back.probes.patch_levels == s.probes.patch_levels and back.probes.patch_checked
    assert not any("patch level" in n for n in back.notes)
    data = redact.redact(s.to_json(), b"key")
    text = json.dumps(data["probes"]["patch_levels"])
    assert "secretdomain" not in text and "DC01" not in text
    assert data["probes"]["patch_levels"][0]["build"] == 20348


class FakeRegistry:
    hklm = b"hklm"

    def __init__(self, values: dict[str, Any] | Exception) -> None:
        self.values = values

    def open_key(self, parent: bytes, path: str) -> bytes:
        assert parent == b"hklm"
        if isinstance(self.values, Exception):
            raise self.values
        assert path == probes.CURRENT_VERSION
        return b"key"

    def query_value(self, key: bytes, name: str) -> winreg.RegValue:
        assert isinstance(self.values, dict)
        return self.values[name] if name in self.values else _absent()

    def close_key(self, key: bytes) -> None:
        pass


def _absent() -> winreg.RegValue:
    raise winreg.RegistryError(winreg.ERROR_FILE_NOT_FOUND, "read")


def test_read_patch_level_success() -> None:
    reg = FakeRegistry({"CurrentBuildNumber": "20348", "UBR": 2000})
    assert probes.read_patch_level(reg, "dc1", ["dc"]) == HostPatch("dc1", ["dc"], 20348, 2000)


@pytest.mark.parametrize(
    ("values", "why"),
    [
        (winreg.RegistryError(winreg.ERROR_ACCESS_DENIED, "open"), "access denied"),
        ({"CurrentBuildNumber": "20348"}, "build or UBR not readable"),
        ({"CurrentBuildNumber": "x", "UBR": 1}, "unexpected type"),
    ],
)
def test_read_patch_level_failures(values: Any, why: str) -> None:
    got = probes.read_patch_level(FakeRegistry(values), "dc1", ["dc"])
    assert got.build is None or got.ubr is None
    assert got.error and why in got.error


def test_patch_level_pipe_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*a: Any, **k: Any) -> None:
        raise winreg.PipeUnavailable

    monkeypatch.setattr(winreg, "SmbPipe", fail)
    got = probes.patch_level("h", 445, "h", ["dc"], "u", "p")
    assert got.error == "RemoteRegistry not running or disabled"


def collector(**kw: Any) -> Collector:
    fields: dict[str, Any] = {"plain_port": 0, "all_dcs": False, "user": "u", "password": "p"}
    return Collector(None, Target("h", **{**fields, **kw}))  # type: ignore[arg-type]


def test_patch_level_reads_each_host_once_with_both_roles(monkeypatch: Any) -> None:
    calls: list[tuple[str, int, str, list[str]]] = []

    def read(host: str, port: int, name: str, roles: list[str], *_: Any) -> HostPatch:
        calls.append((host, port, name, roles))
        return HostPatch(name, roles, 20348, 5386, None)

    monkeypatch.setattr(probes, "patch_level", read)
    c = collector(smb_port=1445)
    c.ca_dns_hosts = ["DC01.lab.test", "CA02.lab.test"]
    result = Probes()
    c._read_patch_levels("DC01.lab.test", [], result)
    assert result.patch_checked and calls == [
        ("h", 1445, "DC01.lab.test", ["dc", "ca"]),
        ("CA02.lab.test", 445, "CA02.lab.test", ["ca"]),
    ]
    assert len(result.patch_levels) == 2


def test_unreadable_patch_level_is_a_note_naming_the_check(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        probes,
        "patch_level",
        lambda _h, _p, name, roles, *_: HostPatch(name, roles, error="denied"),
    )
    c = collector()
    c.ca_dns_hosts = ["DC01.lab.test"]
    c._read_patch_levels("DC01.lab.test", [], Probes())
    assert any("AD-INF-029 and AD-ADCS-022 not judged: denied" in n for n in c.notes)


def test_patch_level_is_opt_out_and_needs_credentials() -> None:
    off = collector(patch_level=False)
    off._probes("dc01", [])
    assert any("--no-patch-level" in n and "AD-INF-029" in n for n in off.notes)
    none = collector(user=None, password=None)
    result = Probes()
    none._read_patch_levels("dc01", [], result)
    assert not result.patch_checked and any("needs credentials" in n for n in none.notes)


# --- preflight -------------------------------------------------------------------------------


def _finding(check: str, *objects: str) -> Finding:
    return Finding(check, "t", Severity.HIGH, "d", "r", list(objects))


def test_preflight_covers_the_first_ten_fixes_and_nothing_else() -> None:
    assert list(PREFLIGHT) == list(FIXES)[:10]


def test_preflight_is_read_only() -> None:
    findings = [_finding(c, "alice") for c in PREFLIGHT] + [_finding("AD-PRIV-004", "bob")]
    script = render_preflight(findings, snapshot())
    changing = (
        "Set-", "Remove-", "Disable-", "Enable-", "New-", "Add-", "Clear-", "Move-", "Rename-",
        "Restore-", "Invoke-Expression", "iex ", "Start-", "Stop-",
    )  # fmt: skip
    for line in script.splitlines():
        if not line.startswith("#"):
            assert not any(word in line for word in changing), line
    assert script.count("Test-AdDoctorPreflight 'AD-") == 10
    assert "# No preflight for these checks: AD-PRIV-004" in script
    code = [x for x in script.splitlines() if not x.startswith("#")]
    assert "Get-ADObject" in script and not any("-WhatIf" in x for x in code)


def test_preflight_quotes_directory_text() -> None:
    script = render_preflight([_finding("AD-KRB-002", "o'neil(*x\nRemove-ADUser")], snapshot())
    line = next(x for x in script.splitlines() if x.startswith("Test-AdDoctorPreflight"))
    assert "o''neil" in line and "\\28\\2ax" in line
    assert "Remove-ADUser" in line and "\\x0a" in line and "\n" not in line


def test_preflight_uses_each_check_flag() -> None:
    script = render_preflight(
        [_finding("AD-KRB-002", "a"), _finding("AD-ACC-004", "b"), _finding("AD-DEL-003", "c$")],
        snapshot(),
    )
    assert "'AD-KRB-002' 'a' '(sAMAccountName=a)' 0x400000 $true" in script
    assert "'AD-ACC-004' 'b' '(sAMAccountName=b)' 0x2 $false" in script
    assert "'AD-DEL-003' 'c$' '(sAMAccountName=c$)' 0x0 $true" in script


def test_preflight_written_by_the_cli(tmp_path: Path, capsys: Any) -> None:
    snap = tmp_path / "s.json"
    snap.write_text(
        json.dumps(snapshot(user("legacy", uac=0x10200 | UAC.DONT_REQ_PREAUTH)).to_json())
    )
    out = tmp_path / "pre.ps1"
    assert main(["analyze", str(snap), "--preflight", str(out), "-f", "json"]) == 0
    capsys.readouterr()
    assert "'AD-KRB-002' 'legacy'" in out.read_text()


# --- rollup ----------------------------------------------------------------------------------


def report(domain: str, **kw: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "tool": "ad-doctor",
        "schema": 2,
        "version": "0.2.4",
        "domain": domain,
        "collected_at": "2026-11-09T00:00:00+00:00",
        "score": 21,
        "grade": "B",
        "category_scores": {"Accounts": 21},
        "findings": [],
        "accepted": [],
        "notes": [],
        "checks": ["AD-KRB-002", "AD-INF-029"],
    }
    data.update(kw)
    return data


FIND = {"id": "AD-KRB-002", "title": "No pre-auth", "severity": "high", "objects": ["a", "b"]}


def write(tmp_path: Path, name: str, data: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


def test_rollup_counts_and_ordering(tmp_path: Path) -> None:
    a = write(tmp_path, "a.json", report("a.test", score=40, findings=[FIND]))
    b = write(tmp_path, "b.json", report("b.test", score=10, findings=[{**FIND, "objects": ["c"]}]))
    doc = rollup.build([b, a])
    assert [r["domain"] for r in doc["domains"]] == ["a.test", "b.test"]
    assert doc["checks"][0]["id"] == "AD-KRB-002"
    assert doc["checks"][0]["domains"] == {"a.test": 2, "b.test": 1}
    assert doc["checks"][0]["objects"] == 3 and doc["checks"][0]["not_judged"] == []
    assert doc["tool"] != "ad-doctor"  # never read as a report by trend or diff


def test_rollup_unknown_is_not_clean(tmp_path: Path) -> None:
    a = write(tmp_path, "a.json", report("a.test", findings=[FIND]))
    notrun = write(tmp_path, "b.json", report("b.test", checks=["AD-INF-029"]))
    noted = write(
        tmp_path, "c.json",
        report("c.test", notes=["could not read: AD-KRB-002 did not judge it"]),
    )  # fmt: skip
    doc = rollup.build([a, notrun, noted])
    assert doc["checks"][0]["not_judged"] == ["b.test", "c.test"]
    assert any("different sets of checks" in n for n in doc["notes"])
    text = rollup.render_text(doc)
    assert "not judged: b.test, c.test" in text and "1/3 domains" in text


def test_rollup_keeps_the_newest_report_of_a_domain(tmp_path: Path) -> None:
    old = write(tmp_path, "old.json", report("a.test", score=99))
    new = write(
        tmp_path, "new.json", report("A.test", score=5, collected_at="2026-11-10T00:00:00+00:00")
    )
    other = write(tmp_path, "b.json", report("b.test"))
    doc = rollup.build([old, new, other])
    assert len(doc["domains"]) == 2
    row = next(r for r in doc["domains"] if r["domain"].lower() == "a.test")
    assert row["score"] == 5 and any("old.json" in n for n in doc["notes"])


def test_rollup_versions_differ_note(tmp_path: Path) -> None:
    a = write(tmp_path, "a.json", report("a.test", version="0.2.3"))
    b = write(tmp_path, "b.json", report("b.test"))
    assert any("different ad-doctor versions" in n for n in rollup.build([a, b])["notes"])


def test_rollup_rejects_other_files(tmp_path: Path) -> None:
    a = write(tmp_path, "a.json", report("a.test"))
    snap = write(tmp_path, "snap.json", {"domain": "x"})
    with pytest.raises(ValueError, match=r"snap\.json: not an ad-doctor JSON report"):
        rollup.build([a, snap])
    with pytest.raises(ValueError, match="at least two"):
        rollup.build([a])
    broken = tmp_path / "broken.json"
    broken.write_text("{")
    with pytest.raises(ValueError, match=r"broken\.json"):
        rollup.build([a, broken])


def test_rollup_cli_and_formats(tmp_path: Path, capsys: Any) -> None:
    a = write(tmp_path, "a.json", report("a.test", findings=[FIND]))
    b = write(tmp_path, "b.json", report("b|test"))
    assert main(["rollup", str(a), str(b)]) == 0
    assert "ad-doctor rollup: 2 domains" in capsys.readouterr().out
    assert main(["rollup", str(a), str(b), "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["tool"] == "ad-doctor-rollup"
    out = tmp_path / "out.md"
    assert main(["rollup", str(a), str(b), "-f", "markdown", "-o", str(out)]) == 0
    assert "b\\|test" in out.read_text()
    assert main(["rollup", str(a)]) == 1
    capsys.readouterr()


def test_rollup_control_characters_stay_on_one_line(tmp_path: Path) -> None:
    a = write(tmp_path, "a.json", report("a\nFAKE.test"))
    b = write(tmp_path, "b.json", report("b.test"))
    rows = rollup.render_text(rollup.build([a, b])).splitlines()
    assert not any(r.startswith("FAKE") for r in rows)


# --- views -----------------------------------------------------------------------------------


NOW = snapshot().collected_at


def test_service_accounts_view() -> None:
    rows = views.service_accounts(
        snapshot(
            user("svc_sql", spns=["MSSQLSvc/db"], pwd_last_set=NOW - timedelta(days=400)),
            user("plain"),
            user("gmsa$", managed=True, is_computer=True),
            user("krbtgt", uac=0x202, spns=["kadmin/changepw"], sid="S-1-5-21-1-1-1-502"),
        )
    )
    assert [r["name"] for r in rows] == ["gmsa$", "svc_sql"]
    sql = rows[1]
    assert sql["kind"] == "user with SPN" and sql["password_age_days"] == 400
    assert sql["enabled"] is True and sql["tier0"] is False
    assert "2 service accounts" in views.render_service_accounts(rows, "text")


def test_service_account_unknown_age_stays_unknown() -> None:
    row = views.service_accounts(snapshot(user("svc", spns=["http/x"], pwd_must_change=True)))[0]
    assert row["password_age_days"] is None
    assert " ? " in views.render_service_accounts([row], "text")


def test_tier0_scorecard_counts_only_tier0() -> None:
    snap = snapshot(
        user("da1", uac=0x200 | UAC.DONT_REQ_PREAUTH, pwd_last_set=NOW - timedelta(days=500)),
        user("other"),
    )
    da_dn = next(a.dn for a in snap.accounts if a.sam == "da1")
    snap = replace(snap, privileged={"Domain Admins": [da_dn]})
    card = views.tier0_scorecard(snap, run_all(snap))
    assert card["accounts"] == 1 and card["enabled_accounts"] == 1
    assert card["without_preauth"] == 1 and card["passwords_over_a_year"] == 1
    assert card["findings_on_tier0_accounts"]["high"] >= 1
    text = views.render_scorecard(card, "text")
    assert "Tier 1 and tier 2 are not in the directory" in text
