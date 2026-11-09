"""New checks, scoring, renderers, accepted risks, baselines, diff and the fix script."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from ad_doctor import accept, sd, viewer
from ad_doctor.checks import REGISTRY, run_all
from ad_doctor.cli import main
from ad_doctor.fixes import render_fixes
from ad_doctor.model import Severity, Trust
from ad_doctor.report import (
    Report,
    render_markdown,
    render_sarif,
    render_text,
)
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_SID, template
from .test_checks import NORMAL, NOW, computer, only, snapshot, user
from .viewer_fixtures import decode_payload

HELPDESK = f"{DOMAIN_SID}-1105"


def test_every_check_has_mitre_or_is_hygiene() -> None:
    from ad_doctor.checks import MITRE

    unmapped = {c.id for c in REGISTRY} - MITRE.keys()
    # functional level, directory health and group loops: hygiene, no technique
    assert unmapped == {"AD-INF-003", "AD-INF-019", "AD-INF-020", "AD-INF-021", "AD-PRIV-018"}


@pytest.mark.parametrize(
    ("os_name", "fires"),
    [
        ("Windows Server 2012 R2 Standard", True),
        ("Windows 10 Pro", True),
        ("Windows 8.1 Pro", True),
        ("Windows 11 Enterprise", False),
        ("Windows Server 2022 Datacenter", False),
        ("Windows Server 2016 Standard", False),  # ends 2027-01-12, after NOW
    ],
)
def test_obsolete_os(os_name: str, fires: bool) -> None:
    findings = run_all(snapshot(computer("PC1", os=os_name)))
    assert ("AD-INF-001" in {f.check_id for f in findings}) is fires


def test_obsolete_dc_is_high() -> None:
    snap = snapshot()
    snap.accounts[2].os = "Windows Server 2008 R2 Standard"
    assert only(snap, "AD-INF-001").severity is Severity.HIGH


def test_admincount_orphan_and_sid_history() -> None:
    snap = snapshot(
        user("ex_admin", admin_count=True),
        user("migrated", sid_history=["S-1-5-21-9-9-9-1104"]),
        user("persist", sid_history=[f"{DOMAIN_SID}-512"]),
    )
    assert only(snap, "AD-ACC-006").objects == ["ex_admin"]
    f = only(snap, "AD-ACC-007")
    assert f.severity is Severity.HIGH
    assert f.objects == ["migrated", "persist"]
    assert "persist" in f.detail and "migrated" not in f.detail


def test_forest_admin_groups_dns_admins_pre2k() -> None:
    admin = user("Administrator")
    snap = snapshot(
        admin,
        privileged={"Domain Admins": [admin.dn], "Schema Admins": [admin.dn]},
        dns_admins=[admin.dn],
        pre2k_members=["CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=lab,DC=test"],
    )
    assert only(snap, "AD-PRIV-003").objects == ["Schema Admins: Administrator"]
    assert only(snap, "AD-PRIV-004").objects == ["Administrator"]
    assert only(snap, "AD-PRIV-005").objects == ["Anonymous Logon"]


def test_infrastructure_checks() -> None:
    snap = snapshot(
        recycle_bin=False, ds_heuristics="00000020000000010", ldap_signing_required=False
    )
    snap.policy.functional_level = 6
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-INF-002"].severity is Severity.LOW
    assert "2012 R2" in found["AD-INF-003"].detail
    assert found["AD-INF-004"].severity is Severity.HIGH
    assert "AdminSDHolder" in found["AD-INF-004"].detail
    assert "AD-INF-005" in found


def test_trusts() -> None:
    snap = snapshot(
        trusts=[
            Trust("ext.test", 3, 2, 0),
            Trust("safe-ext.test", 3, 2, 0x4),
            Trust("inbound-only.test", 1, 2, 0),
            Trust("forest.test", 3, 2, 0x8 | 0x40 | 0x800),
            # TGT delegation matters on the inbound side only
            Trust("outbound-forest.test", 2, 2, 0x8 | 0x800),
            Trust("child.lab.test", 3, 2, 0x20),
        ]
    )
    assert only(snap, "AD-INF-006").objects == [
        "ext.test (external, SID filtering disabled)",
        "forest.test (forest, SID history enabled)",
        "forest.test (forest, TGT delegation enabled)",
    ]


def test_esc5_9_13_15() -> None:
    snap = snapshot(
        acls={
            "PKI:NTAuthCertificates": [Ace(HELPDESK, sd.WRITE_DAC)],
            "PKI:CA lab-CA": [
                Ace(f"{DOMAIN_SID}-517", sd.GENERIC_ALL),
                Ace(f"{DOMAIN_SID}-1000", sd.GENERIC_ALL),  # the CA server itself
            ],
        },
        principals={HELPDESK: "helpdesk", f"{DOMAIN_SID}-1000": "CA01$"},
        ca_hosts=["CA01$"],
        templates=[
            template("T9", no_security_extension=True),
            template("T13", issuance_policies=["1.2.3"]),
            template(
                "T15", schema_version=1, enrollee_supplies_subject=True, ekus=["1.3.6.1.5.5.7.3.1"]
            ),
        ],
        oid_group_links={"1.2.3": "CN=Tier0Linked,DC=lab,DC=test"},
    )
    found = {f.check_id: f.objects for f in run_all(snap)}
    assert found["AD-ADCS-005"] == ["NTAuthCertificates (helpdesk)"]
    assert found["AD-ADCS-006"] == ["T9 (enroll: Domain Users)"]
    assert found["AD-ADCS-007"] == ["T13 (enroll: Domain Users)"]
    assert found["AD-ADCS-008"] == ["T15 (enroll: Domain Users)"]


def test_gpo_only_when_linked() -> None:
    from ad_doctor.model import Gpo

    aces = [Ace(HELPDESK, sd.GENERIC_WRITE), Ace(f"{DOMAIN_SID}-512", sd.GENERIC_ALL)]
    snap = snapshot(
        gpos=[Gpo("Linked", "{A}", ["Domain Controllers OU"], aces), Gpo("Off", "{B}", [], aces)],
        principals={HELPDESK: "helpdesk"},
    )
    assert only(snap, "AD-GPO-001").objects == ["Linked -> Domain Controllers OU (helpdesk)"]


def dirty() -> Report:
    snap = snapshot(
        user("legacy", NORMAL | 0x400000),
        user("svc_web", spns=["HTTP/web"]),
        computer("WS9", laps=False),
        templates=[template("Bad<t>", enrollee_supplies_subject=True)],
    )
    return Report(snap, run_all(snap))


def test_score_and_grade() -> None:
    assert Report(snapshot(), []).score == 0
    assert Report(snapshot(), []).grade == "A"
    r = dirty()
    # 3 high (ESC1, AS-REP, the Domain Users -> ESC1 path) x 15 + 2 medium x 6 + 1 low x 2
    assert r.score == 59
    assert r.grade == "D"
    assert r.category_scores()["Certificate services"] == 15
    assert r.category_scores()["Attack paths"] == 15


def test_renderers() -> None:
    r = dirty()
    text = render_text(r)
    assert "risk score 59/100 (grade D)" in text
    html = viewer.render(viewer.viewmodel(r, r.snap, viewer.Options()))
    assert "Bad<t>" not in html  # names only travel inside the escaped, packed payload
    data = decode_payload(html)
    assert r"Bad\u003ct\u003e" in data and "Bad<t>" not in data
    assert "T1558.004" in data  # MITRE IDs are text: the page links nowhere outside itself
    md = render_markdown(r)
    assert "| high | AD-ADCS-001 |" in md
    sarif = json.loads(render_sarif(r))
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == len(REGISTRY)
    assert {x["ruleId"] for x in run["results"]} == {f.check_id for f in r.findings}
    rule = next(x for x in run["tool"]["driver"]["rules"] if x["id"] == "AD-ADCS-001")
    assert rule["properties"]["security-severity"] == "8.0"


def test_accept_file(tmp_path: Path) -> None:
    path = tmp_path / "accept.toml"
    path.write_text(
        '[[accept]]\ncheck = "ad-krb-003"\nobjects = ["svc_web"]\nreason = "vendor"\n'
        "expires = 2030-01-01\n\n"
        '[[accept]]\ncheck = "AD-SEC-001"\nreason = "old"\nexpires = 2020-01-01\n'
    )
    r = dirty()
    kept, accepted, notes = accept.apply(r.findings, accept.load(path), NOW.date())
    assert "AD-KRB-003" not in {f.check_id for f in kept}
    assert accepted[0].objects == ["svc_web"]
    assert "AD-SEC-001" in {f.check_id for f in kept}
    assert notes == ["acceptance of AD-SEC-001 expired on 2020-01-01"]


def test_accept_file_errors(tmp_path: Path) -> None:
    path = tmp_path / "accept.toml"
    path.write_text('[[accept]]\ncheck = "AD-KRB-003"\nexpires = "soon"\n')
    with pytest.raises(accept.AcceptError, match="missing reason"):
        accept.load(path)


def test_fix_script_is_guarded() -> None:
    r = dirty()
    script = render_fixes(r.findings, r.snap)
    assert "Set-ADAccountControl 'legacy' -DoesNotRequirePreAuth $false -WhatIf" in script
    for line in script.splitlines():
        if line and not line.startswith("#"):
            assert line.endswith("-WhatIf"), line


_PS_QUOTE = "'‘’‚‛"


def _outside_literals(line: str) -> str:
    """The parts of a PowerShell line outside single-quoted (verbatim) strings, by
    PowerShell's rules: any of the five quote characters opens or closes one, and two in a
    row inside it stand for one quote."""
    out, i, n = [], 0, len(line)
    while i < n:
        if line[i] in _PS_QUOTE:
            i += 1
            while i < n:
                if line[i] in _PS_QUOTE:
                    if i + 1 < n and line[i + 1] in _PS_QUOTE:
                        i += 2
                        continue
                    break
                i += 1
            else:
                raise AssertionError(f"unterminated literal: {line}")
            i += 1
        else:
            out.append(line[i])
            i += 1
    return "".join(out)


@pytest.mark.parametrize(
    "name",
    [
        "x’+$(calc.exe)+’u",
        "x‘;calc.exe;‘",
        "x‚$(calc.exe)‛",
        "y$(calc.exe)`\"z'",
        "a'';calc.exe;''$",
        "p*)(calc=1",
    ],
)
def test_fix_lines_keep_hostile_names_inside_literals(name: str) -> None:
    from ad_doctor.fixes import FIXES, snippet
    from ad_doctor.model import Finding

    snap = dirty().snap
    for check_id in FIXES:
        objects = [name, f"{name} -> ctx (more)", f"Group: {name}"]
        f = Finding(check_id, "t", Severity.HIGH, "d", "r", objects=objects)
        for line in snippet(f, snap):
            if line.startswith("#"):
                continue
            rest = _outside_literals(line)
            assert "calc" not in rest, (check_id, line)
            assert '"' not in rest and "`" not in rest, (check_id, line)
    priv7 = snippet(Finding("AD-PRIV-007", "t", Severity.HIGH, "d", "r", objects=["p*)(x$"]), snap)
    assert "-LDAPFilter '(sAMAccountName=p\\2a\\29\\28x$)'" in priv7[0]


def write_snapshot(path: Path, *accounts: object) -> None:
    path.write_text(json.dumps(snapshot(*accounts).to_json()))  # type: ignore[arg-type]


def test_diff_and_baseline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    write_snapshot(old, user("legacy", NORMAL | 0x400000), user("bob", NORMAL | 0x20))
    write_snapshot(new, user("legacy", NORMAL | 0x400000), user("eve", NORMAL | 0x400000))

    assert main(["diff", str(old), str(new), "--fail-on", "high"]) == 2
    out = capsys.readouterr().out
    assert "1 new, 1 resolved" in out
    assert "+ [HIGH  ] AD-KRB-002  eve" in out
    assert "- [MEDIUM] AD-ACC-001  bob" in out

    # with a baseline only new findings gate the exit code
    report = tmp_path / "report.json"
    assert main(["analyze", str(old), "-f", "json", "-o", str(report)]) == 0
    assert main(["analyze", str(old), "--baseline", str(report), "--fail-on", "low"]) == 0
    assert main(["analyze", str(new), "--baseline", str(report), "--fail-on", "high"]) == 2
    data = json.loads(report.read_text())
    assert data["grade"] in "ABCDF" and data["findings"][0]["mitre"]


def test_cli_writes_outputs(tmp_path: Path) -> None:
    snap_path = tmp_path / "snap.json"
    write_snapshot(snap_path, user("legacy", NORMAL | 0x400000))
    for fmt in ("html", "markdown", "sarif", "json"):
        out = tmp_path / f"r.{fmt}"
        assert main(["analyze", str(snap_path), "-f", fmt, "-o", str(out)]) == 0
        assert out.stat().st_size > 200
    fixes = tmp_path / "fix.ps1"
    assert main(["analyze", str(snap_path), "--fixes", str(fixes)]) == 0
    assert "-WhatIf" in fixes.read_text()


def test_cli_reports_bad_accept_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, bad = tmp_path / "snap.json", tmp_path / "a.toml"
    write_snapshot(snap_path)
    bad.write_text("not toml [")
    assert main(["analyze", str(snap_path), "--accept", str(bad)]) == 1
    assert "ad-doctor:" in capsys.readouterr().err


def test_expired_today_boundary() -> None:
    entries = [accept.Entry("AD-SEC-001", set(), "r", NOW.date())]
    snap = snapshot(computer("WS9", laps=False))
    kept, accepted, _ = accept.apply(run_all(snap), entries, NOW.date())
    assert kept == [] and accepted
    kept, _, notes = accept.apply(run_all(snap), entries, NOW.date() + timedelta(days=1))
    assert kept and notes
