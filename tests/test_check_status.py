"""Per-check status: judged, not applicable, or not evaluated with the reason."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from xml.etree import ElementTree

import pytest

from ad_doctor import checks, coverage, report, trend, viewer
from ad_doctor.checks import REGISTRY, run_all
from ad_doctor.cli import main
from ad_doctor.collect import Collector, Target
from ad_doctor.model import CaConfig, DcProbe, Probes, Snapshot, Trust
from ad_doctor.report import Accepted, Report, render_junit, render_sarif

from .test_checks import NOW, computer, snapshot, user
from .test_gpo_local import gpo

UAC_DONT_PREAUTH = 0x400200
REGISTERED = {c.id for c in REGISTRY}


def status(snap: Snapshot, **kw: object) -> dict[str, coverage.CheckStatus]:
    return Report(snap, run_all(snap), **kw).statuses()  # type: ignore[arg-type]


def one(note: str, check_id: str) -> coverage.CheckStatus:
    return status(snapshot(notes=[note]))[check_id]


# --- every note the collector writes feeds the status --------------------------------------

SYSVOL = sorted(coverage.SYSVOL_CHECKS)
LOCAL = sorted(coverage.LOCAL_GROUP_CHECKS)
POL = sorted(coverage.REGISTRY_POL_CHECKS)
FILES = sorted(coverage.POLICY_FILE_CHECKS)
CA = sorted(coverage.CA_CONFIG_CHECKS)
DC_PROBES = ["AD-INF-005", "AD-INF-008", "AD-INF-009", "AD-INF-010"]
NOTES: list[tuple[str, list[str], str]] = [
    # the collector's own wording, one row per place that writes a note
    ("SYSVOL not checked: needs credentials", SYSVOL, coverage.UNREADABLE),
    ("SYSVOL not checked: connection refused", SYSVOL, coverage.UNREADABLE),
    ("SYSVOL not checked by choice: AD-GPP-001 did not judge it", SYSVOL, coverage.SWITCHED_OFF),
    ("SYSVOL files not readable by this account: a, b", SYSVOL, coverage.UNREADABLE),
    (r"Policies\{1}\Machine\Preferences\Groups\Groups.xml: malformed XML, not evaluated", LOCAL,
     coverage.UNREADABLE),
    ("2 GPOs set local groups in the user context (User\\Preferences\\Groups), not evaluated: a",
     LOCAL, coverage.UNREADABLE),
    ("local group settings in GPOs reaching read-only DCs are not evaluated: x", LOCAL,
     coverage.UNREADABLE),
    ("GPO group-membership or remote logon settings name principals that could not be "
     "resolved: a", LOCAL, coverage.UNREADABLE),
    ("2 GPOs set registry values through Preferences (Machine\\Preferences\\Registry): "
     "AD-GPO-009 to -012 do not evaluate them, and they can change what Registry.pol sets: a",
     POL, coverage.UNREADABLE),
    (r"Policies\{1}\Machine\Registry.pol: over 8192 bytes, not evaluated", POL,
     coverage.UNREADABLE),
    (r"Policies\{1}\Machine\Registry.pol: not a valid Registry.pol (x), not evaluated", POL,
     coverage.UNREADABLE),
    ("Registry.pol files not readable by this account: a", POL, coverage.UNREADABLE),
    ("AD-GPO-009, AD-GPO-010, AD-GPO-011 and AD-GPO-012 (registry policy) not judged: SYSVOL "
     "was not read", POL, coverage.UNREADABLE),
    (r"Policies\{1}\Machine\microsoft\windows nt\Audit\audit.csv: over 8192 bytes, not evaluated",
     FILES, coverage.UNREADABLE),
    (r"Policies\{1}\Machine\Preferences\Registry\Registry.xml: over 8192 bytes, not evaluated",
     FILES, coverage.UNREADABLE),
    (r"Policies\{1}\audit.csv: not a valid audit.csv (x), not evaluated", FILES,
     coverage.UNREADABLE),
    (r"Policies\{1}\Registry.xml: not valid Registry.xml (x), not evaluated", FILES,
     coverage.UNREADABLE),
    ("audit.csv or Registry.xml not readable by this account: a", FILES, coverage.UNREADABLE),
    ("GPO from another domain linked at OU=x: not evaluated",
     sorted(coverage.GPO_APPLIED_CHECKS), coverage.UNREADABLE),
    ("CA configuration (ESC6, ESC7, ESC11, ESC16, audit filter) not read: --no-ca-registry", CA,
     coverage.SWITCHED_OFF),
    ("CA configuration (ESC6, ESC7, ESC11, ESC16, audit filter) not read: --no-probes", CA,
     coverage.SWITCHED_OFF),
    ("CA configuration (ESC6, ESC7, ESC11, ESC16, audit filter) not read: needs credentials", CA,
     coverage.UNREADABLE),
    ("CA configuration on ca01 not read: access denied", CA, coverage.UNREADABLE),
    ("x on ca01 uses the policy module y: ESC6 and ESC16 not judged",
     ["AD-ADCS-012", "AD-ADCS-015", "AD-CHAIN-004"], coverage.UNREADABLE),
    ("LDAP signing and channel binding not probed: they need a DOMAIN\\user account with a "
     "password (NTLM)", ["AD-CHAIN-001", "AD-INF-005", "AD-INF-010"], coverage.UNREADABLE),
    ("dc01: LDAP signing probe inconclusive: busy", ["AD-INF-005"], coverage.UNREADABLE),
    ("dc01: LDAP signing probe failed: timed out", ["AD-INF-005"], coverage.UNREADABLE),
    ("LDAP signing not probed by choice: AD-INF-005 did not judge it", ["AD-INF-005"],
     coverage.SWITCHED_OFF),
    ("SMB probes did not run: no SMB connection to the DC", ["AD-INF-008", "AD-INF-009"],
     coverage.UNREADABLE),
    ("dc01: not probed (refused)", DC_PROBES, coverage.UNREADABLE),
    ("enrollment URL http://[x not probed: not a valid URL", ["AD-ADCS-019"], coverage.UNREADABLE),
    ("http://ca/certsrv not probed: refused", ["AD-ADCS-010", "AD-CHAIN-003"],
     coverage.UNREADABLE),
    ("https://ca/certsrv not probed: refused", ["AD-ADCS-019"], coverage.UNREADABLE),
    ("HTTPS enrollment endpoints not probed by choice: AD-ADCS-019 did not judge them",
     ["AD-ADCS-019"], coverage.SWITCHED_OFF),
    ("web enrollment not probed by choice: AD-ADCS-010 and AD-CHAIN-003 did not judge it",
     ["AD-ADCS-010", "AD-CHAIN-003"], coverage.SWITCHED_OFF),
    ("SMB, Print Spooler and channel binding probes not run by choice: AD-INF-008, AD-INF-009, "
     "AD-INF-010 and AD-INF-013 did not judge them",
     ["AD-INF-008", "AD-INF-009", "AD-INF-010", "AD-INF-013"], coverage.SWITCHED_OFF),
    ("3 fine-grained password policy links: only the first 50 checked for their group type",
     ["AD-POL-003"], coverage.UNREADABLE),
    ("x: msDS-AllowedToActOnBehalfOfOtherIdentity could not be parsed: its resource-based "
     "delegation edges are not in the control graph", ["AD-PATH-001"], coverage.UNREADABLE),
    ("snapshot from an older version: the resource-based delegation edges of the control graph "
     "not evaluated", ["AD-PATH-001"], coverage.OLDER_SNAPSHOT),
    ("snapshot from an older version: AD-GPO-009, AD-GPO-010, AD-GPO-011, AD-GPO-012 (registry "
     "policy) not evaluated", POL, coverage.OLDER_SNAPSHOT),
    ("snapshot from an older version: AD-INF-016 and the AES part of AD-INF-015 not evaluated",
     ["AD-INF-015", "AD-INF-016"], coverage.OLDER_SNAPSHOT),
    ("snapshot from an older version: whether a dMSA was visible is not recorded, so AD-INF-007 "
     "may not have seen existing dMSA links", ["AD-INF-007"], coverage.OLDER_SNAPSHOT),
    ("dSHeuristics not readable: AD-INF-004 not judged", ["AD-INF-004"], coverage.UNREADABLE),
    ("search (objectClass=groupPolicyContainer) under CN=Policies,CN=System,DC=x failed: refused",
     sorted(coverage.ALL_GPO_CHECKS), coverage.UNREADABLE),
    ("search (objectClass=*) under CN=Certificate Templates,CN=Public Key Services,x failed: no",
     sorted(coverage.ALL_ADCS_CHECKS), coverage.UNREADABLE),
    ("search (objectClass=trustedDomain) under CN=System,DC=x failed: refused",
     sorted(coverage.TRUST_CHECKS), coverage.UNREADABLE),
]  # fmt: skip


@pytest.mark.parametrize(("note", "ids", "reason"), NOTES, ids=[n[:40] for n, _, _ in NOTES])
def test_every_collection_note_feeds_the_status(note: str, ids: list[str], reason: str) -> None:
    assert sorted(coverage.note_checks(note)) == sorted(ids)
    got = status(snapshot(notes=[note]))
    for check_id in ids:
        assert got[check_id].status == coverage.NOT_EVALUATED, check_id
        assert got[check_id].reason == reason
        assert note in got[check_id].notes


def test_rules_only_name_registered_checks() -> None:
    named = {i for _, ids in coverage.NOTE_RULES for i in ids}
    named |= {i for ids, _, _ in coverage.DATA_GAPS for i in ids}
    named |= {i for _, ids in coverage._NOT_APPLICABLE_NOTES for i in ids}
    assert named <= REGISTERED, named - REGISTERED


@pytest.mark.parametrize(
    "note",
    [
        "x: member has more values than one LDAP page",
        "forest root SID not readable; root admins may be reported",
        "dangling gPLink at x: y does not exist",
        "acceptance of AD-KRB-001 matches no finding any more (stale)",
        "acceptance of AD-KRB-001 expired on 2026-01-01",
        "no GPO reaching a DC sets VulnerableChannelAllowList; a value set in a DC's own "
        "registry cannot be seen by this scan (AD-GPO-008)",
    ],
)
def test_notes_that_hold_no_check_back(note: str) -> None:
    assert coverage.note_checks(note) == []


def test_a_note_written_by_the_acceptance_file_leaves_the_check_judged() -> None:
    got = one("acceptance of AD-KRB-001 matches no finding any more (stale)", "AD-KRB-001")
    assert got.status == coverage.JUDGED and got.outcome == "no_finding"


def test_no_sysvol_turns_the_sysvol_notes_into_switched_off() -> None:
    got = status(
        snapshot(
            notes=[
                "SYSVOL not checked by choice: AD-GPP-001 did not judge it",
                "AD-GPO-008 (Netlogon allow list) not judged: SYSVOL was not read",
            ]
        )
    )
    assert got["AD-GPO-008"].reason == coverage.SWITCHED_OFF


def test_an_unattributed_failed_search_makes_the_score_a_minimum() -> None:
    note = "search (objectClass=foo) under DC=x failed: busy"
    assert coverage.unattributed([note]) == [note]
    summary = coverage.summary(status(snapshot()), [note])
    assert summary["score_is_minimum"] and summary["unattributed_notes"] == [note]


# --- the collector's switches now say what they did ---------------------------------------


def test_no_sysvol_leaves_a_note_naming_what_it_skipped() -> None:
    c = Collector(None, Target("h", sysvol=False))  # type: ignore[arg-type]
    c._sysvol("lab.test", [])
    assert any("by choice" in n and "AD-GPP-001" in n for n in c.notes)


def test_no_probes_says_what_it_skipped() -> None:
    c = Collector(None, Target("h", probes=False, plain_port=0))  # type: ignore[arg-type]
    c.ca_dns_hosts = ["ca01"]
    c._probes("dc01", [])
    assert any("AD-INF-008" in n and "by choice" in n for n in c.notes)
    assert any("AD-ADCS-010" in n and "by choice" in n for n in c.notes)
    assert c._ca_configs("dc01") == []
    assert any("--no-probes" in n for n in c.notes)


def test_http_port_zero_says_web_enrollment_was_not_judged() -> None:
    c = Collector(None, Target("h", http_port=0, plain_port=0, all_dcs=False))  # type: ignore[arg-type]
    c.ca_dns_hosts = ["ca01"]
    c._probe_dc = lambda *_: DcProbe("x")  # type: ignore[assignment,method-assign]
    c._probes("dc01", [])
    assert any("AD-ADCS-010" in n for n in c.notes)


# --- gaps without a note ------------------------------------------------------------------


def _probed() -> Probes:
    return Probes(smb_signing_required=True, spooler_on_dc=False,
                  ldaps_channel_binding_required=True)  # fmt: skip


def test_a_probe_that_holds_none_is_not_evaluated() -> None:
    got = status(snapshot())
    for check_id in ("AD-INF-005", "AD-INF-008", "AD-INF-009", "AD-INF-010", "AD-INF-013"):
        assert got[check_id].status == coverage.NOT_EVALUATED, check_id
        assert got[check_id].reason == coverage.UNREADABLE


def test_a_probe_with_an_answer_is_judged() -> None:
    snap = snapshot(probes=_probed(), ldap_signing_required=True)
    got = status(snap)
    for check_id in ("AD-INF-005", "AD-INF-008", "AD-INF-009", "AD-INF-010"):
        assert got[check_id].status == coverage.JUDGED, check_id


def test_the_relay_chain_needs_the_probes_only_when_anyone_can_join_computers() -> None:
    assert status(snapshot())["AD-CHAIN-001"].status == coverage.JUDGED
    quota = replace(snapshot().policy, machine_account_quota=10)
    assert status(snapshot(policy=quota))["AD-CHAIN-001"].status == coverage.NOT_EVALUATED


def test_an_unread_recycle_bin_backup_and_krbtgt_date_are_not_evaluated() -> None:
    k = user("krbtgt")
    k.pwd_last_set = None
    k.pwd_changed = None
    snap = snapshot(accounts=[k], recycle_bin=None, backup_checked=False)
    got = status(snap)
    for check_id in ("AD-INF-002", "AD-INF-011", "AD-KRB-001"):
        assert got[check_id].status == coverage.NOT_EVALUATED, check_id


def test_cas_without_a_configuration_leave_the_ca_checks_not_evaluated() -> None:
    got = status(snapshot(ca_hosts=["CA01$"]))
    for check_id in coverage.CA_CONFIG_CHECKS:
        assert got[check_id].status == coverage.NOT_EVALUATED


def test_a_ca_that_did_not_answer_for_one_setting_holds_back_that_check_only() -> None:
    ca = CaConfig(name="c", host="ca01", edit_flags=0, interface_flags=None, owner="S-1-5-18",
                  disabled_extensions=[])  # fmt: skip
    snap = snapshot(ca_hosts=["CA01$"], probes=Probes(ca_configs=[ca]))
    got = status(snap)
    assert got["AD-ADCS-014"].status == coverage.NOT_EVALUATED
    assert got["AD-ADCS-012"].status == coverage.JUDGED


def test_sysvol_never_read_holds_back_what_depends_on_it() -> None:
    got = status(snapshot(gpos=[gpo("x", "{1}")]))
    for check_id in coverage.SYSVOL_CHECKS:
        assert got[check_id].status == coverage.NOT_EVALUATED, check_id


# --- how the status is decided -------------------------------------------------------------


def test_a_finding_wins_and_counts_as_partial() -> None:
    bad = user("legacy", UAC_DONT_PREAUTH)
    snap = snapshot(bad, notes=["x: AD-KRB-002 did not judge the rest"])
    got = status(snap)["AD-KRB-002"]
    assert got.status == coverage.JUDGED and got.outcome == "finding" and got.partial
    assert got.to_json()["partial"] is True and got.reason == coverage.UNREADABLE


def test_an_accepted_check_is_judged() -> None:
    snap = snapshot()
    r = Report(snap, [], accepted=[Accepted("AD-KRB-001", ["krbtgt"], "why", "2030-01-01")])
    got = r.statuses()["AD-KRB-001"]
    assert got.status == coverage.JUDGED and got.outcome == "accepted"


def test_only_marks_the_rest_switched_off() -> None:
    r = Report(snapshot(), [], ran=["AD-KRB-001"])
    got = r.statuses()
    assert got["AD-KRB-002"].status == coverage.NOT_EVALUATED
    assert got["AD-KRB-002"].reason == coverage.SWITCHED_OFF
    assert got["AD-KRB-001"].status == coverage.JUDGED


def test_a_check_with_a_note_is_not_evaluated_even_when_it_does_not_apply() -> None:
    snap = snapshot(notes=["AD CS not installed", "CA configuration on x not read: y"])
    got = status(snap)
    assert got["AD-ADCS-001"].status == coverage.NOT_APPLICABLE
    assert got["AD-ADCS-012"].status == coverage.NOT_EVALUATED


def test_no_ad_cs_is_not_applicable_with_the_note_as_the_reason() -> None:
    got = status(snapshot(notes=["AD CS not installed"]))
    assert got["AD-ADCS-001"].status == coverage.NOT_APPLICABLE
    assert got["AD-ADCS-001"].notes == ["AD CS not installed"]
    assert got["AD-CHAIN-004"].status == coverage.NOT_APPLICABLE


def test_no_enterprise_ca_leaves_the_template_checks_judged() -> None:
    got = status(snapshot(notes=["no enterprise CA found, so no template is published"]))
    assert got["AD-ADCS-012"].status == coverage.NOT_APPLICABLE
    assert got["AD-ADCS-001"].status == coverage.JUDGED


def test_no_trusts_is_not_applicable_and_a_trust_makes_them_judged() -> None:
    assert status(snapshot())["AD-INF-015"].status == coverage.NOT_APPLICABLE
    trust = Trust("other.test", 2, 2, 8, 0, None)
    got = status(snapshot(trusts=[trust], trust_details_checked=True))
    assert got["AD-INF-015"].status == coverage.JUDGED


def test_dmsa_checks_do_not_apply_without_a_2025_dc() -> None:
    level = replace(snapshot().policy, functional_level=7)
    dc = computer("dc01", 0x2000, os="Windows Server 2019 Standard")
    got = status(snapshot(accounts=[dc], policy=level))
    assert got["AD-ACL-009"].status == coverage.NOT_APPLICABLE
    hidden = computer("dc01", 0x2000, os=None)
    got = status(snapshot(accounts=[hidden], policy=level))
    assert got["AD-ACL-009"].status == coverage.JUDGED


def test_older_snapshot_reports_the_reason() -> None:
    data = snapshot().to_json()
    del data["psos_checked"]
    got = status(Snapshot.from_json(data))["AD-POL-003"]
    assert got.status == coverage.NOT_EVALUATED and got.reason == coverage.OLDER_SNAPSHOT


# --- never passed anywhere -----------------------------------------------------------------


def _unknown_only() -> Snapshot:
    return snapshot(notes=["dSHeuristics not readable: AD-INF-004 not judged"])


def test_json_carries_the_status_and_says_the_score_is_a_minimum() -> None:
    data = report.report_dict(Report(_unknown_only(), []))
    row = next(r for r in data["check_status"] if r["id"] == "AD-INF-004")
    assert row["status"] == "not_evaluated" and row["reason"] == "unreadable"
    assert row["notes"] == ["dSHeuristics not readable: AD-INF-004 not judged"]
    cov = data["coverage"]
    assert cov["score_is_minimum"] is True and cov["not_evaluated"] >= 1
    assert data["score"] == 0  # no number is made up for what was not judged


def test_every_check_has_a_status_with_a_known_value() -> None:
    rows = report.report_dict(Report(snapshot(), []))["check_status"]
    assert [r["id"] for r in rows] == sorted(REGISTERED)
    assert {r["status"] for r in rows} <= {"judged", "not_applicable", "not_evaluated"}
    for r in rows:
        assert (r["status"] == "not_evaluated") == ("reason" in r)


def test_text_and_markdown_do_not_read_as_clean() -> None:
    r = Report(_unknown_only(), [])
    text = report.render_text(r)
    assert "No findings in the checks judged." in text and "No findings.\n" not in text
    assert "a minimum:" in text and "not evaluated (data unreadable):" in text
    assert "AD-INF-004" in text
    md = report.render_markdown(r)
    assert "## Check status" in md and "a minimum:" in md
    assert "| AD-INF-004 |" in md and "data unreadable" in md


def test_a_failed_search_with_no_check_still_makes_the_text_a_minimum() -> None:
    snap = snapshot(notes=["search (objectClass=foo) under DC=x failed: busy"])
    text = report.render_text(Report(snap, [], recorded={}))
    assert "a minimum: a failed search" in text and "No findings.\n" not in text


def test_text_says_no_findings_only_when_nothing_was_held_back() -> None:
    r = Report(snapshot(), [], recorded={})
    assert "No findings.\n" in report.render_text(r)


def test_markdown_escapes_a_directory_name_in_the_status() -> None:
    r = Report(snapshot(notes=["<b>|x: AD-INF-004 not judged"]), [])
    md = report.render_markdown(r)
    line = next(x for x in md.splitlines() if x.startswith("| AD-INF-004"))
    assert "\\<b>\\|x" in line


def test_junit_marks_it_skipped_and_never_green() -> None:
    root = ElementTree.fromstring(render_junit(Report(_unknown_only(), [])))
    case = next(c for c in root if c.attrib["name"].startswith("AD-INF-004"))
    skipped = case.find("skipped")
    assert skipped is not None and "not evaluated: data unreadable" in skipped.attrib["message"]


def test_junit_without_a_list_shows_a_switched_off_check_as_skipped() -> None:
    root = ElementTree.fromstring(render_junit(Report(snapshot(), [], ran=["AD-KRB-001"])))
    names = {c.attrib["name"].split()[0]: c for c in root}
    assert len(names) == len(REGISTERED)
    assert names["AD-KRB-002"].find("skipped") is not None


def test_junit_counts_not_applicable_as_skipped() -> None:
    root = ElementTree.fromstring(render_junit(Report(snapshot(notes=["AD CS not installed"]), [])))
    case = next(c for c in root if c.attrib["name"].startswith("AD-ADCS-001"))
    skipped = case.find("skipped")
    assert skipped is not None and skipped.attrib["message"].startswith("not applicable")


def test_sarif_carries_the_status_on_rules_and_as_notifications() -> None:
    run = json.loads(render_sarif(Report(_unknown_only(), [])))["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["AD-INF-004"]["properties"]["status"] == "not_evaluated"
    assert rules["AD-INF-004"]["properties"]["statusReason"] == "unreadable"
    assert rules["AD-KRB-002"]["properties"]["status"] == "judged"
    notes = run["invocations"][0]["toolExecutionNotifications"]
    hit = next(n for n in notes if n["associatedRule"]["id"] == "AD-INF-004")
    assert hit["level"] == "warning"
    assert run["properties"]["coverage"]["score_is_minimum"] is True
    assert run["results"] == []  # a check without an answer never becomes a result


def test_the_viewer_gets_the_status_and_counts() -> None:
    vm = viewer.viewmodel(Report(_unknown_only(), []), _unknown_only(), viewer.Options())
    assert vm["coverage"]["score_is_minimum"] is True
    assert any(r["id"] == "AD-INF-004" for r in vm["check_status"])


def test_a_finding_from_a_check_not_evaluated_is_not_resolved_in_the_viewer() -> None:
    bad = user("legacy", UAC_DONT_PREAUTH)
    old = run_all(snapshot(bad))
    opts = viewer.Options(baseline=viewer.Baseline(old, None, "old.json"))
    snap = snapshot(notes=["x: AD-KRB-002 not judged"])
    vm = viewer.viewmodel(Report(snap, run_all(snap)), snap, opts)
    assert vm["baseline"]["resolved"] == []
    assert [r["id"] for r in vm["baseline"]["not_evaluated"]] == ["AD-KRB-002"]


def _write(tmp_path: Path, name: str, snap: Snapshot) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(snap.to_json()))
    return path


def test_diff_does_not_resolve_what_the_newer_run_could_not_judge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = user("legacy", UAC_DONT_PREAUTH)
    old = _write(tmp_path, "old.json", snapshot(bad))
    new = _write(tmp_path, "new.json", snapshot(notes=["x: AD-KRB-002 not judged"]))
    assert main(["diff", str(old), str(new), "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["resolved"] == []
    assert data["not_evaluated"] == [{"id": "AD-KRB-002", "object": "legacy"}]
    assert main(["diff", str(old), str(new)]) == 0
    text = capsys.readouterr().out
    assert "0 resolved, 1 not evaluated in the newer run" in text and "? [" in text


def test_diff_between_reports_uses_their_recorded_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def write(name: str, snap: Snapshot) -> Path:
        path = tmp_path / name
        path.write_text(report.render_json(Report(snap, run_all(snap))))
        return path

    old = write("old.json", snapshot(user("legacy", UAC_DONT_PREAUTH)))
    new = write("new.json", snapshot(notes=["x: AD-KRB-002 not judged"]))
    assert main(["diff", str(old), str(new), "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["resolved"] == []


def test_an_acceptance_of_a_check_not_evaluated_is_not_stale(tmp_path: Path) -> None:
    snap = _write(tmp_path, "s.json", _unknown_only())
    accept = tmp_path / "a.toml"
    accept.write_text('[[accept]]\ncheck = "AD-INF-004"\nreason = "x"\nexpires = 2030-01-01\n')
    out = tmp_path / "r.json"
    assert main(["analyze", str(snap), "--accept", str(accept), "-f", "json", "-o", str(out)]) == 0
    assert not any("stale" in n for n in json.loads(out.read_text())["notes"])


def test_an_acceptance_of_a_judged_check_with_no_finding_is_still_stale(tmp_path: Path) -> None:
    snap = _write(tmp_path, "s.json", snapshot())
    accept = tmp_path / "a.toml"
    accept.write_text('[[accept]]\ncheck = "AD-KRB-002"\nreason = "x"\nexpires = 2030-01-01\n')
    out = tmp_path / "r.json"
    assert main(["analyze", str(snap), "--accept", str(accept), "-f", "json", "-o", str(out)]) == 0
    assert any("stale" in n for n in json.loads(out.read_text())["notes"])


def _report_data(**extra: object) -> dict[str, object]:
    data = {"tool": "ad-doctor", "collected_at": NOW.isoformat(), "version": "x", "score": 0,
            "findings": [], "domain": "lab.test"}  # fmt: skip
    return {**data, **extra}


def test_trend_keeps_exposure_unknown_when_the_path_check_was_not_evaluated() -> None:
    rows = [{"id": "AD-PATH-001", "status": "not_evaluated"}]
    assert trend.point(_report_data(check_status=rows), "x")["exposed"] is None
    assert trend.point(_report_data(), "x")["exposed"] == 0


def test_trend_marks_a_change_in_what_was_not_evaluated() -> None:
    a = trend.point(_report_data(check_status=[]), "a")
    later = (NOW + timedelta(days=1)).isoformat()
    rows = [{"id": "AD-INF-004", "status": "not_evaluated"}]
    b = trend.point(_report_data(check_status=rows, collected_at=later), "b")
    built = trend.build([a], b)
    assert built["markers"][0]["notes"] == ["not evaluated +1"]
    assert built["points"][-1]["not_evaluated"] == 1


def test_view_of_a_report_keeps_its_recorded_status(tmp_path: Path) -> None:
    snap = snapshot(notes=["AD CS not installed"])
    rep = tmp_path / "r.json"
    rep.write_text(report.render_json(Report(snap, [])))
    data = json.loads(rep.read_text())
    recorded = coverage.from_report(data)
    assert recorded is not None and recorded["AD-ADCS-001"].status == coverage.NOT_APPLICABLE
    # the trust checks need a snapshot to say so, and the report remembers it
    assert recorded["AD-INF-015"].status == coverage.NOT_APPLICABLE
    out = tmp_path / "v.html"
    assert main(["view", str(rep), "-o", str(out)]) == 0


def test_older_report_falls_back_to_its_notes() -> None:
    snap = snapshot(notes=["dSHeuristics not readable: AD-INF-004 not judged"])
    got = Report(snap, [], from_snapshot=False).statuses()
    assert got["AD-INF-004"].status == coverage.NOT_EVALUATED
    # no snapshot behind it, so nothing can be said from the data
    assert got["AD-INF-008"].status == coverage.JUDGED


def test_status_does_not_change_the_findings() -> None:
    snap = snapshot(user("legacy", UAC_DONT_PREAUTH), notes=["AD CS not installed"])
    before = [(f.check_id, f.objects) for f in run_all(snap)]
    Report(snap, run_all(snap)).statuses()
    assert before == [(f.check_id, f.objects) for f in run_all(snap)]


def test_ca_unjudged_is_what_ad_adcs_016_reports() -> None:
    ca = CaConfig(name="c", host="ca01", edit_flags=0, interface_flags=None, owner="S-1-5-18",
                  disabled_extensions=[])  # fmt: skip
    assert checks.ca_unjudged(ca) == [("InterfaceFlags", "ESC11")]
