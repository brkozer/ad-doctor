"""Regression tests for the review of tier-0 logon rights, silos, declared tier 0 and the
per-check status: what is unknown stays unknown, and a comparison says why it changed."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from ad_doctor import coverage, declared, gpo_scope, paths, redact, report, sd, viewer
from ad_doctor.checks import REGISTRY, hidden_tier0, run_all
from ad_doctor.cli import main
from ad_doctor.collect import Collector
from ad_doctor.gpo_scope import DENY_LOGON_RIGHTS
from ad_doctor.model import (
    SILO_LEVEL,
    DirObject,
    GpoSettings,
    Severity,
    Snapshot,
    UnreadableMember,
)
from ad_doctor.report import Report
from ad_doctor.resolve import Resolver, SpecError

from .test_checks import ids, only, snapshot
from .test_declared_tier0 import JUMP, MARK, declared_snapshot
from .test_gpo_local import HEAD, LAB
from .test_tiering import (
    CONFIG,
    DA,
    DENY_ALL,
    DOM,
    POLICIES,
    SILOS,
    StubCollector,
    admin,
    domain_admins,
    gpo,
    member,
    policy,
    raw,
    silo,
    silo_routes,
    silo_snap,
    world,
)
from .viewer_fixtures import decode_payload

ADMINISTRATORS = "S-1-5-32-544"
EA = f"{DOM}-519"
HIDDEN = f"CN=veiled,OU=Veiled,{HEAD}"
RBCD_NOTE = (
    "snapshot from an older version: the resource-based delegation edges of the control graph "
    "not evaluated"
)
FAILED_SEARCH = "search CN=Foo,DC=example,DC=test failed: insufficientAccessRights"


def status_of(snap: Snapshot) -> dict[str, coverage.CheckStatus]:
    return coverage.compute(snap, [f.check_id for f in run_all(snap)])


def write(tmp_path: Path, name: str, data: Any) -> str:
    path = tmp_path / name
    text = report.render_json(data) if isinstance(data, Report) else json.dumps(data.to_json())
    path.write_text(text)
    return str(path)


def json_of(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    code = main([*argv, "-f", "json"])
    data: dict[str, Any] = json.loads(capsys.readouterr().out)
    return code, data


# --- T1: Administrators in a deny right, on a member computer ---------------------------------


def _deny_world(deny: list[str], *extra: DirObject, **privileged: Any) -> Snapshot:
    made, settings = gpo({key: deny for key in DENY_LOGON_RIGHTS}, (LAB, False))
    one, two = admin("admin1", 1500), admin("svc_other", 1501)
    groups = {
        "Domain Admins": [one.dn],
        **{name.replace("_", " "): [two.dn] for name in privileged},
    }
    objects = [domain_admins(one), *extra]
    assert settings is not None
    return snapshot(
        one,
        two,
        member(),
        privileged=groups,
        objects=objects,
        gpos=[made],
        gpo_settings={made.guid: settings},
        logon_rights_collected=True,
        site_count=1,
    )


def _enterprise_admins() -> list[DirObject]:
    two = f"CN=svc_other,CN=Users,{HEAD}"
    ea = DirObject(
        f"CN=Enterprise Admins,CN=Users,{HEAD}", "Enterprise Admins", "group", sid=EA, members=[two]
    )
    domain_administrators = DirObject(
        f"CN=Administrators,CN=Builtin,{HEAD}",
        "Administrators",
        "group",
        sid=ADMINISTRATORS,
        members=[ea.dn, f"CN=Domain Admins,CN=Users,{HEAD}"],
    )
    return [ea, domain_administrators]


def test_a_deny_of_administrators_does_not_cover_enterprise_admins_on_a_member() -> None:
    snap = _deny_world([DA, ADMINISTRATORS], *_enterprise_admins(), Enterprise_Admins=True)
    f = only(snap, "AD-PRIV-013")
    assert f.severity is Severity.MEDIUM
    assert "left out: svc_other" in f.objects[0]


def test_a_deny_of_administrators_alone_covers_domain_admins_and_says_it_assumes_so() -> None:
    snap = _deny_world([ADMINISTRATORS], *_enterprise_admins(), Enterprise_Admins=True)
    f = only(snap, "AD-PRIV-013")
    assert "left out: svc_other" in f.objects[0]
    assert "admin1" not in f.objects[0]
    assert gpo_scope.LOCAL_ADMIN_CAVEAT in f.detail


def test_a_direct_member_of_the_domains_administrators_is_not_in_the_local_group() -> None:
    two = f"CN=svc_other,CN=Users,{HEAD}"
    group = DirObject(
        f"CN=Administrators,CN=Builtin,{HEAD}",
        "Administrators",
        "group",
        sid=ADMINISTRATORS,
        members=[two],
    )
    f = only(_deny_world([ADMINISTRATORS], group, Administrators=True), "AD-PRIV-013")
    assert "left out: svc_other" in f.objects[0]


def test_every_tier0_account_in_domain_admins_is_covered_by_administrators() -> None:
    snap = world(gpo({key: [ADMINISTRATORS] for key in DENY_LOGON_RIGHTS}, (LAB, False)),
                 hosts=(member(),))  # fmt: skip
    assert "AD-PRIV-013" not in ids(run_all(snap))


def test_the_member_token_keeps_only_what_a_join_adds() -> None:
    token = {"S-1-5-32-544", "S-1-5-32-551", EA, "S-1-1-0"}
    assert gpo_scope.member_computer_token(token, DOM) == {EA, "S-1-1-0"}
    assert ADMINISTRATORS in gpo_scope.member_computer_token({DA}, DOM)


def test_the_graph_still_reads_the_same_caveat() -> None:
    assert paths.LOCAL_ADMIN_CAVEAT == gpo_scope.LOCAL_ADMIN_CAVEAT


# --- T2: a tier-0 member the scan could not read ----------------------------------------------


def _hide(snap: Snapshot, group: str = "Domain Admins") -> Snapshot:
    return dataclasses.replace(
        snap, unreadable_members=[UnreadableMember(HIDDEN, group, "not returned")]
    )


def _covered_silo() -> Snapshot:
    a1 = admin()
    return silo_snap(silo(a1), policies=(policy(),))


def test_silo_check_of_a_hidden_tier0_member_is_not_evaluated() -> None:
    assert status_of(_covered_silo())["AD-PRIV-014"].outcome == "no_finding"
    got = status_of(_hide(_covered_silo()))["AD-PRIV-014"]
    assert got.status == coverage.NOT_EVALUATED and got.reason == coverage.UNREADABLE


def test_silo_check_that_fires_with_a_hidden_member_is_partial() -> None:
    got = status_of(_hide(silo_snap()))["AD-PRIV-014"]
    assert got.status == coverage.JUDGED and got.partial


def test_a_hidden_member_of_a_group_outside_the_logon_groups_changes_nothing() -> None:
    assert status_of(_hide(_covered_silo(), "Backup Operators"))["AD-PRIV-014"].outcome == (
        "no_finding"
    )


def test_a_hidden_member_of_a_group_nested_in_domain_admins_counts() -> None:
    nested = DirObject(f"CN=T0,{HEAD}", "T0", "group", sid=f"{DOM}-1600")
    a1 = admin()
    da = dataclasses.replace(domain_admins(a1), members=[a1.dn, nested.dn])
    snap = silo_snap(silo(a1), policies=(policy(),), objects=[da, nested])
    hidden = _hide(snap, "T0")
    assert set(hidden_tier0(hidden)) == {HIDDEN}
    assert status_of(hidden)["AD-PRIV-014"].status == coverage.NOT_EVALUATED


def test_silos_below_the_functional_level_stay_not_applicable() -> None:
    snap = _hide(_covered_silo())
    snap.policy.functional_level = SILO_LEVEL - 1
    assert status_of(snap)["AD-PRIV-014"].status == coverage.NOT_APPLICABLE


def test_a_deny_of_the_group_holding_the_hidden_member_really_covers_it() -> None:
    snap = _hide(world(gpo(DENY_ALL, (LAB, False)), hosts=(member(),)))
    assert status_of(snap)["AD-PRIV-013"].outcome == "no_finding"


def test_a_deny_by_account_says_nothing_about_a_hidden_member() -> None:
    by_account = {key: [f"{DOM}-1500"] for key in DENY_LOGON_RIGHTS}
    snap = _hide(world(gpo(by_account, (LAB, False)), hosts=(member(),)))
    assert "AD-PRIV-013" not in ids(run_all(snap))
    got = status_of(snap)["AD-PRIV-013"]
    assert got.status == coverage.NOT_EVALUATED and got.notes


def test_no_computer_to_judge_leaves_nothing_unknown_about_the_hidden_member() -> None:
    assert status_of(_hide(world()))["AD-PRIV-013"].outcome == "no_finding"


# --- T3, D5: what a declaration can move ------------------------------------------------------


def only_declared() -> Snapshot:
    """`outsider` reaches JUMP01$, and nothing outside tier 0 reaches built-in tier 0."""
    snap = declared_snapshot()
    for o in snap.objects:
        if o.name == "IT":
            o.aces = []
    return snap


def test_a_declaration_raises_the_path_check_and_the_score_where_no_built_in_path_exists(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, "s.json", only_declared())
    plain_code, plain = json_of(capsys, "analyze", path, "--fail-on", "high")
    code, seen = json_of(capsys, "analyze", path, "--tier0", "JUMP01$", "--fail-on", "high")
    assert plain_code == 0 and code == 2
    assert seen["score"] == plain["score"] + 15
    f = next(x for x in seen["findings"] if x["id"] == "AD-PATH-001")
    assert f["objects"] == [f"outsider -[full control]-> JUMP01${MARK}"]
    assert f["data"]["paths"] == [] and f["data"]["exposed"] == 0


def test_where_a_built_in_path_exists_a_declaration_leaves_the_score_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, "s.json", declared_snapshot())
    _, plain = json_of(capsys, "analyze", path)
    _, seen = json_of(capsys, "analyze", path, "--tier0", "JUMP01$")
    assert seen["score"] == plain["score"]
    before = next(x for x in plain["findings"] if x["id"] == "AD-PATH-001")
    after = next(x for x in seen["findings"] if x["id"] == "AD-PATH-001")
    assert len(after["objects"]) == len(before["objects"]) + 1
    assert after["data"]["exposed"] == before["data"]["exposed"]


def test_the_docs_say_what_a_declaration_can_move() -> None:
    root = Path(__file__).parent.parent
    text = " ".join((root / "docs/declared-tier0.md").read_text(encoding="utf-8").split())
    changes = " ".join((root / "CHANGELOG.md").read_text(encoding="utf-8").split())
    assert "Every path and number you get without the file" not in text
    assert "a declaration can raise it: the score goes up by 15" in text
    assert "built-in paths, numbers and every other check" not in changes


# --- T4: which checks a note holds back ---------------------------------------------------------


def test_an_unresolved_deny_name_holds_back_only_the_logon_check() -> None:
    note = (
        "deny logon rights name principals that could not be resolved, so AD-PRIV-013 cannot "
        "judge those rights: OTHER\\tier0"
    )
    assert coverage.note_checks(note) == ["AD-PRIV-013"]


def test_the_local_group_note_still_holds_back_the_local_group_checks() -> None:
    note = (
        "GPO group-membership or remote logon settings name principals that could not be resolved"
    )
    assert set(coverage.note_checks(note)) == set(coverage.LOCAL_GROUP_CHECKS)


# --- T5: a sign-in limit that limits nothing ----------------------------------------------------


@pytest.mark.parametrize(
    ("sddl", "opened"),
    [
        ("O:SYG:SYD:(A;;CR;;;WD)", True),
        ("O:SYG:SYD:(A;;CR;;;AU)", True),
        ("O:SYG:SYD:(A;;GA;;;S-1-1-0)", True),
        ('O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "T0"))', False),
        ("O:SYG:SYD:(A;;CR;;;S-1-5-21-1-2-3-515)", False),
        ("O:SYG:SYD:(D;;CR;;;S-1-5-21-1-2-3-1000)(A;;CR;;;WD)", False),
        ("O:SY", False),
    ],
)
def test_an_unconditional_allow_for_everyone_is_what_opens_a_policy(
    sddl: str, opened: bool
) -> None:
    assert sd.sddl_opens_to_anyone(sddl) is opened


def _collected(sddl: str) -> bool:
    extra = {
        (POLICIES, "(objectClass=msDS-AuthNPolicy)"): [
            raw(
                f"CN=P,{POLICIES}",
                name="P",
                **{
                    "msDS-AuthNPolicyEnforced": "TRUE",
                    "msDS-UserAllowedToAuthenticateFrom": sddl,
                },
            )
        ],
        (SILOS, "(objectClass=msDS-AuthNPolicySilo)"): [raw(f"CN=Tier0,{SILOS}", name="Tier0")],
    }
    collector: Collector = StubCollector(silo_routes(extra=extra))
    _, policies, _ = collector._auth_silos(CONFIG, 10)
    return policies[0].limits_user_from


def test_a_policy_that_allows_everyone_does_not_limit_sign_in() -> None:
    assert not _collected("O:SYG:SYD:(A;;CR;;;WD)")
    assert not _collected("O:SYG:SYD:(A;;CR;;;AU)")
    assert _collected("O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(S-1-5-21-1-2-3-1600)}))")


def test_the_silo_check_fires_on_a_policy_that_does_not_limit() -> None:
    a1 = admin()
    f = only(silo_snap(silo(a1), policies=(policy(limits=False),)), "AD-PRIV-014")
    assert "does not limit where users sign in" in f.objects[0]


# --- T6: a SID the snapshot does not hold -------------------------------------------------------


@pytest.mark.parametrize("sid", ["S-1-5-21-1-2-3-9999", "s-1-oops"])
def test_a_sid_the_snapshot_does_not_hold_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sid: str
) -> None:
    path = write(tmp_path, "s.json", declared_snapshot())
    assert main(["analyze", path, "--tier0", sid, "-f", "json"]) == 1
    assert f"no {sid!r} in this snapshot" in capsys.readouterr().err


def test_a_sid_the_snapshot_holds_is_accepted() -> None:
    snap = declared_snapshot()
    resolver = Resolver(snap, paths.build(snap, provenance=True))
    assert declared.nodes(resolver, [JUMP]) == [f"sid:{JUMP}"]


def test_a_missing_sid_is_skipped_when_lenient() -> None:
    snap = declared_snapshot()
    resolver = Resolver(snap, paths.build(snap, provenance=True))
    assert declared.nodes(resolver, ["S-1-5-21-1-2-3-9999"], lenient=True) == []
    with pytest.raises(SpecError, match="9999"):
        declared.nodes(resolver, ["S-1-5-21-1-2-3-9999"])


# --- D2: an incomplete graph is not a clean one -------------------------------------------------


def _gapped(tmp_path: Path, note: str = RBCD_NOTE) -> str:
    snap = only_declared()
    snap.notes.append(note)
    return write(tmp_path, "gap.json", snap)


def test_paths_says_the_graph_is_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _gapped(tmp_path)
    assert main(["paths", path]) == 0
    out = capsys.readouterr().out
    assert "0 principals reach tier 0" in out
    assert "AD-PATH-001 not evaluated (older snapshot)" in out and "resource-based" in out
    assert main(["paths", path, "--chokepoints"]) == 0
    assert "resource-based" in capsys.readouterr().out
    assert main(["paths", path, "-f", "mermaid"]) == 0
    captured = capsys.readouterr()
    assert "resource-based" in captured.err and "resource-based" not in captured.out


def test_paths_json_carries_the_status_and_notes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, data = json_of(capsys, "paths", _gapped(tmp_path))
    assert code == 0
    assert data["status"] == coverage.NOT_EVALUATED and data["reason"] == coverage.OLDER_SNAPSHOT
    assert data["notes"] == [RBCD_NOTE]


def test_paths_found_on_an_incomplete_graph_are_judged_in_part(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = declared_snapshot()
    snap.notes.append("x$: msDS-AllowedToActOnBehalfOfOtherIdentity could not be parsed: its "
                      "resource-based delegation edges are not in the control graph")  # fmt: skip
    code, data = json_of(capsys, "paths", write(tmp_path, "s.json", snap))
    assert code == 0 and data["status"] == "partial" and data["reason"] == coverage.UNREADABLE


def test_a_complete_graph_adds_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "s.json", only_declared())
    _, data = json_of(capsys, "paths", path)
    assert "notes" not in data and "status" not in data
    assert main(["paths", path]) == 0
    assert "note:" not in capsys.readouterr().out
    assert main(["whatif", path, "--fail-if-exposed", "0"]) == 0
    capsys.readouterr()


def test_the_exposure_gate_cannot_pass_on_an_incomplete_graph(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, doc = json_of(capsys, "whatif", _gapped(tmp_path), "--fail-if-exposed", "0")
    assert code == 2 and not doc["check"]["ok"]
    assert "control graph is incomplete" in doc["check"]["problems"][0]
    assert any("resource-based" in n for n in doc["notes"])
    assert doc["path_check"]["status"] == coverage.NOT_EVALUATED


def test_whatif_without_a_gate_only_notes_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, doc = json_of(capsys, "whatif", _gapped(tmp_path))
    assert code == 0 and doc["check"]["ok"]
    assert any("resource-based" in n for n in doc["notes"])


def test_a_plan_on_an_incomplete_graph_does_not_read_as_nothing_to_do(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["plan", _gapped(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "no closable source reaches tier 0" not in out
    assert "incomplete" in out and "resource-based" in out


def test_a_plan_check_fails_on_an_incomplete_graph(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clean = write(tmp_path, "s.json", only_declared())
    plan = str(tmp_path / "plan.toml")
    assert main(["plan", clean, "-f", "toml", "-o", plan]) == 0
    capsys.readouterr()
    code, doc = json_of(capsys, "whatif", _gapped(tmp_path), "--plan", plan, "--check")
    assert code == 2 and any("control graph is incomplete" in p for p in doc["check"]["problems"])


# --- D3: names that could not be resolved -------------------------------------------------------


def test_redaction_rewrites_an_unresolved_deny_holder_and_its_note() -> None:
    name = "SECRETCO\\TierAdminsZed"
    note = (
        f"deny logon rights name principals that could not be resolved, so AD-PRIV-013 ...: {name}"
    )
    made, _ = gpo(None, (LAB, False))
    snap = world(hosts=(member(),))
    snap.gpos.append(made)
    snap.gpo_settings[made.guid] = GpoSettings(
        privileges={DENY_LOGON_RIGHTS[0]: [name, ADMINISTRATORS]}
    )
    snap.notes.append(note)
    out = redact.redact(snap.to_json(), b"key")
    text = json.dumps(out)
    assert "SECRETCO" not in text and "TierAdminsZed" not in text
    holders = next(iter(v for v in out["gpo_settings"].values() if v["privileges"]))
    assert ADMINISTRATORS in holders["privileges"][DENY_LOGON_RIGHTS[0]]
    assert "AD-PRIV-013" in " ".join(out["notes"])


def test_a_well_known_name_in_a_deny_right_stays_readable() -> None:
    name = "BUILTIN\\Administrators"
    made, _ = gpo(None, (LAB, False))
    snap = world(hosts=(member(),))
    snap.gpos.append(made)
    snap.gpo_settings[made.guid] = GpoSettings(privileges={DENY_LOGON_RIGHTS[0]: [name]})
    out = redact.redact(snap.to_json(), b"key")
    assert name in json.dumps(out["gpo_settings"]).replace("\\\\", "\\")


# --- D4: a check the older run did not evaluate -------------------------------------------------


def _silo_run(checked: bool) -> Snapshot:
    a1 = admin()
    return snapshot(a1, privileged={"Domain Admins": [a1.dn]}, silos_checked=checked)


def test_diff_keeps_a_check_the_older_run_did_not_evaluate_out_of_new(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old, new = (
        write(tmp_path, "o.json", _silo_run(False)),
        write(tmp_path, "n.json", _silo_run(True)),
    )
    code = main(["diff", old, new, "--fail-on", "low"])
    out = capsys.readouterr().out
    assert code == 0
    assert "0 new, 0 resolved, 1 not evaluated in the older run" in out
    assert "AD-PRIV-014" in out
    _, data = json_of(capsys, "diff", old, new)
    assert data["new"] == []
    assert [r["id"] for r in data["not_evaluated_before"]] == ["AD-PRIV-014"]


def test_a_real_new_finding_still_fails_the_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old, new = (
        write(tmp_path, "o.json", _silo_run(True)),
        write(tmp_path, "n.json", _silo_run(True)),
    )
    assert main(["diff", old, new, "--fail-on", "low"]) == 0
    capsys.readouterr()
    empty = dataclasses.replace(_silo_run(True), privileged={})
    old = write(tmp_path, "o2.json", empty)
    assert main(["diff", old, new, "--fail-on", "low"]) == 2
    capsys.readouterr()


def test_baseline_keeps_a_check_it_did_not_evaluate_out_of_new(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old, new = (
        write(tmp_path, "o.json", _silo_run(False)),
        write(tmp_path, "n.json", _silo_run(True)),
    )
    code, data = json_of(capsys, "analyze", new, "--baseline", old, "--fail-on", "low")
    assert code == 0
    f = next(x for x in data["findings"] if x["id"] == "AD-PRIV-014")
    assert f["new"] is False
    assert any("the baseline did not evaluate their check" in n for n in data["notes"])


def test_the_viewer_keeps_it_out_of_new_too() -> None:
    old, new = _silo_run(False), _silo_run(True)
    opts = viewer.Options(
        baseline=viewer.Baseline(run_all(old), None, "o.json", {"AD-PRIV-014"}, set())
    )
    vm = viewer.viewmodel(Report(new, run_all(new)), new, opts)
    assert vm["baseline"]["new"] == []
    assert [r["id"] for r in vm["baseline"]["not_evaluated_before"]] == ["AD-PRIV-014"]


# --- D6: a change in the declaration ------------------------------------------------------------


def _reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
    snap = write(tmp_path, "s.json", only_declared())
    off, on = str(tmp_path / "off.json"), str(tmp_path / "on.json")
    assert main(["analyze", snap, "-f", "json", "-o", off]) == 0
    assert main(["analyze", snap, "--tier0", "JUMP01$", "-f", "json", "-o", on]) == 0
    capsys.readouterr()
    return off, on


def test_a_line_leaving_the_file_does_not_read_as_resolved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    off, on = _reports(tmp_path, capsys)
    assert main(["diff", on, off]) == 0
    out = capsys.readouterr().out
    assert "0 new, 0 resolved, 1 from a changed tier-0 declaration" in out
    assert out.count("~ [HIGH") == 1


def test_a_line_added_to_the_file_does_not_fail_the_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    off, on = _reports(tmp_path, capsys)
    code, data = json_of(capsys, "diff", off, on, "--fail-on", "high")
    assert code == 0 and data["new"] == [] and data["resolved"] == []
    assert data["declaration_changed"][0]["id"] == "AD-PATH-001"


def test_a_path_to_an_asset_both_runs_declared_compares_as_usual(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = only_declared()
    closed = only_declared()
    jump = next(o for o in closed.objects if o.name == "JUMP01$")
    jump.aces = [a for a in jump.aces if a.sid == DA]
    args = ["--tier0", "JUMP01$", "-f", "json"]
    open_at, closed_at = str(tmp_path / "a.json"), str(tmp_path / "b.json")
    assert main(["analyze", write(tmp_path, "a_s.json", snap), *args, "-o", open_at]) == 0
    assert main(["analyze", write(tmp_path, "b_s.json", closed), *args, "-o", closed_at]) == 0
    capsys.readouterr()
    code, data = json_of(capsys, "diff", closed_at, open_at, "--fail-on", "high")
    assert code == 2 and len(data["new"]) == 1 and data["declaration_changed"] == []


def test_baseline_report_with_another_declaration_is_not_new(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    off, _ = _reports(tmp_path, capsys)
    snap = write(tmp_path, "s2.json", only_declared())
    code, data = json_of(
        capsys, "analyze", snap, "--tier0", "JUMP01$", "--baseline", off, "--fail-on", "high"
    )
    assert code == 0
    f = next(x for x in data["findings"] if x["id"] == "AD-PATH-001")
    assert f["new"] is False


def test_a_baseline_snapshot_gets_the_declaration_so_a_new_path_is_new(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    closed = only_declared()
    jump = next(o for o in closed.objects if o.name == "JUMP01$")
    jump.aces = [a for a in jump.aces if a.sid == DA]
    old = write(tmp_path, "o.json", closed)
    new = write(tmp_path, "n.json", only_declared())
    code, data = json_of(
        capsys, "analyze", new, "--tier0", "JUMP01$", "--baseline", old, "--fail-on", "high"
    )
    assert code == 2
    assert next(x for x in data["findings"] if x["id"] == "AD-PATH-001")["new"] is True


# --- D8: the reason of a check newer than the report --------------------------------------------


def _schema2(version: str, checks: list[str]) -> dict[str, Any]:
    snap = snapshot()
    data = report.report_dict(Report(snap, [], ran=checks))
    del data["check_status"], data["coverage"]
    data.update(schema=2, version=version, checks=checks)
    return data


def _full_of(version: tuple[int, ...]) -> list[str]:
    out = []
    for c in REGISTRY:
        entry = report.docs.get(c.id)
        since = entry.since if entry else ""
        if since and since != "unreleased" and tuple(map(int, since.split("."))) <= version:
            out.append(c.id)
    return out


def _statuses(data: dict[str, Any]) -> dict[str, coverage.CheckStatus]:
    return coverage.compute(
        snapshot(), [], ran=data["checks"], use_data=False, version=data["version"]
    )


def test_a_check_newer_than_a_full_report_is_older_not_switched_off() -> None:
    got = _statuses(_schema2("0.2.2", _full_of((0, 2, 2))))["AD-PRIV-013"]
    assert got.status == coverage.NOT_EVALUATED and got.reason == coverage.OLDER_SNAPSHOT
    assert "--only" not in " ".join(got.notes) and "0.2.2" in got.notes[0]


def test_a_real_only_in_an_old_report_stays_switched_off() -> None:
    got = _statuses(_schema2("0.2.2", ["AD-KRB-002"]))["AD-PRIV-013"]
    assert got.reason == coverage.SWITCHED_OFF and got.notes == ["not selected by --only"]


def test_a_schema_2_report_gets_the_reason_in_the_viewer(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_schema2("0.2.2", _full_of((0, 2, 2)))))
    html = tmp_path / "r.html"
    assert main(["view", str(path), "--no-encrypt", "-o", str(html)]) == 0
    vm = json.loads(decode_payload(html.read_text(encoding="utf-8")))
    row = next(r for r in vm["check_status"] if r["id"] == "AD-PRIV-013")
    assert row["reason"] == coverage.OLDER_SNAPSHOT
