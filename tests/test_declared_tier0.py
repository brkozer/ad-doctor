"""Declared tier 0: two sets kept apart, the label on every path, "not evaluated" when
the snapshot holds no DACL for the asset, and one implementation with what-if."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ad_doctor import collect, declared, paths, sd
from ad_doctor.checks import run_all
from ad_doctor.cli import main
from ad_doctor.model import DirObject, Snapshot
from ad_doctor.report import Report, render_markdown, render_text
from ad_doctor.resolve import SpecError
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_SID
from .test_checks import computer, user
from .test_round3 import DA, HELPDESK, path_snapshot

JUMP = f"{DOMAIN_SID}-2000"
SERVICE = f"{DOMAIN_SID}-2001"
OUTSIDER = f"{DOMAIN_SID}-1801"
MARK = paths.DECLARED_MARK
COMPUTERS = "CN=Computers,DC=lab,DC=test"


def declared_snapshot(collected: bool = True) -> Snapshot:
    """path_snapshot plus JUMP01$, a server `outsider` has full control of, and svc_other,
    a user. `outsider` has no path to built-in tier 0."""
    snap = path_snapshot()
    jump = computer("JUMP01", sid=JUMP)
    snap.accounts += [jump, user("svc_other", sid=SERVICE)]
    if collected:
        aces = [Ace(OUTSIDER, sd.GENERIC_ALL), Ace(DA, sd.GENERIC_ALL)]
        snap.objects.append(DirObject(jump.dn, jump.sam, "computer", JUMP, DA, aces))
    snap.principals[OUTSIDER] = "outsider"
    return snap


def write(tmp_path: Path, snap: Snapshot, *names: str) -> tuple[str, str]:
    snap_path, file_path = tmp_path / "snap.json", tmp_path / "tier0.toml"
    snap_path.write_text(json.dumps(snap.to_json()))
    file_path.write_text("tier0 = [" + ", ".join(json.dumps(n) for n in names) + "]\n")
    return str(snap_path), str(file_path)


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main([*argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> dict[str, Any]:
    code, out, err = run(capsys, *argv, "-f", "json")
    assert code in (0, 2), err
    data: dict[str, Any] = json.loads(out)
    return data


def asset(d: declared.Declaration, name: str) -> declared.Asset:
    return next(a for a in d.assets if a.name == name)


def report_of(d: dict[str, Any]) -> dict[str, Any]:
    finding: dict[str, Any] = next(f for f in d["findings"] if f["id"] == "AD-PATH-001")
    return finding


# --- the file --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("tier0 = [", "tier0.toml"),
        ('assets = ["x"]', "unknown key 'assets'"),
        ('tier0 = "JUMP01$"', "must be a list"),
        ("tier0 = [1]", "must be a list"),
        ('tier0 = [""]', "must be a list"),
    ],
)
def test_a_bad_file_is_refused_with_its_name(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "tier0.toml"
    path.write_text(text)
    with pytest.raises(declared.DeclaredError, match=message):
        declared.load_file(path)


def test_a_missing_file_and_a_binary_file_are_refused(tmp_path: Path) -> None:
    with pytest.raises(declared.DeclaredError, match="absent"):
        declared.load_file(tmp_path / "absent.toml")
    binary = tmp_path / "bad.toml"
    binary.write_bytes(b"tier0 = \xff\xfe")
    with pytest.raises(declared.DeclaredError, match="bad"):
        declared.load_file(binary)


def test_a_name_the_snapshot_does_not_hold_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "nobody")
    code, _, err = run(capsys, "analyze", snap, "--tier0-file", file)
    assert code == 1 and "no 'nobody' in this snapshot" in err


# --- two sets --------------------------------------------------------------------------


def test_without_a_declaration_nothing_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, _ = write(tmp_path, declared_snapshot(), "JUMP01$")
    report = run_json(capsys, "analyze", snap)
    assert "declared_tier0" not in report
    f = report_of(report)
    assert "declared_paths" not in f["data"] and "declared" not in json.dumps(f)


def test_built_in_paths_and_other_checks_do_not_move(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$", "helpdesk")
    plain = run_json(capsys, "analyze", snap)
    extended = run_json(capsys, "analyze", snap, "--tier0-file", file)
    a, b = report_of(plain), report_of(extended)
    assert b["data"]["paths"] == a["data"]["paths"]
    assert (b["data"]["exposed"], b["data"]["users"]) == (a["data"]["exposed"], a["data"]["users"])
    assert [o for o in b["objects"] if not o.endswith(MARK)] == a["objects"]
    others = [f for f in plain["findings"] if f["id"] != "AD-PATH-001"]
    assert [f for f in extended["findings"] if f["id"] != "AD-PATH-001"] == others


def test_a_declared_group_does_not_become_an_allowed_holder() -> None:
    """Being declared must not silence a finding that names the principal: the checks read
    the built-in set only."""
    snap = declared_snapshot()
    before = {f.check_id: f.objects for f in run_all(snap)}
    d = declared.declare(snap, [("t", ["helpdesk", "IT"])])
    with paths.lend(snap, d.graph, d.analysis):
        after = {f.check_id: f.objects for f in run_all(snap)}
    assert "IT" in d.graph.name(f"sid:{DOMAIN_SID}-1700")
    del before["AD-PATH-001"], after["AD-PATH-001"]
    assert after == before


def test_every_path_says_which_set_it_ends_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    report = run_json(capsys, "analyze", snap, "--tier0-file", file)
    f = report_of(report)
    extended = [o for o in f["objects"] if o.endswith(MARK)]
    assert extended == [f"outsider -[full control]-> JUMP01${MARK}"]
    assert f["keys"][extended[0]] == "declared:outsider"
    assert all(not p["object"].endswith(MARK) for p in f["data"]["paths"])
    record = f["data"]["declared_paths"][0]
    assert record["object"] == extended[0] and record["steps"][-1]["declared"] is True
    assert record["steps"][-1]["tier0"] is False
    assert "Declared tier 0 (not built-in): 1 principals" in f["detail"]
    row = report["declared_tier0"]["assets"][0]
    assert (row["name"], row["set"], row["status"], row["principals"]) == (
        "JUMP01$", "declared", "evaluated", 1,
    )  # fmt: skip


def test_the_finding_exists_when_only_a_declared_target_is_reached(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = declared_snapshot()
    for o in snap.objects:
        if o.name == "IT":
            o.aces = []
    snap_path, file = write(tmp_path, snap, "JUMP01$")
    assert "AD-PATH-001" not in {
        f["id"] for f in run_json(capsys, "analyze", snap_path)["findings"]
    }
    f = report_of(run_json(capsys, "analyze", snap_path, "--tier0-file", file))
    assert f["objects"] == [f"outsider -[full control]-> JUMP01${MARK}"]
    assert f["severity"] == "high" and f["data"]["paths"] == []


def test_a_name_already_built_in_stays_built_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "Domain Admins")
    report = run_json(capsys, "analyze", snap, "--tier0-file", file)
    row = report["declared_tier0"]["assets"][0]
    assert (row["set"], row["status"]) == ("built-in", "evaluated") and "principals" not in row
    assert not [o for o in report_of(report)["objects"] if o.endswith(MARK)]


def test_paths_through_built_in_tier0_are_not_counted_again() -> None:
    snap = declared_snapshot()
    d = declared.declare(snap, [("t", ["JUMP01$"])])
    assert d.analysis.declared is not None
    starts = {d.graph.name(p.start) for p in d.analysis.declared.paths}
    assert starts == {"outsider"}  # Domain Admins hold it too, and are tier 0


def test_a_declared_asset_on_a_longer_chain_counts_for_both_targets() -> None:
    """Per asset, a route through another declared asset still counts."""
    snap = declared_snapshot()
    other = user("svc_other", sid=SERVICE)
    snap.objects.append(
        DirObject(other.dn, "svc_other", "user", SERVICE, DA, [Ace(JUMP, sd.GENERIC_ALL)])
    )
    d = declared.declare(snap, [("t", ["JUMP01$", "svc_other"])])
    reach = d.analysis.declared
    assert reach is not None
    assert reach.principals[f"sid:{SERVICE}"] >= reach.principals[f"sid:{JUMP}"] > 0
    assert not {d.graph.name(p.start) for p in reach.paths} & {"JUMP01$", "svc_other"}


# --- not evaluated ---------------------------------------------------------------------


def test_no_dacl_means_not_evaluated_not_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(collected=False), "JUMP01$")
    report = run_json(capsys, "analyze", snap, "--tier0-file", file)
    row = report["declared_tier0"]["assets"][0]
    assert row["status"] == "not_evaluated" and "not in this snapshot" in row["reason"]
    assert [n for n in report["notes"] if n.startswith("declared tier 0: JUMP01$")]
    status = next(s for s in report["check_status"] if s["id"] == "AD-PATH-001")
    assert status.get("partial") or status["status"] == "not_evaluated"


def test_no_finding_and_no_dacl_is_not_passed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = declared_snapshot(collected=False)
    for o in snap.objects:
        if o.name == "IT":
            o.aces = []
    snap_path, file = write(tmp_path, snap, "JUMP01$")
    report = run_json(capsys, "analyze", snap_path, "--tier0-file", file)
    assert "AD-PATH-001" not in {f["id"] for f in report["findings"]}
    status = next(s for s in report["check_status"] if s["id"] == "AD-PATH-001")
    assert status["status"] == "not_evaluated"


def test_an_unreadable_dacl_is_not_evaluated_either() -> None:
    snap = declared_snapshot()
    jump = next(o for o in snap.objects if o.sid == JUMP)
    jump.owner, jump.aces = None, []
    d = declared.declare(snap, [("t", ["JUMP01$"])])
    a = asset(d, "JUMP01$")
    assert a.status == declared.NOT_EVALUATED and a.reason == declared.UNREADABLE
    assert d.notes == [
        "declared tier 0: JUMP01$: not evaluated, its owner and DACL could not be read when the "
        "snapshot was collected; AD-PATH-001 did not judge who controls it directly, and shows "
        "only the paths that need no DACL of its own"
    ]


def test_paths_without_its_dacl_are_still_shown_with_the_status() -> None:
    """A right inherited from the container needs no DACL of the asset: real, but the
    asset stays not evaluated, so the count is a floor."""
    snap = declared_snapshot(collected=False)
    inherit = Ace(OUTSIDER, sd.GENERIC_ALL)
    snap.objects.append(
        DirObject(
            COMPUTERS, "Computers", "container", owner=DA, aces=[inherit], inheritable=[inherit]
        )
    )
    d = declared.declare(snap, [("t", ["JUMP01$"])])
    assert d.analysis.declared is not None
    assert [p.render(d.graph) for p in d.analysis.declared.paths] == [
        f"outsider -[full control (inherited)]-> JUMP01${MARK}"
    ]
    assert asset(d, "JUMP01$").status == declared.NOT_EVALUATED


# --- commands --------------------------------------------------------------------------


def test_paths_text_json_mermaid_and_chokepoints_label_the_declared_set(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(collected=False), "JUMP01$")
    _, text, _ = run(capsys, "paths", snap, "--tier0-file", file)
    assert "not evaluated: its owner and DACL are not in this snapshot" in text
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    _, text, _ = run(capsys, "paths", snap, "--tier0-file", file)
    assert "declared tier 0 (extended targets" in text and text.rstrip().endswith(MARK.strip())
    data = run_json(capsys, "paths", snap, "--tier0-file", file)
    assert data["declared_paths"][0]["object"].endswith(MARK)
    assert data["declared_paths"][0]["steps"][0]["changes"]
    assert data["declared_tier0"]["paths"] == 1 and not data["paths"][0]["object"].endswith(MARK)
    _, mermaid, _ = run(capsys, "paths", snap, "--tier0-file", file, "-f", "mermaid")
    assert "declared tier 0" in mermaid
    _, points, _ = run(capsys, "paths", snap, "--chokepoints", "--tier0-file", file)
    assert "1 paths to declared tier 0" in points
    data = run_json(capsys, "paths", snap, "--chokepoints", "--tier0-file", file)
    assert data["declared_paths"] == 1 and data["declared_chokepoints"] == []


def test_the_notes_of_a_mermaid_diagram_go_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(collected=False), "JUMP01$")
    _, out, err = run(capsys, "paths", snap, "--tier0-file", file, "-f", "mermaid")
    assert "not evaluated" in err and "note:" not in out


def test_the_flag_and_the_file_add_up(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "svc_other")
    report = run_json(capsys, "analyze", snap, "--tier0", "JUMP01$", "--tier0-file", file)
    rows = report["declared_tier0"]["assets"]
    assert {(r["name"], r["source"]) for r in rows} == {
        ("JUMP01$", "--tier0"),
        ("svc_other", "tier0.toml"),
    }


def test_text_and_markdown_say_it(tmp_path: Path) -> None:
    snap = declared_snapshot()
    d = declared.declare(snap, [("t.toml", ["JUMP01$"])])
    with paths.lend(snap, d.graph, d.analysis):
        report = Report(snap, run_all(snap), declared=d.summary())
    text = render_text(report)
    assert "declared tier 0 (extended targets" in text and "1 principals have a path" in text
    md = render_markdown(report)
    assert "## Declared tier 0" in md and "built-in tier 0 is unchanged" in md


def test_an_accepted_declared_path_leaves_the_data_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    accept = tmp_path / "accept.toml"
    accept.write_text(
        '[[accept]]\ncheck = "AD-PATH-001"\nobjects = ["declared:outsider"]\n'
        'reason = "known"\nexpires = 2099-01-01\n'
    )
    report = run_json(capsys, "analyze", snap, "--tier0-file", file, "--accept", str(accept))
    f = report_of(report)
    assert f["data"]["declared_paths"] == [] and not [o for o in f["objects"] if o.endswith(MARK)]


def test_a_baseline_snapshot_gets_the_same_declaration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    report = run_json(capsys, "analyze", snap, "--tier0-file", file, "--baseline", snap)
    assert report_of(report)["new"] is False


def test_a_name_missing_from_the_baseline_is_not_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old = path_snapshot()
    old_path = tmp_path / "old.json"
    old_path.write_text(json.dumps(old.to_json()))
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    report = run_json(capsys, "analyze", snap, "--tier0-file", file, "--baseline", str(old_path))
    assert report_of(report)["new"] is True


def test_view_labels_paths_and_lists_the_assets(tmp_path: Path) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$", "svc_other")
    page = tmp_path / "page.html"
    assert (
        main(
            ["view", snap, "--tier0-file", file, "--no-encrypt", "--graph", "none", "-o", str(page)]
        )
        == 0
    )
    from .viewer_fixtures import decode_payload

    vm = json.loads(decode_payload(page.read_text(encoding="utf-8")))
    rows = vm["paths"]["list"]
    assert [r.get("declared", False) for r in rows].count(True) == 1
    assert [a["status"] for a in vm["declared_tier0"]["assets"]] == ["evaluated", "not_evaluated"]
    last = rows[-1]["steps"][-1]["node"]
    assert vm["paths"]["nodes"][last]["declared"] is True
    assert "--tier0-file tier0.toml" in vm["meta"]["command"]


def test_view_of_a_report_keeps_it_and_refuses_a_new_declaration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    report_path = tmp_path / "report.json"
    assert main(["analyze", snap, "--tier0-file", file, "-f", "json", "-o", str(report_path)]) == 0
    capsys.readouterr()
    page = tmp_path / "r.html"
    assert main(["view", str(report_path), "--no-encrypt", "-o", str(page)]) == 0
    from .viewer_fixtures import decode_payload

    vm = json.loads(decode_payload(page.read_text(encoding="utf-8")))
    assert vm["declared_tier0"]["paths"] == 1
    capsys.readouterr()
    code, _, err = run(capsys, "view", str(report_path), "--tier0-file", file, "--no-encrypt")
    assert code == 1 and "need a snapshot" in err


# --- one implementation with what-if ---------------------------------------------------


def test_plan_takes_the_file_and_marks_what_it_treats_as_tier0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    doc = run_json(capsys, "plan", snap, "--tier0-file", file)
    assert doc["assumptions"] == [
        {"node": f"sid:{JUMP}", "name": "JUMP01$", "source": "tier0.toml"}
    ]
    assert doc["before"]["holders"] or doc["before"]["exposed"]
    assert MARK in json.dumps(doc["paths"]) or doc["after"]["exposed"] == 0


def test_exposure_counts_the_same_in_paths_and_in_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    data = run_json(capsys, "paths", snap, "--tier0-file", file)
    doc = run_json(capsys, "plan", snap, "--tier0-file", file)
    assert data["declared_tier0"]["exposed_with_declared"] == doc["before"]["exposed"]
    assert data["declared_tier0"]["users_with_declared"] == doc["before"]["users"]


def test_whatif_says_not_evaluated_for_the_same_asset(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, file = write(tmp_path, declared_snapshot(collected=False), "JUMP01$")
    doc = run_json(capsys, "whatif", snap, "--tier0-file", file, "--paths-only")
    assert doc["assumptions"][0]["status"] == "not_evaluated"
    assert [n for n in doc["notes"] if "JUMP01$: not evaluated" in n]
    _, text, _ = run(capsys, "whatif", snap, "--tier0-file", file, "--paths-only")
    assert "JUMP01$ (tier0.toml, not evaluated)" in text


def test_the_tier0_flag_of_whatif_goes_through_the_same_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, _ = write(tmp_path, declared_snapshot(collected=False), "JUMP01$")
    doc = run_json(capsys, "whatif", snap, "--tier0", "JUMP01$", "--paths-only")
    assert doc["assumptions"][0]["status"] == "not_evaluated"
    code, _, err = run(capsys, "whatif", snap, "--tier0", "nobody", "--paths-only")
    assert code == 1 and "no 'nobody' in this snapshot" in err


def test_nodes_raises_on_a_missing_name_and_skips_it_when_lenient() -> None:
    from ad_doctor.resolve import Resolver

    snap = declared_snapshot()
    resolver = Resolver(snap, paths.build(snap, provenance=True))
    with pytest.raises(SpecError):
        declared.nodes(resolver, ["nobody"])
    assert declared.nodes(resolver, ["nobody", "JUMP01$", "JUMP01$"], lenient=True) == [
        f"sid:{JUMP}"
    ]


# --- collection ------------------------------------------------------------------------


class Recorder(collect.Collector):
    """Records the BASE reads of `_objects` and returns nothing else."""

    def __init__(self, target: collect.Target) -> None:
        super().__init__(None, target)  # type: ignore[arg-type]
        self.reads: list[tuple[str, list[str]]] = []

    def search(self, *a: Any, **k: Any) -> list[dict[str, list[Any]]]:
        return []

    def optional(
        self, base: str, flt: str, attrs: list[str], **kw: Any
    ) -> list[dict[str, list[Any]]]:
        self.reads.append((base, attrs))
        return []


def test_collect_reads_the_dacl_of_declared_accounts_only() -> None:
    plain, jump, svc = (
        user("plain", sid="S-1"),
        computer("JUMP01", sid="S-2"),
        user("svc", sid="S-3"),
    )
    by_sid = user("bysid", sid=f"{DOMAIN_SID}-77")
    c = Recorder(collect.Target("h", declared_tier0=["jump01", svc.dn, f"{DOMAIN_SID}-77"]))
    c._objects("DC=lab,DC=test", [plain, jump, svc, by_sid], set())
    read = [(b, a) for b, a in c.reads if b in (plain.dn, jump.dn, svc.dn, by_sid.dn)]
    assert sorted(b for b, _ in read) == sorted([jump.dn, svc.dn, by_sid.dn])
    assert all("nTSecurityDescriptor" in a and collect.REPL_METADATA not in a for _, a in read)
    assert jump.pwd_changed is None and not c.pwd_unread


def test_collect_reads_nothing_more_without_a_declaration() -> None:
    plain = user("plain", sid="S-1")
    c = Recorder(collect.Target("h"))
    c._objects("DC=lab,DC=test", [plain], set())
    assert plain.dn not in {b for b, _ in c.reads}


def test_scan_gives_the_names_to_the_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path, file = write(tmp_path, declared_snapshot(), "JUMP01$")
    seen: list[collect.Target] = []

    def fake(target: collect.Target) -> Snapshot:
        seen.append(target)
        return declared_snapshot()

    monkeypatch.setattr("ad_doctor.cli.collect", fake)
    code, out, err = run(capsys, "scan", "dc", "--tier0-file", file, "-f", "json")
    assert code == 0, err
    assert seen[0].declared_tier0 == ["JUMP01$"]
    assert json.loads(out)["declared_tier0"]["assets"][0]["status"] == "evaluated"
    assert (tmp_path / "snap.json").read_text() and snap_path


def test_a_bad_file_fails_before_any_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "t.toml").write_text("nope = 1")

    def fail(target: collect.Target) -> Snapshot:
        raise AssertionError("connected")

    monkeypatch.setattr("ad_doctor.cli.collect", fail)
    code, _, err = run(
        capsys,
        "collect",
        "dc",
        "-o",
        str(tmp_path / "o.json"),
        "--tier0-file",
        str(tmp_path / "t.toml"),
    )
    assert code == 1 and "unknown key" in err


def test_a_note_about_helpdesk_keeps_its_owner_sid_valid() -> None:
    """The fixture's helpdesk has rights through IT, so its own path stays built-in."""
    snap = declared_snapshot()
    d = declared.declare(snap, [("t", ["JUMP01$"])])
    assert any(p.start == f"sid:{HELPDESK}" for p in d.analysis.paths)
