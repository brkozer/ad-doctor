"""The whatif and plan commands: naming changes, the plan file and its lifecycle,
--check exit codes, outputs (text, JSON, Markdown, TOML, fix lines) and their wording."""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ad_doctor import changes, fixes, paths, planfile, sd
from ad_doctor.cli import main
from ad_doctor.model import CertTemplate, DirObject, Gmsa, Snapshot
from ad_doctor.resolve import Resolver, SpecError, edge_id, finding_specs, split
from ad_doctor.sd import Ace

from .test_features import _outside_literals
from .test_round3 import path_snapshot
from .test_round4 import entra_snapshot
from .whatif_fixtures import HELPDESK, OPS, TEAM_OU, kitchen_sink, lab_snapshots

ROOT = Path(__file__).resolve().parents[1]


def write(tmp_path: Path, snap: Snapshot, name: str = "snap.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(snap.to_json()))
    return path


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main([*argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    code, out, err = run(capsys, *argv, "-f", "json")
    assert out, err
    return code, json.loads(out)


def resolver(snap: Snapshot) -> Resolver:
    g = paths.build(snap, provenance=True)
    from ad_doctor.checks import run_all

    return Resolver(snap, g, lambda: run_all(snap))


def kinds(r: Resolver, prims: list[int]) -> list[tuple[str, ...]]:
    return [r.prov.prims[p] for p in prims]


# -- naming a change ----------------------------------------------------------------------


def test_split_keeps_quoted_separators() -> None:
    assert split('member:"Domain Admins":grp1') == ["member", "Domain Admins", "grp1"]
    assert split('a->"b:c":d', ("->", ":")) == ["a", "b:c", "d"]
    with pytest.raises(SpecError):
        split('x:"open')


def test_typed_specs_resolve_to_one_change_each() -> None:
    snap = kitchen_sink()
    r = resolver(snap)
    head = snap.domain_dn.lower()
    cases = {
        "adminsdholder:helpdesk": ("adminsdholder-ace", HELPDESK),
        f'member:"Domain Admins":"CN=Nested,{TEAM_OU}"': (
            "member",
            f"cn=domain admins,cn=users,{head}",
            f"cn=nested,{TEAM_OU.lower()}",
        ),
        'template:Esc1:enroll:"Domain Users"': ("template-ace", "Esc1", f"{snap.domain_sid}-513"),
        "template:Esc1:enrollee-supplies-subject": (
            "template-flag",
            "Esc1",
            "enrollee-supplies-subject",
        ),
        "pki:NTAuthCertificates:helpdesk": ("pki-ace", "PKI:NTAuthCertificates", HELPDESK),
        f"inherited-ace:{TEAM_OU}:ops": ("inherited-ace", TEAM_OU.lower(), OPS),
        "gmsa:svc_gmsa:reader": (
            "gmsa-reader",
            f"cn=svc_gmsa,cn=managed service accounts,{head}",
            f"{snap.domain_sid}-1108",
        ),
    }
    for spec, want in cases.items():
        got = r.resolve(spec)
        assert got.status == "applied", (spec, got)
        assert kinds(r, got.prims) == [want], spec


def test_change_id_path_step_edge_and_bundle() -> None:
    snap = path_snapshot()
    r = resolver(snap)
    by_path = r.resolve('path:"Helpdesk"#1')
    assert kinds(r, by_path.prims)[0][0] == "ace" and "step 1 of Helpdesk" in by_path.notes[0]
    cid = changes.change_id(r.prov.prims[by_path.prims[0]])
    assert r.resolve(cid).prims == by_path.prims
    edge = r.resolve('edge:Helpdesk->IT:"write members"')
    assert edge.prims == by_path.prims
    hexid = edge_id(
        paths._sid_node(f"{snap.domain_sid}-1900"),
        paths._sid_node(f"{snap.domain_sid}-1700"),
        "write members",
    )
    assert r.resolve(hexid).prims == by_path.prims
    bundle = r.resolve("all-rights-of:helpdesk")
    assert {r.prov.prims[p][0] for p in bundle.prims} == {"ace"}
    assert r.resolve("c:000000000000").status == "absent"


def test_finding_fingerprints_resolve() -> None:
    from ad_doctor.report import fingerprint

    snap = kitchen_sink()
    r = resolver(snap)
    fp = fingerprint("AD-ACL-002", "helpdesk")
    got = r.resolve(f"fp:{fp}")
    assert kinds(r, got.prims) == [("adminsdholder-ace", HELPDESK)]
    findings = {f.check_id: f for f in r.findings()}
    path = findings["AD-PATH-001"]
    first = fingerprint("AD-PATH-001", path.key(path.objects[0]))
    assert r.resolve(f"fp:{first}#1").prims
    weak = next(f for f in r.findings() if finding_specs(f.check_id, f.objects[0]) is None)
    with pytest.raises(SpecError, match="a setting, not a right"):
        r.resolve(f"fp:{fingerprint(weak.check_id, weak.key(weak.objects[0]))}")


def test_rewrites_are_said() -> None:
    snap = kitchen_sink()
    r = resolver(snap)
    copy = r.resolve(f'ace:"CN=Domain Admins,CN=Users,{snap.domain_dn}":helpdesk')
    assert copy.status == "rewritten"
    assert ("adminsdholder-ace", HELPDESK) in kinds(r, copy.prims)
    assert any("SDProp copy" in n for n in copy.notes)
    inherited = r.resolve(f'ace:"CN=bob,{TEAM_OU}":ops')
    assert inherited.status == "rewritten"
    assert kinds(r, inherited.prims) == [("inherited-ace", TEAM_OU.lower(), OPS)]
    assert any("inherited from" in n for n in inherited.notes)


def test_refusals_and_absent() -> None:
    snap = kitchen_sink()
    r = resolver(snap)
    with pytest.raises(SpecError, match="disable"):
        r.resolve("disable:helpdesk")
    with pytest.raises(SpecError, match="narrowing"):
        r.resolve(f"ace:{TEAM_OU}:ops:reset")
    with pytest.raises(SpecError, match="Administrators"):
        r.resolve('member:Administrators:"Domain Admins"')
    with pytest.raises(SpecError, match="cannot be removed"):
        r.resolve(f'edge:Team->"CN=bob,{TEAM_OU}"')
    with pytest.raises(SpecError, match="unknown kind"):
        r.resolve("nonsense:x")
    absent = r.resolve('member:"Domain Admins":nobody')
    assert absent.status == "absent" and not absent.prims


def test_ambiguous_names_list_the_candidates() -> None:
    snap = kitchen_sink()
    twin = DirObject(
        f"CN=helpdesk,OU=Other,{snap.domain_dn}", "helpdesk", "group", sid=f"{snap.domain_sid}-4000"
    )
    snap.objects.append(twin)
    r = resolver(snap)
    with pytest.raises(SpecError, match="ambiguous"):
        r.resolve("adminsdholder:helpdesk")
    assert r.resolve(f"adminsdholder:{HELPDESK}").prims


# -- the plan file ------------------------------------------------------------------------


HOSTILE = 'x"\\\n\t\r\x01 \ud800y'


def test_plan_file_round_trip_is_byte_identical() -> None:
    plan = planfile.PlanFile(
        domain="lab.test",
        domain_sid="S-1-5-21-1-2-3",
        goal="all-paths",
        tier0=["SYNC01$", HOSTILE.replace("\ud800", "")],
        changes=[
            planfile.entry_for(("member", "cn=g,dc=lab,dc=test", "cn=m,dc=lab,dc=test"), "lbl"),
        ],
        keeps=[
            planfile.Entry(
                {"kind": "ace", "object": "dc=lab,dc=test", "trustee": "S-1-5-21-1-2-3-1137"},
                reason=HOSTILE,
                expires=date(2027, 6, 30),
            )
        ],
        expect={"closes_all": True, "max_exposed_percent": 0, "max_holders": 2},
    )
    plan.changes[0].due = date(2026, 11, 30)
    plan.changes[0].ticket = "OPS-42"
    text = planfile.dumps(plan)
    again = planfile.dumps(planfile.loads(text))
    assert again == text
    assert planfile.loads(text).keeps[0].reason == HOSTILE.replace("\ud800", "�")


def test_plan_file_errors() -> None:
    with pytest.raises(planfile.PlanError, match="keep needs"):
        planfile.loads('[[keep]]\nkind = "owner"\nobject = "cn=x"\n')
    with pytest.raises(planfile.PlanError, match="unknown change kind"):
        planfile.loads('[[change]]\nkind = "teleport"\n')
    with pytest.raises(planfile.PlanError, match="expect"):
        planfile.loads("[expect]\nmax_holders = true\n")


def test_toml_string_matches_the_viewer() -> None:
    js = (ROOT / "src/ad_doctor/viewer_assets/core.js").read_text(encoding="utf-8")
    assert "function tomlString(value)" in js
    assert planfile.toml_string('a"b\\c\nd\x7f') == '"a\\"b\\\\c\\nd\\u007f"'


@pytest.fixture
def lab(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[Path, Path]:
    snap_path = write(tmp_path, kitchen_sink())
    plan_path = tmp_path / "plan.toml"
    code, _, err = run(capsys, "plan", str(snap_path), "-f", "toml", "-o", str(plan_path))
    assert code == 0, err
    return snap_path, plan_path


def test_plan_toml_reproduces_the_numbers(
    lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path, plan_path = lab
    _, planned = run_json(capsys, "plan", str(snap_path))
    code, checked = run_json(capsys, "whatif", str(snap_path), "--plan", str(plan_path), "--check")
    assert code == 0, checked["check"]
    for side in ("before", "after"):
        assert checked[side] == planned[side], side
    assert [c["id"] for c in checked["changes"]] == [c["id"] for c in planned["changes"]]
    assert {s["status"] for s in checked["plan_status"]} == {"open"}


def test_lifecycle_against_a_changed_snapshot(
    lab: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, plan_path = lab
    plan = planfile.load(plan_path)
    assert len(plan.changes) >= 2
    first, second = plan.changes[0], plan.changes[1]
    # the first change made in AD, the second overdue
    snap = kitchen_sink()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    changes.apply(snap, g.prov, [g.prov.index[first.prim]])
    second.due = date(2020, 1, 1)
    # a typo in a third entry, an edited ID in a fourth
    stale = planfile.entry_for(("member", "cn=nope,dc=lab,dc=test", "cn=x,dc=lab,dc=test"))
    edited = planfile.entry_for(plan.changes[-1].prim)
    edited.id = "c:000000000000"
    plan.changes += [stale, edited]
    plan_path.write_text(planfile.dumps(plan))
    newer = write(tmp_path, snap, "newer.json")
    code, doc = run_json(capsys, "whatif", str(newer), "--plan", str(plan_path), "--check")
    status = {s["id"]: s["status"] for s in doc["plan_status"]}
    assert status[first.id] == "done"
    assert status[second.id] == "overdue"
    assert status[stale.id] == "stale"
    assert code == 3
    assert any("was edited" in p for p in doc["check"]["problems"])
    # without --check the same file is reported, not failed
    code, doc = run_json(capsys, "whatif", str(newer), "--plan", str(plan_path))
    assert code == 0


def test_ineffective_change_is_rot(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap = path_snapshot()
    snap_path = write(tmp_path, snap)
    plan_path = tmp_path / "plan.toml"
    r = resolver(snap)
    # outsider has no path: a change on it closes nothing
    extra = DirObject(
        f"CN=Spare,OU=Groups,{snap.domain_dn}", "Spare", "group", sid=f"{snap.domain_sid}-2500"
    )
    extra.members = [f"CN=outsider,CN=Users,{snap.domain_dn}"]
    snap.objects.append(extra)
    snap_path = write(tmp_path, snap)
    r = resolver(snap)
    member = r.resolve(f'member:Spare:"CN=outsider,CN=Users,{snap.domain_dn}"')
    assert member.prims, member
    plan = planfile.PlanFile(snap.domain, snap.domain_sid, goal="exposure")
    plan.changes = [planfile.entry_for(r.prov.prims[member.prims[0]])]
    plan_path.write_text(planfile.dumps(plan))
    code, doc = run_json(capsys, "whatif", str(snap_path), "--plan", str(plan_path), "--check")
    assert doc["plan_status"][0]["status"] == "ineffective"
    assert code == 3


def test_expect_block_and_gates(lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, plan_path = lab
    plan = planfile.load(plan_path)
    keep = plan.changes[:1]
    plan.changes = keep
    plan.expect = {"closes_all": True, "max_exposed_percent": 0, "max_holders": 0}
    plan_path.write_text(planfile.dumps(plan))
    code, doc = run_json(capsys, "whatif", str(snap_path), "--plan", str(plan_path), "--check")
    assert code == 2
    assert any("[expect]" in p for p in doc["check"]["problems"])
    code, _ = run_json(capsys, "whatif", str(snap_path), "--fail-if-exposed", "0")
    assert code == 2


def test_other_domain_is_rot(lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, plan_path = lab
    plan = planfile.load(plan_path)
    plan.domain_sid = "S-1-5-21-9-9-9"
    plan_path.write_text(planfile.dumps(plan))
    code, doc = run_json(capsys, "whatif", str(snap_path), "--plan", str(plan_path), "--check")
    assert code == 3 and "the plan is for" in doc["check"]["problems"][0]


def test_expired_keep_is_a_candidate_again(
    lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path, plan_path = lab
    plan = planfile.load(plan_path)
    first = plan.changes[0]
    plan.keeps = [
        planfile.Entry(dict(first.values), reason="vendor", expires=date(2026, 12, 31)),
    ]
    plan_path.write_text(planfile.dumps(plan))
    _, kept = run_json(capsys, "plan", str(snap_path), "--plan", str(plan_path))
    assert first.id not in [c["id"] for c in kept["changes"]]
    plan.keeps[0].expires = date(2020, 1, 1)
    plan_path.write_text(planfile.dumps(plan))
    _, again = run_json(capsys, "plan", str(snap_path), "--plan", str(plan_path))
    assert first.id in [c["id"] for c in again["changes"]]
    assert any("expired" in n for n in again["notes"])


def test_absent_change_is_an_error_only_when_strict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path = write(tmp_path, kitchen_sink())
    spec = 'member:"Domain Admins":nobody'
    code, doc = run_json(capsys, "whatif", str(snap_path), "--remove", spec)
    assert code == 0 and doc["changes"][0]["status"] == "absent"
    code, _, err = run(capsys, "whatif", str(snap_path), "--remove", spec, "--strict")
    assert code == 1 and "absent" in err


# -- findings ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "clears", "appears"),
    [
        ("adminsdholder:helpdesk", "AD-ACL-002", None),
        ('ace:"CN=Domain Admins,CN=Users,DC=lab,DC=test":helpdesk', "AD-ACL-004", None),
        ('template:Esc1:"Domain Users"', "AD-ADCS-001", None),
        ("pki:NTAuthCertificates:helpdesk", "AD-ADCS-005", None),
        ("ca:lab-CA:officer:ManageCertificates", "AD-ADCS-013", None),
        ("gmsa:svc_gmsa:reader", None, None),
        ('gpo-entry:LabLocalAdmins:S-1-5-32-544:"S-1-5-21-1-2-3-3003"', None, None),
        (f'member:"Domain Admins":"CN=Nested,{TEAM_OU}"', None, "AD-ACC-006"),
    ],
)
def test_findings_table_rows(
    spec: str, clears: str | None, appears: str | None, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    snap_path = write(tmp_path, kitchen_sink())
    code, doc = run_json(capsys, "whatif", str(snap_path), "--remove", spec)
    assert code == 0, doc
    assert doc["changes"][0]["status"] in ("applied", "rewritten"), doc["changes"][0]
    cleared = {r["check"] for r in doc["findings"]["cleared"]}
    new = {r["check"] for r in doc["findings"]["new"]}
    if clears:
        assert clears in cleared, cleared
        assert any(x.startswith(clears) for x in doc["changes"][0]["expected_to_clear"])
    if appears:
        assert appears in new, new


def test_fail_on_a_finding_that_would_appear(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path = write(tmp_path, kitchen_sink())
    spec = f'member:"Domain Admins":"CN=Nested,{TEAM_OU}"'
    code, _ = run_json(capsys, "whatif", str(snap_path), "--remove", spec, "--fail-on", "low")
    assert code == 2


# -- outputs -------------------------------------------------------------------------------


CHANGE_KEYS = {
    "id", "kind", "spec", "label", "class", "cost", "status", "source", "notes", "warnings",
    "edges_removed", "edges_on_paths", "objects_affected", "identity", "fix", "rollback",
    "expected_to_clear",
}  # fmt: skip
TOP_KEYS = {
    "tool", "kind", "schema", "version", "simulated", "snapshot", "changes", "before", "after",
    "paths", "findings", "accounts", "assumptions", "plan_status", "check", "notes",
    "caveats",
}  # fmt: skip


def test_json_keys(lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, plan_path = lab
    _, doc = run_json(capsys, "plan", str(snap_path))
    assert set(doc) == TOP_KEYS | {"steps", "recommendation"}
    assert doc["simulated"] is True and doc["schema"] == 1
    assert set(doc["snapshot"]) == {"domain", "domain_sid", "collected_at", "sha256", "file"}
    assert set(doc["changes"][0]) == CHANGE_KEYS
    assert set(doc["before"]) == {"exposed", "users", "holders", "routes"}
    assert set(doc["paths"]) == {"closed", "rerouted", "open", "unclosable", "new"}
    assert set(doc["findings"]) == {"rechecked", "cleared", "new", "changed", "accepted"}
    assert set(doc["recommendation"]) == {
        "goal", "near", "cost", "changes", "lower_bound", "exact", "proven_minimum",
        "inexact_primitives", "alternatives", "method_order", "budget", "note",
    }  # fmt: skip
    assert set(doc["steps"][0]) == {
        "n", "title", "changes", "exposed_after", "holders_after", "routes_after", "closes",
    }  # fmt: skip
    _, doc = run_json(capsys, "whatif", str(snap_path), "--plan", str(plan_path))
    assert set(doc) == TOP_KEYS


def test_text_markdown_and_ps1(lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, _ = lab
    code, text, _ = run(capsys, "plan", str(snap_path))
    assert code == 0
    assert text.startswith("Plan on the lab.test snapshot of")
    assert "(simulated; AD unchanged)" in text
    assert "proven minimum (for paths ad-doctor sees)" in text
    assert "heuristic" in text and "Caveats:" in text
    _, md, _ = run(capsys, "plan", str(snap_path), "-f", "markdown")
    assert md.startswith("# Plan for lab.test") and "### Step 1:" in md and "Rollback:" in md
    _, ps1, _ = run(capsys, "plan", str(snap_path), "-f", "ps1")
    assert "#Requires -Modules ActiveDirectory" in ps1 and "# --- c:" in ps1
    for line in ps1.splitlines():
        assert not line or line.startswith("#") or line.endswith("-WhatIf"), line
        assert "dsacls" not in line or line.startswith("#")


def test_budget_and_options(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap_path = write(tmp_path, kitchen_sink())
    _, text, _ = run(capsys, "plan", str(snap_path), "--max-changes", "1")
    assert "heuristic, no guarantee" in text
    _, doc = run_json(capsys, "plan", str(snap_path), "--allow", "member")
    assert {c["kind"] for c in doc["changes"]} <= {"member"}
    code, _, err = run(capsys, "plan", str(snap_path), "--allow", "teleport")
    assert code == 1 and "--allow" in err
    _, doc = run_json(capsys, "plan", str(snap_path), "--keep", "adminsdholder:helpdesk")
    assert "adminsdholder-ace" not in {c["kind"] for c in doc["changes"]}
    _, doc = run_json(capsys, "plan", str(snap_path), "--from", "carol")
    assert doc["recommendation"]["goal"] == "from"


def test_sync_server_is_unclosable_with_the_tier0_suggestion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path = write(tmp_path, entra_snapshot(helpdesk_reset=True))
    _, doc = run_json(capsys, "plan", str(snap_path), "--goal", "all-paths")
    unclosable = doc["paths"]["unclosable"]
    assert any("ENTRA01" in u["name"] and "tier 0" in u["suggest"] for u in unclosable)
    msol = f"{entra_snapshot().domain_sid}-1400"
    assert all(c["identity"].get("trustee") != msol for c in doc["changes"])
    _, doc = run_json(capsys, "plan", str(snap_path), "--goal", "all-paths", "--tier0", "ENTRA01$")
    assert not any("ENTRA01" in u["name"] for u in doc["paths"]["unclosable"])


def test_older_snapshot_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap_path = write(tmp_path, kitchen_sink(inherited_bit=False))
    _, doc = run_json(capsys, "plan", str(snap_path))
    assert any("INHERITED_ACE" in n for n in doc["notes"])


def test_paths_json_gains_change_ids_and_chokepoint_ids(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path = write(tmp_path, path_snapshot())
    _, out, _ = run(capsys, "paths", str(snap_path), "-f", "json")
    doc = json.loads(out)
    steps = [s for p in doc["paths"] for s in p["steps"]]
    assert all(re.fullmatch(r"c:[0-9a-f]{12}", c) for s in steps for c in s["changes"])
    assert any(s["changes"] for s in steps)
    member_steps = [s for s in steps if s["how"] == "member of"]
    assert member_steps
    _, out, _ = run(
        capsys, "paths", str(snap_path), "--chokepoints", "--minimum", "1", "-f", "json"
    )
    rows = json.loads(out)["chokepoints"]
    assert all(re.fullmatch(r"edge:[0-9a-f]{12}", r["id"]) for r in rows if r["kind"] == "edge")
    assert all("id" not in r for r in rows if r["kind"] == "node")


WORDS = re.compile(r"\b(fixed|fixes|resolved|secure|safe)\b", re.I)


def test_wording(lab: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, plan_path = lab
    texts = []
    for fmt in ("text", "markdown"):
        texts.append(run(capsys, "plan", str(snap_path), "-f", fmt)[1])
        texts.append(run(capsys, "whatif", str(snap_path), "--plan", str(plan_path), "-f", fmt)[1])
    texts.append((ROOT / "docs/whatif.md").read_text(encoding="utf-8"))
    for text in texts:
        bad = WORDS.findall(text)
        assert not bad, bad
    # "closed" only for holders with no path left
    _, doc = run_json(capsys, "whatif", str(snap_path), "--plan", str(plan_path))
    after = {r["path"]["start"]["id"] for r in doc["paths"]["open"]}
    assert not after & {r["path"]["start"]["id"] for r in doc["paths"]["closed"]}


# -- fix lines with hostile names -----------------------------------------------------------


EVIL = [
    "x’+$(calc.exe)+’u",
    "x‘;calc.exe;‘",
    "y$(calc.exe)`\"z'",
    "a'';calc.exe;''$",
    "Evil\nRemove-ADUser alice -Confirm:$false #`|\r\n" + chr(0x2028) + "x",
]


@pytest.mark.parametrize("name", EVIL)
def test_change_lines_keep_hostile_names_inside_literals(name: str) -> None:
    snap = kitchen_sink()
    evil_ou = DirObject(f"OU={name},{snap.domain_dn}", name, "ou")
    evil_ou.inheritable = [Ace(HELPDESK, sd.GENERIC_ALL, None, None)]
    group = DirObject(f"CN={name},{snap.domain_dn}", name, "group", sid=f"{snap.domain_sid}-4100")
    group.members = [f"CN={name} m,{snap.domain_dn}"]
    snap.objects += [evil_ou, group]
    snap.templates.append(
        CertTemplate(
            name, True, True, False, 0, [], [Ace(HELPDESK, sd.CONTROL_ACCESS, sd.CERT_ENROLL)]
        )
    )
    snap.gmsas.append(Gmsa(name, f"CN={name},{snap.domain_dn}", [HELPDESK, OPS]))
    g = paths.build(snap, provenance=True)
    prov = g.prov
    assert prov is not None
    where = changes.Where(snap, prov)
    head = snap.domain_dn.lower()
    keys = [
        ("inherited-ace", f"ou={name.lower()},{head}", HELPDESK),
        ("member", f"cn={name.lower()},{head}", f"cn={name.lower()} m,{head}"),
        ("template-ace", name, HELPDESK),
        ("template-flag", name, "enrollee-supplies-subject"),
        ("gmsa-reader", f"cn={name.lower()},{head}", OPS),
        ("owner", f"cn={name.lower()},{head}"),
        ("delegation", f"cn={name.lower()},{head}", "constrained:" + name),
        ("gplink", "{X}", f"ou={name.lower()},{head}"),
        ("ca-right", name, HELPDESK, "ManageCA"),
        ("gpo-entry", "{X}", "S-1-5-32-544", HELPDESK),
    ]
    prims = [prov.prim(k) for k in keys]
    facts = changes.facts(snap, prov, where, prims)
    for p in prims:
        lines = fixes.change_lines(facts[p], snap) + fixes.rollback_lines(facts[p], snap)
        assert lines, keys[prims.index(p)]
        for line in lines:
            assert "\n" not in line and "\r" not in line and " " not in line
            if line.startswith("#"):
                continue
            assert line.endswith("-WhatIf"), line
            rest = _outside_literals(line)
            assert "calc" not in rest and "Remove-ADUser" not in rest, line
            assert '"' not in rest and "`" not in rest, line
            assert "dsacls" not in line


def test_ace_lines_remove_the_specific_aces() -> None:
    snap = kitchen_sink()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    where = changes.Where(snap, g.prov)
    p = g.prov.index[("adminsdholder-ace", HELPDESK)]
    lines = fixes.change_lines(changes.facts(snap, g.prov, where, [p])[p], snap)
    assert "RemoveAccessRuleSpecific" in lines[0]
    assert f"'{HELPDESK}'" in lines[0] and f"-eq {sd.GENERIC_ALL}" in lines[0]
    assert lines[0].endswith("Set-Acl -LiteralPath $p -AclObject $a -WhatIf")
    assert any("SDProp removes the copies on" in x for x in lines)


# -- the lab (AD_DOCTOR_WHATIF_SNAPSHOTS) ------------------------------------------------


@pytest.mark.parametrize("path", lab_snapshots(), ids=str)
def test_lab_plan_file_round_trip(
    path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan_path = tmp_path / "plan.toml"
    code, planned = run_json(capsys, "plan", str(path))
    assert code == 0
    assert run(capsys, "plan", str(path), "-f", "toml", "-o", str(plan_path))[0] == 0
    code, checked = run_json(capsys, "whatif", str(path), "--plan", str(plan_path), "--check")
    assert code == 0, checked["check"]
    assert checked["before"] == planned["before"] and checked["after"] == planned["after"]
    text = plan_path.read_text(encoding="utf-8")
    assert planfile.dumps(planfile.loads(text)) == text
    _, ps1, _ = run(capsys, "plan", str(path), "-f", "ps1")
    for line in ps1.splitlines():
        assert not line or line.startswith("#") or line.endswith("-WhatIf"), line


def test_accepted_findings_are_kept_and_left_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path = write(tmp_path, kitchen_sink())
    accepted = tmp_path / "accept.toml"
    accepted.write_text(
        '[[accept]]\ncheck = "AD-ACL-002"\nobjects = ["helpdesk"]\n'
        'reason = "vendor"\nexpires = 2099-01-01\n'
    )
    _, plain = run_json(capsys, "plan", str(snap_path))
    assert "adminsdholder-ace" in {c["kind"] for c in plain["changes"]}
    _, kept = run_json(capsys, "plan", str(snap_path), "--accept", str(accepted))
    assert "adminsdholder-ace" not in {c["kind"] for c in kept["changes"]}
    _, doc = run_json(
        capsys, "whatif", str(snap_path), "--remove", "adminsdholder:helpdesk",
        "--accept", str(accepted),
    )  # fmt: skip
    assert "AD-ACL-002" not in {r["check"] for r in doc["findings"]["cleared"]}
    assert doc["findings"]["accepted"] >= 1


def test_output_is_the_same_under_another_hash_seed(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    snap_path = write(tmp_path, entra_snapshot(helpdesk_reset=True))
    outs = set()
    for seed in ("0", "1", "4242"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        done = subprocess.run(
            [sys.executable, "-m", "ad_doctor", "plan", str(snap_path), "--goal", "all-paths",
             "-f", "json"],
            env=env, capture_output=True, text=True, check=True,
        )  # fmt: skip
        outs.add(done.stdout)
    assert len(outs) == 1
