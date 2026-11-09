"""The viewer's phase-2 data: history and trend, encryption, the embedded graph and the
precomputed blast radius, and the acceptance drafts the page writes."""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import shutil
import subprocess
import tomllib
from collections import Counter
from datetime import date
from pathlib import Path

import pytest

from ad_doctor import accept, changes, paths, sd, seal, trend, viewer_graph, whatif
from ad_doctor.checks import REGISTRY, run_all
from ad_doctor.cli import main
from ad_doctor.model import Finding, Severity
from ad_doctor.sd import Ace

from .test_acl_adcs import template
from .test_checks import NORMAL, snapshot, user
from .viewer_fixtures import (
    HOSTILE,
    HOSTILE_DOMAIN,
    PASSPHRASE,
    bench_snapshot,
    build,
    decode_payload,
    full_snapshots,
    with_sids,
    xss_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
GOOD = "orbit-lemon-tundra-violet"  # a test value, 24 characters


@pytest.fixture(scope="module")
def pages(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return build(tmp_path_factory.mktemp("viewer2"))


def _vm(page: Path) -> dict:
    return json.loads(decode_payload(page.read_text(encoding="utf-8")))


def _meta(html: str) -> dict:
    m = re.search(r'id="adoc-meta" type="application/json">([^<]*)<', html)
    assert m is not None
    return json.loads(m[1])


def _write(tmp: Path, snap: object, name: str = "snap.json") -> Path:
    path = tmp / name
    path.write_text(json.dumps(snap.to_json()))  # type: ignore[attr-defined]
    return path


# --- report JSON -------------------------------------------------------------------------


def test_report_json_is_versioned_and_lists_the_checks_that_ran(tmp_path: Path) -> None:
    src = _write(tmp_path, snapshot())
    out = tmp_path / "r.json"
    assert main(["analyze", str(src), "-f", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["schema"] == 2 and data["checks"] == sorted(c.id for c in REGISTRY)
    assert main(["analyze", str(src), "-f", "json", "--only", "ad-krb-002", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["checks"] == ["AD-KRB-002"]


# --- trend ---------------------------------------------------------------------------------


def test_trend_points_and_markers(pages: dict[str, Path]) -> None:
    t = _vm(pages["full"])["trend"]
    points = t["points"]
    names = ["2026-08.json", "2026-09.json", "2026-10.json", "this run"]
    assert [p["name"] for p in points] == names
    assert points[0]["version"] == "0.5.0" and points[0]["checks"] is None
    assert points[2]["checks"] == points[1]["checks"] + 2
    notes = {m["index"]: m["notes"] for m in t["markers"]}
    assert notes[1][0].startswith("ad-doctor 0.5.0 → ")
    assert notes[2][0] == "checks +2"
    # this run adds --invariants: five more checks than the reports in the history
    assert notes[3] == ["checks +5", "new: " + ", ".join(f"AD-INV-00{i}" for i in range(1, 6))]
    # the template on a control path in every run: exposure carried from AD-PATH-001
    assert all(isinstance(p["exposed"], int) and isinstance(p["users"], int) for p in points)
    assert sum(points[-1]["counts"].values()) == len(_vm(pages["full"])["findings"])
    assert t["categories"] and set(points[-1]["categories"]) == set(t["categories"])


def test_trend_exposure_without_a_path_finding() -> None:
    base = {"tool": "ad-doctor", "collected_at": "2026-10-01T00:00:00+00:00", "findings": []}
    assert trend.point(base, "x")["exposed"] == 0  # no path: nobody exposed
    assert trend.point({**base, "checks": ["AD-ACC-001"]}, "x")["exposed"] is None  # not run
    accepted = {**base, "accepted": [{"check_id": "AD-PATH-001"}]}
    assert trend.point(accepted, "x")["exposed"] is None  # accepted away: unknown
    detail = "1 principals ... 3 of 40 enabled users (7%)"
    path = {"id": "AD-PATH-001", "severity": "high", "objects": ["a"], "detail": detail}
    old = {**base, "findings": [path]}
    assert (trend.point(old, "x")["exposed"], trend.point(old, "x")["users"]) == (3, 40)


def test_history_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _write(tmp_path, snapshot())
    hist = tmp_path / "hist"
    hist.mkdir()
    (hist / "snap.json").write_text(src.read_text())  # a snapshot is skipped, not an error
    args = ["view", str(src), "--graph", "none", "-o", str(tmp_path / "o.html")]
    assert main([*args, "--history", str(hist)]) == 1
    assert "no ad-doctor JSON report" in capsys.readouterr().err
    other = snapshot()
    other.domain = "other.test"
    assert main(["analyze", str(_write(tmp_path, other, "o.json")), "-f", "json",
                 "-o", str(hist / "o.json")]) == 0  # fmt: skip
    assert main([*args, "--history", str(hist)]) == 1
    assert "not 'lab.test'" in capsys.readouterr().err
    assert main([*args, "--history", str(tmp_path / "missing")]) == 1
    assert "not a directory" in capsys.readouterr().err


# --- encryption ----------------------------------------------------------------------------


def _unseal(html: str, passphrase: str) -> dict:
    meta = _meta(html)
    m = re.search(r'id="adoc-data" type="application/json">([^<]*)<', html)
    assert m is not None
    packed = seal.unseal(base64.b64decode(m[1]), passphrase, meta)
    return json.loads(gzip.decompress(packed))


def test_sealed_page_hides_everything_but_the_header(pages: dict[str, Path]) -> None:
    html = pages["sealed"].read_text(encoding="utf-8")
    meta = _meta(html)
    assert meta["encrypted"] is True
    assert set(meta) == {"schema", "version", "built_at", "kdf", "cipher", "sha256", "bytes",
                         "encrypted"}  # fmt: skip
    assert meta["kdf"]["iterations"] == 600_000 and len(base64.b64decode(meta["kdf"]["salt"])) == 16
    assert len(base64.b64decode(meta["cipher"]["nonce"])) == 12
    for secret in (PASSPHRASE, "lab.test", "WebLegacy", "AD-KRB-002"):
        assert secret not in html
    vm = _unseal(html, PASSPHRASE)
    assert vm["meta"]["domain"] == "lab.test" and vm["meta"]["embedded"]["encrypted"] is True
    assert vm["graph"] is not None and vm["trend"] is not None
    with pytest.raises(ValueError):
        _unseal(html, PASSPHRASE + "x")
    # the readable header is bound to the ciphertext
    tampered = html.replace(meta["built_at"], "2020-01-01T00:00:00+00:00")
    with pytest.raises(ValueError):
        _unseal(tampered, PASSPHRASE)


def test_view_encrypts_by_default_with_a_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    src = _write(tmp_path, xss_snapshot())
    out = tmp_path / "x.html"
    monkeypatch.delenv(seal.ENV, raising=False)
    assert main(["view", str(src), "-o", str(out)]) == 1
    err = capsys.readouterr().err
    assert seal.ENV in err and "--no-encrypt" in err and not out.exists()
    assert "--graph none to leave the graph out" in err
    monkeypatch.setenv(seal.ENV, "short")
    assert main(["view", str(src), "-o", str(out)]) == 1
    assert "shorter than 14 characters" in capsys.readouterr().err
    monkeypatch.setenv(seal.ENV, "a" * 20)
    assert main(["view", str(src), "-o", str(out)]) == 1
    assert "fewer than 6 different characters" in capsys.readouterr().err
    monkeypatch.setenv(seal.ENV, GOOD)
    assert main(["view", str(src), "-o", str(out)]) == 0
    html = out.read_text()
    assert "encrypted" in capsys.readouterr().out and _meta(html)["encrypted"] is True
    assert out.stat().st_mode & 0o777 == 0o600
    assert GOOD not in html and HOSTILE_DOMAIN not in html and HOSTILE[0] not in html
    assert GOOD not in json.dumps(_unseal(html, GOOD))  # not in the payload either
    # read once and dropped, so a browser started with --open does not inherit it
    assert seal.ENV not in os.environ
    # without a graph nothing is encrypted unless asked
    assert main(["view", str(src), "--graph", "none", "-o", str(out)]) == 0
    assert _meta(out.read_text())["encrypted"] is False
    assert main(["view", str(src), "--graph", "none", "--encrypt", "-o", str(out)]) == 1
    err = capsys.readouterr().err
    assert "--encrypt was given" in err and "--graph none" not in err


def test_prompted_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    src = _write(tmp_path, snapshot())
    monkeypatch.delenv(seal.ENV, raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    answers = iter([GOOD, GOOD + "!"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert main(["view", str(src), "-o", str(tmp_path / "p.html")]) == 1
    err = capsys.readouterr().err
    assert "the two passphrases differ" in err and "bits)" in err
    answers = iter([GOOD, GOOD])
    assert main(["view", str(src), "-o", str(tmp_path / "p.html")]) == 0


def test_suggested_passphrases() -> None:
    assert len(seal.WORDS) == len(set(seal.WORDS)) == 512
    assert all(re.fullmatch(r"[a-z]{3,7}", w) for w in seal.WORDS)
    words = seal.suggest().split("-")
    assert len(words) == 7 and set(words) <= set(seal.WORDS)
    assert seal.problem(seal.suggest()) is None and seal.suggestion_bits() == 63
    assert seal.problem("é" * 3 + "abcdefghijk") is None  # length in characters, NFC


# --- graph and blast radius ------------------------------------------------------------------


def test_whatif_model_only_with_the_full_graph(pages: dict[str, Path]) -> None:
    vm = _vm(pages["full"])
    model = vm["whatif_model"]
    assert model is not None and vm["graph"] is not None
    # large-domain mode and no graph: no interactive what-if (design decision D13)
    assert _vm(pages["paths"])["whatif_model"] is None
    assert _vm(pages["whatif"])["whatif_model"] is None
    assert _vm(pages["clean"])["whatif_model"] is None


def test_whatif_model_of_the_page_matches_the_graph(pages: dict[str, Path]) -> None:
    vm = _vm(pages["full"])
    _, new = full_snapshots()
    g = paths.build(new, provenance=True)
    assert g.prov is not None
    model = vm["whatif_model"]
    numbers = viewer_graph.prim_numbers(g)
    assert len(model["prim"]) == len(vm["graph"]["dst"])
    assert len(model["prim_kind"]) == len(g.prov.prims)
    kinds = {p: model["kinds"][model["prim_kind"][numbers[p]]] for p in range(len(g.prov.prims))}
    assert kinds == {p: key[0] for p, key in enumerate(g.prov.prims)}
    plan = vm["whatif"]["changes"]
    ids = [c["id"] for c in plan if c.get("id")]
    assert ids and set(model["plan"]) == set(ids)
    assert {
        numbers[g.prov.lookup(key)] for key in g.prov.prims if changes.change_id(key) in ids
    } == set(model["plan"].values())


def test_whatif_model_marks_what_needs_a_rebuild() -> None:
    from .whatif_fixtures import kitchen_sink

    snap = kitchen_sink()
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    data = viewer_graph.compact(g, snap)
    model = viewer_graph.whatif_model(g, snap, data)
    numbers = viewer_graph.prim_numbers(g)
    marked, at = set(), 0
    for d in model["rebuild"]:
        at += d
        marked.add(at)
    want = {numbers[p] for p in range(len(g.prov.prims)) if g.prov.needs_rebuild(p)}
    assert marked == want and want
    # the masked graph agrees that these cannot be masked
    assert not whatif.maskable(g.prov, [next(p for p, n in numbers.items() if n in want)])


def test_whatif_model_lists_each_edge_once() -> None:
    """Every edge is coded: the next new primitive, an earlier one, or a fixed reason; the
    edges with more than one reason are listed apart."""
    from .whatif_fixtures import delegation_snapshot, kitchen_sink

    for snap in (kitchen_sink(), delegation_snapshot()):
        g = paths.build(snap, provenance=True)
        assert g.prov is not None
        data = viewer_graph.compact(g, snap)
        model = viewer_graph.whatif_model(g, snap, data)
        n = len(model["prim_kind"])
        fresh = 0
        for v in model["prim"]:
            assert v < 0 or v <= fresh
            fresh += v == 0
        assert fresh <= n
        for edge, items in model["options"]:
            assert 0 <= edge < len(data["dst"])
            assert all(p < n and 0 <= label < len(data["labels"]) for p, label in items)
        for edge, p, gate in model["gated"]:
            assert 0 <= edge < len(data["dst"]) and p < n and 0 <= gate < len(model["gates"])


def test_full_graph_is_the_snapshot_graph(pages: dict[str, Path]) -> None:
    vm = _vm(pages["full"])
    assert vm["blast"] == {"mode": "full"} and vm["meta"]["embedded"]["graph"] == "full"
    g = vm["graph"]
    _, new = full_snapshots()
    built = paths.build(new)
    assert len(g["names"]) == len(viewer_graph.nodes_of(built))
    assert sum(g["deg"]) == len(g["dst"]) == len(g["how"]) == sum(map(len, built.edges.values()))
    assert {a[0] for a in g["accounts"]} == {a.sam for a in new.accounts if a.sid}
    assert g["domain_sid"] == new.domain_sid
    assert g["sids"] and all(0 <= i < len(g["names"]) for i in g["sids"].values())


def test_paths_mode_precomputes_holders_and_named_accounts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    esc = [template("Esc", enrollee_supplies_subject=True)]
    src = _write(tmp_path, snapshot(user("eve", NORMAL), templates=esc))
    out = tmp_path / "p.html"
    args = ["view", str(src), "--no-encrypt", "-o", str(out)]
    assert main([*args, "--graph", "paths", "--blast-radius-for", "eve"]) == 0
    vm = _vm(out)
    assert vm["graph"] is None and vm["blast"]["mode"] == "paths"
    subjects = {s["name"]: s for s in vm["blast"]["subjects"]}
    eve, users = subjects["eve"], subjects["Domain Users"]
    assert eve["account"] and eve["reaches"] and users["holder"] and users["reaches"]
    # eve reaches tier 0 through her primary group, Domain Users
    assert eve["tier0"][0]["steps"][-1][1] == "template Esc"
    assert eve["count"] == sum(eve["kinds"].values()) >= 1
    assert all(len(row) == 5 for row in eve["objects"])
    assert main([*args, "--graph", "paths", "--blast-radius-for", "nobody"]) == 1
    assert "no account 'nobody'" in capsys.readouterr().err
    assert main([*args, "--graph", "full", "--blast-radius-for", "eve"]) == 1
    assert "goes with --graph paths" in capsys.readouterr().err


def test_auto_graph_mode_follows_the_domain_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _write(tmp_path, snapshot())
    out = tmp_path / "a.html"
    assert main(["view", str(src), "--no-encrypt", "-o", str(out)]) == 0
    assert _vm(out)["meta"]["embedded"]["graph"] == "full"
    monkeypatch.setattr(viewer_graph, "FULL_GRAPH_OBJECTS", 1)
    assert main(["view", str(src), "--no-encrypt", "-o", str(out)]) == 0
    assert _vm(out)["meta"]["embedded"]["graph"] == "paths"


def test_a_report_has_no_graph(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _write(tmp_path, snapshot())
    report = tmp_path / "r.json"
    assert main(["analyze", str(src), "-f", "json", "-o", str(report)]) == 0
    out = tmp_path / "r.html"
    assert main(["view", str(report), "-o", str(out)]) == 0  # no graph: not encrypted
    vm = _vm(out)
    assert vm["graph"] is None and vm["blast"] is None
    assert main(["view", str(report), "--graph", "full", "-o", str(out)]) == 1
    assert "need a snapshot" in capsys.readouterr().err


def test_precomputed_blast_radius_matches_paths_blast_radius() -> None:
    """The indexed search of paths mode finds what paths.blast_radius finds."""
    snap = bench_snapshot(1500)
    g = paths.build(snap)
    c = viewer_graph.Indexed(viewer_graph.compact(g, snap), viewer_graph.nodes_of(g))
    analysis = paths.analyze(snap)
    cases = [[p.start] for p in analysis.paths[:5]]
    cases += [paths.identity_nodes(snap, a.sam) for a in snap.accounts[::400]]
    for starts in cases:
        controlled, tier0 = paths.blast_radius(g, starts)
        got = viewer_graph.subject(c, starts, g.name(starts[0]), "x")
        assert got["count"] == len(controlled)
        assert got["tier0_count"] == len(tier0)
        want = [viewer_graph.path_record(g, p) for p in tier0[: viewer_graph.TIER0_PATHS]]
        assert got["tier0"] == want
        rows = {
            (g.name(n), p.steps[-1][1], g.name(p.steps[-2][0] if len(p.steps) > 1 else p.start))
            for n, p in controlled.items()
        }
        assert {(name, how, parent) for name, _, _, how, parent in got["objects"]} <= rows
        assert sum(got["kinds"].values()) == len(controlled)


def test_paths_mode_holders_are_searched_like_the_cli() -> None:
    """A path holder that is an account gets `ad-doctor blast-radius`'s answer (its
    implicit groups included), and HOLDERS counts distinct principals, not paths."""
    held = with_sids(snapshot(user("eve", NORMAL), user("kc", NORMAL)))
    eve = next(a.sid for a in held.accounts if a.sam == "eve")
    enroll = Ace(eve, sd.CONTROL_ACCESS, sd.CERT_ENROLL)
    held.templates = [
        template("ByEve", enrollee_supplies_subject=True, aces=[enroll]),
        template("ByUsers", enrollee_supplies_subject=True),  # eve reaches it via Domain Users
    ]
    account_holders = 0
    for snap in (held, full_snapshots()[1], bench_snapshot(1500)):
        g = paths.build(snap)
        analysis = paths.analyze(snap)
        got = viewer_graph.precomputed(g, snap, analysis, [])
        distinct = list(dict.fromkeys(p.start for p in analysis.paths))
        assert len(got) == min(viewer_graph.HOLDERS, len(distinct))
        assert len({s["sid"] for s in got}) == len(got)
        sids = {a.sid: a for a in snap.accounts}
        for s in got:
            a = sids.get(s["sid"])
            starts = paths.identity_nodes(snap, a.sid) if a else [f"sid:{s['sid']}"]
            controlled, tier0 = paths.blast_radius(g, starts)
            assert (s["count"], s["tier0_count"]) == (len(controlled), len(tier0)), s["name"]
            assert s["kinds"] == dict(Counter(g.kind(n) for n in controlled))
            account_holders += a is not None
    assert account_holders  # eve holds a path herself


# --- acceptance drafts (the JavaScript writes them, accept.py reads them) -----------------------


@pytest.mark.skipif(shutil.which("node") is None, reason="needs Node")
def test_accept_draft_from_the_page_round_trips(tmp_path: Path) -> None:
    hostile = ['say "hi"\\ there', "line\nbreak\ttab", "\u2028 sep", "naïve-ünï", "<img src=x>"]
    entries = [
        {"check": "AD-KRB-002", "objects": hostile, "reason": 'r "quoted"\n2nd line',
         "expires": "2027-03-31", "owner": "infra\\ops", "ticket": "OPS-1"},
        {"check": "AD-ACC-001", "objects": [], "all": True, "reason": "lab",
         "expires": "2027-01-01", "owner": "", "ticket": ""},
    ]  # fmt: skip
    info = {"domain": "lab.test\n[[accept]]", "date": "2026-11-05"}
    run = subprocess.run(
        ["node", str(ROOT / "tests/js/run.mjs"), "acceptDraft"],
        input=json.dumps([entries, info]), capture_output=True, text=True, check=True,
    )  # fmt: skip
    text = json.loads(run.stdout)
    path = tmp_path / "accept-draft.toml"
    path.write_text(text, encoding="utf-8")
    tomllib.loads(text)
    got = accept.load(path)
    assert [(e.check, e.objects, e.reason, e.expires, e.owner, e.ticket) for e in got] == [
        ("AD-KRB-002", set(hostile), 'r "quoted"\n2nd line', date(2027, 3, 31), "infra\\ops",
         "OPS-1"),
        ("AD-ACC-001", set(), "lab", date(2027, 1, 1), "", ""),
    ]  # fmt: skip
    # and accept.py applies it to the objects it names
    findings = [Finding("AD-KRB-002", "t", Severity.MEDIUM, "", "", [*hostile, "eve"])]
    kept, accepted, _ = accept.apply(findings, got, date(2026, 11, 5))
    assert kept[0].objects == ["eve"] and sorted(accepted[0].objects) == sorted(hostile)


def test_draft_keys_match_what_accept_reads(pages: dict[str, Path]) -> None:
    """The page drafts an AD-PATH-001 path by its key, the start principal."""
    vm = _vm(pages["full"])
    f = next(f for f in vm["findings"] if f["id"] == "AD-PATH-001")
    snap = full_snapshots()[1]
    found = next(x for x in run_all(snap) if x.check_id == "AD-PATH-001")
    entries = [accept.Entry("AD-PATH-001", {f["keys"][0]}, "r", date(2027, 1, 1))]
    _, accepted, _ = accept.apply([found], entries, date(2026, 11, 5))
    assert accepted and found.objects[0] in accepted[0].objects
