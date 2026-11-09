"""Snapshots and pages for the viewer tests, shared by pytest, the browser tests and the
Node tests of the page's JavaScript.

    uv run python -m tests.viewer_fixtures tests/browser/build
    uv run python -m tests.viewer_fixtures parity tests/js/build [SNAPSHOT.json ...]

The first writes `xss.html` (directory names that are XSS payloads, everywhere a name can
appear), `full.html` (every screen populated: baseline, history, acceptances, invariants,
fix lines, the full graph), `sealed.html` (the same, encrypted with PASSPHRASE),
`paths.html` (large-domain mode), `clean.html` (no findings, from analyze -f html),
`bench.html` (a 1,500-user bench.py domain, for long lists), `declared.html` (declared
tier-0 assets, one of them not evaluated) and
`old-report.json` (the baseline as a JSON report, for the drag-and-drop diff). The second
writes the compact graph and Python's blast radius of a set of accounts for each snapshot
(the XSS fixture, the full fixture, a 3,000-user bench.py domain, and any given), which
tests/js/blast.test.mjs compares with the JavaScript search, and `whatif-*.json`: the
what-if model and Python's answer for every single removal, random sets and a plan's
prefixes on each what-if fixture (and any snapshot given), for tests/js/whatif.test.mjs.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from ad_doctor import changes, cut, paths, sd, viewer_graph, whatif
from ad_doctor.cli import main
from ad_doctor.model import DirObject, Snapshot
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_SID, template
from .test_checks import NORMAL, NOW, computer, snapshot, user

LS, PS = chr(0x2028), chr(0x2029)
# Each would run script if it reached an HTML parser, a URL, or a template engine.
HOSTILE = [
    '<img src=x onerror="window.__pwned=1">',
    "</script><script>window.__pwned=2</script>",
    "javascript:window.__pwned=3",
    '"><svg onload=window.__pwned=4>',
    f"line{LS}break{PS}end",
    "{{constructor.constructor('window.__pwned=5')()}}",
    "__proto__",
    '=HYPERLINK("x")',
    "w" * 300,
]
HOSTILE_DOMAIN = "<svg onload=window.__pwned=6>.test"
PASSPHRASE = "fixture-only passphrase 7x"  # test value for sealed.html, not a secret
_DATA = re.compile(r'<script id="adoc-data" type="application/json">([^<]*)</script>')


def decode_payload(page: str) -> str:
    """The viewmodel JSON text embedded in a page (still escaped)."""
    m = _DATA.search(page)
    assert m is not None, "no payload in the page"
    return gzip.decompress(base64.b64decode(m[1])).decode()


def xss_snapshot() -> Snapshot:
    """Every name a finding, a path or a note can show is hostile."""
    sid = f"{DOMAIN_SID}-2001"
    group = DirObject(
        dn="CN=g,OU=x,DC=lab,DC=test",
        name=HOSTILE[3],
        kind="group",
        sid=sid,
    )
    domain = DirObject(
        dn="DC=lab,DC=test",
        name="lab",
        kind="domain",
        aces=[
            Ace(sid, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
            Ace(sid, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL),
        ],
    )
    snap = snapshot(
        *[user(name, NORMAL | 0x400000) for name in HOSTILE if "," not in name],
        computer("WS<b>9</b>", laps=False),
        templates=[template(HOSTILE[0], enrollee_supplies_subject=True)],
        objects=[group, domain],
        principals={sid: HOSTILE[3]},
        domain=HOSTILE_DOMAIN,
    )
    snap.acls["domain"] = list(domain.aces)
    snap.notes.append(f"note with {HOSTILE[1]} and {HOSTILE[4]}")
    return with_sids(snap)


def with_sids(snap: Snapshot) -> Snapshot:
    """Give each account a SID (the helpers leave it empty), so the accounts are graph
    nodes the blast-radius screen can search from."""
    for i, a in enumerate(snap.accounts):
        if not a.sid:
            a.sid = f"{DOMAIN_SID}-{3000 + i}"
    return snap


def full_snapshots() -> tuple[Snapshot, Snapshot]:
    """(old, new): a baseline and a later run with new, resolved and changed findings."""
    old = snapshot(
        user("legacy", NORMAL | 0x400000),
        user("bob", NORMAL | 0x20),
        templates=[template("WebLegacy", enrollee_supplies_subject=True)],
        collected_at=NOW - timedelta(days=31),
    )
    new = snapshot(
        user("legacy", NORMAL | 0x400000),
        user("eve", NORMAL | 0x400000),
        user("svc_web", spns=["HTTP/web"]),
        computer("WS9", laps=False),
        templates=[template("WebLegacy", enrollee_supplies_subject=True)],
    )
    return with_sids(old), with_sids(new)


ACCEPT = """
[[accept]]
check = "AD-KRB-003"
objects = ["svc_web"]
reason = "vendor appliance, 30-character password"
expires = 2026-11-20
owner = "infra"
ticket = "OPS-12"

[[accept]]
check = "AD-SEC-001"
reason = "lab"
expires = 2026-01-01

[[accept]]
check = "AD-ACC-004"
reason = "nothing matches this any more"
expires = 2027-06-30
"""

INVARIANTS = """
[settings]
machine_account_quota = 0
min_pwd_length = 16

[templates]
published = ["User", "Machine"]
"""


def history(work: Path, old: Snapshot) -> Path:
    """Three earlier reports: one from an older ad-doctor (schema 1: no check list), one
    with two checks fewer, and the baseline run; the trend marks both changes."""
    hist = work / "history"
    hist.mkdir()
    for days, name in ((90, "2026-08.json"), (60, "2026-09.json"), (31, "2026-10.json")):
        snap = Snapshot.from_json(old.to_json())
        snap.collected_at = NOW - timedelta(days=days)
        src = work / f"snap-{days}.json"
        src.write_text(json.dumps(snap.to_json()))
        assert main(["analyze", str(src), "-f", "json", "-o", str(hist / name)]) == 0
    first = json.loads((hist / "2026-08.json").read_text())
    first["version"] = "0.5.0"
    del first["schema"], first["checks"]
    (hist / "2026-08.json").write_text(json.dumps(first))
    second = json.loads((hist / "2026-09.json").read_text())
    second["checks"] = second["checks"][2:]
    (hist / "2026-09.json").write_text(json.dumps(second))
    return hist


def build(out: Path) -> dict[str, Path]:
    """Write the pages (and the old report) into `out`; return their paths."""
    out.mkdir(parents=True, exist_ok=True)
    names = [
        "xss",
        "full",
        "sealed",
        "paths",
        "clean",
        "bench",
        "whatif",
        "noplan",
        "live",
        "redacted",
        "allpaths",
        "declared",
        "minimum",
        "unevaluated",
        "partial",
        "older",
    ]
    pages = {name: out / f"{name}.html" for name in names}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        xss = work / "xss.json"
        xss.write_text(json.dumps(xss_snapshot().to_json()))
        plan = work / "xss-plan.json"
        assert main(["plan", str(xss), "-f", "json", "-o", str(plan)]) == 0
        args = ["view", str(xss), "--fixes", "--no-encrypt", "-o", str(pages["xss"])]
        assert main([*args, "--whatif", str(plan)]) == 0
        old, new = full_snapshots()
        (work / "old.json").write_text(json.dumps(old.to_json()))
        (work / "new.json").write_text(json.dumps(new.to_json()))
        (work / "accept.toml").write_text(ACCEPT)
        (work / "inv.toml").write_text(INVARIANTS)
        args = ["view", str(work / "new.json"), "--baseline", str(work / "old.json")]
        args += ["--accept", str(work / "accept.toml"), "--invariants", str(work / "inv.toml")]
        args += ["--history", str(history(work, old)), "--fixes"]
        assert main(["plan", str(work / "new.json"), "-f", "json", "-o", str(work / "p.json")]) == 0
        args += ["--whatif", str(work / "p.json")]
        # a result that failed its check, with a rerouted path and a blast radius
        failed = json.loads((work / "p.json").read_text(encoding="utf-8"))
        failed["kind"] = "whatif"
        failed["check"] = {"ok": False, "problems": ["[expect] closes_all: still open"]}
        failed["plan_status"] = [
            {"id": "c:000000000000", "label": "remove x", "status": "stale", "due": None,
             "problems": ["does not resolve"], "note": None}
        ]  # fmt: skip
        failed["paths"]["rerouted"] = [
            {"fingerprint": "f", "before": {"object": "a -> b"}, "after": {"object": "a -> c -> b"}}
        ]
        failed["accounts"] = [
            {
                "account": "alice",
                "before": {"count": 9, "tier0": 2},
                "after": {"count": 3, "tier0": 0},
            }
        ]
        failed["findings"]["rechecked"] = False
        failed["steps"], failed["recommendation"] = [], None  # as whatif writes it
        failed["changes"].append(
            {"id": None, "spec": "member:x:y", "label": "member:x:y", "cost": None,
             "status": "absent", "notes": [], "warnings": []}
        )  # fmt: skip
        (work / "failed.json").write_text(json.dumps(failed), encoding="utf-8")
        view = ["view", str(work / "new.json"), "--whatif", str(work / "failed.json")]
        assert main([*view, "--no-encrypt", "--graph", "none", "-o", str(pages["whatif"])]) == 0
        assert main([*args, "--no-encrypt", "-o", str(pages["full"])]) == 0
        saved = os.environ.get("AD_DOCTOR_VIEW_PASSPHRASE")
        os.environ["AD_DOCTOR_VIEW_PASSPHRASE"] = PASSPHRASE
        try:
            assert main([*args, "-o", str(pages["sealed"])]) == 0
        finally:
            if saved is None:
                os.environ.pop("AD_DOCTOR_VIEW_PASSPHRASE", None)
            else:
                os.environ["AD_DOCTOR_VIEW_PASSPHRASE"] = saved
        # large-domain mode on a small domain: only precomputed principals
        args = ["view", str(work / "new.json"), "--graph", "paths", "--no-encrypt"]
        assert main([*args, "-o", str(pages["paths"])]) == 0
        # the full graph and no plan: the What-if screen starts from nothing
        args = ["view", str(work / "new.json"), "--no-encrypt", "-o", str(pages["noplan"])]
        assert main(args) == 0
        # what the page's downloaded plan is checked against (tests/browser)
        shutil.copy(work / "new.json", out / "full-snapshot.json")
        shutil.copy(xss, out / "xss-snapshot.json")
        shutil.copy(work / "new.json", out / "noplan-snapshot.json")
        write_live_page(work, pages["live"], out / "live-snapshot.json")
        # a redacted snapshot and no plan: the download does not resolve against the real one
        red = out / "redacted-snapshot.json"
        os.environ["AD_DOCTOR_REDACT_KEY"] = "fixture-only redaction key"
        try:
            assert main(["redact", str(work / "new.json"), "-o", str(red)]) == 0
        finally:
            os.environ.pop("AD_DOCTOR_REDACT_KEY", None)
        args = ["view", str(red), "--no-encrypt", "-o", str(pages["redacted"])]
        assert main(args) == 0
        # the result of an all-paths plan: the goal has to reach the page without a recommendation
        src, toml, result = str(work / "new.json"), work / "all.toml", work / "all-whatif.json"
        args = ["plan", src, "--goal", "all-paths", "-f", "toml", "-o", str(toml)]
        assert main(args) == 0
        assert main(["whatif", src, "--plan", str(toml), "-f", "json", "-o", str(result)]) == 0
        shutil.copy(work / "new.json", out / "allpaths-snapshot.json")
        args = ["view", str(work / "new.json"), "--whatif", str(result), "--no-encrypt"]
        assert main([*args, "-o", str(pages["allpaths"])]) == 0
        # a clean domain, as `analyze -f html` writes it (no graph, no findings)
        clean = work / "clean.json"
        clean.write_text(
            json.dumps(with_sids(snapshot(user("alice", NORMAL), computer("WS1"))).to_json())
        )
        assert main(["analyze", str(clean), "-f", "html", "-o", str(pages["clean"])]) == 0
        # every check judged, and a failed search no rule ties to a check
        report_of_clean = work / "clean-report.json"
        assert main(["analyze", str(clean), "-f", "json", "-o", str(report_of_clean)]) == 0
        data = json.loads(report_of_clean.read_text(encoding="utf-8"))
        for row in data["check_status"]:
            row.update(status="judged", outcome="no_finding", notes=[])
            row.pop("reason", None)
        data["notes"] = ["search CN=Foo,DC=example,DC=test failed: insufficientAccessRights"]
        report_of_clean.write_text(json.dumps(data), encoding="utf-8")
        args = ["view", str(report_of_clean), "--no-encrypt", "-o", str(pages["minimum"])]
        assert main(args) == 0
        # the control graph is missing the resource-based delegation edges
        gap = "the resource-based delegation edges of the control graph not evaluated"
        snap = with_sids(snapshot(user("alice", NORMAL), computer("WS1")))
        snap.notes.append(f"snapshot from an older version: {gap}")
        (work / "gap.json").write_text(json.dumps(snap.to_json()))
        args = ["view", str(work / "gap.json"), "--graph", "none", "--no-encrypt"]
        assert main([*args, "-o", str(pages["unevaluated"])]) == 0
        partly = json.loads((work / "new.json").read_text(encoding="utf-8"))
        partly["notes"] = [*partly.get("notes", []), f"snapshot from an older version: {gap}"]
        (work / "partly.json").write_text(json.dumps(partly))
        args = ["view", str(work / "partly.json"), "--graph", "none", "--no-encrypt"]
        assert main([*args, "-o", str(pages["partial"])]) == 0
        # a check the baseline did not evaluate, and a finding it brings now
        admin = user("adm_x", sid="S-1-5-21-1-2-3-1500")
        groups = {"Domain Admins": [admin.dn]}
        for name, checked in (("was.json", False), ("now.json", True)):
            made = snapshot(admin, privileged=groups, silos_checked=checked)
            (work / name).write_text(json.dumps(made.to_json()))
        args = ["view", str(work / "now.json"), "--baseline", str(work / "was.json")]
        assert main([*args, "--graph", "none", "--no-encrypt", "-o", str(pages["older"])]) == 0
        from .test_declared_tier0 import declared_snapshot

        extended = work / "declared.json"
        extended.write_text(json.dumps(declared_snapshot().to_json()))
        (work / "tier0.toml").write_text('tier0 = ["JUMP01$", "svc_other"]\n')
        args = ["view", str(extended), "--tier0-file", str(work / "tier0.toml"), "--graph", "none"]
        assert main([*args, "--no-encrypt", "-o", str(pages["declared"])]) == 0
        # a 1,500-user bench.py domain: AD-PATH-001 has enough objects for the long list
        bench = work / "bench.json"
        bench.write_text(json.dumps(bench_snapshot(1500).to_json()))
        args = ["view", str(bench), "--graph", "none", "-o", str(pages["bench"])]
        assert main(args) == 0
        report = out / "old-report.json"
        # judged by the same invariants as the built-in baseline, so the diffs agree
        args = ["analyze", str(work / "old.json"), "--invariants", str(work / "inv.toml")]
        assert main([*args, "-f", "json", "-o", str(report)]) == 0
    return pages


def write_live_page(work: Path, page: Path, snapshot_copy: Path) -> None:
    """A domain with a plan, chokepoints, an edge no change can take out, and one change
    of the plan that only the command line can evaluate (the edge a rebuild decides)."""
    from .test_whatif import FIXTURES

    snap = FIXTURES["gpo-local"]()
    src = work / "live.json"
    src.write_text(json.dumps(snap.to_json()))
    shutil.copy(src, snapshot_copy)
    plan = work / "live-plan.json"
    assert main(["plan", str(src), "-f", "json", "-o", str(plan)]) == 0
    doc = json.loads(plan.read_text(encoding="utf-8"))
    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    rebuild = next(p for p in range(len(g.prov.prims)) if g.prov.needs_rebuild(p))
    plain = next(p for p, key in enumerate(g.prov.prims) if key[0] == "gpo-entry")
    for p in (plain, rebuild):
        key = g.prov.prims[p]
        doc["changes"].append(
            {"id": changes.change_id(key), "kind": key[0], "label": changes.describe(snap, key),
             "class": "removable", "cost": 1, "status": "applied", "notes": [], "warnings": []}
        )  # fmt: skip
    plan.write_text(json.dumps(doc), encoding="utf-8")
    args = ["view", str(src), "--whatif", str(plan), "--no-encrypt", "-o", str(page)]
    assert main(args) == 0


# --- parity data for the JavaScript graph search ------------------------------------------


def bench_snapshot(users: int = 3000) -> Snapshot:
    """A bench.py domain (scripts/ is not a package)."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "bench.py"
    spec = importlib.util.spec_from_file_location("ad_doctor_bench", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snap: Snapshot = module.build(users, 7)
    return snap


def blast_case(g: paths.Graph, snap: Snapshot, sam: str, index: dict[str, int]) -> dict[str, Any]:
    """Python's blast radius of one account: count, a digest over every (node, path) in
    discovery order, the first rows for debugging, and the tier-0 paths."""
    starts = paths.identity_nodes(snap, sam)
    controlled, tier0 = paths.blast_radius(g, starts)
    rows = [f"{index[n]}\t{p.render(g)}" for n, p in controlled.items()]
    return {
        "account": sam,
        "count": len(controlled),
        "digest": hashlib.sha256("\n".join(rows).encode()).hexdigest(),
        "first": rows[:40],
        "tier0": [p.render(g) for p in tier0],
    }


def parity(snap: Snapshot, sample: int = 0) -> dict[str, Any]:
    g = paths.build(snap)
    compact = viewer_graph.compact(g, snap)
    index = {n: i for i, n in enumerate(viewer_graph.nodes_of(g))}
    accounts = [a for a in snap.accounts if a.sid]
    if sample and len(accounts) > sample:
        step = len(accounts) // sample
        picked = accounts[::step] + [a for a in accounts if a.admin_count or a.is_dc]
        accounts = list({a.sid: a for a in picked}.values())
    return {
        "domain": snap.domain,
        "graph": compact,
        "cases": [blast_case(g, snap, a.sam, index) for a in accounts],
    }


def write_parity(out: Path, extra: list[Path]) -> list[Path]:
    from .whatif_fixtures import adcs_snapshot, delegation_snapshot

    out.mkdir(parents=True, exist_ok=True)
    snaps = {"xss": (xss_snapshot(), 0), "full": (full_snapshots()[1], 0)}
    snaps["bench3000"] = (bench_snapshot(), 60)
    snaps["delegation"] = (delegation_snapshot(), 0)
    snaps["adcs"] = (adcs_snapshot(), 0)
    for path in extra:
        snaps[path.stem] = (Snapshot.from_json(json.loads(path.read_text())), 200)
    written = []
    for name, (snap, sample) in snaps.items():
        target = out / f"parity-{name}.json"
        target.write_text(json.dumps(parity(snap, sample)))
        written.append(target)
    written += write_whatif_parity(out, extra)
    return written


# --- parity data for the page's what-if ----------------------------------------------------


def _digest(rows: list[str]) -> str:
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def _whatif_case(
    snap: Snapshot,
    g: paths.Graph,
    base: whatif.State,
    index: dict[str, int],
    numbers: dict[int, int],
    removed: list[int],
    sams: list[str],
    reach: set[str],
    m: cut.Model,
    extra: list[str],
) -> dict[str, Any]:
    """Python's answer for one set of removals, for tests/js/whatif.test.mjs: digests over
    everything order-sensitive, with enough raw rows to debug a difference."""
    assert g.prov is not None
    case: dict[str, Any] = {"removed": sorted(numbers[p] for p in removed)}
    if not whatif.maskable(g.prov, removed):
        case["rebuild"] = True
        return case
    mg = whatif.masked(g, snap, removed, extra)
    after = whatif.state(snap, mg)
    closed, rerouted, still = whatif.classify(base, after)
    label = paths.edge_text
    edge_rows = [
        f"{index[src]} {index[dst]} {label(mg, src, dst, how)}"
        for src in sorted(mg.edges, key=index.__getitem__)
        for dst, how in mg.edges[src]
    ]
    found_rows = [f"{index[n]}\t{p.render(mg)}" for n, p in after.found.items()]
    holder_rows = [f"{index[n]}\t{p.render(mg)}" for n, p in after.holders.items()]

    def now(n: str) -> str:
        return (after.holders.get(n) or after.found[n]).render(mg)

    rerouted_rows = [
        f"{index[n]}\t{base.holders[n].render(base.graph)}\t{now(n)}" for n in rerouted
    ]
    open_rows = [f"{index[n]}\t{now(n)}" for n in still]
    new_rows = [
        f"{index[n]}\t{p.render(mg)}" for n, p in after.holders.items() if n not in base.holders
    ]
    case.update(
        routes=None if set(removed) & m.dropped else cut.routes(m, removed),
        tier0=sorted(index[n] for n in mg.tier0),
        edges=_digest(edge_rows),
        edge_count=len(edge_rows),
        order=[index[s] for s in mg.edges if s in reach],
        found=_digest(found_rows),
        found_count=len(found_rows),
        found_first=found_rows[:10],
        holders=_digest(holder_rows),
        holder_count=len(holder_rows),
        holders_first=holder_rows[:10],
        exposed=after.exposed,
        users=after.users,
        closed=_digest([str(index[n]) for n in closed]),
        closed_count=len(closed),
        rerouted=_digest(rerouted_rows),
        rerouted_count=len(rerouted_rows),
        open=_digest(open_rows),
        open_count=len(open_rows),
        new=_digest(new_rows),
        new_count=len(new_rows),
        blast=[blast_case(mg, snap, sam, index) for sam in sams],
    )
    return case


def whatif_parity(
    snap: Snapshot,
    singles: int,
    sets: int,
    with_plan: bool = True,
    seed: int = 11,
    assume: bool = False,
    goal: str = "exposure",
) -> dict[str, Any]:
    """The model and Python's answers: every single removal (or `singles` of them), random
    sets, and the plan's step prefixes. Rebuild cases only check the flag."""
    from .whatif_fixtures import random_sets

    g = paths.build(snap, provenance=True)
    assert g.prov is not None
    prims = len(g.prov.prims)
    numbers = viewer_graph.prim_numbers(g)
    data = viewer_graph.compact(g, snap)
    extra = sorted(paths.direct_holders(g, paths.paths_to_tier0(g)))[:1] if assume else []
    model = viewer_graph.whatif_model(g, snap, data, (), extra, goal)
    index = {n: i for i, n in enumerate(viewer_graph.nodes_of(g))}
    view = whatif.masked(g, snap, (), extra)
    reach = whatif.reaching(view)
    base = whatif.state(snap, view)
    keeps = changes.default_keeps(snap, g.prov)
    m = cut.build_model(snap, g, cut.sources_for(snap, view, goal), keeps, extra)
    picked: list[list[int]] = []
    if singles < 0 or singles >= prims:
        picked += [[p] for p in range(prims)]
    elif singles:
        picked += random_sets(prims, singles, seed, most=1)
    if prims:
        picked += random_sets(prims, sets, seed + 1)
    if with_plan and prims:
        steps = cut.plan(snap, g).changes
        picked += [steps[: k + 1] for k in range(len(steps))]
    accounts = [a.sam for a in snap.accounts if a.sid][:3]
    return {
        "domain": snap.domain,
        "graph": data,
        "whatif": model,
        "before": {
            "exposed": base.exposed,
            "users": base.users,
            "holders": len(base.holders),
            "found": len(base.found),
            "routes": cut.routes(m),
        },
        "cases": [
            _whatif_case(snap, g, base, index, numbers, removed, accounts, reach, m, extra)
            for removed in picked
        ],
    }


def write_whatif_parity(out: Path, extra: list[Path]) -> list[Path]:
    from .test_whatif import FIXTURES

    written = []
    for name, make in FIXTURES.items():
        target = out / f"whatif-{name}.json"
        target.write_text(json.dumps(whatif_parity(make(), -1, 50)))
        written.append(target)
    for name, make in FIXTURES.items():
        target = out / f"whatif-assume-{name}.json"
        target.write_text(json.dumps(whatif_parity(make(), -1, 20, assume=True, goal="all-paths")))
        written.append(target)
    target = out / "whatif-bench3000.json"
    target.write_text(json.dumps(whatif_parity(bench_snapshot(), 200, 50)))
    written.append(target)
    for path in extra:
        snap = Snapshot.from_json(json.loads(path.read_text()))
        big = len(snap.accounts) > 5000
        data = whatif_parity(snap, 40 if big else -1, 20 if big else 200, with_plan=not big)
        target = out / f"whatif-{path.stem}.json"
        target.write_text(json.dumps(data))
        written.append(target)
    return written


if __name__ == "__main__":
    if sys.argv[1:2] == ["parity"]:
        for path in write_parity(Path(sys.argv[2]), [Path(p) for p in sys.argv[3:]]):
            print(path)
    else:
        for name, path in build(Path(sys.argv[1] if len(sys.argv) > 1 else "build")).items():
            print(f"{name}: {path}")
