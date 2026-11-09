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
tests/js/blast.test.mjs compares with the JavaScript search.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from ad_doctor import paths, sd, viewer_graph
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
    pages = {
        name: out / f"{name}.html"
        for name in ("xss", "full", "sealed", "paths", "clean", "bench", "whatif", "declared")
    }
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
        # a clean domain, as `analyze -f html` writes it (no graph, no findings)
        clean = work / "clean.json"
        clean.write_text(
            json.dumps(with_sids(snapshot(user("alice", NORMAL), computer("WS1"))).to_json())
        )
        assert main(["analyze", str(clean), "-f", "html", "-o", str(pages["clean"])]) == 0
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
    return written


if __name__ == "__main__":
    if sys.argv[1:2] == ["parity"]:
        for path in write_parity(Path(sys.argv[2]), [Path(p) for p in sys.argv[3:]]):
            print(path)
    else:
        for name, path in build(Path(sys.argv[1] if len(sys.argv) > 1 else "build")).items():
            print(f"{name}: {path}")
