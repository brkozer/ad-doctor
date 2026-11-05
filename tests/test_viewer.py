"""The HTML viewer (`ad-doctor view`, `-f html`), chokepoints and path identities."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from html.parser import HTMLParser
from importlib import resources
from pathlib import Path

import pytest

from ad_doctor import accept, paths, viewer
from ad_doctor.checks import run_all
from ad_doctor.cli import main
from ad_doctor.model import Finding, Severity
from ad_doctor.report import Report, finding_keys, fingerprint, legacy_keys, report_dict

from .test_acl_adcs import template
from .test_checks import NORMAL, only, snapshot, user
from .viewer_fixtures import (
    HOSTILE,
    HOSTILE_DOMAIN,
    build,
    decode_payload,
    full_snapshots,
    xss_snapshot,
)

ASSETS = resources.files("ad_doctor").joinpath("viewer_assets")

# Ways to turn a string into markup or code, to store data, or to reach the network.
BANNED = [
    r"\.innerHTML",
    r"\.outerHTML",
    r"insertAdjacentHTML",
    r"document\.write",
    r"\beval\s*\(",
    r"\bnew\s+Function\b",
    r"\bFunction\s*\(",
    r"setTimeout\s*\(\s*[\"'`]",
    r"setInterval\s*\(\s*[\"'`]",
    r"createContextualFragment",
    r"DOMParser",
    r"\.srcdoc",
    r"javascript:",
    r"localStorage",
    r"sessionStorage",
    r"indexedDB",
    r"document\.cookie",
    r"XMLHttpRequest",
    r"WebSocket",
    r"EventSource",
    r"sendBeacon",
    r"serviceWorker",
    r"importScripts",
    r"window\.open",
    r"\.src\s*=",
    r"\.action\s*=",
    r"postMessage",
]


def _code(text: str) -> str:
    """JavaScript without its comments (they explain the rules, using the banned words)."""
    return re.sub(r"(^|\s)//[^\n]*", r"\1", text)


def test_js_has_no_html_sinks_and_no_storage() -> None:
    js = "\n".join(
        _code(ASSETS.joinpath(name).read_text(encoding="utf-8")) for name in ("core.js", "app.js")
    )
    hits = [p for p in BANNED if re.search(p, js)]
    assert hits == []
    # the only request is the About screen's self-check, which the CSP must refuse
    assert re.findall(r"fetch\([^)]*\)", js) == ['fetch("data:text/plain,ad-doctor")']
    # attributes go through the allowlist; no handler or URL attribute is in it
    allowed = re.search(r'new RegExp\(\s*"\^\(([^)]*)\)', js.replace('" +\n      "', ""))
    assert allowed is not None
    names = set(allowed[1].split("|"))
    assert not {"href", "src", "style", "srcdoc", "action", "formaction", "xlink:href"} & names
    assert not any(n.startswith("on") for n in names)


def test_css_loads_nothing() -> None:
    css = ASSETS.joinpath("app.css").read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[tuple[dict[str, str | None], str]] = []
        self.styles: list[str] = []
        self.urls: list[str] = []
        self.csp = ""
        self._open: str | None = None
        self._attrs: dict[str, str | None] = {}
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        for key in ("src", "href", "action", "srcset", "data", "poster"):
            if a.get(key):
                self.urls.append(str(a[key]))
        if tag == "meta" and a.get("http-equiv") == "Content-Security-Policy":
            self.csp = str(a["content"])
        if tag in ("script", "style"):
            self._open, self._attrs, self._text = tag, a, []

    def handle_data(self, data: str) -> None:
        if self._open:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._open:
            body = "".join(self._text)
            if tag == "script":
                self.scripts.append((self._attrs, body))
            else:
                self.styles.append(body)
            self._open = None


def _sha(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


@pytest.fixture(scope="module")
def pages(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return build(tmp_path_factory.mktemp("viewer"))


def test_page_is_locked_down(pages: dict[str, Path]) -> None:
    html = pages["full"].read_text(encoding="utf-8")
    page = _Page()
    page.feed(html)
    code = [body for attrs, body in page.scripts if "type" not in attrs]
    data = [attrs.get("id") for attrs, _ in page.scripts if attrs.get("type") == "application/json"]
    assert len(code) == 1 and data == ["adoc-meta", "adoc-data"] and len(page.styles) == 1
    directives = dict(d.split(" ", 1) for d in page.csp.split("; "))
    assert directives["default-src"] == "'none'"
    assert directives["connect-src"] == "'none'"
    assert directives["script-src"] == f"'{_sha(code[0])}'"
    assert directives["style-src"] == f"'{_sha(page.styles[0])}'"
    assert directives["form-action"] == directives["base-uri"] == "'none'"
    assert directives["require-trusted-types-for"] == "'script'"
    # nothing to load: the only URL is the inline favicon
    assert [u for u in page.urls if not u.startswith("data:image/svg+xml,")] == []
    assert "http://" not in code[0].replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in code[0]


def test_hostile_names_stay_data(pages: dict[str, Path]) -> None:
    html = pages["xss"].read_text(encoding="utf-8")
    payload = decode_payload(html)
    # outside the packed payload the page holds only the template and the build metadata
    for name in [*HOSTILE, HOSTILE_DOMAIN]:
        assert name not in html
    # inside it, nothing can end the script element or start markup, even once unpacked
    for ch in "<>&" + chr(0x2028) + chr(0x2029):
        assert ch not in payload
    vm = json.loads(payload)
    assert vm["meta"]["domain"] == HOSTILE_DOMAIN
    names = json.dumps(vm, ensure_ascii=False)
    for name in HOSTILE[:4]:
        assert json.dumps(name, ensure_ascii=False)[1:-1] in names
    assert vm["paths"] is not None
    assert {n["name"] for n in vm["paths"]["nodes"]} >= {f"template {HOSTILE[0]}", HOSTILE[3]}
    meta = re.search(r'id="adoc-meta" type="application/json">([^<]*)<', html)
    assert meta is not None
    built = json.loads(meta[1])
    assert built["sha256"] == hashlib.sha256(payload.encode()).hexdigest()
    assert built["encrypted"] is False


def test_view_writes_a_private_file_and_opens_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    snap_path = tmp_path / "snap.json"
    snap_path.write_text(json.dumps(xss_snapshot().to_json()))
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))
    assert main(["view", str(snap_path), "--no-encrypt", "--open"]) == 0
    out = tmp_path / "snap.html"
    assert out.stat().st_mode & 0o777 == 0o600
    assert opened == [out.resolve().as_uri()]
    assert "wrote" in capsys.readouterr().out
    # the same name as the input would overwrite it
    assert main(["view", str(out), "-o", str(out)]) == 1


def test_view_of_a_json_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap_path, report = tmp_path / "snap.json", tmp_path / "report.json"
    snap_path.write_text(json.dumps(xss_snapshot().to_json()))
    assert main(["analyze", str(snap_path), "-f", "json", "-o", str(report)]) == 0
    out = tmp_path / "r.html"
    assert main(["view", str(report), "-o", str(out)]) == 0
    vm = json.loads(decode_payload(out.read_text()))
    assert vm["meta"]["source"] == "report" and vm["paths"]["list"]
    assert vm["meta"]["embedded"]["fixes"] is False
    # the parts that need a snapshot say so instead of building something half-empty
    capsys.readouterr()
    assert main(["view", str(report), "--fixes", "-o", str(out)]) == 1
    assert "needs a snapshot" in capsys.readouterr().err


def test_full_viewmodel(pages: dict[str, Path]) -> None:
    vm = json.loads(decode_payload(pages["full"].read_text()))
    b = vm["baseline"]
    assert {(r["id"], r["object"]) for r in b["new"]} >= {("AD-KRB-002", "eve")}
    assert ("AD-ACC-001", "bob") in {(r["id"], r["object"]) for r in b["resolved"]}
    status = {a["check"]: a["status"] for a in vm["acceptances"]}
    assert status == {"AD-KRB-003": "expiring", "AD-SEC-001": "expired", "AD-ACC-004": "stale"}
    inv = {s["section"]: s for s in vm["invariants"]["sections"]}
    assert not inv["settings"]["holds"] and not inv["templates"]["holds"]
    assert vm["lifecycle"] == {
        "accepted": 1, "expiring": 1, "expired": 1, "stale": 1, "drift": 2,
        "new": len(b["new"]),
    }  # fmt: skip
    krb = next(f for f in vm["findings"] if f["id"] == "AD-KRB-002")
    assert krb["fix"] and all(line.endswith("-WhatIf") for line in krb["fix"] if line[0] != "#")
    assert krb["doc"]["url"].endswith("/checks/AD-KRB-002/") and krb["doc"]["risk"]
    assert len(krb["fingerprints"]) == len(krb["objects"])
    assert vm["top_actions"][0]["id"] == "AD-ADCS-001"  # on the only control path


def test_scan_and_analyze_html_use_the_viewer(tmp_path: Path) -> None:
    _, new = full_snapshots()
    snap_path, out = tmp_path / "snap.json", tmp_path / "r.html"
    snap_path.write_text(json.dumps(new.to_json()))
    assert main(["analyze", str(snap_path), "-f", "html", "-o", str(out)]) == 0
    html = out.read_text()
    assert "Content-Security-Policy" in html and 'id="adoc-data"' in html
    vm = json.loads(decode_payload(html))
    assert vm["meta"]["command"] == "ad-doctor analyze snap.json -f html"
    assert vm["baseline"] is None and "fix" not in vm["findings"][0]


def test_safe_json_escapes_everything_that_matters() -> None:
    text = viewer.safe_json({"k": "</script><!-- & " + chr(0x2028) + chr(0x2029)})
    assert re.fullmatch(r"[^<>&  ]*", text)
    assert json.loads(text)["k"].startswith("</script>")


# --- paths: structured data, identities, chokepoints ------------------------------------


def test_path_finding_carries_structure_and_stable_keys() -> None:
    snap = snapshot(templates=[template("Esc", enrollee_supplies_subject=True)])
    f = only(snap, "AD-PATH-001")
    assert f.objects == ["Domain Users -[enroll (ESC1-3)]-> template Esc"]
    assert f.keys == {f.objects[0]: "Domain Users"}
    (p,) = f.data["paths"]
    assert p["start"]["name"] == "Domain Users" and p["start"]["kind"] == "group"
    assert p["steps"] == [
        {"how": "enroll (ESC1-3)", "id": "tier0:template:Esc", "name": "template Esc",
         "kind": "template", "tier0": True},
    ]  # fmt: skip
    rep = report_dict(Report(snap, [f]))["findings"][0]
    assert rep["fingerprints"][f.objects[0]] == fingerprint("AD-PATH-001", "Domain Users")
    assert rep["keys"] == f.keys and rep["data"]["paths"] == f.data["paths"]


def test_a_path_that_changes_route_is_not_new() -> None:
    old = Finding("AD-PATH-001", "t", Severity.HIGH, "", "", ["svc -[owns]-> X"])
    old.keys = legacy_keys("AD-PATH-001", old.objects)
    new = Finding("AD-PATH-001", "t", Severity.HIGH, "", "", ["svc -[member of]-> G -[owns]-> X"])
    new.keys = {new.objects[0]: "svc"}
    assert finding_keys([old]) == finding_keys([new]) == {("AD-PATH-001", "svc")}
    assert legacy_keys("AD-ACC-001", ["bob"]) == {}


def test_diff_shows_the_path_and_ignores_a_new_route(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    esc = [template("Esc", enrollee_supplies_subject=True)]
    old.write_text(json.dumps(snapshot(templates=esc).to_json()))
    new.write_text(json.dumps(snapshot(user("eve", NORMAL | 0x400000), templates=esc).to_json()))
    assert main(["diff", str(old), str(new)]) == 0
    out = capsys.readouterr().out
    assert "1 new, 0 resolved" in out and "AD-KRB-002  eve" in out


def test_accept_a_path_by_its_start() -> None:
    snap = snapshot(templates=[template("Esc", enrollee_supplies_subject=True)])
    entries = [accept.Entry("AD-PATH-001", {"domain users"}, "r", snap.collected_at.date())]
    kept, accepted, _ = accept.apply(run_all(snap), entries, snap.collected_at.date())
    assert "AD-PATH-001" not in {f.check_id for f in kept}
    assert accepted[0].objects == ["Domain Users -[enroll (ESC1-3)]-> template Esc"]
    assert accept.status(entries[0], snap.collected_at.date()) == "expiring"


def test_chokepoints() -> None:
    a = paths.Path("a", [("m", "x"), ("T", "y")])
    b = paths.Path("b", [("m", "x"), ("T", "y")])
    c = paths.Path("m", [("T", "y")])
    d = paths.Path("d", [("T", "z")])
    got = paths.chokepoints([a, b, c, d])
    assert got[0] == paths.Chokepoint("T", 3, "m", "y")
    assert got[1] == paths.Chokepoint("m", 3)  # starts one path, on two more
    assert paths.Chokepoint("T", 4) not in got  # the tier-0 end is not a place to cut
    assert [c.count for c in got] == [3, 3]  # a -> m and b -> m are different edges
    # the viewer shows m once: the edge m -> T and the node m break the same three paths
    assert viewer.merged_chokepoints(got) == [paths.Chokepoint("T", 3, "m", "y")]
    e = paths.Path("e", [("m", "w"), ("T", "v")])  # m on four paths, m -[y]-> T on three
    assert paths.Chokepoint("m", 4) in viewer.merged_chokepoints(paths.chokepoints([a, b, c, e]))
    assert paths.chokepoints([d]) == []
    assert paths.chokepoints([d], minimum=1)[0].is_edge


def test_paths_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap = xss_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap.to_json()))
    assert main(["paths", str(path)]) == 0
    assert "principals reach tier 0" in capsys.readouterr().out
    assert main(["paths", str(path), "--chokepoints", "--minimum", "1", "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["paths"] >= 2 and data["chokepoints"]
    assert main(["paths", str(path), "-f", "mermaid"]) == 0
    assert capsys.readouterr().out.startswith("```mermaid\nflowchart LR")
    assert main(["paths", str(path), "--chokepoints"]) == 0
    assert "paths to tier 0; shared by 2 or more" in capsys.readouterr().out
