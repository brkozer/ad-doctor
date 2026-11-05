"""Risk score and report renderers (text, JSON, Markdown, HTML, SARIF)."""

from __future__ import annotations

import hashlib
import json
import re
import textwrap
from dataclasses import dataclass, field
from html import escape
from typing import Any
from xml.sax.saxutils import escape as xml_escape
from xml.sax.saxutils import quoteattr

from . import __version__, docgen
from . import catalog as docs  # report.catalog() exists
from .checks import MITRE, REGISTRY
from .model import CATEGORIES, Finding, Severity, Snapshot

WEIGHT = {Severity.HIGH: 15, Severity.MEDIUM: 6, Severity.LOW: 2, Severity.INFO: 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (70, "D"), (100, "F")]


@dataclass
class Accepted:
    check_id: str
    objects: list[str]
    reason: str
    expires: str


@dataclass
class Report:
    snap: Snapshot
    findings: list[Finding]
    accepted: list[Accepted] = field(default_factory=list)
    # (check_id, object) pairs not present in the baseline; None when no baseline was given
    new: set[tuple[str, str]] | None = None

    @property
    def score(self) -> int:
        """0 (nothing found) to 100; each finding adds its severity weight."""
        return min(100, sum(WEIGHT[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        return next(g for limit, g in GRADES if self.score <= limit)

    def category_scores(self) -> dict[str, int]:
        scores = {c: 0 for c in dict.fromkeys(CATEGORIES.values())}
        for f in self.findings:
            scores[f.category] = min(100, scores[f.category] + WEIGHT[f.severity])
        return scores

    def counts(self) -> dict[Severity, int]:
        return {s: sum(f.severity == s for f in self.findings) for s in Severity}

    def is_new(self, f: Finding) -> bool:
        return self.new is not None and any((f.check_id, o) in self.new for o in f.objects)


def fingerprint(check_id: str, obj: str) -> str:
    """Stable ID of one finding on one object, for ticket systems and SARIF."""
    return hashlib.sha256(f"{check_id}|{obj}".encode()).hexdigest()[:16]


def finding_keys(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.check_id, o) for f in findings for o in f.objects}


# --- text ----------------------------------------------------------------------------

SEVERITY_COLOR = {
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
INDENT = " " * 9
WIDTH = 100


def _wrap(text: str, prefix: str = "", prefix_len: int = 0) -> str:
    lines = textwrap.wrap(text, WIDTH - len(INDENT) - prefix_len, break_on_hyphens=False)
    first = f"{INDENT}{prefix}{lines[0]}" if lines else INDENT + prefix
    rest = [INDENT + " " * prefix_len + line for line in lines[1:]]
    return "\n".join([first, *rest])


def render_text(r: Report, color: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    snap = r.snap
    lines = [
        c(BOLD, f"ad-doctor {__version__}")
        + f"  domain {snap.domain}  {len(snap.accounts)} accounts  "
        f"{len(snap.templates)} cert templates  {snap.collected_at:%Y-%m-%d %H:%M} UTC",
        "",
    ]
    if not r.findings:
        lines += ["No findings.", ""]
    for f in r.findings:
        tag = c(SEVERITY_COLOR[f.severity], f"[{str(f.severity).upper():6}]")
        new = c(BOLD, " NEW") if r.is_new(f) else ""
        lines.append(f"{tag} {c(BOLD, f.check_id)}  {f.title}{new}")
        lines.append(_wrap(f.detail))
        shown = f.objects[:10]
        more = f" (+{len(f.objects) - len(shown)} more)" if len(f.objects) > len(shown) else ""
        lines.append(_wrap(", ".join(shown) + more, c(DIM, "objects:") + " ", len("objects: ")))
        lines.append(_wrap(f.remediation, c(DIM, "fix:") + " ", len("fix: ")))
        lines.append("")
    for a in r.accepted:
        scope = ", ".join(a.objects) if a.objects else "all objects"
        lines.append(c(DIM, f"accepted: {a.check_id} ({scope}) until {a.expires}: {a.reason}"))
    for note in snap.notes:
        lines.append(c(DIM, f"note: {note}"))
    counts = r.counts()
    lines.append(
        f"risk score {c(BOLD, str(r.score))}/100 (grade {r.grade})  "
        + "  ".join(c(SEVERITY_COLOR[s], f"{s!s} {counts[s]}") for s in reversed(Severity))
    )
    if r.findings:
        lines.append(c(DIM, "details and fixes for a finding: ad-doctor explain <ID>"))
    return "\n".join(lines)


# --- JSON ----------------------------------------------------------------------------


def report_dict(r: Report) -> dict[str, Any]:
    return {
        "tool": "ad-doctor",
        "version": __version__,
        "domain": r.snap.domain,
        "collected_at": r.snap.collected_at.isoformat(),
        "score": r.score,
        "grade": r.grade,
        "category_scores": r.category_scores(),
        "findings": [
            {
                "id": f.check_id,
                "title": f.title,
                "category": f.category,
                "severity": str(f.severity),
                "detail": f.detail,
                "remediation": f.remediation,
                "objects": f.objects,
                "fingerprints": {o: fingerprint(f.check_id, o) for o in f.objects},
                "mitre": f.mitre,
                **({"new": r.is_new(f)} if r.new is not None else {}),
            }
            for f in r.findings
        ],
        "accepted": [a.__dict__ for a in r.accepted],
        "notes": r.snap.notes,
    }


def render_json(r: Report) -> str:
    return json.dumps(report_dict(r), indent=2)


# --- Markdown ------------------------------------------------------------------------


_CONTROL = re.compile("[\x00-\x1f\x7f\x85\u2028\u2029]")
_BACKTICKS = re.compile("`+")


def _flat(text: str) -> str:
    """One line: object and detail text carries directory names, and a line break in one
    would end the list item or paragraph and let the rest be read as Markdown."""
    return _CONTROL.sub(" ", text)


def _md(text: str) -> str:
    return _flat(text).replace("|", "\\|")


def _code(text: str) -> str:
    """A code span that holds any text: its fence is longer than every backtick run."""
    text = _flat(text)
    fence = "`" * (max((len(m) for m in _BACKTICKS.findall(text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _docs_suffix(check_id: str) -> str:
    e = docs.get(check_id)
    return f" ([docs]({e.url}))" if e else ""


def render_markdown(r: Report) -> str:
    snap = r.snap
    counts = r.counts()
    out = [
        f"# ad-doctor report: {snap.domain}",
        "",
        f"Collected {snap.collected_at:%Y-%m-%d %H:%M} UTC with ad-doctor {__version__}. "
        f"Risk score **{r.score}/100** (grade **{r.grade}**): "
        + ", ".join(f"{counts[s]} {s}" for s in reversed(Severity))
        + ".",
        "",
        "| Severity | ID | Finding | Objects |",
        "|---|---|---|---|",
    ]
    for f in r.findings:
        objs = ", ".join(f.objects[:5]) + (
            f" (+{len(f.objects) - 5})" if len(f.objects) > 5 else ""
        )
        out.append(f"| {f.severity} | {f.check_id} | {_md(f.title)} | {_md(objs)} |")
    for f in r.findings:
        out += [
            "",
            f"## {f.check_id}: {f.title}",
            "",
            f"**Severity:** {f.severity}. **Category:** {f.category}."
            + (f" **ATT&CK:** {', '.join(f.mitre)}." if f.mitre else ""),
            "",
            _flat(f.detail),
            "",
            f"**Fix:** {_flat(f.remediation)}" + _docs_suffix(f.check_id),
            "",
            *[f"- {_code(o)}" for o in f.objects],
        ]
        if f.check_id == "AD-PATH-001":
            out += ["", *mermaid_paths(f.objects)]
    if r.accepted:
        out += ["", "## Accepted risks", ""]
        for a in r.accepted:
            scope = ", ".join(a.objects) or "all objects"
            out.append(f"- {a.check_id} ({scope}), until {a.expires}: {a.reason}")
    if snap.notes:
        out += ["", "## Notes", "", *[f"- {_flat(n)}" for n in snap.notes]]
    return "\n".join(out) + "\n"


PATH_STEP = re.compile(r" -\[([^\]]+)\]-> ")


def mermaid_paths(paths: list[str], limit: int = 15) -> list[str]:
    """A Mermaid flowchart of rendered control paths (`a -[how]-> b -[how]-> c`)."""
    ids: dict[str, str] = {}

    def node(name: str) -> str:
        if name not in ids:
            ids[name] = f"n{len(ids)}"
        label = _flat(name).replace('"', "'")
        return f'{ids[name]}["{label}"]'

    lines = ["```mermaid", "flowchart LR"]
    edges = set()
    for path in paths[:limit]:
        parts = PATH_STEP.split(path)
        for i in range(0, len(parts) - 2, 2):
            src, how, dst = parts[i], parts[i + 1], parts[i + 2]
            edge = f'    {node(src)} -- "{how}" --> {node(dst)}'
            if edge not in edges:
                edges.add(edge)
                lines.append(edge)
    if len(paths) > limit:
        lines.append(f'    more["+{len(paths) - limit} more paths"]')
    lines.append("```")
    return lines


# --- HTML ----------------------------------------------------------------------------

HTML_STYLE = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;
--high:#c2261d;--medium:#b86e00;--low:#2a6fb0;--info:#7a7a7f;--ok:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--fg:#ececee;
--muted:#9a9aa0;--line:#2e2e33;--high:#ff6b5e;--medium:#f0a63a;--low:#6aa8ff;--info:#9a9aa0;
--ok:#4cc27f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.muted{color:var(--muted)}.grid{display:grid;gap:16px;
grid-template-columns:repeat(auto-fit,minmax(220px,1fr));align-items:start;margin-top:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.score{font-size:44px;font-weight:700;line-height:1}.grade{font-size:15px;color:var(--muted)}
.bar{height:8px;border-radius:4px;background:var(--line);overflow:hidden;margin-top:6px}
.bar>span{display:block;height:100%}
.cat{display:flex;justify-content:space-between;font-size:14px;margin-top:10px}
.sev{display:inline-block;min-width:64px;text-align:center;font-size:12px;font-weight:600;
text-transform:uppercase;border-radius:4px;padding:2px 6px;color:#fff}
.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}
.sev.low{background:var(--low)}.sev.info{background:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;
margin:10px 0;padding:0 16px}summary{cursor:pointer;padding:14px 0;display:flex;gap:12px;
align-items:center;list-style:none}summary::-webkit-details-marker{display:none}
summary code{color:var(--muted);font-size:13px}.body{padding:0 0 16px}
.objs{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.objs code{background:var(--bg);border:1px solid var(--line);border-radius:4px;
padding:1px 6px;font-size:13px;overflow-wrap:anywhere}
.tag{font-size:12px;color:var(--muted);margin-left:auto;white-space:nowrap}
.new{color:var(--high);font-weight:700;font-size:12px}
a{color:var(--low)}ul{padding-left:20px}
"""


def _color(score: int) -> str:
    if score == 0:
        return "var(--ok)"
    return "var(--high)" if score > 45 else "var(--medium)" if score > 10 else "var(--low)"


def _doc_link(check_id: str) -> str:
    code = f"<code>{escape(check_id)}</code>"
    e = docs.get(check_id)
    return f'<a href="{escape(e.url)}">{code}</a>' if e else code


def render_html(r: Report) -> str:
    snap = r.snap
    counts = r.counts()
    cats = "".join(
        f'<div class="cat"><span>{escape(c)}</span><span>{s}</span></div>'
        f'<div class="bar"><span style="width:{max(s, 2)}%;background:{_color(s)}"></span></div>'
        for c, s in r.category_scores().items()
    )
    sev_rows = "".join(
        f'<div class="cat"><span><span class="sev {s}">{s}</span></span>'
        f"<span>{counts[s]}</span></div>"
        for s in reversed(Severity)
    )
    items = []
    for f in r.findings:
        mitre = ", ".join(
            f'<a href="https://attack.mitre.org/techniques/{escape(t.replace(".", "/"))}/">'
            f"{escape(t)}</a>"
            for t in f.mitre
        )
        objs = "".join(f"<code>{escape(o)}</code>" for o in f.objects)
        new = '<span class="new">NEW</span>' if r.is_new(f) else ""
        items.append(
            f"<details{' open' if f.severity is Severity.HIGH else ''}><summary>"
            f'<span class="sev {f.severity}">{f.severity}</span>'
            f"<strong>{escape(f.title)}</strong>{new}"
            f'<span class="tag">{escape(f.category)} · {_doc_link(f.check_id)}</span>'
            f'</summary><div class="body"><p>{escape(f.detail)}</p>'
            f'<div class="objs">{objs}</div>'
            f"<p><strong>Fix:</strong> {escape(f.remediation)}</p>"
            + (f'<p class="muted">MITRE ATT&amp;CK: {mitre}</p>' if mitre else "")
            + "</div></details>"
        )
    accepted = "".join(
        f"<li><code>{a.check_id}</code> ({escape(', '.join(a.objects) or 'all objects')}) "
        f"until {escape(a.expires)}: {escape(a.reason)}</li>"
        for a in r.accepted
    )
    notes = "".join(f"<li>{escape(n)}</li>" for n in snap.notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ad-doctor: {escape(snap.domain)}</title><style>{HTML_STYLE}</style></head>
<body><main>
<h1>Active Directory report: {escape(snap.domain)}</h1>
<div class="muted">Collected {snap.collected_at:%Y-%m-%d %H:%M} UTC · ad-doctor {__version__} ·
{len(snap.accounts)} accounts · {len(snap.templates)} certificate templates</div>
<div class="grid">
<div class="card"><div class="muted">Risk score</div>
<div class="score" style="color:{_color(r.score)}">{r.score}<span class="grade">/100</span></div>
<div class="grade">Grade {r.grade} · lower is better</div>
<div class="bar"><span style="width:{max(r.score, 2)}%;background:{_color(r.score)}"></span></div>
</div>
<div class="card"><div class="muted">Findings by severity</div>{sev_rows}</div>
<div class="card"><div class="muted">Risk by category</div>{cats}</div>
</div>
<h2>Findings ({len(r.findings)})</h2>
{"".join(items) or "<p>No findings.</p>"}
{f"<h2>Accepted risks</h2><ul>{accepted}</ul>" if accepted else ""}
{f"<h2>Notes</h2><ul>{notes}</ul>" if notes else ""}
</main></body></html>
"""


# --- SARIF ---------------------------------------------------------------------------

SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


def catalog(r: Report) -> list[tuple[str, str]]:
    """(id, title) of every registered check plus findings from elsewhere (invariants)."""
    known = [(c.id, c.title) for c in REGISTRY]
    ids = {c for c, _ in known}
    extra = {f.check_id: f.title for f in r.findings if f.check_id not in ids}
    return known + sorted(extra.items())


def _sarif_help(e: docs.Entry, f: Finding | None) -> dict[str, str]:
    """GitHub code scanning shows help.markdown under every alert of the rule."""
    fix = f.remediation if f is not None else f"see {e.url}"
    refs = "\n".join(f"- [{x.title}]({x.url})" for x in e.references)
    md = docgen.absolute_links(
        f"{e.risk}\n\n## Fix\n\n{e.remediation}\n\n## References\n\n{refs}\n\n"
        f"[Full documentation]({e.url})"
    )
    return {"text": f"{e.summary}\n\nFix: {fix}", "markdown": md}


def render_sarif(r: Report) -> str:
    by_id = {f.check_id: f for f in r.findings}
    rules: list[dict[str, Any]] = []
    for check_id, title in catalog(r):
        props: dict[str, Any] = {
            "tags": [
                "security",
                "active-directory",
                *(f"mitre/{t}" for t in MITRE.get(check_id, ())),
            ]
        }
        rule: dict[str, Any] = {
            "id": check_id,
            "name": check_id.lower().replace("-", "_"),
            "shortDescription": {"text": title},
            "properties": props,
        }
        f = by_id.get(check_id)
        e = docs.get(check_id)
        if e is not None:
            rule["fullDescription"] = {"text": e.summary}
            rule["helpUri"] = e.url
            rule["help"] = _sarif_help(e, f)
            top = Severity[e.top_severity.upper()]
            props["security-severity"] = SECURITY_SEVERITY.get(top, "1.0")
        elif f is not None:
            rule["help"] = {"text": f.remediation}
        if f is not None:
            # the severity it fired with beats the worst case the catalog lists
            props["security-severity"] = SECURITY_SEVERITY.get(f.severity, "1.0")
        rules.append(rule)
    results = [
        {
            "ruleId": f.check_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.detail} Object: {o}"},
            "partialFingerprints": {"adDoctor/v1": fingerprint(f.check_id, o)},
            "locations": [
                {
                    "physicalLocation": {"artifactLocation": {"uri": f"ad/{r.snap.domain}"}},
                    "logicalLocations": [{"name": o, "fullyQualifiedName": f"{r.snap.domain}/{o}"}],
                }
            ],
        }
        for f in r.findings
        for o in f.objects
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ad-doctor",
                        "version": __version__,
                        "informationUri": "https://github.com/brkozer/ad-doctor",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# --- JUnit ---------------------------------------------------------------------------


def render_junit(r: Report, ran: list[str] | None = None) -> str:
    """One test case per check: failed when it found something, skipped when accepted."""
    by_id = {f.check_id: f for f in r.findings}
    accepted = {a.check_id for a in r.accepted}
    checks = catalog(r)
    registered = {c.id for c in REGISTRY}
    # checks that ran, plus findings that do not come from a registered check (invariants)
    ids = set(ran if ran is not None else registered) | (by_id.keys() - registered)
    cases = []
    for check_id, title in checks:
        if check_id not in ids:
            continue
        name = quoteattr(f"{check_id} {title}")
        f = by_id.get(check_id)
        if f is not None:
            lines = [f.detail, *f.objects, f"fix: {f.remediation}"]
            if (e := docs.get(check_id)) is not None:
                lines.append(f"docs: {e.url}")
            body = xml_escape("\n".join(lines))
            cases.append(
                f'  <testcase classname="ad-doctor.{f.category}" name={name}>'
                f"<failure type={quoteattr(str(f.severity))} message={quoteattr(f.title)}>"
                f"{body}</failure></testcase>"
            )
        elif check_id in accepted:
            cases.append(
                f'  <testcase classname="ad-doctor" name={name}>'
                '<skipped message="accepted risk"/></testcase>'
            )
        else:
            cases.append(f'  <testcase classname="ad-doctor" name={name}/>')
    failures = sum(1 for i in ids if i in by_id)
    skipped = sum(1 for i in ids if i in accepted and i not in by_id)
    suite = quoteattr(f"ad-doctor {r.snap.domain}")
    header = (
        f'<testsuite name={suite} tests="{len(cases)}" failures="{failures}" '
        f'skipped="{skipped}" errors="0">'
    )
    return "\n".join(['<?xml version="1.0" encoding="UTF-8"?>', header, *cases, "</testsuite>"])
