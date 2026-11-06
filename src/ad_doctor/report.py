"""Risk score and report renderers (text, JSON, Markdown, SARIF, JUnit; HTML is viewer.py)."""

from __future__ import annotations

import hashlib
import json
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any
from xml.sax.saxutils import escape as xml_escape
from xml.sax.saxutils import quoteattr

from . import __version__, docgen
from . import catalog as docs  # report.catalog() exists
from .checks import MITRE, REGISTRY
from .fixes import one_line
from .model import CATEGORIES, Finding, Severity, Snapshot

WEIGHT = {Severity.HIGH: 15, Severity.MEDIUM: 6, Severity.LOW: 2, Severity.INFO: 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (70, "D"), (100, "F")]
# version of the JSON report's layout: 2 added `schema` and `checks` (the check IDs that ran)
REPORT_SCHEMA = 2


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
    # check IDs that ran, when known (a trend marks the scans where the set changed)
    ran: list[str] | None = None

    @property
    def score(self) -> int:
        """0 (nothing found) to 100; each finding adds its severity weight."""
        return score_of(self.findings)

    @property
    def grade(self) -> str:
        return grade_of(self.score)

    def category_scores(self) -> dict[str, int]:
        scores = {c: 0 for c in dict.fromkeys(CATEGORIES.values())}
        for f in self.findings:
            scores[f.category] = min(100, scores[f.category] + WEIGHT[f.severity])
        return scores

    def counts(self) -> dict[Severity, int]:
        return {s: sum(f.severity == s for f in self.findings) for s in Severity}

    def is_new(self, f: Finding) -> bool:
        return self.new is not None and any((f.check_id, f.key(o)) in self.new for o in f.objects)


def score_of(findings: list[Finding]) -> int:
    return min(100, sum(WEIGHT[f.severity] for f in findings))


def grade_of(score: int) -> str:
    return next(g for limit, g in GRADES if score <= limit)


def fingerprint(check_id: str, obj: str) -> str:
    """Stable ID of one finding on one object, for ticket systems and SARIF. `obj` is the
    object's identity (`Finding.key`), so a path that changes shape keeps its fingerprint."""
    return hashlib.sha256(f"{check_id}|{obj}".encode()).hexdigest()[:16]


def finding_keys(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.check_id, f.key(o)) for f in findings for o in f.objects}


def legacy_keys(check_id: str, objects: list[str]) -> dict[str, str]:
    """Identities for a JSON report written before reports carried `keys`: an AD-PATH-001
    object is a rendered path, and its identity is the principal it starts from."""
    if check_id != "AD-PATH-001":
        return {}
    return {o: PATH_STEP.split(o, 1)[0] for o in objects}


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
        lines.append(_wrap(one_line(f.detail)))
        shown = [one_line(o) for o in f.objects[:10]]
        more = f" (+{len(f.objects) - len(shown)} more)" if len(f.objects) > len(shown) else ""
        lines.append(_wrap(", ".join(shown) + more, c(DIM, "objects:") + " ", len("objects: ")))
        lines.append(_wrap(one_line(f.remediation), c(DIM, "fix:") + " ", len("fix: ")))
        lines.append("")
    for a in r.accepted:
        scope = ", ".join(a.objects) if a.objects else "all objects"
        accepted = f"accepted: {a.check_id} ({scope}) until {a.expires}: {a.reason}"
        lines.append(c(DIM, one_line(accepted)))
    for note in snap.notes:
        lines.append(c(DIM, f"note: {one_line(note)}"))
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
        "schema": REPORT_SCHEMA,
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
                "fingerprints": {o: fingerprint(f.check_id, f.key(o)) for o in f.objects},
                "mitre": f.mitre,
                **({"new": r.is_new(f)} if r.new is not None else {}),
                **_extra(f),
            }
            for f in r.findings
        ],
        "accepted": [a.__dict__ for a in r.accepted],
        "notes": r.snap.notes,
        **({"checks": sorted(r.ran)} if r.ran is not None else {}),
    }


def _extra(f: Finding) -> dict[str, Any]:
    """keys and data, limited to the objects still in the finding (acceptances remove some)."""
    out: dict[str, Any] = {}
    keys = {o: f.keys[o] for o in f.objects if o in f.keys}
    if keys:
        out["keys"] = keys
    if f.data:
        data = dict(f.data)
        if isinstance(data.get("paths"), list):
            kept = set(f.objects)
            data["paths"] = [p for p in data["paths"] if p.get("object") in kept]
        out["data"] = data
    return out


def render_json(r: Report) -> str:
    return json.dumps(report_dict(r), indent=2)


# --- Markdown ------------------------------------------------------------------------


_CONTROL = re.compile("[\x00-\x1f\x7f\x85\u2028\u2029]")
_BACKTICKS = re.compile("`+")
# Not allowed in XML 1.0 even as an entity; directory text can hold them
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_safe(text: str) -> str:
    return _XML_ILLEGAL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def _flat(text: str) -> str:
    """One line: object and detail text carries directory names, and a line break in one
    would end the list item or paragraph and let the rest be read as Markdown."""
    return _CONTROL.sub(" ", text)


def _prose(text: str) -> str:
    """Text outside a code span: a tag in a directory name stays text."""
    return _flat(text).replace("<", "\\<")


def _md(text: str) -> str:
    return _prose(text).replace("|", "\\|")


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
            _prose(f.detail),
            "",
            f"**Fix:** {_prose(f.remediation)}" + _docs_suffix(f.check_id),
            "",
            *[f"- {_code(o)}" for o in f.objects],
        ]
        if f.check_id == "AD-PATH-001":
            out += ["", *mermaid_paths(f.objects)]
    if r.accepted:
        out += ["", "## Accepted risks", ""]
        for a in r.accepted:
            scope = ", ".join(a.objects) or "all objects"
            out.append(_prose(f"- {a.check_id} ({scope}), until {a.expires}: {a.reason}"))
    if snap.notes:
        out += ["", "## Notes", "", *[f"- {_prose(n)}" for n in snap.notes]]
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
            "partialFingerprints": {"adDoctor/v1": fingerprint(f.check_id, f.key(o))},
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
            body = xml_escape(_xml_safe("\n".join(lines)))
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
    suite = quoteattr(_xml_safe(f"ad-doctor {r.snap.domain}"))
    header = (
        f'<testsuite name={suite} tests="{len(cases)}" failures="{failures}" '
        f'skipped="{skipped}" errors="0">'
    )
    return "\n".join(['<?xml version="1.0" encoding="UTF-8"?>', header, *cases, "</testsuite>"])
