"""Risk score and report renderers (text, JSON, Markdown, SARIF, JUnit; HTML is viewer.py)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import textwrap
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape
from xml.sax.saxutils import quoteattr

from . import __version__, coverage, docgen
from . import catalog as docs  # report.catalog() exists
from .checks import MITRE, REGISTRY
from .fixes import one_line
from .model import CATEGORIES, Finding, Severity, Snapshot

WEIGHT = {Severity.HIGH: 15, Severity.MEDIUM: 6, Severity.LOW: 2, Severity.INFO: 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (70, "D"), (100, "F")]
# version of the JSON report's layout: 2 added `schema` and `checks` (the check IDs that ran);
# 3 added `check_status` (what each check could judge) and `coverage` (its counts)
REPORT_SCHEMA = 3


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
    # what a JSON report recorded per check; a snapshot has none and works it out
    recorded: dict[str, coverage.CheckStatus] | None = None
    # False for a JSON report: only its notes are left of the snapshot behind it
    from_snapshot: bool = True
    # declared.Declaration.summary() when tier-0 assets were declared; None otherwise
    declared: dict[str, Any] | None = None
    # the ad-doctor version that wrote the JSON report this is built from
    report_version: str | None = None

    def statuses(self) -> dict[str, coverage.CheckStatus]:
        """Every check of this run: judged, not applicable, or not evaluated and why."""
        if self.recorded is not None:
            return self.recorded
        return coverage.compute(
            self.snap,
            [f.check_id for f in self.findings],
            [a.check_id for a in self.accepted],
            self.ran,
            use_data=self.from_snapshot,
            version=self.report_version,
        )

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


Key = tuple[str, str]


@dataclass
class Changes:
    """Two runs compared. Only `added` and `resolved` are changes in the domain."""

    added: list[Key]
    resolved: list[Key]
    # gone, but the newer run did not judge the check
    not_evaluated_now: list[Key]
    # there now, but the older run did not judge the check
    not_evaluated_before: list[Key]
    # a path to an asset one of the two runs did not declare
    declaration: list[Key]


def declared_nodes(summary: dict[str, Any] | None) -> set[str]:
    """The graph nodes a run declared as tier 0, from its `declared_tier0` block."""
    assets = summary.get("assets", []) if summary else []
    return {str(a["node"]) for a in assets if a.get("set") == "declared"}


def _declared_ends(findings: list[Finding]) -> dict[Key, str]:
    """The key of each path to a declared asset -> the node it ends at."""
    return {
        (f.check_id, f.key(p["object"])): str(p["steps"][-1]["id"])
        for f in findings
        for p in f.data.get("declared_paths", [])
        if p.get("steps")
    }


def compare(
    old: list[Finding],
    new: list[Finding],
    old_unknown: set[str],
    new_unknown: set[str],
    old_declared: set[str] | None,
    new_declared: set[str] | None,
) -> Changes:
    """What changed between two runs. A check one side did not judge says nothing about the
    other side's findings, and a path to an asset only one side declared is a change in the
    declaration, not in the domain. A declaration of None means the same as the other side's."""

    def moved(key: Key, ends: dict[Key, str], other: set[str] | None) -> bool:
        return other is not None and key in ends and ends[key] not in other

    before, after = finding_keys(old), finding_keys(new)
    ends_old, ends_new = _declared_ends(old), _declared_ends(new)
    out = Changes([], [], [], [], [])
    unknown = old_declared is None or new_declared is None
    for key in sorted(after - before):
        if not unknown and moved(key, ends_new, old_declared):
            out.declaration.append(key)
        elif key[0] in old_unknown:
            out.not_evaluated_before.append(key)
        else:
            out.added.append(key)
    for key in sorted(before - after):
        if not unknown and moved(key, ends_old, new_declared):
            out.declaration.append(key)
        elif key[0] in new_unknown:
            out.not_evaluated_now.append(key)
        else:
            out.resolved.append(key)
    out.declaration.sort()
    return out


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


MAX_LISTED_CHECKS = 20


def _listed(ids: list[str]) -> str:
    more = len(ids) - MAX_LISTED_CHECKS
    return ", ".join(ids[:MAX_LISTED_CHECKS]) + (f" (+{more} more)" if more > 0 else "")


def _status_lines(statuses: dict[str, coverage.CheckStatus]) -> list[str]:
    """The checks a reader must not take for clean, by reason."""
    rows = list(statuses.values())
    counts = coverage.summary(statuses, [])
    lines = [
        f"checks: {counts[coverage.JUDGED]} judged, {counts[coverage.NOT_APPLICABLE]} not "
        f"applicable, {counts[coverage.NOT_EVALUATED]} not evaluated"
    ]
    for reason, text in coverage.REASON_TEXT.items():
        ids = [s.id for s in rows if s.status == coverage.NOT_EVALUATED and s.reason == reason]
        if ids:
            lines.append(f"not evaluated ({text}): {_listed(ids)}")
    na = [s.id for s in rows if s.status == coverage.NOT_APPLICABLE]
    if na:
        lines.append(f"not applicable: {_listed(na)}")
    partial = [s.id for s in rows if s.partial]
    if partial:
        lines.append(f"judged in part: {_listed(partial)}")
    return lines


def _minimum(statuses: dict[str, coverage.CheckStatus], notes: list[str]) -> str:
    """How the score reads when some checks gave no answer; empty when all of them did."""
    if not any(s.status == coverage.NOT_EVALUATED for s in statuses.values()):
        return (
            "a minimum: a failed search was not tied to a check"
            if coverage.unattributed(notes)
            else ""
        )
    n = sum(s.status == coverage.NOT_EVALUATED for s in statuses.values())
    return f"a minimum: {n} check{'s' if n != 1 else ''} not evaluated" if n else ""


def render_text(r: Report, color: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    snap = r.snap
    statuses = r.statuses()
    minimum = _minimum(statuses, snap.notes)
    lines = [
        c(BOLD, f"ad-doctor {__version__}")
        + f"  domain {snap.domain}  {len(snap.accounts)} accounts  "
        f"{len(snap.templates)} cert templates  {snap.collected_at:%Y-%m-%d %H:%M} UTC",
        "",
    ]
    if not r.findings:
        lines += ["No findings in the checks judged." if minimum else "No findings.", ""]
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
    lines += [one_line(line) for line in declared_lines(r.declared)]
    for note in snap.notes:
        lines.append(c(DIM, f"note: {one_line(note)}"))
    lines += [c(DIM, line) for line in _status_lines(statuses)]
    counts = r.counts()
    lines.append(
        f"risk score {c(BOLD, str(r.score))}/100 (grade {r.grade})  "
        + (f"{minimum}  " if minimum else "")
        + "  ".join(c(SEVERITY_COLOR[s], f"{s!s} {counts[s]}") for s in reversed(Severity))
    )
    if r.findings:
        lines.append(c(DIM, "details and fixes for a finding: ad-doctor explain <ID>"))
    return "\n".join(lines)


# --- JSON ----------------------------------------------------------------------------


def report_dict(r: Report) -> dict[str, Any]:
    statuses = r.statuses()
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
        **({"declared_tier0": r.declared} if r.declared is not None else {}),
        **({"checks": sorted(r.ran)} if r.ran is not None else {}),
        "check_status": [s.to_json() for _, s in sorted(statuses.items())],
        "coverage": coverage.summary(statuses, r.snap.notes),
    }


def _extra(f: Finding) -> dict[str, Any]:
    """keys and data, limited to the objects still in the finding (acceptances remove some)."""
    out: dict[str, Any] = {}
    keys = {o: f.keys[o] for o in f.objects if o in f.keys}
    if keys:
        out["keys"] = keys
    if f.data:
        data = dict(f.data)
        kept = set(f.objects)
        for key in ("paths", "declared_paths"):
            if isinstance(data.get(key), list):
                data[key] = [p for p in data[key] if p.get("object") in kept]
        out["data"] = data
    return out


def render_json(r: Report) -> str:
    return json.dumps(report_dict(r), indent=2)


def write_private(path: Path, text: str | Iterable[str]) -> None:
    """Write a file only its owner can read: snapshots, reports and fix scripts describe
    how to attack the domain they came from."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)  # the mode above applies only to a new file
        out = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    with out:
        out.writelines([text] if isinstance(text, str) else text)


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
    statuses = r.statuses()
    minimum = _minimum(statuses, snap.notes)
    out = [
        f"# ad-doctor report: {snap.domain}",
        "",
        f"Collected {snap.collected_at:%Y-%m-%d %H:%M} UTC with ad-doctor {__version__}. "
        f"Risk score **{r.score}/100** (grade **{r.grade}**): "
        + ", ".join(f"{counts[s]} {s}" for s in reversed(Severity))
        + "."
        + (f" The score is {minimum}." if minimum else ""),
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
    if r.declared is not None:
        out += [
            "",
            "## Declared tier 0",
            "",
            *[f"- {_prose(x)}" for x in declared_lines(r.declared)],
        ]
    out += _markdown_status(statuses)
    if snap.notes:
        out += ["", "## Notes", "", *[f"- {_prose(n)}" for n in snap.notes]]
    return "\n".join(out) + "\n"


def declared_lines(declared: dict[str, Any] | None) -> list[str]:
    """The declared tier-0 assets, one line each, then the totals."""
    if declared is None:
        return []
    lines = ["declared tier 0 (extended targets; built-in tier 0 is unchanged):"]
    for a in declared["assets"]:
        where = f"  {a['name']} ({a['kind']}, from {a['source']}): "
        if a["set"] == "built-in":
            lines.append(where + "already built-in tier 0")
        elif a["status"] == "not_evaluated":
            seen = a.get("principals", 0)
            lines.append(
                f"{where}not evaluated: {a['reason']}; {seen} principals have a path that needs "
                "no DACL of its own"
            )
        else:
            lines.append(f"{where}{a.get('principals', 0)} principals have a path")
    lines.append(
        f"  {declared['paths']} principals hold a path to a declared asset; "
        f"{declared['exposed_with_declared']} of {declared['users_with_declared']} enabled "
        "users outside both sets have a path to either"
    )
    return lines


def _status_why(s: coverage.CheckStatus) -> str:
    reason = coverage.REASON_TEXT.get(s.reason or "", "")
    return reason + (": " if reason and s.notes else "") + "; ".join(s.notes)


def _markdown_status(statuses: dict[str, coverage.CheckStatus]) -> list[str]:
    rows = sorted(statuses.values(), key=lambda s: s.id)
    counts = coverage.summary(statuses, [])
    out = [
        "",
        "## Check status",
        "",
        f"{counts[coverage.JUDGED]} judged, {counts[coverage.NOT_APPLICABLE]} not applicable, "
        f"{counts[coverage.NOT_EVALUATED]} not evaluated.",
    ]
    for status, heading in (
        (coverage.NOT_EVALUATED, "Not evaluated"),
        (coverage.NOT_APPLICABLE, "Not applicable"),
    ):
        hits = [s for s in rows if s.status == status]
        if hits:
            out += ["", f"| {heading} | Check | Why |", "|---|---|---|"]
            out += [f"| {s.id} | {_md(s.title)} | {_md(_status_why(s))} |" for s in hits]
    return out


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


def _sarif_notifications(r: Report) -> list[dict[str, Any]]:
    """The collection notes; one that names checks says which were not fully judged."""
    out: list[dict[str, Any]] = []
    for note in r.snap.notes:
        checks = sorted(coverage.named_checks(note))
        item: dict[str, Any] = {
            "level": "warning" if checks else "note",
            "message": {"text": note},
        }
        if checks:
            item["properties"] = {"notJudged": checks}
        out.append(item)
    return out


def _sarif_status(statuses: dict[str, coverage.CheckStatus]) -> list[dict[str, Any]]:
    """A check that gave no answer is a condition of this run, not a result: one notification
    each, tied to its rule."""
    return [
        {
            "level": "note" if s.reason == coverage.SWITCHED_OFF else "warning",
            "message": {"text": f"{s.id} not evaluated: {_status_why(s)}"},
            "associatedRule": {"id": s.id},
            "properties": {"status": s.status, "reason": s.reason},
        }
        for _, s in sorted(statuses.items())
        if s.status == coverage.NOT_EVALUATED
    ]


def render_sarif(r: Report) -> str:
    by_id = {f.check_id: f for f in r.findings}
    statuses = r.statuses()
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
        if (st := statuses.get(check_id)) is not None:
            props["status"] = st.status
            if st.reason is not None:
                props["statusReason"] = st.reason
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
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolConfigurationNotifications": _sarif_notifications(r),
                        "toolExecutionNotifications": _sarif_status(statuses),
                    }
                ],
                "results": results,
                "properties": {"coverage": coverage.summary(statuses, r.snap.notes)},
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# --- JUnit ---------------------------------------------------------------------------


def render_junit(r: Report, ran: list[str] | None = None) -> str:
    """One test case per check: failed when it found something, skipped when accepted, not
    applicable or not evaluated. `ran` narrows the cases; without it every check is listed,
    so a check that was switched off shows as skipped rather than vanishing."""
    by_id = {f.check_id: f for f in r.findings}
    accepted = {a.check_id for a in r.accepted}
    statuses = r.statuses()
    checks = catalog(r)
    registered = {c.id for c in REGISTRY}
    # checks that ran, plus findings that do not come from a registered check (invariants)
    ids = set(ran if ran is not None else registered) | (by_id.keys() - registered)
    unknown = {c for c, s in statuses.items() if s.status != coverage.JUDGED}
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
        elif check_id in unknown:
            st = statuses[check_id]
            label = "not applicable" if st.status == coverage.NOT_APPLICABLE else "not evaluated"
            why = quoteattr(_xml_safe(f"{label}: {_status_why(st)}"))
            cases.append(
                f'  <testcase classname="ad-doctor" name={name}><skipped message={why}/></testcase>'
            )
        else:
            cases.append(f'  <testcase classname="ad-doctor" name={name}/>')
    failures = sum(1 for i in ids if i in by_id)
    skipped = sum(1 for i in ids if (i in accepted or i in unknown) and i not in by_id)
    suite = quoteattr(_xml_safe(f"ad-doctor {r.snap.domain}"))
    header = (
        f'<testsuite name={suite} tests="{len(cases)}" failures="{failures}" '
        f'skipped="{skipped}" errors="0">'
    )
    notes = xml_escape(_xml_safe("\n".join(r.snap.notes)))
    out = ['<?xml version="1.0" encoding="UTF-8"?>', header, *cases]
    if notes:
        out.append(f"  <system-out>{notes}</system-out>")
    return "\n".join([*out, "</testsuite>"])
