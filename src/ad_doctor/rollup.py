"""One view over the JSON reports of several domains (`ad-doctor rollup`).

Each report is one domain, as `scan -f json` or `analyze -f json` writes it. Scores are shown
per domain and never averaged. A check that did not run in a domain, or that a note says could
not judge everything, is listed as not judged there: that is different from a clean result.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .coverage import named_checks
from .fixes import one_line
from .report import _md
from .trend import SEVERITIES, point

ROLLUP_SCHEMA = 1


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"rollup: {path.name}: {exc}") from exc
    if not isinstance(data, dict) or data.get("tool") != "ad-doctor" or "domain" not in data:
        raise ValueError(f"rollup: {path.name}: not an ad-doctor JSON report (use -f json)")
    return data


def _not_judged(data: dict[str, Any]) -> list[str]:
    found = {cid for note in data.get("notes", []) for cid in named_checks(str(note))}
    return sorted(found)


def _row(data: dict[str, Any], name: str) -> dict[str, Any]:
    p = point(data, name)
    checks = p.pop("checks")
    p["domain"] = str(data["domain"])
    p["checks"] = len(checks) if checks is not None else None
    p["accepted"] = len(data.get("accepted", []))
    p["not_judged"] = _not_judged(data)
    return p


def build(paths: list[Path]) -> dict[str, Any]:
    """The rollup document: one row per domain and one per check that fired anywhere."""
    if len(paths) < 2:
        raise ValueError("rollup: needs at least two JSON reports")
    newest: dict[str, tuple[dict[str, Any], str]] = {}
    notes = []
    for path in sorted(paths):
        data = _load(path)
        key = str(data["domain"]).lower()
        if key in newest:
            kept, kept_name = newest[key]
            if str(data["collected_at"]) > str(kept["collected_at"]):
                newest[key] = (data, path.name)
                dropped = kept_name
            else:
                dropped = path.name
            notes.append(f"{dropped}: an older report of {data['domain']}, not used")
        else:
            newest[key] = (data, path.name)
    if len(newest) < 2:
        notes.append("only one domain among these reports")
    reports = [newest[k] for k in sorted(newest)]
    rows = [_row(data, name) for data, name in reports]

    versions = {r["version"] for r in rows}
    if len(versions) > 1:
        notes.append(
            f"reports come from different ad-doctor versions: {', '.join(sorted(versions))}"
        )
    sets = [frozenset(d["checks"]) for d, _ in reports if isinstance(d.get("checks"), list)]
    if len(set(sets)) > 1:
        notes.append("reports ran different sets of checks: scores are not comparable")
    for data, name in reports:
        if not isinstance(data.get("checks"), list):
            notes.append(f"{name}: the report does not list which checks ran")

    checks: dict[str, dict[str, Any]] = {}
    for data, _ in reports:
        domain = str(data["domain"])
        for f in data.get("findings", []):
            entry = checks.setdefault(
                str(f["id"]),
                {
                    "id": str(f["id"]),
                    "title": str(f.get("title", "")),
                    "severity": str(f.get("severity", "info")),
                    "objects": 0,
                    "domains": {},
                },
            )
            entry["objects"] += len(f.get("objects", []))
            entry["domains"][domain] = len(f.get("objects", []))
            if SEVERITIES.index(str(f.get("severity", "info"))) < SEVERITIES.index(
                entry["severity"]
            ):
                entry["severity"] = str(f.get("severity"))
    for entry in checks.values():
        unjudged, accepted = [], []
        for data, _ in reports:
            domain = str(data["domain"])
            if domain in entry["domains"]:
                continue
            ran = data.get("checks")
            if (isinstance(ran, list) and entry["id"] not in ran) or entry["id"] in _not_judged(
                data
            ):
                unjudged.append(domain)
            if any(a.get("check_id") == entry["id"] for a in data.get("accepted", [])):
                accepted.append(domain)
        entry["not_judged"] = unjudged
        entry["accepted"] = accepted
    ordered = sorted(
        checks.values(),
        key=lambda c: (-len(c["domains"]), SEVERITIES.index(c["severity"]), c["id"]),
    )
    rows.sort(key=lambda r: (-int(r["score"]), r["domain"].lower()))
    return {
        "tool": "ad-doctor-rollup",
        "schema": ROLLUP_SCHEMA,
        "version": __version__,
        "reports": len(rows),
        "domains": rows,
        "checks": ordered,
        "notes": notes,
    }


def render_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2)


def _exposure(row: dict[str, Any]) -> str:
    if row.get("exposed") is None:
        return "unknown"
    return f"{row['exposed']}/{row['users']}" if row.get("users") else str(row["exposed"])


def _counts(row: dict[str, Any]) -> Counter[str]:
    return Counter(row["counts"])


def render_text(doc: dict[str, Any]) -> str:
    lines = [f"ad-doctor rollup: {doc['reports']} domains, scores not averaged", ""]
    header = (
        f"{'DOMAIN':32} {'GR':>2} {'SCORE':>5} {'HIGH':>4} {'MED':>3} {'LOW':>3} {'INFO':>4} "
        f"{'OBJECTS':>7} {'CHECKS':>6}  {'EXPOSED':10} {'SCANNED':10}"
    )
    lines.append(header)
    for r in doc["domains"]:
        c = _counts(r)
        ran = "?" if r["checks"] is None else str(r["checks"])
        lines.append(
            f"{one_line(r['domain'])[:32]:32} {r['grade']:>2} {r['score']:>5} {c['high']:>4} "
            f"{c['medium']:>3} {c['low']:>3} {c['info']:>4} {r['objects']:>7} {ran:>6}  "
            f"{_exposure(r):10} {str(r['at'])[:10]:10}"
        )
        if r["not_judged"]:
            lines.append(f"  not judged here: {', '.join(r['not_judged'])}")
    lines += ["", "Findings across domains:"]
    for c in doc["checks"]:
        total = doc["reports"]
        lines.append(
            f"  {c['id']:12} {c['severity']:6} {len(c['domains'])}/{total} domains, "
            f"{c['objects']} objects: {one_line(c['title'])}"
        )
        where = ", ".join(f"{one_line(d)} ({n})" for d, n in sorted(c["domains"].items()))
        lines.append(f"    {where}")
        if c["not_judged"]:
            lines.append(f"    not judged: {', '.join(one_line(d) for d in c['not_judged'])}")
        if c["accepted"]:
            lines.append(f"    accepted: {', '.join(one_line(d) for d in c['accepted'])}")
    if doc["notes"]:
        lines += ["", "Notes:"] + [f"  {one_line(n)}" for n in doc["notes"]]
    return "\n".join(lines)


def render_markdown(doc: dict[str, Any]) -> str:
    lines = [
        f"# ad-doctor rollup: {doc['reports']} domains",
        "",
        "Scores are per domain and are not averaged.",
        "",
        "| Domain | Grade | Score | High | Medium | Low | Info | Objects | Checks | Scanned |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in doc["domains"]:
        c = _counts(r)
        ran = "?" if r["checks"] is None else r["checks"]
        lines.append(
            f"| {_md(r['domain'])} | {r['grade']} | {r['score']} | {c['high']} | {c['medium']} "
            f"| {c['low']} | {c['info']} | {r['objects']} | {ran} | {str(r['at'])[:10]} |"
        )
    lines += [
        "",
        "## Findings across domains",
        "",
        "| Check | Severity | Domains | Objects | Not judged in | Accepted in |",
        "|---|---|---|---|---|---|",
    ]
    for c in doc["checks"]:
        domains = ", ".join(f"{_md(d)} ({n})" for d, n in sorted(c["domains"].items()))
        unjudged = ", ".join(_md(d) for d in c["not_judged"]) or "-"
        accepted = ", ".join(_md(d) for d in c["accepted"]) or "-"
        lines.append(
            f"| {c['id']} {_md(c['title'])} | {c['severity']} | {domains} | {c['objects']} "
            f"| {unjudged} | {accepted} |"
        )
    if doc["notes"]:
        lines += ["", "## Notes", ""] + [f"- {_md(n)}" for n in doc["notes"]]
    return "\n".join(lines)
