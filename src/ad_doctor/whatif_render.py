"""Text, Markdown and fix-script output of `whatif` and `plan`, written from the JSON
document so every format says the same thing.

Wording: "closes in the snapshot", "would clear", "rerouted" when a path remains, "proven
minimum (for paths ad-doctor sees)" only when it is proven, "heuristic" on every ordering
or budget claim.
"""

from __future__ import annotations

import json
from typing import Any

from .fixes import one_line, render_change_script

SHOW = 20  # rows of a list in text output; JSON has them all


def _when(doc: dict[str, Any]) -> str:
    stamp = str(doc["snapshot"]["collected_at"])
    return stamp[:16].replace("T", " ") + " UTC"


def _pct(n: int, total: int) -> str:
    return f"{100 * n // total}%" if total else "0%"


def _clip(rows: list[str], indent: str = "    ") -> list[str]:
    out = [indent + r for r in rows[:SHOW]]
    if len(rows) > SHOW:
        out.append(f"{indent}... and {len(rows) - SHOW} more (all of them in -f json)")
    return out


def _path_text(rec: dict[str, Any]) -> str:
    return str(rec["object"])


def _numbers(doc: dict[str, Any]) -> list[str]:
    b, a = doc["before"], doc["after"]

    def routes(x: dict[str, Any]) -> str:
        return "-" if x["routes"] is None else str(x["routes"])

    return [
        f"  {'':24}{'before':>12}{'after':>12}",
        f"  {'exposed users':24}{b['exposed']:>6} of {b['users']:<4}"
        f"{a['exposed']:>6} of {a['users']:<4}",
        f"  {'':24}{_pct(b['exposed'], b['users']):>12}{_pct(a['exposed'], a['users']):>12}",
        f"  {'principals with a path':24}{b['holders']:>12}{a['holders']:>12}",
        f"  {'routes (changes needed)':24}{routes(b):>12}{routes(a):>12}",
    ]


def _paths(doc: dict[str, Any]) -> list[str]:
    p = doc["paths"]
    out = []
    if p["closed"]:
        out.append(f"Closes in the snapshot ({len(p['closed'])}):")
        out += _clip([r["path"]["start"]["name"] for r in p["closed"]])
    if p["rerouted"]:
        out.append(f"Rerouted: still a path, another one ({len(p['rerouted'])}):")
        rows = []
        for r in p["rerouted"]:
            rows += [f"was {_path_text(r['before'])}", f"  now {_path_text(r['after'])}"]
        out += _clip(rows)
    if p["open"]:
        out.append(f"Still open, same path ({len(p['open'])}):")
        out += _clip([_path_text(r["path"]) for r in p["open"]])
    if p["unclosable"]:
        out.append("Cannot be closed by removing a right (needs a decision):")
        for u in p["unclosable"][:SHOW]:
            out += [f"    {u['why']}", f"      -> {u['suggest']}"]
        if len(p["unclosable"]) > SHOW:
            out.append(f"    ... and {len(p['unclosable']) - SHOW} more")
    return out


def _findings(doc: dict[str, Any]) -> list[str]:
    f = doc["findings"]
    if not f["rechecked"]:
        return ["Findings: not rechecked (--paths-only)."]
    out = ["Findings, rechecked on the changed snapshot:"]
    if f["cleared"]:
        out.append(f"  would clear ({len(f['cleared'])}):")
        out += _clip([f"{r['check']}  {r['object']}" for r in f["cleared"]])
    if f["new"]:
        out.append(f"  would appear ({len(f['new'])}):")
        out += _clip([f"{r['check']}  {r['object']}" for r in f["new"]])
    if f["changed"]:
        out.append(f"  would change ({len(f['changed'])}):")
        out += _clip([f"{r['check']}  {r['object']}" for r in f["changed"]])
    if not (f["cleared"] or f["new"] or f["changed"]):
        out.append("  none would clear or appear")
    if f.get("accepted"):
        out.append(f"  ({f['accepted']} accepted findings left out)")
    return out


def _change_rows(c: dict[str, Any], status: bool) -> list[str]:
    head = f"{c['status']:10} " if status else ""
    ident = c["id"] or "-"
    out = [f"  {head}{ident}  {c['label']}"]
    pad = "  " + " " * len(head) + " " * (len(ident) + 2)
    if c["kind"] is not None and c["source"] == "remove" and c["spec"] != c["label"]:
        out.append(f"{pad}{c['spec']}")
    for w in c["warnings"]:
        out.append(f"{pad}warning: {w}")
    for n in c["notes"]:
        out.append(f"{pad}{n}")
    return out


def render_text(doc: dict[str, Any]) -> str:
    plan = doc["kind"] == "plan"
    snap = doc["snapshot"]
    title = "Plan" if plan else "What-if"
    out = [
        f"{title} on the {snap['domain']} snapshot of {_when(doc)} (simulated; AD unchanged)",
        "",
    ]
    if plan:
        rec = doc["recommendation"]
        goal = {
            "exposure": "close the paths of enabled users outside tier 0",
            "all-paths": "close every AD-PATH-001 path",
            "from": "close the paths of the principals named with --from",
        }[rec["goal"]]
        out.append(f"Goal: {goal}.")
        out += ["", "Tier-0 paths:", *_numbers(doc), ""]
        if doc["steps"]:
            label = "budget, heuristic" if rec["budget"] is not None else "heuristic order"
            out.append(f"Steps ({label}; each closes in the snapshot what it says):")
            by_id = {c["id"]: c for c in doc["changes"]}
            for s in doc["steps"]:
                out.append(
                    f"  {s['n']:>2}. {s['title']}  ->  exposed {s['exposed_after']}, "
                    f"principals {s['holders_after']}, routes {s['routes_after']}"
                )
                for cid in s["changes"]:
                    c = by_id[cid]
                    extra = [f"warning: {w}" for w in c["warnings"]] + c["notes"]
                    out.append(f"        {cid}  {c['label']}  (cost {c['cost']})")
                    out += [f"          {x}" for x in extra]
        else:
            out.append("Nothing to change: no closable source reaches tier 0.")
        out += ["", _verdict(rec)]
        if rec["alternatives"]:
            other = "the sources" if rec["near"] == "tier0" else "tier 0"
            out.append(f"Another cut of equal cost exists nearer {other} (--near).")
        if rec["note"]:
            out.append(f"Note: {rec['note']}.")
        out.append("")
    else:
        out.append("Changes:")
        for c in doc["changes"]:
            out += _change_rows(c, status=True)
        if not doc["changes"]:
            out.append("  none")
        out += ["", "Tier-0 paths:", *_numbers(doc), ""]
    out += _paths(doc)
    out += ["", *_findings(doc)]
    if doc.get("accounts"):
        out += ["", "Blast radius:"]
        for a in doc["accounts"]:
            b, f = a["before"], a["after"]
            out.append(
                f"  {a['account']}: {b['count']} objects ({b['tier0']} tier 0) -> "
                f"{f['count']} objects ({f['tier0']} tier 0)"
            )
    if doc.get("plan_status"):
        out += ["", "Plan status:"]
        for s in doc["plan_status"]:
            due = f" (due {s['due']})" if s["due"] else ""
            out.append(f"  {s['status']:12}{s['id']}  {s['label']}{due}")
            for x in [*s["problems"], *([s["note"]] if s["note"] else [])]:
                out.append(f"              {x}")
    if doc["check"]["problems"] or doc.get("plan_status"):
        out += ["", "Check: " + ("ok" if doc["check"]["ok"] else "failed")]
        out += [f"  - {x}" for x in doc["check"]["problems"]]
    if plan:
        name = doc["snapshot"]["file"]
        out += [
            "",
            "Save and verify:",
            f"  ad-doctor plan {name} -f toml -o plan.toml     # the plan file",
            f"  ad-doctor plan {name} -f ps1 -o plan.ps1       # fix lines, all -WhatIf",
            f"  ad-doctor plan {name} -f markdown -o plan.md   # one section per step",
            "  ad-doctor whatif NEW.json --plan plan.toml --check   # after the changes",
        ]
    if doc.get("notes"):
        out += ["", *[f"Note: {n}" for n in doc["notes"]]]
    out += ["", "Caveats:", *[f"  - {c}" for c in doc["caveats"]]]
    return "\n".join(one_line(x).rstrip() for x in out) + "\n"


def _verdict(rec: dict[str, Any]) -> str:
    size = f"{rec['changes']} change{'s' if rec['changes'] != 1 else ''} (cost {rec['cost']})"
    lb = rec["lower_bound"]
    if rec["budget"] is not None:
        return f"Budget of {rec['budget']}: {size}; heuristic, no guarantee."
    if rec["proven_minimum"]:
        return f"{size}: proven minimum (for paths ad-doctor sees)."
    return (
        f"Plan of {size}; at least {lb['changes']} changes (cost {lb['cost']}) are needed. "
        f"{rec['inexact_primitives']} changes join routes the model cannot split, so this is "
        "not shown to be the minimum."
    )


def _md(text: str) -> str:
    """Directory text inside a Markdown code span: one line, no backticks breaking out."""
    return "`` " + one_line(text).replace("`", "'") + " ``"


def _fence(lines: list[str]) -> str:
    """A code fence longer than any run of backticks in the lines."""
    longest = max((len(run) for line in lines for run in _runs(line)), default=0)
    return "`" * max(3, longest + 1)


def _runs(line: str) -> list[str]:
    out, cur = [], ""
    for ch in line:
        if ch == "`":
            cur += ch
        elif cur:
            out.append(cur)
            cur = ""
    return [*out, cur] if cur else out


def render_markdown(doc: dict[str, Any]) -> str:
    snap = doc["snapshot"]
    plan = doc["kind"] == "plan"
    b, a = doc["before"], doc["after"]
    out = [
        f"# {'Plan' if plan else 'What-if'} for {one_line(snap['domain'])}",
        "",
        f"Simulated on the snapshot of {_when(doc)}; AD is unchanged.",
        "",
        "| | before | after |",
        "|---|---|---|",
        f"| exposed users | {b['exposed']} of {b['users']} | {a['exposed']} of {a['users']} |",
        f"| principals with a path | {b['holders']} | {a['holders']} |",
        f"| routes (changes needed) | {b['routes'] if b['routes'] is not None else '-'} | "
        f"{a['routes'] if a['routes'] is not None else '-'} |",
        "",
    ]
    if plan:
        out += [_verdict(doc["recommendation"]), "", "The order of the steps is a heuristic.", ""]
    by_id = {c["id"]: c for c in doc["changes"]}
    sections: list[tuple[str, list[dict[str, Any]], list[str]]] = []
    if plan:
        for s in doc["steps"]:
            sections.append(
                (
                    f"Step {s['n']}: {s['title']}",
                    [by_id[c] for c in s["changes"]],
                    [
                        f"After this step: {s['exposed_after']} users exposed, "
                        f"{s['holders_after']} principals with a path.",
                        *(
                            ["Closes in the snapshot the paths of: " + ", ".join(s["closes"])]
                            if s.get("closes")
                            else []
                        ),
                    ],
                )
            )
    else:
        for c in doc["changes"]:
            if c["id"] is not None:
                sections.append((c["label"], [c], []))
    together = ", with the other changes," if len(doc["changes"]) > 1 else ""
    for title, items, lines in sections:
        out += [f"### {one_line(title)}", ""]
        out += lines + ([""] if lines else [])
        for c in items:
            out += [f"**{c['id']}**: {one_line(c['label'])}", ""]
            out.append(f"- What: {_md(c['spec'])} ({c['kind']}, cost {c['cost']})")
            if c["expected_to_clear"]:
                out.append(
                    f"- Why: would clear{together} "
                    + "; ".join(_md(x) for x in c["expected_to_clear"])
                )
            else:
                out.append(f"- Why: takes away {c['edges_on_paths']} edges on paths to tier 0")
            for w in c["warnings"]:
                out.append(f"- Warning: {one_line(w)}")
            for n in c["notes"]:
                out.append(f"- Note: {one_line(n)}")
            fence = _fence([*c["fix"], *c["rollback"]])
            out += ["", "Fix (every command runs with -WhatIf):", "", fence + "powershell"]
            out += c["fix"] + [fence, "", "Rollback:", "", fence + "powershell"]
            out += c["rollback"] + [fence, ""]
    if doc["paths"]["unclosable"]:
        out += ["### Cannot be closed by removing a right", ""]
        for u in doc["paths"]["unclosable"]:
            out.append(f"- {_md(u['why'])}: {one_line(u['suggest'])}")
        out.append("")
    f = doc["findings"]
    if f["rechecked"]:
        out += ["### Findings", ""]
        out += [f"- would clear: {r['check']} {_md(r['object'])}" for r in f["cleared"]]
        out += [f"- would appear: {r['check']} {_md(r['object'])}" for r in f["new"]]
        if not (f["cleared"] or f["new"]):
            out.append("- none would clear or appear")
        out.append("")
    out += ["### Caveats", "", *[f"- {one_line(c)}" for c in doc["caveats"]], ""]
    return "\n".join(out)


def render_ps1(doc: dict[str, Any]) -> str:
    sections = []
    for c in doc["changes"]:
        if c["id"] is None:
            continue
        sections.append((f"{c['id']} {c['label']}", c["fix"], c["expected_to_clear"]))
    title = "plan fix lines" if doc["kind"] == "plan" else "what-if fix lines"
    return render_change_script(doc["snapshot"]["domain"], _when(doc), sections, title) + "\n"


def render_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2) + "\n"
