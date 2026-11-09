"""The HTML report: one self-contained, offline file (`ad-doctor view`, `-f html`).

Python computes everything (checks, paths, chokepoints, the baseline diff, acceptances,
invariants) into a viewmodel; the page only renders, filters and navigates it. The page
is a fixed template with the viewer's own CSS and JavaScript inlined from package data
and the viewmodel embedded as data:

- The viewmodel is JSON with `<`, `>`, `&`, U+2028 and U+2029 escaped, gzip-compressed and
  base64-encoded inside `<script type="application/json">`, which the browser never runs.
  Directory names are attacker-controlled (any user can create a computer while
  MachineAccountQuota is above 0), so no name can close the element or reach a parser.
- A meta Content-Security-Policy allows exactly the inlined script and style by SHA-256,
  and nothing else: no network (`connect-src 'none'`), no forms, no frames, no plugins.
- The JavaScript only ever writes text (`textContent`); tests grep it for HTML sinks.

The raw snapshot is never embedded, only what the report already says plus the paths and,
with `--graph`, the control graph (viewer_graph.py) or blast radius computed from it. A
file with a graph is encrypted by default (seal.py). `--history` adds a trend (trend.py).
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import itertools
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from functools import cache
from importlib import resources
from typing import Any

from . import __version__, accept, catalog, coverage, explain, paths, seal, trend, viewer_graph
from .fixes import _name as object_name
from .fixes import snippet
from .invariants import IDS as INVARIANT_IDS
from .model import Finding, Severity, Snapshot
from .report import (
    Report,
    compare,
    declared_nodes,
    finding_keys,
    fingerprint,
    grade_of,
    mermaid_paths,
    report_dict,
    score_of,
)

SCHEMA = 1
TOP_ACTIONS = 5
# which invariants.toml section each AD-INV check enforces
INVARIANT_SECTIONS = {
    "groups": "AD-INV-001",
    "limits": "AD-INV-002",
    "settings": "AD-INV-003",
    "dcsync": "AD-INV-004",
    "templates": "AD-INV-005",
}
# characters that could end the script element, start markup, or end a line in an
# old JavaScript parser; each becomes its JSON \u escape
_UNSAFE_CHARS = "<>&\u2028\u2029"
_UNSAFE = {c: f"\\u{ord(c):04x}" for c in _UNSAFE_CHARS}
_UNSAFE_RE = re.compile(f"[{_UNSAFE_CHARS}]")
_SLOT = re.compile(r"__(CSP|CSS|JS|META|DATA)__")


@dataclass
class Baseline:
    """The earlier run that `--baseline` compares with."""

    findings: list[Finding]
    collected_at: str | None  # ISO time, when the file says
    name: str  # the file name, for the Changes screen
    unknown: set[str] = field(default_factory=set)  # check IDs the earlier run did not evaluate
    declared: set[str] | None = None  # nodes it declared; None: what this run declares


@dataclass
class Options:
    source: str = "snapshot"  # or "report": a JSON report has no snapshot behind it
    redacted: bool = False
    baseline: Baseline | None = None
    entries: list[accept.Entry] | None = None  # the --accept file, after accept.apply()
    ran: set[str] | None = None  # check IDs that ran (stale acceptances are judged on them)
    spec: dict[str, Any] | None = None  # the --invariants file
    fixes: bool = False  # embed the fix script lines per finding
    command: str = ""  # how the file was built, without secrets
    history: list[dict[str, Any]] | None = None  # trend points from --history
    graph: str = "none"  # none, paths or full (viewer_graph.choose resolves auto)
    blast_for: list[str] | None = None  # --blast-radius-for accounts (paths mode)
    encrypted: bool = False  # recorded in the payload's metadata; render() encrypts
    whatif: dict[str, Any] | None = None  # a `plan` or `whatif -f json` result


# --- viewmodel ------------------------------------------------------------------------


def viewmodel(r: Report, snap: Snapshot | None, opts: Options) -> dict[str, Any]:
    rep = report_dict(r)
    today = r.snap.collected_at.date()
    findings = [
        _finding(f, d, snap, opts) for f, d in zip(r.findings, rep["findings"], strict=True)
    ]
    path_block = _paths(r.findings)
    path_ids: list[str] = path_block.pop("node_ids") if path_block else []
    counts = r.counts()
    vm: dict[str, Any] = {
        "schema": SCHEMA,
        "meta": _meta(r, snap, opts),
        "score": r.score,
        "grade": r.grade,
        "counts": {str(s): counts[s] for s in reversed(Severity)},
        "categories": [[c, s] for c, s in r.category_scores().items()],
        "findings": findings,
        "paths": path_block,
        "top_actions": _top_actions(r.findings, path_block),
        "accepted": rep["accepted"],
        "acceptances": _acceptances(opts.entries, today, opts.ran),
        "invariants": _invariants(r.findings, opts.spec),
        "baseline": _baseline(r, opts),
        "notes": list(r.snap.notes),
        "declared_tier0": r.declared,
        "check_status": rep["check_status"],
        "coverage": rep["coverage"],
        "trend": trend.build(opts.history, trend.point(rep, "this run"))
        if opts.history is not None
        else None,
        "graph": None,
        "blast": None,
        "whatif": _whatif(opts.whatif, opts.fixes),
        "whatif_model": None,
    }
    if snap is not None and opts.graph != "none":
        _graph(vm, snap, opts, path_ids)
    vm["lifecycle"] = _lifecycle(vm)
    return vm


def _graph(vm: dict[str, Any], snap: Snapshot, opts: Options, path_ids: list[str]) -> None:
    if opts.graph == "full":
        g = paths.build(snap, provenance=True)
        vm["graph"] = viewer_graph.compact(g, snap)
        vm["blast"] = {"mode": "full"}
        doc = opts.whatif or {}
        plan_ids = [c["id"] for c in (vm["whatif"] or {}).get("changes", []) if c.get("id")]
        assume = [str(a["node"]) for a in doc.get("assumptions") or [] if a.get("node")]
        # a plan document says it in its recommendation, a what-if document at the top
        goal = (doc.get("recommendation") or {}).get("goal") or doc.get("goal")
        steps: list[tuple[str, str]] = []
        for p in (vm["paths"] or {}).get("list", []):
            ids = [p["start"], *(s["node"] for s in p["steps"])]
            steps += [(path_ids[a], path_ids[b]) for a, b in itertools.pairwise(ids)]
        model = viewer_graph.whatif_model(
            g,
            snap,
            vm["graph"],
            plan_ids,
            assume,
            goal if goal == "all-paths" else "exposure",
            steps,
        )
        where = {n: i for i, n in enumerate(viewer_graph.nodes_of(g))}
        model["path_nodes"] = [where.get(n, -1) for n in path_ids]
        from . import whatif_cmd  # imported here as in cli.py: only the full graph needs it

        model["limits"] = whatif_cmd.limits("ad-doctor whatif NEW.json --plan plan.toml --check")
        model["redacted_note"] = whatif_cmd.REDACTED_NOTE if opts.redacted else None
        vm["whatif_model"] = model
    else:
        analysis = paths.analyze(snap)
        subjects = viewer_graph.precomputed(analysis.graph, snap, analysis, opts.blast_for or [])
        vm["blast"] = {
            "mode": "paths",
            "subjects": subjects,
            "limits": {"tier0": viewer_graph.TIER0_PATHS, "per_kind": viewer_graph.PER_KIND},
        }


WHATIF_CHANGE_KEYS = (
    "id", "kind", "spec", "label", "class", "cost", "status", "notes", "warnings",
    "objects_affected", "expected_to_clear",
)  # fmt: skip


def whatif_problem(doc: Any, domain: str, sha256: str | None) -> str | None:
    """Why a JSON file cannot go on the What-if screen of this report, or None."""
    if not isinstance(doc, dict) or doc.get("tool") != "ad-doctor":
        return "it is not ad-doctor output"
    if doc.get("kind") not in ("plan", "whatif") or doc.get("schema") != 1:
        return "it is not `plan -f json` or `whatif -f json` output"
    snap = doc.get("snapshot")
    if not isinstance(snap, dict):
        return "it has no snapshot block"
    if str(snap.get("domain", "")).lower() != domain.lower():
        return f"it is for {snap.get('domain')}, this report for {domain}"
    if sha256 is not None and snap.get("sha256") != sha256:
        return "it was made from another snapshot file; run plan on this one"
    return _whatif_shape(doc)


def _fits(value: Any, kind: str) -> bool:
    if kind.endswith("?") and value is None:
        return True
    kind = kind.rstrip("?")
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "strs":
        return isinstance(value, list) and all(isinstance(x, str) for x in value)
    if kind == "rows":
        return isinstance(value, list) and all(isinstance(x, dict) for x in value)
    return isinstance(value, {"str": str, "bool": bool, "obj": dict}[kind])


def _bad_key(where: str, obj: dict[str, Any], spec: dict[str, str]) -> str | None:
    for key, kind in spec.items():
        if not _fits(obj.get(key), kind):
            return f"{where}{key} is not what `plan -f json` writes"
    return None


_NUMBERS = {"exposed": "int", "users": "int", "holders": "int", "routes": "int?"}
_WHATIF_TOP = {
    "changes": "rows", "before": "obj", "after": "obj", "paths": "obj", "findings": "obj",
    "check": "obj", "steps": "rows?", "recommendation": "obj?", "plan_status": "rows?",
    "goal": "str?", "accounts": "rows?", "assumptions": "rows?", "notes": "strs?",
    "caveats": "strs?",
}  # fmt: skip
_WHATIF_ROWS: dict[str, dict[str, str]] = {
    "changes": {
        "id": "str?", "spec": "str?", "label": "str", "cost": "int?", "status": "str?",
        "notes": "strs?", "warnings": "strs?", "fix": "strs?", "rollback": "strs?",
    },
    "steps": {
        "n": "int", "title": "str", "changes": "strs", "exposed_after": "int",
        "holders_after": "int", "routes_after": "int?",
    },
    "plan_status": {
        "id": "str", "label": "str", "status": "str", "due": "str?", "problems": "strs",
        "note": "str?",
    },
    "accounts": {"account": "str", "before": "obj", "after": "obj"},
    "assumptions": {"name": "str", "source": "str", "status": "str?"},
}  # fmt: skip
_WHATIF_RECOMMENDATION = {
    "goal": "str", "near": "str", "cost": "int", "changes": "int", "budget": "int?",
    "proven_minimum": "bool", "alternatives": "bool", "lower_bound": "obj?",
}  # fmt: skip


def _whatif_shape(doc: dict[str, Any]) -> str | None:
    """The page only writes text, but a wrong type would break the screen: refuse it here."""
    problem = _bad_key("", doc, _WHATIF_TOP)
    if problem:
        return problem
    for block in ("before", "after"):
        if problem := _bad_key(f"{block}.", doc[block], _NUMBERS):
            return problem
    for key, spec in _WHATIF_ROWS.items():
        for row in doc.get(key) or []:
            problem = _bad_key(f"{key}: ", row, spec)
            if problem:
                return problem
    rec = doc.get("recommendation")
    if rec is not None and (problem := _bad_key("recommendation.", rec, _WHATIF_RECOMMENDATION)):
        return problem
    p = doc["paths"]
    for key in ("closed", "rerouted", "open", "new", "unclosable"):
        if not _fits(p.get(key), "rows"):
            return f"paths.{key} is not what `plan -f json` writes"
    for key in ("closed", "open", "new"):
        if not all(isinstance(r.get("path"), dict) for r in p[key]):
            return f"paths.{key} is not what `plan -f json` writes"
    for r in p["rerouted"]:
        if not (isinstance(r.get("before"), dict) and isinstance(r.get("after"), dict)):
            return "paths.rerouted is not what `plan -f json` writes"
    for r in p["unclosable"]:
        if problem := _bad_key("paths.unclosable: ", r, {"why": "str", "suggest": "str"}):
            return problem
    f = doc["findings"]
    if not (_fits(f.get("cleared", []), "rows") and _fits(f.get("new", []), "rows")):
        return "findings is not what `plan -f json` writes"
    if not _fits(doc["check"].get("problems", []), "strs"):
        return "check.problems is not what `plan -f json` writes"
    return None


def _whatif(doc: dict[str, Any] | None, fixes: bool) -> dict[str, Any] | None:
    """The part of a plan or what-if result the What-if screen shows. Fix lines go in
    only with --fixes, as for findings, and by then cli.py has rebuilt them from the
    snapshot (whatif_cmd.rebuild_fix_lines)."""
    if doc is None:
        return None
    keys = WHATIF_CHANGE_KEYS + (("fix", "rollback") if fixes else ())

    def path_rows(rows: list[dict[str, Any]]) -> list[str]:
        return [str(r["path"].get("object", "")) for r in rows]

    p = doc.get("paths") or {}
    f = doc.get("findings") or {}
    return {
        "kind": doc["kind"],
        "version": doc.get("version"),
        "collected_at": (doc.get("snapshot") or {}).get("collected_at"),
        "changes": [{k: c.get(k) for k in keys} for c in doc.get("changes", [])],
        "before": doc.get("before"),
        "after": doc.get("after"),
        "steps": doc.get("steps") or [],
        "recommendation": doc.get("recommendation"),
        "paths": {
            "closed": path_rows(p.get("closed", [])),
            "rerouted": [
                {
                    "before": str(r["before"].get("object", "")),
                    "after": str(r["after"].get("object", "")),
                }
                for r in p.get("rerouted", [])
            ],
            "open": path_rows(p.get("open", [])),
            "new": path_rows(p.get("new", [])),
            "unclosable": [
                {"name": u.get("name"), "why": u.get("why"), "suggest": u.get("suggest")}
                for u in p.get("unclosable", [])
            ],
        },
        "findings": {
            "rechecked": bool(f.get("rechecked")),
            "cleared": f.get("cleared", []),
            "new": f.get("new", []),
        },
        "check": {
            "ok": bool((doc.get("check") or {}).get("ok", True)),
            "problems": (doc.get("check") or {}).get("problems", []),
        },
        "plan_status": doc.get("plan_status") or [],
        "accounts": doc.get("accounts") or [],
        "assumptions": doc.get("assumptions") or [],
        "notes": doc.get("notes") or [],
        "caveats": doc.get("caveats") or [],
    }


def _meta(r: Report, snap: Snapshot | None, opts: Options) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "domain": r.snap.domain,
        "collected_at": r.snap.collected_at.isoformat(),
        "version": __version__,
        "built_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source": opts.source,
        "redacted": opts.redacted,
        "command": opts.command,
        "embedded": {
            "report": True,
            "paths": any(f.check_id == "AD-PATH-001" for f in r.findings),
            "graph": opts.graph if snap is not None and opts.graph != "none" else False,
            "history": len(opts.history) if opts.history is not None else 0,
            "baseline": opts.baseline is not None,
            "acceptances": opts.entries is not None,
            "invariants": opts.spec is not None,
            "fixes": opts.fixes and snap is not None,
            "whatif": opts.whatif is not None,
            "snapshot": False,
            "encrypted": opts.encrypted,
        },
    }
    if snap is not None:
        users = [a for a in snap.accounts if not a.is_computer and not a.managed]
        meta["counts"] = {
            "users": len(users),
            "enabled_users": sum(a.enabled for a in users),
            "computers": sum(a.is_computer for a in snap.accounts),
            "templates": len(snap.templates),
            "gpos": len(snap.gpos),
        }
        meta["dcs"] = [{"name": d.name, "error": d.error} for d in snap.probes.dcs]
    return meta


def _finding(f: Finding, d: dict[str, Any], snap: Snapshot | None, opts: Options) -> dict[str, Any]:
    item = {k: v for k, v in d.items() if k not in ("fingerprints", "keys", "data")}
    # parallel to objects: object names are directory data and make poor JSON keys
    item["fingerprints"] = [d["fingerprints"][o] for o in f.objects]
    if f.keys:
        item["keys"] = [f.key(o) for o in f.objects]
    entry = catalog.get(f.check_id)
    if entry is not None:
        item["doc"] = {
            "summary": entry.summary,
            "risk": _paragraphs(entry.risk),
            "url": entry.url,
        }
    if opts.fixes and snap is not None:
        item["fix"] = snippet(f, snap)
    return item


def _paragraphs(md: str) -> list[str]:
    """Catalog Markdown as plain paragraphs: the page shows text, never markup."""
    text = explain._plain(md, 10_000)
    return [" ".join(p.split()) for p in re.split(r"\n\s*\n", text) if p.strip()]


def _paths(findings: list[Finding]) -> dict[str, Any] | None:
    """AD-PATH-001 as a node table plus paths of node indexes, chokepoints and Mermaid."""
    f = next((f for f in findings if f.check_id == "AD-PATH-001"), None)
    if f is None or not isinstance(f.data.get("paths"), list):
        return None
    kept = set(f.objects)
    records = [p for p in f.data["paths"] if p.get("object") in kept]
    extended = [p for p in f.data.get("declared_paths", []) if p.get("object") in kept]
    nodes: list[dict[str, Any]] = []
    index: dict[str, int] = {}

    def node(rec: dict[str, Any]) -> int:
        if rec["id"] not in index:
            index[rec["id"]] = len(nodes)
            item = {k: rec[k] for k in ("name", "kind", "tier0")}
            if rec["id"].startswith("sid:"):
                item["sid"] = rec["id"].removeprefix("sid:")
            nodes.append(item)
        if rec.get("declared"):
            nodes[index[rec["id"]]]["declared"] = True
        return index[rec["id"]]

    rows = []
    for i, p in enumerate([*records, *extended]):
        rows.append(
            {
                **({"declared": True} if i >= len(records) else {}),
                "object": p["object"],
                "key": f.key(p["object"]),
                "fingerprint": fingerprint(f.check_id, f.key(p["object"])),
                "start": node(p["start"]),
                "steps": [{"how": s["how"], "node": node(s)} for s in p["steps"]],
            }
        )
    points = merged_chokepoints(paths.chokepoints([paths.Path.from_record(p) for p in records]))
    chokepoints = [
        {
            "count": c.count,
            "to": index[c.target],
            **({"from": index[c.source], "how": c.how} if c.source is not None else {}),
        }
        for c in points
    ]
    mentions = _mentions(findings, nodes)
    for i, item in enumerate(nodes):
        if mentions[i]:
            item["findings"] = mentions[i]
    exposed, users = f.data.get("exposed"), f.data.get("users")
    shown = [p["object"] for p in [*records, *extended]]
    mermaid = mermaid_paths(shown, limit=len(shown))
    return {
        "detail": f.detail,
        "exposed": exposed,
        "users": users,
        "broad": "Broad groups have a path" in f.detail,
        "nodes": nodes,
        "node_ids": list(index),
        "list": rows,
        "chokepoints": chokepoints,
        "mermaid": "\n".join(mermaid[1:-1]),  # without the Markdown fence
    }


def merged_chokepoints(points: list[paths.Chokepoint]) -> list[paths.Chokepoint]:
    """Chokepoints without the node rows that repeat an edge row: a node shared by exactly
    the paths of an edge into or out of it is one place to break them, not two (every
    path through the edge passes the node, so equal counts mean the same paths)."""
    edge_counts = set()
    for c in points:
        if c.source is not None:
            edge_counts.add((c.source, c.count))
            edge_counts.add((c.target, c.count))
    return [c for c in points if c.source is not None or (c.target, c.count) not in edge_counts]


def _mentions(findings: list[Finding], nodes: list[dict[str, Any]]) -> list[list[str]]:
    """For each node, the other findings whose objects name it as a whole word
    ("LabESC1 (enroll: Domain Users)" names both the template and the group)."""
    texts = [
        (f.check_id, "\n".join(o.lower() for o in f.objects))
        for f in findings
        if f.check_id != "AD-PATH-001"
    ]
    out = []
    for n in nodes:
        name = _bare(n["name"])
        word = re.compile(rf"(?<![\w$-]){re.escape(name)}(?![\w$-])")
        out.append(sorted({c for c, text in texts if name in text and word.search(text)}))
    return out


def _bare(name: str) -> str:
    """A node name as findings write it: paths say "template X", "GPO X", "CA X"."""
    return re.sub(r"^(template|GPO|CA) ", "", name).lower()


def _top_actions(findings: list[Finding], block: dict[str, Any] | None) -> list[dict[str, Any]]:
    """High findings, those on the first step of the most control paths first."""
    firsts: list[set[str]] = []
    if block is not None:
        names = [_bare(n["name"]) for n in block["nodes"]]
        for p in block["list"]:
            first = {names[p["start"]]}
            if p["steps"]:
                first.add(names[p["steps"][0]["node"]])
            firsts.append(first)
    order = {f.check_id: i for i, f in enumerate(findings)}
    ranked = []
    for f in findings:
        # invariant drift restates other findings as policy; it has its own tile
        if f.severity < Severity.HIGH or f.check_id == "AD-PATH-001" or f.check_id in INVARIANT_IDS:
            continue
        objs = {object_name(o).lower() for o in f.objects} | {o.lower() for o in f.objects}
        on_paths = sum(1 for first in firsts if first & objs)
        ranked.append((-on_paths, f.check_id.startswith("AD-CHAIN-"), order[f.check_id], f))
    ranked.sort(key=lambda x: x[:3])
    return [
        {
            "id": f.check_id,
            "title": f.title,
            "paths": -neg,
            "objects": len(f.objects),
            "remediation": f.remediation,
        }
        for neg, _, _, f in ranked[:TOP_ACTIONS]
    ]


def _acceptances(
    entries: list[accept.Entry] | None, today: date, ran: set[str] | None
) -> list[dict[str, Any]] | None:
    if entries is None:
        return None
    return [
        {
            "check": e.check,
            "objects": sorted(e.objects),
            "reason": e.reason,
            "owner": e.owner,
            "ticket": e.ticket,
            "expires": e.expires.isoformat(),
            "days": (e.expires - today).days,
            "status": accept.status(e, today, ran),
        }
        for e in entries
    ]


def _invariants(findings: list[Finding], spec: dict[str, Any] | None) -> dict[str, Any] | None:
    if spec is None:
        return None
    fired = {f.check_id: f for f in findings if f.check_id in INVARIANT_IDS}
    sections = []
    for section, check_id in INVARIANT_SECTIONS.items():
        if section not in spec:
            continue
        declared = [[k, _jsonable(v)] for k, v in sorted(spec[section].items())]
        f = fired.get(check_id)
        sections.append(
            {
                "section": section,
                "check": check_id,
                "title": INVARIANT_IDS[check_id],
                "declared": declared,
                "holds": f is None,
                "drift": f.objects if f is not None else [],
                "detail": f.detail if f is not None else "",
            }
        )
    return {"sections": sections}


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _baseline(r: Report, opts: Options) -> dict[str, Any] | None:
    b = opts.baseline
    if b is None:
        return None
    old = b.findings
    if opts.entries is not None:  # judge the old run by the same acceptances
        entries = copy.deepcopy(opts.entries)
        old = accept.apply(old, entries, r.snap.collected_at.date(), None)[0]
    unknown = coverage.unevaluated(r.statuses())
    changes = compare(old, r.findings, b.unknown, unknown, b.declared, declared_nodes(r.declared))
    before = {(f.check_id, f.key(o)): (f, o) for f in old for o in f.objects}
    after = {(f.check_id, f.key(o)): (f, o) for f in r.findings for o in f.objects}

    def row(f: Finding, o: str) -> dict[str, Any]:
        return {
            "id": f.check_id,
            "title": f.title,
            "severity": str(f.severity),
            "object": o,
            "fingerprint": fingerprint(f.check_id, f.key(o)),
        }

    changed = []
    for key in sorted(before.keys() & after.keys()):
        (of, oo), (nf, no) = before[key], after[key]
        if oo != no or of.severity != nf.severity:
            changed.append({**row(nf, no), "before": oo, "before_severity": str(of.severity)})
    old_paths = next((f for f in old if f.check_id == "AD-PATH-001"), None)
    score = score_of(old)
    return {
        "name": b.name,
        "collected_at": b.collected_at,
        "score": score,
        "grade": grade_of(score),
        "new": [row(*after[k]) for k in changes.added],
        # a finding of a check this run could not evaluate is not known to be gone
        "resolved": [row(*before[k]) for k in changes.resolved],
        "not_evaluated": [row(*before[k]) for k in changes.not_evaluated_now],
        # nor is one the earlier run could not evaluate known to be new
        "not_evaluated_before": [row(*after[k]) for k in changes.not_evaluated_before],
        "declaration_changed": [row(*(after.get(k) or before[k])) for k in changes.declaration],
        "changed": changed,
        "unchanged": len(finding_keys(r.findings) & finding_keys(old)) - len(changed),
        "exposed": old_paths.data.get("exposed") if old_paths else None,
        "users": old_paths.data.get("users") if old_paths else None,
        "paths": len(old_paths.objects) if old_paths else 0,
    }


def _lifecycle(vm: dict[str, Any]) -> dict[str, int | None]:
    rows = vm["acceptances"] or []
    status = [a["status"] for a in rows]
    inv = vm["invariants"]
    return {
        "accepted": sum(len(a["objects"]) or 1 for a in vm["accepted"]),
        "expiring": status.count("expiring") if vm["acceptances"] is not None else None,
        "expired": status.count("expired") if vm["acceptances"] is not None else None,
        "stale": status.count("stale") if vm["acceptances"] is not None else None,
        "drift": sum(not s["holds"] for s in inv["sections"]) if inv is not None else None,
        "new": len(vm["baseline"]["new"]) if vm["baseline"] is not None else None,
    }


# --- the page --------------------------------------------------------------------------


def safe_json(value: Any) -> str:
    """JSON that cannot end the script element it sits in or start markup."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return _UNSAFE_RE.sub(lambda m: _UNSAFE[m[0]], text)


def csp_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


@cache
def assets() -> tuple[str, str, str]:
    """(page template, CSS, JavaScript) from package data."""
    root = resources.files("ad_doctor").joinpath("viewer_assets")
    page, css, core, app = (
        root.joinpath(n).read_text(encoding="utf-8")
        for n in ("index.html", "app.css", "core.js", "app.js")
    )
    js = core + "\n" + app  # core.js: the parts Node tests run (graph search, TOML, diff)
    if "</style" in css.lower() or "</script" in js.lower():
        raise ValueError("viewer assets must not contain a closing style or script tag")
    return page, css, js


def policy(css: str, js: str) -> str:
    return "; ".join(
        [
            "default-src 'none'",
            f"script-src '{csp_hash(js)}'",
            f"style-src '{csp_hash(css)}'",
            "img-src data:",
            "connect-src 'none'",
            "form-action 'none'",
            "base-uri 'none'",
            "frame-src 'none'",
            "object-src 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types 'none'",
        ]
    )


def render(vm: dict[str, Any], passphrase: str | None = None) -> str:
    """The page. With a passphrase the packed payload is encrypted (seal.py) and only the
    version, build time, cipher parameters, size and the ciphertext's SHA-256 stay
    readable."""
    page, css, js = assets()
    data = safe_json(vm).encode()
    packed = gzip.compress(data, mtime=0)
    meta: dict[str, Any] = {
        "schema": SCHEMA,
        "version": __version__,
        "built_at": vm["meta"]["built_at"],
    }
    if passphrase is None:
        meta |= {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        meta["encrypted"] = False
    else:
        packed, meta = seal.seal(packed, passphrase, meta)
        meta |= {"sha256": hashlib.sha256(packed).hexdigest(), "bytes": len(packed)}
        meta["encrypted"] = True
    slots = {
        "CSP": policy(css, js),
        "CSS": css,
        "JS": js,
        "META": safe_json(meta),
        "DATA": base64.b64encode(packed).decode(),
    }
    return _SLOT.sub(lambda m: slots[m[1]], page)
