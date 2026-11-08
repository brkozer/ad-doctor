"""The `whatif` and `plan` commands: resolve the changes, evaluate them on the snapshot,
check a plan file, and build the document every output format is written from.

Nothing here opens a connection to a directory. The snapshot is changed in memory only,
for the findings recheck, after everything that needs it as collected has run.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from . import __version__, accept, changes, cut, invariants, paths, planfile, whatif
from .checks import run_all
from .model import Finding, Severity, Snapshot
from .paths import Graph
from .provenance import Provenance
from .report import fingerprint
from .resolve import ORPHAN_NOTE, Resolved, Resolver, SpecError, canonical

SCHEMA = 1


@dataclass
class Context:
    """One loaded snapshot, its graph and what the options add."""

    path: Path
    snap: Snapshot
    g: Graph
    sha256: str
    redacted: bool
    resolver: Resolver
    spec: dict[str, Any] | None
    entries: list[accept.Entry]
    today: date
    notes: list[str] = field(default_factory=list)
    _baseline: list[Finding] | None = None

    @property
    def prov(self) -> Provenance:
        assert self.g.prov is not None
        return self.g.prov

    def baseline(self) -> list[Finding]:
        if self._baseline is None:
            with paths.lend(self.snap, self.g):
                self._baseline = recheck(self.spec)(self.snap)
        return self._baseline


def recheck(spec: dict[str, Any] | None) -> Callable[[Snapshot], list[Finding]]:
    def run(snap: Snapshot) -> list[Finding]:
        findings = run_all(snap)
        if spec is not None:
            findings += invariants.evaluate(snap, spec)
        return findings

    return run


def load(args: argparse.Namespace) -> Context:
    # the run makes millions of small objects that live until it ends and hold no
    # cycles; collecting less often saves about a fifth of the time on large domains
    gc.set_threshold(100_000, 50, 100)
    raw = Path(args.snapshot).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw)
    del raw  # as big as the file
    if not isinstance(data, dict) or data.get("tool") == "ad-doctor":
        raise ValueError(f"{args.snapshot}: what-if needs a snapshot, not a report")
    snap = Snapshot.from_json(data)
    redacted = bool(data.get("redacted"))
    del data
    g = paths.build(snap, provenance=True)
    gc.freeze()  # the snapshot and the graph stay to the end: never scan them again
    spec = invariants.load(args.invariants) if args.invariants else None
    entries = accept.load(args.accept) if args.accept else []
    ctx = Context(
        Path(args.snapshot),
        snap,
        g,
        digest,
        redacted,
        Resolver(snap, g),
        spec,
        entries,
        snap.collected_at.date(),
    )
    ctx.resolver._findings = ctx.baseline
    if not snap.ace_inheritance_checked:
        ctx.notes.append(
            "older snapshot without the INHERITED_ACE flag: an inherited ACE copy is a change "
            "of its own, so a plan can list a copy and its source (too large, never too small)"
        )
    if redacted:
        ctx.notes.append(
            "redacted snapshot: change IDs differ from the real snapshot's, so a plan made "
            "from it does not resolve against the real one"
        )
    return ctx


def tier0_nodes(ctx: Context, names: Iterable[str]) -> list[str]:
    out = []
    for name in names:
        node = ctx.resolver.node(name)
        if node is None:
            raise SpecError(f"--tier0 / [assume] tier0: no {name!r} in this snapshot")
        out.append(node)
    return list(dict.fromkeys(out))


def assumptions(ctx: Context, groups: list[tuple[str, list[str]]]) -> list[dict[str, str]]:
    """The nodes treated as tier 0 without a change, with where each name came from:
    they move every number, so every output lists them."""
    rows: dict[str, dict[str, str]] = {}
    for source, names in groups:
        for name in names:
            node = ctx.resolver.node(name)
            if node is not None and node not in rows:
                rows[node] = {"node": node, "name": ctx.g.name(node), "source": source}
    return list(rows.values())


def caveats(snap: Snapshot, check_hint: str) -> list[str]:
    return [
        f"Simulated on the snapshot of {snap.collected_at:%Y-%m-%d %H:%M} UTC; AD is unchanged "
        "and nothing was applied.",
        "SDProp runs every 60 minutes: an ACE removed from a protected object comes back unless "
        "it also goes from AdminSDHolder.",
        "Removing an ACE at an OU or container changes every object below it (the count is next "
        "to the change); older snapshots cannot tell inherited copies apart and may list them.",
        "adminCount stays set on accounts removed from protected groups (AD-ACC-006).",
        "Group Policy applies at the next refresh (90 minutes or more), and local groups keep "
        "members a GPO added.",
        "Kerberos tickets keep their group memberships until they expire (10 hours by default).",
        "Certificates already issued stay valid until they expire or are revoked.",
        "Other domain controllers see a change after replication.",
        "Edges ad-doctor does not see stay: sessions, local admin outside Group Policy, "
        "unconstrained delegation, constrained delegation without protocol transition, "
        "delegation to a service account, certificate paths that need DC or CA patch levels "
        "(ESC9, ESC15, ESC6 without ESC16), trusts, Deny ACEs.",
        "What an attacker already planted is not undone.",
        f"Collect again after the changes and run: {check_hint}",
    ]


# -- records ---------------------------------------------------------------------------------


def _edge_counts(
    g: Graph, before: whatif.State, prims: Iterable[int]
) -> dict[int, tuple[int, int, int]]:
    """(edges the change takes away, of which on a path to tier 0, objects they reach),
    per change."""
    prov = g.prov
    assert prov is not None
    idx = whatif._index(prov)
    on_path = set(before.found) | before.graph.tier0
    out = {}
    for p in prims:
        total = hot = 0
        reached: set[str] = set()
        for src in idx.srcs.get(p, ()):
            why = prov.why[src]
            for i, (dst, _) in enumerate(g.edges[src]):
                found, _ = cut._instances(prov, src, i, why[i])
                if p in found:
                    total += 1
                    reached.add(dst)
                    if src in before.found and dst in on_path:
                        hot += 1
        out[p] = (total, hot, len(reached))
    return out


def change_notes(f: changes.Facts, assessment: changes.Assessment) -> list[str]:
    kind = f.prim[0]
    notes = []
    if kind == "inherited-ace":
        notes.append(f"inherited by {f.copies} objects below, which lose it too")
    if kind == "adminsdholder-ace":
        notes.append(
            f"SDProp removes the copies on {f.copies} protected objects at its next run "
            "(60 minutes)"
        )
    if f.orphan:
        notes.append(ORPHAN_NOTE)
    if kind == "member" and assessment.cost == changes.TIER0_MEMBER_COST:
        notes.append("takes away tier-0 rights; AD-ACC-006 flags the adminCount left behind")
    if kind in ("gplink", "gpo-entry"):
        notes.append("takes effect at the next Group Policy refresh")
    if kind == "template-flag":
        notes.append("certificates already issued from the template stay valid")
    return notes


@dataclass
class Prepared:
    """Per change: facts, class and cost, taken before the snapshot is changed."""

    facts: dict[int, changes.Facts]
    assess: dict[int, changes.Assessment]

    @classmethod
    def of(cls, ctx: Context, prims: Iterable[int], tier0: set[str]) -> Prepared:
        prov = ctx.g.prov
        assert prov is not None
        wanted = list(dict.fromkeys(prims))
        fx = changes.facts(ctx.snap, prov, ctx.resolver.where, wanted)
        cx = changes.Context(ctx.snap)
        return cls(fx, {p: changes.assess(ctx.snap, prov.prims[p], tier0, cx) for p in wanted})


def record(
    ctx: Context,
    p: int,
    prep: Prepared,
    counts: dict[int, tuple[int, int, int]],
    spec: str,
    status: str,
    notes: list[str],
    clears: list[str],
    source: str = "remove",
) -> dict[str, Any]:
    from .fixes import change_lines, rollback_lines

    prov = ctx.g.prov
    assert prov is not None
    prim = prov.prims[p]
    f, a = prep.facts[p], prep.assess[p]
    edges, hot, reached = counts.get(p, (0, 0, 0))
    if prim[0] == "inherited-ace":
        # older snapshots and synthetic ones hold no copies: count what the edges reach
        f.copies = max(f.copies, reached - 1)
    warnings = [a.warning] if a.warning else []
    return {
        "id": changes.change_id(prim),
        "kind": prim[0],
        "spec": spec or canonical(ctx.snap, prim, ctx.resolver.where),
        "label": f.label,
        "class": a.cls,
        "cost": a.cost,
        "status": status,
        "source": source,
        "notes": [*notes, *change_notes(f, a)],
        "warnings": warnings,
        "edges_removed": edges,
        "edges_on_paths": hot,
        "objects_affected": 1 + f.copies if prim[0] in changes.ACE_KINDS else 1,
        "identity": changes.fields(prim),
        "fix": change_lines(f, ctx.snap),
        "rollback": rollback_lines(f, ctx.snap),
        "expected_to_clear": clears,
    }


def _path_rec(g: Graph, node: str, p: paths.Path) -> dict[str, Any]:
    return {"fingerprint": fingerprint("AD-PATH-001", g.ident(node)), "path": p.record(g)}


def paths_block(res: whatif.Result, unclosable: list[cut.Unclosable]) -> dict[str, Any]:
    bg, ag = res.before.graph, res.after.graph
    bg_holders = res.before.holders
    rerouted = []
    for node in res.rerouted:
        new = res.after.holders.get(node) or res.after.found[node]
        rerouted.append(
            {
                "fingerprint": fingerprint("AD-PATH-001", bg.ident(node)),
                "before": res.before.holders[node].record(bg),
                "after": new.record(ag),
            }
        )
    return {
        "closed": [_path_rec(bg, n, res.before.holders[n]) for n in res.closed],
        "rerouted": rerouted,
        "open": [
            _path_rec(ag, n, res.after.holders.get(n) or res.after.found[n]) for n in res.open
        ],
        "new": [_path_rec(ag, n, p) for n, p in res.after.holders.items() if n not in bg_holders],
        "unclosable": [
            {"node": u.node, "name": bg.name(u.node), "why": u.why, "suggest": u.suggest}
            for u in unclosable
        ],
    }


def _accepted_keys(entries: list[accept.Entry], findings: list[Finding], today: date) -> set[str]:
    if not entries:
        return set()
    fresh = [
        accept.Entry(e.check, set(e.objects), e.reason, e.expires, e.owner, e.ticket)
        for e in entries
    ]
    _, accepted, _ = accept.apply(findings, fresh, today)
    texts = {(a.check_id, o) for a in accepted for o in a.objects}
    return {
        fingerprint(f.check_id, f.key(o))
        for f in findings
        for o in f.objects
        if (f.check_id, o) in texts
    }


def findings_block(ctx: Context, res: whatif.Result) -> dict[str, Any]:
    if not res.findings_rechecked:
        return {"rechecked": False, "cleared": [], "new": [], "changed": [], "accepted": 0}
    accepted = _accepted_keys(ctx.entries, res.findings_before, ctx.today)
    accepted |= _accepted_keys(ctx.entries, res.findings_after, ctx.today)
    meta = {f.check_id: f for f in [*res.findings_before, *res.findings_after]}

    def enrich(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        out = []
        for r in rows:
            if r["fingerprint"] in accepted:
                continue
            f = meta[r["check"]]
            out.append({**r, "title": f.title, "severity": str(f.severity)})
        return out

    cleared, new, changed = enrich(res.cleared), enrich(res.new), enrich(res.changed)
    total = len(res.cleared) + len(res.new) + len(res.changed)
    return {
        "rechecked": True,
        "cleared": cleared,
        "new": new,
        "changed": changed,
        "accepted": total - len(cleared) - len(new) - len(changed),
    }


def expected_map(ctx: Context, wanted: set[int]) -> dict[str, list[int]]:
    """Finding fingerprint -> the changes among `wanted` that it maps to (the findings
    table), from the snapshot before any change."""
    out: dict[str, list[int]] = {}
    if not wanted:
        return out
    for f in ctx.baseline():
        for o in f.objects:
            hits = [p for p in ctx.resolver.finding_changes(f, o) if p in wanted]
            if hits:
                out[fingerprint(f.check_id, f.key(o))] = hits
    return out


def clears_for(
    findings: dict[str, Any], expected: dict[str, list[int]], p: int, closed_by: dict[str, set[int]]
) -> list[str]:
    out = []
    for r in findings.get("cleared", []):
        if p in expected.get(r["fingerprint"], ()) or p in closed_by.get(r["fingerprint"], ()):
            out.append(f"{r['check']} {r['object']}")
    return out


def numbers(state: whatif.State, routes: int | None) -> dict[str, Any]:
    return {
        "exposed": state.exposed,
        "users": state.users,
        "holders": len(state.holders),
        "routes": routes,
    }


def document(ctx: Context, kind: str) -> dict[str, Any]:
    snap = ctx.snap
    return {
        "tool": "ad-doctor",
        "kind": kind,
        "schema": SCHEMA,
        "version": __version__,
        "simulated": True,
        "snapshot": {
            "domain": snap.domain,
            "domain_sid": snap.domain_sid,
            "collected_at": snap.collected_at.isoformat(),
            "sha256": ctx.sha256,
            "file": ctx.path.name,
        },
    }


# -- whatif -----------------------------------------------------------------------------------


@dataclass
class Status:
    entry: planfile.Entry
    status: str
    p: int | None = None
    problems: list[str] = field(default_factory=list)
    note: str = ""


def lifecycle(ctx: Context, plan: planfile.PlanFile) -> list[Status]:
    """done, open, overdue or stale per [[change]] (ineffective comes later)."""
    out = []
    for e in plan.changes:
        prim = e.prim
        problems = []
        if e.id and e.id != e.expected_id:
            problems.append(
                f"id {e.id} does not match its fields ({e.expected_id}): the file was edited"
            )
        bad = ctx.resolver.entry_problem(prim)
        if bad is not None:
            st = Status(e, "stale", None, [*problems, bad])
        elif ctx.resolver.exists(prim):
            st = Status(e, "open", ctx.resolver.register(prim), problems)
            if e.due is not None and e.due < ctx.today:
                st.status = "overdue"
        elif ctx.resolver.anchor_exists(prim):
            st = Status(e, "done", None, problems)
        else:
            st = Status(e, "stale", None, problems)
            st.problems.append("does not resolve in this snapshot: renamed, deleted or a typo")
        out.append(st)
    return out


def _reach(ctx: Context, m: cut.Model, removed: Iterable[int], extra: list[str]) -> set[str]:
    view = whatif.masked(ctx.g, ctx.snap, removed, extra)
    return cut._reach_to(m, view, view.tier0)


def mark_ineffective(
    ctx: Context, statuses: list[Status], removed: set[int], extra: list[str], m: cut.Model
) -> None:
    """An open change whose removal closes nothing on top of the others is ineffective."""
    prov = ctx.g.prov
    assert prov is not None
    candidates = [s for s in statuses if s.p is not None]
    if not candidates:
        return
    full = _reach(ctx, m, removed, extra)
    for s in candidates:
        assert s.p is not None
        if prov.needs_rebuild(s.p):
            s.note = "not tested for ineffectiveness: it can move GPO scope or tier 0"
            continue
        if _reach(ctx, m, removed - {s.p}, extra) == full:
            s.status = "ineffective"
            s.problems.append("open, but removing it closes nothing now: the paths go around it")


def default_routes_keeps(
    ctx: Context, allow: Iterable[str], extra_keeps: dict[int, str]
) -> dict[int, str]:
    prov = ctx.g.prov
    assert prov is not None
    keeps = {} if "warn" in set(allow) else changes.default_keeps(ctx.snap, prov)
    keeps.update(extra_keeps)
    return keeps


def file_keeps(ctx: Context, plan: planfile.PlanFile | None) -> dict[int, str]:
    out: dict[int, str] = {}
    if plan is None:
        return out
    for e in plan.keeps:
        assert e.expires is not None
        if e.expires < ctx.today:
            ctx.notes.append(
                f"keep {e.expected_id} ({e.reason}) expired on {e.expires}: a candidate again"
            )
            continue
        p = ctx.g.prov.lookup(e.prim) if ctx.g.prov else None
        if p is not None:
            out[p] = e.reason
    return out


def option_keeps(
    ctx: Context, snapshot_findings: Callable[[], list[Finding]]
) -> tuple[dict[int, str], list[str]]:
    """Keeps from --invariants and --accept, and the accepted AD-PATH-001 holders."""
    prov = ctx.g.prov
    assert prov is not None
    keeps: dict[int, str] = {}
    if ctx.spec is not None:
        keeps.update(changes.invariant_keeps(ctx.snap, prov, ctx.spec))
    holders: list[str] = []
    active = [e for e in ctx.entries if e.expires >= ctx.today]
    if not active:
        return keeps, holders
    findings = snapshot_findings()
    fresh = [accept.Entry(e.check, set(e.objects), e.reason, e.expires) for e in active]
    _, accepted, _ = accept.apply(findings, fresh, ctx.today)
    by_text = {(f.check_id, o): f for f in findings for o in f.objects}
    for a in accepted:
        for o in a.objects:
            f = by_text.get((a.check_id, o))
            if f is None:
                continue
            if f.check_id == "AD-PATH-001":
                holders.append(f.key(o))
                continue
            for p in ctx.resolver.finding_changes(f, o):
                keeps.setdefault(p, f"accepted: {a.reason}")
    return keeps, holders


def run_whatif(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    ctx = load(args)
    prov = ctx.g.prov
    assert prov is not None
    plan = planfile.load(args.plan) if args.plan else None
    problems_rot: list[str] = []
    problems_gate: list[str] = []
    resolved: list[Resolved] = []
    ctx.resolver.want_ids(x.strip() for x in args.remove or [])
    for spec in args.remove or []:
        r = ctx.resolver.resolve(spec)
        if r.status == "absent" and (args.strict or args.check):
            raise SpecError(f"{spec}: {'; '.join(r.notes)}")
        resolved.append(r)
    statuses: list[Status] = []
    goal, sources_from, allow = "exposure", [], []
    tier0_names = list(args.tier0 or [])
    plan_tier0: list[str] = []
    if plan is not None:
        if plan.domain_sid and plan.domain_sid != ctx.snap.domain_sid:
            problems_rot.append(
                f"the plan is for {plan.domain} ({plan.domain_sid}), the snapshot for "
                f"{ctx.snap.domain} ({ctx.snap.domain_sid})"
            )
        else:
            statuses = lifecycle(ctx, plan)
            tier0_names += plan.tier0
            plan_tier0 = list(plan.tier0)
        goal, sources_from, allow = plan.goal, plan.sources, plan.allow
    extra = tier0_nodes(ctx, tier0_names)
    removed: set[int] = {p for r in resolved for p in r.prims}
    removed |= {s.p for s in statuses if s.p is not None}
    accounts = list(args.account or [])
    for a in accounts:
        if not paths.identity_nodes(ctx.snap, a):
            raise SpecError(f"--account: no account {a!r} in this snapshot")

    # everything that reads the snapshot as collected, before level 2 changes it
    tier0 = set(whatif.masked(ctx.g, ctx.snap, (), extra).tier0)
    prep = Prepared.of(ctx, sorted(removed), tier0)
    findings_needed = not args.paths_only
    expected = expected_map(ctx, removed) if findings_needed else {}
    keeps_opt, accepted_holders = (
        option_keeps(ctx, ctx.baseline) if ctx.entries or ctx.spec else ({}, [])
    )
    keeps = default_routes_keeps(ctx, allow, {**file_keeps(ctx, plan), **keeps_opt})
    view = whatif.masked(ctx.g, ctx.snap, (), extra)
    srcs = cut.sources_for(
        ctx.snap,
        view,
        "exposure" if goal == "from" and not sources_from else goal,
        sources_from,
        cut.accepted_holders(ctx.g, accepted_holders),
    )
    m = cut.build_model(ctx.snap, ctx.g, srcs, keeps, extra)
    routes_before = cut.routes(m)
    ok = whatif.maskable(prov, removed)
    routes_after = cut.routes(m, removed)
    if statuses:
        mark_ineffective(ctx, statuses, removed, extra, m)
    # a route kept by a change the plan removes is not kept any more
    left = {k: v for k, v in keeps.items() if k not in removed}
    kept_model = (
        m if len(left) == len(keeps) else cut.build_model(ctx.snap, ctx.g, srcs, left, extra)
    )
    unclosable = kept_model.sink_like - kept_model.tier0
    if findings_needed:
        ctx.baseline()

    res = whatif.run(ctx.snap, ctx.g, removed, accounts, True, extra, None, recheck(ctx.spec))
    closes_all = None
    if plan is not None and "closes_all" in plan.expect:
        # judged on the graph after the changes: someone a change took out of tier 0 is a
        # source now, and a route that ended at them is gone. Routes the model holds as
        # unclosable (kept or fixed) do not count.
        sources = set(m.sources) | set(
            cut.sources_for(
                ctx.snap,
                res.after.graph,
                "exposure" if goal == "from" and not sources_from else goal,
                sources_from,
                cut.accepted_holders(res.after.graph, accepted_holders),
            )
        )
        closes_all = not any(
            x in res.after.found and x not in res.after.graph.tier0 and x not in unclosable
            for x in sources
        )
    counts = _edge_counts(ctx.g, res.before, removed)
    doc = document(ctx, "whatif")
    closed_by = _closed_by(ctx, res, removed)
    recs: list[tuple[int | None, dict[str, Any]]] = []
    seen: set[int] = set()
    for r in resolved:
        if not r.prims:
            recs.append((None, _absent_record(r)))
        for p in r.prims:
            if p not in seen:
                seen.add(p)
                recs.append((p, record(ctx, p, prep, counts, r.spec, r.status, r.notes, [])))
    for s in statuses:
        if s.p is not None and s.p not in seen:
            seen.add(s.p)
            recs.append((s.p, record(ctx, s.p, prep, counts, "", "applied", [], [], "plan")))
    paths_doc = paths_block(res, m.unclosable)
    del m
    fb = level2(ctx, res, findings_needed)
    for prim, rec in recs:
        if prim is not None:
            rec["expected_to_clear"] = clears_for(fb, expected, prim, closed_by)
    doc["changes"] = [rec for _, rec in recs]
    doc["before"] = numbers(res.before, routes_before)
    doc["after"] = numbers(res.after, routes_after)
    doc["paths"] = paths_doc
    doc["findings"] = fb
    doc["accounts"] = res.accounts
    doc["assumptions"] = assumptions(
        ctx, [("--tier0", list(args.tier0 or [])), ("plan file", plan_tier0)]
    )
    doc["plan_status"] = [
        {
            "id": s.entry.id or s.entry.expected_id,
            # built from the identity fields: the file's own label is free text anyone
            # can edit, and must not stand next to an ID that does something else
            "label": changes.describe(ctx.snap, s.entry.prim, ctx.resolver.where),
            "status": s.status,
            "due": s.entry.due.isoformat() if s.entry.due else None,
            "problems": s.problems,
            "note": s.note,
        }
        for s in statuses
    ]
    for s in statuses:
        problems_rot += [f"{s.entry.id or s.entry.expected_id}: {x}" for x in s.problems]
    if plan is not None and args.check:
        problems_gate += expect_problems(plan.expect, res, closes_all)
    if args.fail_if_exposed is not None and res.after.exposed > args.fail_if_exposed:
        problems_gate.append(
            f"{res.after.exposed} users exposed after the changes; --fail-if-exposed allows "
            f"{args.fail_if_exposed}"
        )
    if args.fail_on:
        level = Severity[args.fail_on.upper()]
        bad = [r for r in fb["new"] if Severity[r["severity"].upper()] >= level]
        if bad:
            problems_gate.append(f"{len(bad)} findings at {args.fail_on} or above would appear")
    notes = list(ctx.notes)
    if not ok:
        notes.append(
            "a change can move GPO scope or who can be impersonated: paths come from a rebuilt "
            "graph, routes from the "
            "flow model on the masked graph"
        )
    if args.paths_only:
        notes.append("--paths-only: findings were not rechecked")
    if plan_tier0 and args.check:
        notes.append(
            f"the plan file treats {len(plan_tier0)} nodes as tier 0 ([assume] tier0): the "
            "numbers and the check count them as tier 0; review an edit there like a change"
        )
    doc["notes"] = notes
    if problems_rot and not args.check:
        notes += [f"plan: {x}" for x in problems_rot]
        problems_rot = []
    code = 3 if problems_rot else 2 if problems_gate else 0
    doc["check"] = {
        "ok": not problems_rot and not problems_gate,
        "problems": [*problems_rot, *problems_gate],
    }
    name = args.plan.name if args.plan else "plan.toml"
    hint = f"ad-doctor whatif NEW.json --plan {name} --check"
    doc["caveats"] = caveats(ctx.snap, hint)
    return doc, code


def level2(ctx: Context, res: whatif.Result, findings: bool) -> dict[str, Any]:
    """The findings recheck, after the graph has let go of its memory (nothing after
    level 1 needs it)."""
    if not findings:
        return findings_block(ctx, res)
    graphs = {id(x): x for x in (ctx.g, res.before.graph, res.after.graph)}
    whatif.release(*graphs.values())
    whatif.finish(res, ctx.snap, ctx.prov, ctx.baseline(), recheck(ctx.spec))
    return findings_block(ctx, res)


def _absent_record(r: Resolved) -> dict[str, Any]:
    return {
        "id": None,
        "kind": None,
        "spec": r.spec,
        "label": r.spec,
        "class": None,
        "cost": None,
        "status": "absent",
        "source": "remove",
        "notes": r.notes,
        "warnings": [],
        "edges_removed": 0,
        "edges_on_paths": 0,
        "objects_affected": 0,
        "identity": {},
        "fix": [],
        "rollback": [],
        "expected_to_clear": [],
    }


def _closed_by(ctx: Context, res: whatif.Result, removed: set[int]) -> dict[str, set[int]]:
    """AD-PATH-001 fingerprint of each closed holder -> the changes on its old path."""
    prov = ctx.g.prov
    assert prov is not None
    out: dict[str, set[int]] = {}
    g = res.before.graph
    for node in res.closed:
        p = res.before.holders[node]
        hits: set[int] = set()
        src = p.start
        for dst, how in p.steps:
            why = prov.why.get(src)
            for i, (d, label) in enumerate(ctx.g.edges.get(src, ())):
                if d == dst and label == how and why is not None:
                    hits |= set(cut._instances(prov, src, i, why[i])[0]) & removed
            src = dst
        out[fingerprint("AD-PATH-001", g.ident(node))] = hits
    return out


def expect_problems(
    expect: dict[str, bool | int], res: whatif.Result, closes_all: bool | None
) -> list[str]:
    out = []
    after = res.after
    if expect.get("closes_all") and closes_all is False:
        out.append("[expect] closes_all: some sources the plan can close still reach tier 0")
    limit = expect.get("max_exposed_percent")
    over = isinstance(limit, int) and after.exposed * 100 > limit * max(after.users, 1)
    if over and not isinstance(limit, bool):
        pct = 100 * after.exposed / max(after.users, 1)
        out.append(f"[expect] max_exposed_percent {limit}: {pct:.1f}% exposed after the plan")
    holders = expect.get("max_holders")
    if isinstance(holders, int) and not isinstance(holders, bool) and len(after.holders) > holders:
        out.append(f"[expect] max_holders {holders}: {len(after.holders)} holders after the plan")
    return out


# -- plan -------------------------------------------------------------------------------------


def run_plan(args: argparse.Namespace) -> tuple[dict[str, Any], int, planfile.PlanFile]:
    ctx = load(args)
    prov = ctx.g.prov
    assert prov is not None
    given = planfile.load(args.plan) if args.plan else None
    allow = list(dict.fromkeys([*(args.allow or []), *(given.allow if given else [])]))
    if "disable" in allow:
        raise SpecError("disable is not in this version")
    kinds = [a for a in allow if a != "warn"]
    for k in kinds:
        if k not in changes.FIELDS:
            raise SpecError(f"--allow takes warn or a change kind ({', '.join(changes.FIELDS)})")
    keeps = file_keeps(ctx, given)
    ctx.resolver.want_ids(x.strip() for x in args.keep or [])
    for spec in args.keep or []:
        r = ctx.resolver.resolve(spec)
        if r.status == "absent":
            ctx.notes.append(f"--keep {spec}: absent in this snapshot")
        for i in r.prims:
            keeps[i] = "--keep"
    findings = ctx.baseline
    opt, accepted_holders = option_keeps(ctx, findings) if ctx.entries or ctx.spec else ({}, [])
    keeps.update(opt)
    if kinds:
        for i, key in enumerate(prov.prims):
            if key[0] not in kinds:
                keeps.setdefault(i, "not in --allow")
    names = list(args.sources or []) or (given.sources if given else [])
    goal = "from" if names else args.goal
    tier0_names = [*(args.tier0 or []), *(given.tier0 if given else [])]
    extra = tier0_nodes(ctx, tier0_names)
    for n in names:
        if ctx.resolver.node(n) is None:
            raise SpecError(f"--from: no {n!r} in this snapshot")
    p = cut.plan(
        ctx.snap,
        ctx.g,
        "exposure" if goal == "from" else goal,
        args.near,
        names,
        keeps,
        allow,
        extra,
        accepted_holders,
        args.max_changes,
        ctx.resolver.where,
    )
    tier0 = set(whatif.masked(ctx.g, ctx.snap, (), extra).tier0)
    prep = Prepared.of(ctx, p.changes, tier0)
    findings_needed = not args.paths_only
    expected = expected_map(ctx, set(p.changes)) if findings_needed else {}
    step_closed = _step_holders(ctx, p, extra) if args.format == "markdown" else {}
    res = whatif.run(ctx.snap, ctx.g, p.changes, (), True, extra, None, recheck(ctx.spec))
    expected_after = p.steps[-1].exposed_after if p.steps else p.before[0]
    if not res.maskable and res.after.exposed != expected_after:
        # the cut reads the masked graph; a rebuild (GPO scope, a CA right holder out of
        # tier 0) shows what the model could not
        p.proven = p.exact = False
        p.note = "; ".join(
            x
            for x in (
                p.note,
                f"the rebuilt graph leaves {res.after.exposed} users exposed where the model "
                f"expected {expected_after}: not shown to be the minimum",
            )
            if x
        )
    counts = _edge_counts(ctx.g, res.before, p.changes)
    closed_by = _closed_by(ctx, res, set(p.changes))
    doc = document(ctx, "plan")
    recs = {c: record(ctx, c, prep, counts, "", "applied", [], [], "plan") for c in p.changes}
    g = res.before.graph
    step_rows = [
        {
            "n": s.n,
            "title": s.title,
            "changes": [changes.change_id(prov.prims[c]) for c in s.changes],
            "exposed_after": s.exposed_after,
            "holders_after": s.holders_after,
            "routes_after": s.routes_after,
            "closes": [g.name(n) for n in step_closed.get(s.n, [])],
        }
        for s in p.steps
    ]
    paths_doc = paths_block(res, p.unclosable)
    fb = level2(ctx, res, findings_needed)
    for c, rec in recs.items():
        rec["expected_to_clear"] = clears_for(fb, expected, c, closed_by)
    doc["changes"] = [recs[c] for c in p.changes]
    routes_after = p.steps[-1].routes_after if p.steps else p.before[2]
    doc["before"] = numbers(res.before, p.before[2])
    doc["after"] = numbers(res.after, routes_after)
    doc["paths"] = paths_doc
    doc["findings"] = fb
    doc["accounts"] = []
    doc["assumptions"] = assumptions(
        ctx, [("--tier0", list(args.tier0 or [])), ("plan file", given.tier0 if given else [])]
    )
    doc["steps"] = step_rows
    doc["recommendation"] = {
        "goal": goal,
        "near": p.near,
        "cost": p.cost,
        "changes": len(p.changes),
        "lower_bound": {"changes": p.lower_bound[0], "cost": p.lower_bound[1]},
        "exact": p.exact,
        "proven_minimum": p.proven,
        "inexact_primitives": p.inexact,
        "alternatives": p.alternatives,
        "method_order": p.method_order,
        "budget": args.max_changes,
        "note": p.note,
    }
    doc["plan_status"] = []
    doc["check"] = {"ok": True, "problems": []}
    notes = list(ctx.notes)
    if args.paths_only:
        notes.append("--paths-only: findings were not rechecked")
    if not res.maskable:
        notes.append(
            "a change can move GPO scope or who can be impersonated, so the paths after it "
            "come from a rebuilt graph"
        )
    doc["notes"] = notes
    doc["caveats"] = caveats(ctx.snap, "ad-doctor whatif NEW.json --plan plan.toml --check")
    out = planfile.PlanFile(
        domain=ctx.snap.domain,
        domain_sid=ctx.snap.domain_sid,
        made_against=ctx.snap.collected_at,
        made_by=f"ad-doctor {__version__} plan",
        goal=goal,
        sources=names,
        allow=allow,
        tier0=[_tier0_name(ctx, n) for n in extra],
        changes=[planfile.entry_for(prov.prims[c], recs[c]["label"]) for c in p.changes],
        keeps=list(given.keeps) if given else [],
    )
    if args.max_changes is None:
        users = max(res.after.users, 1)
        out.expect = {
            "max_exposed_percent": math.ceil(100 * res.after.exposed / users),
            "max_holders": len(res.after.holders),
        }
        # --keep and --allow KIND are not in the file: on a check, what they held back
        # would count as closable
        if not (args.keep or kinds):
            out.expect = {"closes_all": True, **out.expect}
    return doc, 0, out


def _tier0_name(ctx: Context, node: str) -> str:
    """A node's name for [assume] tier0 when it resolves back to the node, else its ID."""
    name = ctx.g.name(node)
    try:
        if ctx.resolver.node(name) == node:
            return name
    except SpecError:
        pass
    return node.split(":", 1)[-1]


def _step_holders(ctx: Context, p: cut.Plan, extra: list[str]) -> dict[int, list[str]]:
    """Per step, the AD-PATH-001 holders it closes in the snapshot (masked graph)."""
    out: dict[int, list[str]] = {}
    applied: list[int] = []
    before = set(whatif.state(ctx.snap, whatif.masked(ctx.g, ctx.snap, (), extra)).holders)
    for s in p.steps:
        applied += s.changes
        now = set(whatif.state(ctx.snap, whatif.masked(ctx.g, ctx.snap, applied, extra)).holders)
        out[s.n] = sorted(before - now)
        before = now
    return out


def rebuild_fix_lines(snap: Snapshot, doc: dict[str, Any]) -> str | None:
    """Replace the label and fix lines of each change in a plan or what-if result with the
    ones this snapshot gives for its ID. The JSON is a file anyone can edit, and these lines
    are offered for copying. Returns why that cannot be done, or None."""
    from .fixes import change_lines, rollback_lines

    g = paths.build(snap, provenance=True)
    prov = g.prov
    assert prov is not None
    wanted = {c["id"] for c in doc["changes"] if c.get("id")}
    found: dict[str, int] = {}
    for i, prim in enumerate(prov.prims):
        change = changes.change_id(prim)
        if change in wanted:
            found[change] = i
    if missing := sorted(wanted - set(found)):
        return f"change {missing[0]} is not in this snapshot"
    facts = changes.facts(snap, prov, Resolver(snap, g).where, list(found.values()))
    counts = _edge_counts(g, whatif.state(snap, g), found.values())
    for c in doc["changes"]:
        if not c.get("id"):
            c.pop("fix", None)
            c.pop("rollback", None)
            continue
        p = found[c["id"]]
        f = facts[p]
        if prov.prims[p][0] == "inherited-ace":  # as record() counts them
            f.copies = max(f.copies, counts[p][2] - 1)
        c.update(label=f.label, fix=change_lines(f, snap), rollback=rollback_lines(f, snap))
    return None


def snapshot_hint(path: Path) -> str:
    return path.name
