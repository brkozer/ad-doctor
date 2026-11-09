"""Command line: collect a snapshot, analyze it, compare two runs."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from . import (
    __version__,
    accept,
    catalog,
    coverage,
    explain,
    invariants,
    opengraph,
    patches,
    paths,
    redact,
    rollup,
    seal,
    trend,
    viewer,
    viewer_graph,
    views,
)
from .checks import MITRE, REGISTRY, run_all
from .collect import CollectError, Target, collect
from .fixes import one_line, render_fixes, render_preflight
from .model import DomainPolicy, Finding, Severity, Snapshot
from .report import (
    Accepted,
    Report,
    compare,
    declared_lines,
    declared_nodes,
    legacy_keys,
    mermaid_paths,
    render_json,
    render_junit,
    render_markdown,
    render_sarif,
    render_text,
)

RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "sarif": render_sarif,
    "junit": render_junit,
}
FORMATS = ["text", "json", "markdown", "html", "sarif", "junit"]


def _target(args: argparse.Namespace) -> Target:
    password = os.environ.get("AD_DOCTOR_PASSWORD")
    if args.user and password is None and not args.kerberos:
        password = getpass.getpass(f"Password for {args.user}: ")
    port = args.port or (636 if args.ldaps else 389)
    return Target(
        declared_tier0=[n for _, names in _tier0_groups(args) for n in names],
        host=args.host,
        port=port,
        user=args.user,
        password=password,
        use_ssl=args.ldaps,
        sysvol=not args.no_sysvol,
        smb_port=args.smb_port,
        # --no-probes means every probe, the signing bind included
        plain_port=0 if args.no_probes else args.signing_probe_port,
        http_port=args.http_port,
        https_port=args.https_port,
        probes=not args.no_probes,
        kerberos=args.kerberos,
        all_dcs=not args.single_dc,
        ca_registry=not args.no_ca_registry,
        dc_probes=args.dc_probes,
        patch_level=not args.no_patch_level,
    )


def _tier0_groups(args: argparse.Namespace) -> list[tuple[str, list[str]]]:
    """The names declared as tier 0, per where they came from; empty without either flag."""
    named, path = getattr(args, "tier0", None), getattr(args, "tier0_file", None)
    if not named and not path:
        return []
    from . import declared

    from_file = declared.load_file(path) if path else []
    groups = [("--tier0", list(named or [])), (path.name if path else "", from_file)]
    return [(source, names) for source, names in groups if names]


def _run_checks(
    snap: Snapshot,
    only: list[str] | None,
    groups: list[tuple[str, list[str]]],
    lenient: bool = False,
) -> tuple[list[Finding], dict[str, Any] | None]:
    """The findings, and with a declaration what the report says about it. AD-PATH-001
    sees the declaration through the graph it is lent."""
    if not groups:
        return run_all(snap, only), None
    from . import declared

    decl = declared.declare(snap, groups, lenient)
    snap.notes.extend(decl.notes)
    with paths.lend(snap, decl.graph, decl.analysis):
        return run_all(snap, only), decl.summary()


def _write_private(path: Path, text: str | Iterable[str]) -> None:
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


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def _use_color(stream: Any) -> bool:
    if "NO_COLOR" in os.environ:
        return False
    return "FORCE_COLOR" in os.environ or bool(stream.isatty())


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a snapshot or report")
    return data


def _report_findings(data: dict[str, Any]) -> list[Finding]:
    return [
        Finding(
            f["id"],
            f["title"],
            Severity[f["severity"].upper()],
            f["detail"],
            f["remediation"],
            f["objects"],
            f.get("mitre", []),
            f.get("keys") or legacy_keys(f["id"], f["objects"]),
            f.get("data", {}),
        )
        for f in data["findings"]
    ]


def _findings_from(
    path: Path,
    only: list[str] | None = None,
    spec: dict[str, Any] | None = None,
    groups: list[tuple[str, list[str]]] | None = None,
) -> tuple[str, list[Finding], set[str], set[str] | None]:
    """Findings from either a saved snapshot (analyzed like the current run) or a JSON report,
    the checks that could not be evaluated there, and the nodes it declared as tier 0 (None
    when `groups` were applied to it, so it declares what the current run does)."""
    data = _load_json(path)
    if data.get("tool") == "ad-doctor":
        findings = _report_findings(data)
        recorded = coverage.from_report(data)
        if recorded is None:
            ran = data.get("checks")
            recorded = coverage.compute(
                _snapshot_of_report(data),
                {f.check_id for f in findings},
                ran=ran if isinstance(ran, list) else None,
                use_data=False,
                version=str(data.get("version", "")),
            )
        declared = declared_nodes(data.get("declared_tier0"))
        return data["domain"], findings, coverage.unevaluated(recorded), declared
    snap = Snapshot.from_json(data)
    # a name the earlier snapshot does not hold is no reason to refuse the comparison
    findings, _ = _run_checks(snap, only, groups or [], lenient=True)
    if spec is not None:
        findings += invariants.evaluate(snap, spec)
    wanted = {i.upper() for i in only} if only else None
    ran = None if wanted is None else [c.id for c in REGISTRY if c.id in wanted]
    statuses = coverage.compute(snap, {f.check_id for f in findings}, ran=ran)
    return snap.domain, findings, coverage.unevaluated(statuses), None if groups else set()


def _fails(findings: list[Finding], level: str | None) -> bool:
    return bool(level) and any(f.severity >= Severity[str(level).upper()] for f in findings)


def cmd_diff(args: argparse.Namespace) -> int:
    domain, old, old_unknown, old_declared = _findings_from(args.old)
    _, new, unknown, new_declared = _findings_from(args.new)
    changes = compare(old, new, old_unknown, unknown, old_declared, new_declared)
    added, removed = changes.added, changes.resolved
    unverified, earlier = changes.not_evaluated_now, changes.not_evaluated_before
    declaration = changes.declaration
    sev = {f.check_id: f.severity for f in [*old, *new]}
    title = {f.check_id: f.title for f in [*old, *new]}
    # keys are identities; show the object text (a path's identity is only its start)
    shown = {(f.check_id, f.key(o)): o for f in [*old, *new] for o in f.objects}
    if args.format == "json":
        print(
            json.dumps(
                {
                    "domain": domain,
                    "new": [
                        {"id": c, "object": shown[c, o], "severity": str(sev[c])} for c, o in added
                    ],
                    "resolved": [{"id": c, "object": shown[c, o]} for c, o in removed],
                    "not_evaluated": [{"id": c, "object": shown[c, o]} for c, o in unverified],
                    "not_evaluated_before": [
                        {"id": c, "object": shown[c, o], "severity": str(sev[c])}
                        for c, o in earlier
                    ],
                    "declaration_changed": [
                        {"id": c, "object": shown[c, o]} for c, o in declaration
                    ],
                },
                indent=2,
            )
        )
    else:
        tail = f", {len(unverified)} not evaluated in the newer run" if unverified else ""
        tail += f", {len(earlier)} not evaluated in the older run" if earlier else ""
        tail += f", {len(declaration)} from a changed tier-0 declaration" if declaration else ""
        print(f"{domain}: {len(added)} new, {len(removed)} resolved{tail}")
        for c, o in added:
            print(f"+ [{str(sev[c]).upper():6}] {c}  {shown[c, o]}  ({title[c]})")
        for c, o in removed:
            print(f"- [{str(sev[c]).upper():6}] {c}  {shown[c, o]}  ({title[c]})")
        for c, o in unverified:
            print(f"? [{str(sev[c]).upper():6}] {c}  {shown[c, o]}  ({title[c]})")
        for c, o in earlier:
            print(
                f"? [{str(sev[c]).upper():6}] {c}  {shown[c, o]}  (not evaluated in the older run)"
            )
        for c, o in declaration:
            print(f"~ [{str(sev[c]).upper():6}] {c}  {shown[c, o]}  (declared in one run only)")
    fresh = set(added)
    new_findings = [f for f in new for o in f.objects if (f.check_id, f.key(o)) in fresh]
    return 2 if _fails(new_findings, args.fail_on) else 0


def _step_changes(g: paths.Graph, p: paths.Path) -> list[list[str]]:
    """Per step of a path, the IDs of the changes that remove that edge (empty when it
    cannot be removed), for `whatif --remove`."""
    from .changes import change_id
    from .cut import _instances

    prov = g.prov
    assert prov is not None
    out = []
    src = p.start
    for dst, how in p.steps:
        ids: dict[str, None] = {}
        why = prov.why.get(src)
        for i, (d, label) in enumerate(g.edges.get(src, ())):
            if d == dst and label == how and why is not None:
                for c in _instances(prov, src, i, why[i])[0]:
                    ids[change_id(prov.prims[c])] = None
        out.append(list(ids))
        src = dst
    return out


def _path_json(g: paths.Graph, p: paths.Path) -> dict[str, Any]:
    rec = p.record(g)
    for step, ids in zip(rec["steps"], _step_changes(g, p), strict=True):
        step["changes"] = ids
    return rec


def cmd_paths(args: argparse.Namespace) -> int:
    snap = Snapshot.from_json(_load_json(args.snapshot))
    json_out = args.format == "json"
    groups = _tier0_groups(args)
    summary: dict[str, Any] | None = None
    if groups:
        from . import declared

        decl = declared.declare(snap, groups)
        a, summary = decl.analysis, decl.summary()
        notes = decl.notes
    else:
        a = paths.analyze(snap, paths.build(snap, provenance=json_out and not args.chokepoints))
        notes = []
    g = a.graph
    extended = a.declared.paths if a.declared else []
    gap = coverage.path_gaps([*snap.notes, *notes], bool(a.paths or extended))
    if args.chokepoints:
        return _print_chokepoints(args, snap, a, extended, summary, gap)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "domain": snap.domain,
                    "exposed_users": a.exposed,
                    "enabled_users": a.users,
                    "paths": [_path_json(g, p) for p in a.paths],
                    **gap,
                    **(
                        {
                            "declared_tier0": summary,
                            "declared_paths": [_path_json(g, p) for p in extended],
                        }
                        if summary is not None
                        else {}
                    ),
                },
                indent=2,
            )
        )
    elif args.format == "mermaid":
        shown = [p.render(g) for p in [*a.paths, *extended]]
        print("\n".join(mermaid_paths(shown, limit=len(shown))))
        _print_gap(gap, sys.stderr)  # stdout stays one diagram
    else:
        print(
            f"{snap.domain}: {len(a.paths)} principals reach tier 0; {a.exposed} of {a.users} "
            f"enabled users ({a.percent}%) have a path"
        )
        for p in a.paths:
            print(f"  {len(p.steps)} hop{'s' if len(p.steps) != 1 else ' '}  {p.render(g)}")
        for line in declared_lines(summary):
            print(line)
        for p in extended:
            print(f"  {len(p.steps)} hop{'s' if len(p.steps) != 1 else ' '}  {p.render(g)}")
        _print_gap(gap, sys.stdout)
    return 0


def _print_gap(gap: dict[str, Any], stream: Any) -> None:
    for line in coverage.path_gap_lines(gap):
        print(f"note: {one_line(line)}", file=stream)


def _print_chokepoints(
    args: argparse.Namespace,
    snap: Snapshot,
    a: paths.Analysis,
    extended: list[paths.Path],
    summary: dict[str, Any] | None,
    gap: dict[str, Any],
) -> int:
    from .resolve import edge_id

    g = a.graph
    points = paths.chokepoints(a.paths, args.minimum)
    declared_points = paths.chokepoints(extended, args.minimum)
    if args.format == "json":

        def rows(found: list[paths.Chokepoint]) -> list[dict[str, Any]]:
            return [
                {
                    "count": c.count,
                    "kind": "edge" if c.is_edge else "node",
                    **({"from": g.name(c.source), "how": c.how} if c.source is not None else {}),
                    "node": g.name(c.target),
                    **({"id": edge_id(c.source, c.target, c.how)} if c.source is not None else {}),
                }
                for c in found
            ]

        out: dict[str, Any] = {"paths": len(a.paths), "chokepoints": rows(points), **gap}
        if summary is not None:
            out["declared_tier0"] = summary
            out["declared_paths"] = len(extended)
            out["declared_chokepoints"] = rows(declared_points)
        print(json.dumps(out, indent=2))
        return 0

    def show(found: list[paths.Chokepoint], total: int) -> None:
        for c in found:
            where = (
                f"edge  {g.name(c.source)} -[{c.how}]-> {g.name(c.target)}"
                if c.source is not None
                else f"node  {g.name(c.target)}"
            )
            print(f"  {c.count:>4}/{total}  {where}")
        if not found:
            print("  none: every path takes its own route")

    print(f"{snap.domain}: {len(a.paths)} paths to tier 0; shared by {args.minimum} or more:")
    show(points, len(a.paths))
    if summary is not None:
        for line in declared_lines(summary):
            print(line)
        print(f"{len(extended)} paths to declared tier 0; shared by {args.minimum} or more:")
        show(declared_points, len(extended))
    _print_gap(gap, sys.stdout)
    return 0


def _whatif_output(args: argparse.Namespace, doc: dict[str, Any], plan: Any = None) -> None:
    from . import planfile, whatif_render

    fmt = args.format
    if fmt == "toml":
        text = planfile.dumps(plan)
    elif fmt == "json":
        text = whatif_render.render_json(doc)
    elif fmt == "markdown":
        text = whatif_render.render_markdown(doc)
    elif fmt == "ps1":
        text = whatif_render.render_ps1(doc)
    else:
        text = whatif_render.render_text(doc)
    if args.output:
        _write_private(args.output, text)
    else:
        sys.stdout.write(text)


def _whatif_errors() -> tuple[type[BaseException], ...]:
    from .planfile import PlanError
    from .resolve import SpecError
    from .whatif import ModelMismatch

    return (*ERRORS, SpecError, PlanError, ModelMismatch)


def cmd_whatif(args: argparse.Namespace) -> int:
    from . import whatif_cmd
    from .whatif import ModelMismatch

    try:
        doc, code = whatif_cmd.run_whatif(args)
        _whatif_output(args, doc)
    except _whatif_errors() as exc:
        bug = (
            " (a bug in ad-doctor's model: please report it)"
            if isinstance(exc, ModelMismatch)
            else ""
        )
        print(f"ad-doctor: {exc}{bug}", file=sys.stderr)
        return 1
    return code


def cmd_plan(args: argparse.Namespace) -> int:
    from . import whatif_cmd
    from .whatif import ModelMismatch

    try:
        doc, code, plan = whatif_cmd.run_plan(args)
        _whatif_output(args, doc, plan)
    except _whatif_errors() as exc:
        bug = (
            " (a bug in ad-doctor's model: please report it)"
            if isinstance(exc, ModelMismatch)
            else ""
        )
        print(f"ad-doctor: {exc}{bug}", file=sys.stderr)
        return 1
    return code


def cmd_blast_radius(args: argparse.Namespace) -> int:
    snap = Snapshot.from_json(_load_json(args.snapshot))
    starts = paths.identity_nodes(snap, args.account)
    if not starts:
        print(f"ad-doctor: no account {args.account!r} in the snapshot", file=sys.stderr)
        return 1
    g = paths.build(snap)
    controlled, tier0 = paths.blast_radius(g, starts)
    if args.format == "json":
        rows = [
            {"object": g.name(n), "tier0": n in g.tier0, "path": p.render(g)}
            for n, p in controlled.items()
        ]
        rows.sort(key=lambda x: (not x["tier0"], str(x["object"]).lower()))
        print(json.dumps({"account": args.account, "reaches_tier0": bool(tier0), "controls": rows},
                         indent=2))  # fmt: skip
    else:
        verdict = "REACHES TIER 0" if tier0 else "does not reach tier 0"
        print(f"{args.account}: controls {len(controlled)} objects, {verdict}")
        for p in tier0[:20]:
            print(f"  ! {p.render(g)}")
        for n, p in sorted(controlled.items(), key=lambda x: g.name(x[0]).lower()):
            if n not in g.tier0:
                print(f"    {p.render(g)}")
    return 2 if tier0 else 0


def cmd_export_graph(args: argparse.Namespace) -> int:
    snap = Snapshot.from_json(_load_json(args.snapshot))
    payload = opengraph.export(snap, paths_only=args.paths_only)
    # in pieces: the whole text of a big graph takes more memory than the graph itself
    _write_private(args.output, json.JSONEncoder(indent=1).iterencode(payload))
    graph = payload["graph"]
    print(f"wrote {args.output} ({len(graph['nodes'])} nodes, {len(graph['edges'])} edges)")
    return 0


def cmd_redact(args: argparse.Namespace) -> int:
    key = os.environ.get("AD_DOCTOR_REDACT_KEY")
    if not key:
        print(
            "ad-doctor: set AD_DOCTOR_REDACT_KEY (keep it to redact later snapshots the same way)",
            file=sys.stderr,
        )
        return 1
    data = redact.redact(_load_json(args.snapshot), key.encode())
    _write_private(args.output, json.dumps(data, indent=2))
    print(f"wrote {args.output}")
    return 0


ERRORS = (
    CollectError,
    seal.PassphraseError,
    accept.AcceptError,
    invariants.InvariantError,
    OSError,
    ValueError,
    KeyError,
)


def _analyze(
    args: argparse.Namespace,
    snap: Snapshot,
    findings: list[Finding],
    from_report: bool = False,
    report_data: dict[str, Any] | None = None,
    declared: dict[str, Any] | None = None,
) -> tuple[Report, viewer.Options]:
    """Invariants, acceptances and the baseline on top of the findings: the part of a run
    that scan, analyze and view share. Returns the report and what the viewer needs."""
    only = getattr(args, "only", None)
    spec = invariants.load(args.invariants) if args.invariants else None
    if spec is not None:
        if from_report:
            raise ValueError("--invariants needs a snapshot, not a JSON report")
        findings += invariants.evaluate(snap, spec)
        findings.sort(key=lambda f: (-f.severity, f.check_id))
    if not from_report:
        snap.notes = [*snap.notes, *patches.notes(snap)]
    report = Report(snap, findings, from_snapshot=not from_report, declared=declared)
    if from_report and report_data is not None:
        report.declared = report_data.get("declared_tier0")
        report.recorded = coverage.from_report(report_data)
        report.report_version = str(report_data.get("version", ""))
        checks = report_data.get("checks")
        report.ran = list(checks) if isinstance(checks, list) else None
    if not from_report:
        wanted = {i.upper() for i in only or []}
        report.ran = [c.id for c in REGISTRY if not wanted or c.id in wanted]
        report.ran += list(invariants.IDS) if spec is not None else []
    unknown = coverage.unevaluated(report.statuses())
    opts = viewer.Options(spec=spec)
    if args.accept:
        entries = accept.load(args.accept)
        today = snap.collected_at.date()
        if from_report:
            ran = {f.check_id for f in findings} | {a.check_id for a in report.accepted}
            ran |= {c.id for c in REGISTRY}
        else:
            ran = {c.id for c in REGISTRY if not only or c.id in {i.upper() for i in only}}
        if spec is not None:
            ran |= set(invariants.IDS)
        # a check that gave no answer cannot make an acceptance stale
        ran -= unknown
        kept, accepted, notes = accept.apply(findings, entries, today, ran)
        report.findings = kept
        report.accepted += accepted
        snap.notes.extend(notes)
        opts.entries, opts.ran = entries, ran
    if args.baseline:
        _, old, was_unknown, was_declared = _findings_from(
            args.baseline, only, spec, _tier0_groups(args)
        )
        changes = compare(
            old,
            report.findings,
            was_unknown,
            unknown,
            was_declared,
            declared_nodes(report.declared),
        )
        report.new = set(changes.added)
        if changes.not_evaluated_before:
            snap.notes.append(
                f"--baseline: {len(changes.not_evaluated_before)} findings are not marked new "
                "because the baseline did not evaluate their check"
            )
        if changes.declaration:
            snap.notes.append(
                f"--baseline: {len(changes.declaration)} paths are not marked new or resolved "
                "because only one of the two runs declared the asset they reach"
            )
        stamp = _load_json(args.baseline).get("collected_at")
        opts.baseline = viewer.Baseline(old, stamp, args.baseline.name, was_unknown, was_declared)
    return report, opts


def _command(args: argparse.Namespace) -> str:
    """How a page was built, for its About screen: file names only, never a host, user
    or secret."""
    parts = ["ad-doctor", args.cmd]
    if args.cmd in ("analyze", "view"):
        parts.append(getattr(args, "snapshot", None) or args.input)
    for flag in ("baseline", "accept", "invariants", "whatif"):
        if getattr(args, flag, None):
            parts += [f"--{flag}", getattr(args, flag)]
    if getattr(args, "tier0_file", None):
        parts += ["--tier0-file", args.tier0_file]
    if args.cmd == "view":
        parts += ["--fixes"] if args.fixes else []
        parts += ["--history", Path(args.history)] if args.history else []
        parts += ["--graph", args.graph] if args.graph != "auto" else []
        for account in args.blast_radius_for or []:
            parts += ["--blast-radius-for", account]
        parts += {True: ["--encrypt"], False: ["--no-encrypt"], None: []}[args.encrypt]
    else:
        parts += ["-f", "html"]
    return " ".join(str(Path(p).name) if isinstance(p, Path) else p for p in parts)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _snapshot_of_report(data: dict[str, Any]) -> Snapshot:
    """A JSON report has no snapshot: an empty one carries its domain, time and notes."""
    return Snapshot(
        domain=data["domain"],
        domain_dn="",
        domain_sid="",
        collected_at=datetime.fromisoformat(data["collected_at"]),
        policy=DomainPolicy(0, False, 0, None, 0, 0),
        accounts=[],
        privileged={},
        protected_users=[],
        notes=list(data.get("notes", [])),
    )


def _passphrase(graph: str, explicit: bool) -> str:
    """The viewer passphrase: AD_DOCTOR_VIEW_PASSPHRASE, else a prompt (twice) on a
    terminal. Never echoed, never written into the file. The variable is removed from
    this process's environment once read, so a browser started by --open does not
    inherit it."""
    why = (
        "--encrypt was given"
        if explicit
        else {"full": "it embeds the control graph", "paths": "it embeds blast-radius data"}[graph]
    )
    text = os.environ.pop(seal.ENV, None)
    if text is None:
        if not sys.stdin.isatty():
            hint = "" if explicit else " (or --graph none to leave the graph out)"
            raise seal.PassphraseError(
                f"the file is encrypted because {why}: set {seal.ENV}, or pass --no-encrypt "
                f"to write it in the clear{hint}"
            )
        print(
            f"The file is encrypted because {why}. Use at least {seal.MIN_LENGTH} characters, "
            f"for example this random one ({seal.suggestion_bits()} bits): {seal.suggest()}",
            file=sys.stderr,
        )
        text = getpass.getpass("Passphrase for the viewer file: ")
        if seal.problem(text) is None and getpass.getpass("Again: ") != text:
            raise seal.PassphraseError("the two passphrases differ")
    why_not = seal.problem(text)
    if why_not is not None:
        raise seal.PassphraseError(
            f"the passphrase {why_not}; for example: {seal.suggest()} "
            f"({seal.suggestion_bits()} bits)"
        )
    return text


def _emit(text: str, output: Path | None) -> int:
    if output:
        _write_private(output, text + "\n")
    else:
        print(text)
    return 0


def cmd_rollup(args: argparse.Namespace) -> int:
    doc = rollup.build(args.reports)
    render = {
        "text": rollup.render_text,
        "json": rollup.render_json,
        "markdown": rollup.render_markdown,
    }
    return _emit(render[args.format](doc), args.output)


def cmd_views(args: argparse.Namespace) -> int:
    snap = Snapshot.from_json(_load_json(args.snapshot))
    if args.cmd == "service-accounts":
        text = views.render_service_accounts(views.service_accounts(snap), args.format)
    else:
        text = views.render_scorecard(views.tier0_scorecard(snap, run_all(snap)), args.format)
    return _emit(text, args.output)


def cmd_view(args: argparse.Namespace) -> int:
    out = args.output or args.input.with_suffix(".html")
    if out.resolve() == args.input.resolve():
        print("ad-doctor: the output would overwrite the input; pass -o", file=sys.stderr)
        return 1
    try:
        data = _load_json(args.input)
        redacted = bool(data.get("redacted"))
        if data.get("tool") == "ad-doctor":
            snap = _snapshot_of_report(data)
            findings = _report_findings(data)
            if args.fixes:
                raise ValueError("--fixes needs a snapshot, not a JSON report")
            if _tier0_groups(args):
                raise ValueError("--tier0 and --tier0-file need a snapshot, not a JSON report")
            if args.graph not in ("auto", "none") or args.blast_radius_for:
                raise ValueError("--graph and --blast-radius-for need a snapshot, not a report")
            report, opts = _analyze(args, snap, findings, from_report=True, report_data=data)
            report.accepted = [Accepted(**a) for a in data.get("accepted", [])] + report.accepted
            opts.source, source = "report", None
        else:
            source = Snapshot.from_json(data)
            del data  # the parsed file is as big as the snapshot
            found, decl = _run_checks(source, None, _tier0_groups(args))
            report, opts = _analyze(args, source, found, declared=decl)
            opts.graph = viewer_graph.choose(args.graph, source)
            if args.blast_radius_for and opts.graph != "paths":
                raise ValueError("--blast-radius-for goes with --graph paths (full has them all)")
        if args.history:
            opts.history = trend.load(args.history, report.snap.domain)
        opts.encrypted = args.encrypt if args.encrypt is not None else opts.graph != "none"
        passphrase = _passphrase(opts.graph, args.encrypt is True) if opts.encrypted else None
        opts.redacted = redacted
        opts.fixes = args.fixes
        opts.blast_for = args.blast_radius_for
        opts.command = _command(args)
        if args.whatif:
            try:
                doc = _load_json(args.whatif)
            except RecursionError:
                raise ValueError(f"--whatif {args.whatif.name}: nested too deeply") from None
            digest = None if source is None else _sha256(args.input)
            why = viewer.whatif_problem(doc, report.snap.domain, digest)
            if why is not None:
                raise ValueError(f"--whatif {args.whatif.name}: {why}")
            if args.fixes and source is not None:
                from . import whatif_cmd  # imported here as for the whatif command

                why = whatif_cmd.rebuild_fix_lines(source, doc)
                if why is not None:
                    raise ValueError(f"--whatif {args.whatif.name}: {why}")
            opts.whatif = doc
        page = viewer.render(viewer.viewmodel(report, source, opts), passphrase)
        _write_private(out, page)
    except ERRORS as exc:
        print(f"ad-doctor: {exc}", file=sys.stderr)
        return 1
    extras = [plural_findings(len(report.findings)), f"graph {opts.graph}"]
    if opts.history is not None:
        extras.append(f"{len(opts.history)} earlier reports")
    extras.append("encrypted" if opts.encrypted else "not encrypted")
    print(f"wrote {out} ({len(page.encode()) // 1024} KB, {', '.join(extras)})")
    if args.open:
        import webbrowser

        webbrowser.open(out.resolve().as_uri())
    return 0


def plural_findings(n: int) -> str:
    return f"{n} finding{'' if n == 1 else 's'}"


def _explain(query: str, fmt: str, web: bool) -> int:
    entry = catalog.find(query)
    if entry is None:
        known = query.strip().upper() in explain.titles()
        why = "has no catalog entry yet" if known else "is not a check ID or alias"
        print(f"ad-doctor: {query!r} {why} (ad-doctor checks lists them)", file=sys.stderr)
        return 1
    if web:
        import webbrowser

        webbrowser.open(entry.url)
        return 0
    render = {"text": explain.render_text, "markdown": explain.render_markdown,
              "json": explain.render_json}[fmt]  # fmt: skip
    print(render(entry))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ad-doctor", description="Read-only Active Directory misconfiguration audit."
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def tier0_args(p: argparse.ArgumentParser, what: str) -> None:
        p.add_argument("--tier0", action="append", metavar="NAME", help=f"{what} (repeatable)")
        p.add_argument(
            "--tier0-file",
            type=Path,
            metavar="TOML",
            help='the same for every name of a file: tier0 = ["JUMP01$", ...]',
        )

    def conn_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("host", help="domain controller host name or address")
        p.add_argument("--port", type=int)
        p.add_argument("--ldaps", action="store_true", help="LDAP over TLS (port 636)")
        p.add_argument(
            "-u",
            "--user",
            help="DOMAIN\\user (NTLM) or a DN/UPN (simple bind); "
            "password from AD_DOCTOR_PASSWORD or prompt",
        )
        p.add_argument("--no-sysvol", action="store_true", help="skip the SYSVOL (SMB) checks")
        p.add_argument("--smb-port", type=int, default=445)
        p.add_argument(
            "--http-port", type=int, default=80, help="CA web enrollment port for ESC8 (0 to skip)"
        )
        p.add_argument(
            "--https-port",
            type=int,
            default=443,
            help="HTTPS port for CA web enrollment and CES URLs (0 to skip)",
        )
        p.add_argument(
            "--no-probes",
            action="store_true",
            help="skip every probe: LDAP signing, SMB, channel binding, enrollment and the "
            "CA registry",
        )
        p.add_argument(
            "--no-ca-registry",
            action="store_true",
            help="do not read CA settings (ESC6/7/11/16, audit filter) over the winreg pipe; "
            "opening it starts RemoteRegistry on the CA if it is stopped, and EDR or Defender for "
            "Identity may alert on remote registry access",
        )
        p.add_argument(
            "--dc-probes",
            action="store_true",
            help="also probe each DC for WebClient (named pipe), SMBv1 (one negotiate) and the "
            "TLS versions of LDAPS (handshakes only); off by default, and --no-probes wins",
        )
        p.add_argument(
            "--no-patch-level",
            action="store_true",
            help="do not read each DC's and CA's build and UBR over the winreg pipe (AD-INF-029, "
            "AD-ADCS-022); opening it starts RemoteRegistry if it is stopped",
        )
        p.add_argument(
            "--single-dc",
            action="store_true",
            help="probe only the DC being scanned, not every DC in the domain",
        )
        p.add_argument(
            "-k",
            "--kerberos",
            action="store_true",
            help="bind with Kerberos from the current ticket cache (needs ad-doctor[kerberos])",
        )
        p.add_argument(
            "--signing-probe-port",
            type=int,
            default=389,
            metavar="PORT",
            help="plain LDAP port for the LDAP signing probe (0 to skip; needs DOMAIN\\user)",
        )

    def out_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("-f", "--format", choices=FORMATS, default="text", help="report format")
        p.add_argument("-o", "--output", type=Path, help="write the report to a file")
        p.add_argument("--only", nargs="+", metavar="ID", help="run only these check IDs")
        p.add_argument(
            "--fail-on",
            choices=[str(s) for s in Severity],
            help="exit 2 at this severity or above (only new findings with --baseline)",
        )
        p.add_argument("--accept", type=Path, metavar="TOML", help="accepted-risk file")
        p.add_argument(
            "--baseline", type=Path, metavar="JSON", help="earlier report or snapshot to diff"
        )
        p.add_argument(
            "--fixes", type=Path, metavar="PS1", help="write a reviewable remediation script"
        )
        p.add_argument(
            "--preflight",
            type=Path,
            metavar="PS1",
            help="write a read-only script to run before the fixes (first 10 fixes only)",
        )
        p.add_argument(
            "--invariants",
            type=Path,
            metavar="TOML",
            help="declared state to check (policy as code)",
        )

    extended = "add this asset to the declared tier-0 targets, kept apart from built-in tier 0"

    p_scan = sub.add_parser("scan", help="collect and analyze in one go")
    conn_args(p_scan)
    out_args(p_scan)
    tier0_args(p_scan, extended + "; its owner and DACL are read too")

    p_collect = sub.add_parser("collect", help="save a snapshot for later analysis")
    conn_args(p_collect)
    p_collect.add_argument("-o", "--output", type=Path, required=True)
    tier0_args(p_collect, "also read the owner and DACL of this account, for a later --tier0")

    p_analyze = sub.add_parser("analyze", help="analyze a saved snapshot")
    p_analyze.add_argument("snapshot", type=Path)
    out_args(p_analyze)
    tier0_args(p_analyze, extended)

    p_diff = sub.add_parser("diff", help="compare two snapshots or JSON reports")
    p_diff.add_argument("old", type=Path)
    p_diff.add_argument("new", type=Path)
    p_diff.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p_diff.add_argument("--fail-on", choices=[str(s) for s in Severity])

    p_blast = sub.add_parser(
        "blast-radius", help="what one account controls, and whether that reaches tier 0"
    )
    p_blast.add_argument("snapshot", type=Path)
    p_blast.add_argument("account", help="sAMAccountName or SID")
    p_blast.add_argument("-f", "--format", choices=["text", "json"], default="text")

    p_paths = sub.add_parser("paths", help="control paths to tier 0, or where to break them")
    p_paths.add_argument("snapshot", type=Path)
    p_paths.add_argument(
        "--chokepoints",
        action="store_true",
        help="rank the edges and nodes that the most paths share (break those first; "
        "`ad-doctor plan` computes the cheapest set of changes)",
    )
    p_paths.add_argument(
        "--minimum", type=int, default=2, metavar="N", help="with --chokepoints: shared by N+"
    )
    p_paths.add_argument("-f", "--format", choices=["text", "json", "mermaid"], default="text")
    tier0_args(p_paths, extended)

    def whatif_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("snapshot", type=Path)
        tier0_args(p, "treat this node as tier 0 (an assumption, not a change)")
        p.add_argument("--accept", type=Path, metavar="TOML", help="accepted-risk file")
        p.add_argument(
            "--invariants", type=Path, metavar="TOML", help="declared state (policy as code)"
        )
        p.add_argument(
            "--paths-only",
            action="store_true",
            help="paths and exposure only; do not recheck the findings",
        )
        p.add_argument("-o", "--output", type=Path, help="write to a file")

    p_whatif = sub.add_parser(
        "whatif",
        help="what removing rights, memberships or links would change (on the snapshot)",
        description="Evaluate changes on a snapshot, never on AD: the tier-0 paths that close "
        "or are rerouted, exposure, findings that would clear or appear. Name a change by ID "
        '(c:...), finding (fp:...), path step (path:"Domain Users"#1), edge, or typed spec '
        '(member:"Domain Admins":alice, ace:"<DN>":helpdesk, adminsdholder:helpdesk, ...). '
        "Exit codes: 0 ok, 1 error, 2 a gate failed, 3 plan rot under --check.",
    )
    whatif_common(p_whatif)
    p_whatif.add_argument(
        "--remove", action="append", metavar="SPEC", help="a change to evaluate (repeatable)"
    )
    p_whatif.add_argument("--plan", type=Path, metavar="TOML", help="evaluate a plan file")
    p_whatif.add_argument(
        "--account",
        action="append",
        metavar="NAME",
        help="show this account's blast radius before and after (repeatable)",
    )
    p_whatif.add_argument(
        "--strict", action="store_true", help="a change absent in this snapshot is an error"
    )
    p_whatif.add_argument(
        "--check",
        action="store_true",
        help="exit 3 on plan rot (stale, ineffective, edited IDs, another domain), 2 when the "
        "plan's [expect] block fails",
    )
    p_whatif.add_argument(
        "--fail-if-exposed",
        type=int,
        metavar="N",
        help="exit 2 when more than N users are exposed after the changes",
    )
    p_whatif.add_argument(
        "--fail-on",
        choices=[str(s) for s in Severity],
        help="exit 2 when a finding at this severity or above would appear",
    )
    p_whatif.add_argument(
        "-f", "--format", choices=["text", "json", "markdown", "ps1"], default="text"
    )

    p_plan = sub.add_parser(
        "plan",
        help="the cheapest set of changes that closes the tier-0 paths (on the snapshot)",
        description="Compute the cheapest set of removals that closes every path ad-doctor "
        "sees (a minimum cut), says when it is a proven minimum, orders it (a heuristic) and "
        "writes it as text, JSON, Markdown, a plan file or fix lines. Never touches AD.",
    )
    whatif_common(p_plan)
    p_plan.add_argument(
        "--goal",
        choices=["exposure", "all-paths"],
        default="exposure",
        help="exposure: enabled users outside tier 0 (default); all-paths: every AD-PATH-001 "
        "holder",
    )
    p_plan.add_argument(
        "--from",
        dest="sources",
        action="append",
        metavar="NAME",
        help="close the paths of these principals only (repeatable)",
    )
    p_plan.add_argument(
        "--max-changes",
        type=_positive,
        metavar="K",
        help="a budget of K changes, 1 or more (heuristic)",
    )
    p_plan.add_argument(
        "--near",
        choices=["tier0", "source"],
        default="tier0",
        help="of equal-cost cuts, the one nearest tier 0 (default) or the sources",
    )
    p_plan.add_argument(
        "--allow",
        action="append",
        metavar="KIND|warn",
        help="warn: also propose the Entra sync account's DCSync; a change kind: propose "
        "only kinds named this way (repeatable)",
    )
    p_plan.add_argument(
        "--keep", action="append", metavar="SPEC", help="never propose this change (repeatable)"
    )
    p_plan.add_argument(
        "--plan", type=Path, metavar="TOML", help="a plan file whose keeps and [assume] apply"
    )
    p_plan.add_argument(
        "-f", "--format", choices=["text", "json", "markdown", "toml", "ps1"], default="text"
    )

    p_view = sub.add_parser(
        "view", help="write the interactive report: one offline HTML file, no server"
    )
    p_view.add_argument("input", type=Path, metavar="SNAPSHOT|REPORT")
    p_view.add_argument(
        "--baseline", type=Path, metavar="JSON", help="earlier report or snapshot to compare"
    )
    p_view.add_argument("--accept", type=Path, metavar="TOML", help="accepted-risk file")
    p_view.add_argument(
        "--invariants", type=Path, metavar="TOML", help="declared state (needs a snapshot)"
    )
    p_view.add_argument(
        "--fixes", action="store_true", help="include each finding's fix script lines"
    )
    p_view.add_argument(
        "-o", "--output", type=Path, metavar="HTML", help="default: the input name with .html"
    )
    p_view.add_argument(
        "--history",
        type=Path,
        metavar="DIR",
        help="earlier JSON reports of this domain (-f json output) for the Trend screen",
    )
    p_view.add_argument(
        "--graph",
        choices=["auto", "none", "paths", "full"],
        default="auto",
        help="control graph for the Blast radius screen: full (every account, searched in "
        "the page), paths (precomputed for path holders), none; auto: full up to "
        f"{viewer_graph.FULL_GRAPH_OBJECTS:,} directory objects, else paths",
    )
    p_view.add_argument(
        "--blast-radius-for",
        action="append",
        metavar="ACCOUNT",
        help="with --graph paths: also precompute this account's blast radius (repeatable)",
    )
    p_view.add_argument(
        "--encrypt",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=f"encrypt the file with a passphrase ({seal.ENV} or a prompt); the default "
        "when a graph is embedded",
    )
    p_view.add_argument(
        "--whatif",
        type=Path,
        metavar="JSON",
        help="a `plan -f json` or `whatif -f json` result of this snapshot, for the What-if screen",
    )
    p_view.add_argument("--open", action="store_true", help="open it in the default browser")
    tier0_args(p_view, extended)

    p_rollup = sub.add_parser("rollup", help="compare JSON reports of several domains")
    p_rollup.add_argument("reports", type=Path, nargs="+", metavar="REPORT")
    p_rollup.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    p_rollup.add_argument("-o", "--output", type=Path)

    p_service = sub.add_parser("service-accounts", help="list the service accounts of a snapshot")
    p_service.add_argument("snapshot", type=Path)
    p_service.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p_service.add_argument("-o", "--output", type=Path)

    p_card = sub.add_parser("tier-scorecard", help="tier-0 counts from a snapshot, without a score")
    p_card.add_argument("snapshot", type=Path)
    p_card.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p_card.add_argument("-o", "--output", type=Path)

    p_redact = sub.add_parser("redact", help="pseudonymize a snapshot for sharing")
    p_redact.add_argument("snapshot", type=Path)
    p_redact.add_argument("-o", "--output", type=Path, required=True)

    p_graph = sub.add_parser(
        "export-graph", help="write the control graph as BloodHound OpenGraph JSON"
    )
    p_graph.add_argument("snapshot", type=Path)
    p_graph.add_argument("-o", "--output", type=Path, required=True)
    p_graph.add_argument(
        "--paths-only", action="store_true", help="only nodes and edges on paths to tier 0"
    )

    p_checks = sub.add_parser("checks", help="list available checks")
    p_checks.add_argument("-f", "--format", choices=["text", "json"], default="text")

    p_explain = sub.add_parser("explain", help="what a check looks for and how to fix it (offline)")
    p_explain.add_argument("check", help="check ID or alias (AD-ADCS-001, esc1, kerberoasting)")
    p_explain.add_argument("-f", "--format", choices=["text", "markdown", "json"], default="text")
    p_explain.add_argument(
        "--web", action="store_true", help="open the online page in a browser instead"
    )

    args = parser.parse_args(argv)

    if args.cmd == "explain":
        return _explain(args.check, args.format, args.web)
    if args.cmd == "whatif":
        return cmd_whatif(args)
    if args.cmd == "plan":
        return cmd_plan(args)

    if args.cmd == "checks":
        rows: list[dict[str, Any]] = []
        for c in REGISTRY:
            row: dict[str, Any] = {"id": c.id, "title": c.title}
            row["mitre"] = list(MITRE.get(c.id, ()))
            if (e := catalog.get(c.id)) is not None:
                row |= {"summary": e.summary, "url": e.url}
            rows.append(row)
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                print(f"{row['id']:12} {row['title']}")
        return 0

    try:
        if args.cmd == "diff":
            return cmd_diff(args)
        if args.cmd == "blast-radius":
            return cmd_blast_radius(args)
        if args.cmd == "redact":
            return cmd_redact(args)
        if args.cmd == "export-graph":
            return cmd_export_graph(args)
        if args.cmd == "paths":
            return cmd_paths(args)
        if args.cmd == "view":
            return cmd_view(args)
        if args.cmd == "rollup":
            return cmd_rollup(args)
        if args.cmd in ("service-accounts", "tier-scorecard"):
            return cmd_views(args)
        if args.cmd == "analyze":
            snap = Snapshot.from_json(_load_json(args.snapshot))
        else:
            snap = collect(_target(args))
        if args.cmd == "collect":
            _write_private(args.output, json.dumps(snap.to_json(), indent=2))
            print(f"wrote {args.output} ({len(snap.accounts)} accounts)")
            return 0

        found, decl = _run_checks(snap, args.only, _tier0_groups(args))
        report, opts = _analyze(args, snap, found, declared=decl)
    except ERRORS as exc:
        print(f"ad-doctor: {exc}", file=sys.stderr)
        return 1

    if args.fixes:
        _write_private(args.fixes, render_fixes(report.findings, snap))
    if args.preflight:
        _write_private(args.preflight, render_preflight(report.findings, snap))
    if args.format == "text":
        text = render_text(report, color=not args.output and _use_color(sys.stdout))
    elif args.format == "junit":
        text = render_junit(report)
    elif args.format == "html":
        # the same page as `ad-doctor view`, with the defaults: no fix lines, nothing extra
        opts.command = _command(args)
        text = viewer.render(viewer.viewmodel(report, snap, opts))
    else:
        text = RENDERERS[args.format](report)
    if args.output:
        _write_private(args.output, text if text.endswith("\n") else text + "\n")
    else:
        print(text)

    gate = report.findings
    if report.new is not None:
        gate = [f for f in gate if report.is_new(f)]
    return 2 if _fails(gate, args.fail_on) else 0
