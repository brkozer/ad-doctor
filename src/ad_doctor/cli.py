"""Command line: collect a snapshot, analyze it, compare two runs."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__, accept, catalog, explain, invariants, opengraph, paths, redact
from .checks import MITRE, REGISTRY, run_all
from .collect import CollectError, Target, collect
from .fixes import render_fixes
from .model import Finding, Severity, Snapshot
from .report import (
    Report,
    finding_keys,
    render_html,
    render_json,
    render_junit,
    render_markdown,
    render_sarif,
    render_text,
)

RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
    "junit": render_junit,
}


def _target(args: argparse.Namespace) -> Target:
    password = os.environ.get("AD_DOCTOR_PASSWORD")
    if args.user and password is None and not args.kerberos:
        password = getpass.getpass(f"Password for {args.user}: ")
    port = args.port or (636 if args.ldaps else 389)
    return Target(
        host=args.host,
        port=port,
        user=args.user,
        password=password,
        use_ssl=args.ldaps,
        sysvol=not args.no_sysvol,
        smb_port=args.smb_port,
        plain_port=args.signing_probe_port,
        http_port=args.http_port,
        probes=not args.no_probes,
        kerberos=args.kerberos,
        all_dcs=not args.single_dc,
        ca_registry=not args.no_ca_registry,
    )


def _write_private(path: Path, text: str) -> None:
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
        out.write(text)


def _use_color(stream: Any) -> bool:
    if "NO_COLOR" in os.environ:
        return False
    return "FORCE_COLOR" in os.environ or bool(stream.isatty())


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a snapshot or report")
    return data


def _findings_from(
    path: Path, only: list[str] | None = None, spec: dict[str, Any] | None = None
) -> tuple[str, list[Finding]]:
    """Findings from either a saved snapshot (analyzed like the current run) or a
    JSON report."""
    data = _load_json(path)
    if data.get("tool") == "ad-doctor":
        return data["domain"], [
            Finding(
                f["id"],
                f["title"],
                Severity[f["severity"].upper()],
                f["detail"],
                f["remediation"],
                f["objects"],
                f.get("mitre", []),
            )
            for f in data["findings"]
        ]
    snap = Snapshot.from_json(data)
    findings = run_all(snap, only)
    if spec is not None:
        findings += invariants.evaluate(snap, spec)
    return snap.domain, findings


def _fails(findings: list[Finding], level: str | None) -> bool:
    return bool(level) and any(f.severity >= Severity[str(level).upper()] for f in findings)


def cmd_diff(args: argparse.Namespace) -> int:
    domain, old = _findings_from(args.old)
    _, new = _findings_from(args.new)
    before, after = finding_keys(old), finding_keys(new)
    added = sorted(after - before)
    removed = sorted(before - after)
    sev = {f.check_id: f.severity for f in [*old, *new]}
    title = {f.check_id: f.title for f in [*old, *new]}
    if args.format == "json":
        print(
            json.dumps(
                {
                    "domain": domain,
                    "new": [{"id": c, "object": o, "severity": str(sev[c])} for c, o in added],
                    "resolved": [{"id": c, "object": o} for c, o in removed],
                },
                indent=2,
            )
        )
    else:
        print(f"{domain}: {len(added)} new, {len(removed)} resolved")
        for c, o in added:
            print(f"+ [{str(sev[c]).upper():6}] {c}  {o}  ({title[c]})")
        for c, o in removed:
            print(f"- [{str(sev[c]).upper():6}] {c}  {o}  ({title[c]})")
    new_findings = [f for f in new for o in f.objects if (f.check_id, o) in set(added)]
    return 2 if _fails(new_findings, args.fail_on) else 0


def cmd_blast_radius(args: argparse.Namespace) -> int:
    snap = Snapshot.from_json(_load_json(args.snapshot))
    starts = paths.identity_nodes(snap, args.account)
    if not starts:
        print(f"ad-doctor: no account {args.account!r} in the snapshot", file=sys.stderr)
        return 1
    g = paths.build(snap)
    controlled = paths.reachable(g, starts)
    tier0 = sorted((p for n, p in controlled.items() if n in g.tier0), key=lambda p: len(p.steps))
    if starts[0] in g.tier0:  # the account itself (or its primary group) is tier 0
        tier0.insert(0, paths.Path(starts[0], []))
    elif any(s in g.tier0 for s in starts[1:]):
        start = next(s for s in starts[1:] if s in g.tier0)
        tier0.insert(0, paths.Path(starts[0], [(start, "primary group")]))
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
    _write_private(args.output, json.dumps(payload, indent=1))
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
            "--no-probes",
            action="store_true",
            help="skip every probe: SMB, channel binding, ESC8 and the CA registry",
        )
        p.add_argument(
            "--no-ca-registry",
            action="store_true",
            help="do not read CA settings (ESC6/7/11/16) over the winreg pipe; opening it "
            "starts RemoteRegistry on the CA if it is stopped, and EDR or Defender for "
            "Identity may alert on remote registry access",
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
        p.add_argument(
            "-f", "--format", choices=["text", *RENDERERS], default="text", help="report format"
        )
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
            "--invariants",
            type=Path,
            metavar="TOML",
            help="declared state to check (policy as code)",
        )

    p_scan = sub.add_parser("scan", help="collect and analyze in one go")
    conn_args(p_scan)
    out_args(p_scan)

    p_collect = sub.add_parser("collect", help="save a snapshot for later analysis")
    conn_args(p_collect)
    p_collect.add_argument("-o", "--output", type=Path, required=True)

    p_analyze = sub.add_parser("analyze", help="analyze a saved snapshot")
    p_analyze.add_argument("snapshot", type=Path)
    out_args(p_analyze)

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
        if args.cmd == "analyze":
            snap = Snapshot.from_json(_load_json(args.snapshot))
        else:
            snap = collect(_target(args))
        if args.cmd == "collect":
            _write_private(args.output, json.dumps(snap.to_json(), indent=2))
            print(f"wrote {args.output} ({len(snap.accounts)} accounts)")
            return 0

        findings = run_all(snap, args.only)
        spec = invariants.load(args.invariants) if args.invariants else None
        if spec is not None:
            findings += invariants.evaluate(snap, spec)
            findings.sort(key=lambda f: (-f.severity, f.check_id))
        report = Report(snap, findings)
        if args.accept:
            entries = accept.load(args.accept)
            today = snap.collected_at.date()
            ran = {
                c.id for c in REGISTRY if not args.only or c.id in {i.upper() for i in args.only}
            }
            if spec is not None:
                ran |= set(invariants.IDS)
            report.findings, report.accepted, notes = accept.apply(findings, entries, today, ran)
            snap.notes.extend(notes)
        if args.baseline:
            _, old = _findings_from(args.baseline, args.only, spec)
            report.new = finding_keys(report.findings) - finding_keys(old)
    except (
        CollectError,
        accept.AcceptError,
        invariants.InvariantError,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"ad-doctor: {exc}", file=sys.stderr)
        return 1

    if args.fixes:
        _write_private(args.fixes, render_fixes(report.findings, snap))
    if args.format == "text":
        text = render_text(report, color=not args.output and _use_color(sys.stdout))
    elif args.format == "junit":
        only = {i.upper() for i in args.only or []}
        text = render_junit(report, [c.id for c in REGISTRY if not only or c.id in only])
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
