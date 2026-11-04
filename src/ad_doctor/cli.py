"""Command line: collect a snapshot, analyze it, compare two runs."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__, accept
from .checks import MITRE, REGISTRY, run_all
from .collect import CollectError, Target, collect
from .fixes import render_fixes
from .model import Finding, Severity, Snapshot
from .report import (
    Report,
    finding_keys,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_text,
)

RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
}


def _target(args: argparse.Namespace) -> Target:
    password = os.environ.get("AD_DOCTOR_PASSWORD")
    if args.user and password is None:
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
    )


def _use_color(stream: Any) -> bool:
    if "NO_COLOR" in os.environ:
        return False
    return "FORCE_COLOR" in os.environ or bool(stream.isatty())


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a snapshot or report")
    return data


def _findings_from(path: Path) -> tuple[str, list[Finding]]:
    """Findings from either a saved snapshot or a JSON report."""
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
    return snap.domain, run_all(snap)


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

    p_checks = sub.add_parser("checks", help="list available checks")
    p_checks.add_argument("-f", "--format", choices=["text", "json"], default="text")

    args = parser.parse_args(argv)

    if args.cmd == "checks":
        rows = [
            {"id": c.id, "title": c.title, "mitre": list(MITRE.get(c.id, ()))} for c in REGISTRY
        ]
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                print(f"{row['id']:12} {row['title']}")
        return 0

    try:
        if args.cmd == "diff":
            return cmd_diff(args)
        if args.cmd == "analyze":
            snap = Snapshot.from_json(_load_json(args.snapshot))
        else:
            snap = collect(_target(args))
        if args.cmd == "collect":
            args.output.write_text(json.dumps(snap.to_json(), indent=2), encoding="utf-8")
            print(f"wrote {args.output} ({len(snap.accounts)} accounts)")
            return 0

        findings = run_all(snap, args.only)
        report = Report(snap, findings)
        if args.accept:
            entries = accept.load(args.accept)
            today = snap.collected_at.date()
            report.findings, report.accepted, notes = accept.apply(findings, entries, today)
            snap.notes.extend(notes)
        if args.baseline:
            _, old = _findings_from(args.baseline)
            report.new = finding_keys(report.findings) - finding_keys(old)
    except (CollectError, accept.AcceptError, OSError, ValueError, KeyError) as exc:
        print(f"ad-doctor: {exc}", file=sys.stderr)
        return 1

    if args.fixes:
        args.fixes.write_text(render_fixes(report.findings, snap), encoding="utf-8")
    if args.format == "text":
        text = render_text(report, color=not args.output and _use_color(sys.stdout))
    else:
        text = RENDERERS[args.format](report)
    if args.output:
        args.output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    else:
        print(text)

    gate = report.findings
    if report.new is not None:
        gate = [f for f in gate if report.is_new(f)]
    return 2 if _fails(gate, args.fail_on) else 0
