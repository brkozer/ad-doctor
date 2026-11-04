"""Command line: collect a snapshot, analyze it, or both."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__
from .checks import REGISTRY, run_all
from .collect import CollectError, Target, collect
from .model import Finding, Severity, Snapshot


def _target(args: argparse.Namespace) -> Target:
    password = os.environ.get("AD_DOCTOR_PASSWORD")
    if args.user and password is None:
        password = getpass.getpass(f"Password for {args.user}: ")
    port = args.port or (636 if args.ldaps else 389)
    return Target(args.host, port, args.user, password, args.ldaps)


def render_text(snap: Snapshot, findings: list[Finding]) -> str:
    lines = [
        f"ad-doctor {__version__}  domain {snap.domain}  "
        f"{len(snap.accounts)} accounts  {snap.collected_at:%Y-%m-%d %H:%M} UTC",
        "",
    ]
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines.append(f"[{str(f.severity).upper():6}] {f.check_id}  {f.title}")
        lines.append(f"         {f.detail}")
        shown = f.objects[:10]
        more = f" (+{len(f.objects) - len(shown)} more)" if len(f.objects) > len(shown) else ""
        lines.append(f"         objects: {', '.join(shown)}{more}")
        lines.append(f"         fix: {f.remediation}")
        lines.append("")
    counts = {s: sum(f.severity == s for f in findings) for s in Severity}
    lines.append("summary: " + "  ".join(f"{s!s} {counts[s]}" for s in reversed(Severity)))
    return "\n".join(lines)


def render_json(snap: Snapshot, findings: list[Finding]) -> str:
    return json.dumps(
        {
            "tool": "ad-doctor",
            "version": __version__,
            "domain": snap.domain,
            "collected_at": snap.collected_at.isoformat(),
            "findings": [
                {
                    "id": f.check_id,
                    "title": f.title,
                    "severity": str(f.severity),
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "objects": f.objects,
                }
                for f in findings
            ],
        },
        indent=2,
    )


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

    def out_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("-f", "--format", choices=["text", "json"], default="text")
        p.add_argument("--only", nargs="+", metavar="ID", help="run only these check IDs")
        p.add_argument(
            "--fail-on", choices=[str(s) for s in Severity], help="exit 2 at this severity or above"
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

    sub.add_parser("checks", help="list available checks")

    args = parser.parse_args(argv)

    if args.cmd == "checks":
        for c in REGISTRY:
            print(f"{c.id}  {c.title}")
        return 0

    try:
        if args.cmd == "analyze":
            snap = Snapshot.from_json(json.loads(args.snapshot.read_text()))
        else:
            snap = collect(_target(args))
    except CollectError as exc:
        print(f"ad-doctor: {exc}", file=sys.stderr)
        return 1

    if args.cmd == "collect":
        args.output.write_text(json.dumps(snap.to_json(), indent=2))
        print(f"wrote {args.output} ({len(snap.accounts)} accounts)")
        return 0

    findings = run_all(snap, args.only)
    print(render_json(snap, findings) if args.format == "json" else render_text(snap, findings))
    if args.fail_on and any(f.severity >= Severity[args.fail_on.upper()] for f in findings):
        return 2
    return 0
