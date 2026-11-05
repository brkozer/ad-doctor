"""`ad-doctor explain`: one check's catalog entry, offline, in the terminal."""

from __future__ import annotations

import json
import re
import textwrap

from . import catalog, docgen, invariants
from .checks import REGISTRY

_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BULLET = re.compile(r"\s*(\d+\.|-)\s+")


def titles() -> dict[str, str]:
    """Every check ID the CLI can report, with its title."""
    return {c.id: c.title for c in REGISTRY} | invariants.IDS


def _plain(md: str, width: int) -> str:
    """Markdown to terminal text: code blocks and tables kept as they are, prose wrapped,
    emphasis dropped, and links to other site pages reduced to their text (the check ID)."""
    md = _LINK.sub(lambda m: f"{m[1]} <{m[2]}>" if m[2].startswith("http") else m[1], md)
    md = md.replace("**", "").replace("`", "")
    md = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?!\w)", r"\1", md)
    out: list[str] = []
    in_code = False
    for line in textwrap.dedent(md).splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code or not line.strip() or line.lstrip().startswith("|"):
            out.append(line.rstrip())
            continue
        indent = len(line) - len(line.lstrip())
        bullet = _BULLET.match(line)
        hang = " " * (len(bullet[0]) if bullet else indent)
        out.append(textwrap.fill(line.strip(), width, initial_indent=" " * indent,
                                 subsequent_indent=hang))  # fmt: skip
    return "\n".join(out)


def render_text(e: catalog.Entry, width: int = 88) -> str:
    head = f"{e.id}  {titles().get(e.id, '')}".rstrip()
    lines = [
        head,
        "=" * min(len(head), width),
        textwrap.fill(e.summary, width),
        "",
        f"Category:  {docgen.category(e.id)}",
        f"Severity:  {' / '.join(e.severities)}",
        f"MITRE:     {', '.join(e.mitre) or '-'}",
        f"Reads:     {', '.join(docgen.SOURCE_LABEL[s] for s in e.data_sources)}",
    ]
    if e.aliases:
        lines.append(f"Aliases:   {', '.join(e.aliases)}")
    lines.append(f"Docs:      {e.url}")
    sections = [
        ("Why it matters", e.risk),
        ("How ad-doctor detects it", e.detection),
        ("Severity", e.severity_logic),
        ("False positives and limits", e.false_positives),
        ("Fix", e.remediation),
    ]
    for name, body in sections:
        if body:
            lines += ["", name.upper(), _plain(body, width)]
    if e.verify:
        lines += ["", "VERIFY", f"  {e.verify}"]
    if e.related:
        lines += ["", "RELATED", f"  {', '.join(e.related)}"]
    lines += ["", "REFERENCES"]
    lines += [f"  {r.title}\n    {r.url}" for r in e.references]
    lines += [f"  MITRE ATT&CK {t}\n    {docgen.attack_url(t)}" for t in e.mitre]
    return "\n".join(lines)


def render_markdown(e: catalog.Entry) -> str:
    """The page the documentation site shows, with links made absolute."""
    return docgen.absolute_links(docgen.check_page(e, titles().get(e.id, e.id)))


def render_json(e: catalog.Entry) -> str:
    data = {
        "id": e.id,
        "title": titles().get(e.id, ""),
        "category": docgen.category(e.id),
        "url": e.url,
        "summary": e.summary,
        "aliases": list(e.aliases),
        "severities": list(e.severities),
        "severity_logic": e.severity_logic,
        "mitre": list(e.mitre),
        "data_sources": list(e.data_sources),
        "attributes": list(e.attributes),
        "risk": e.risk,
        "detection": e.detection,
        "false_positives": e.false_positives,
        "remediation": e.remediation,
        "verify": e.verify,
        "related": list(e.related),
        "references": [{"title": r.title, "url": r.url, "kind": r.kind} for r in e.references],
        "since": e.since,
    }
    return json.dumps(data, indent=2)
