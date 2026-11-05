"""Markdown generated from the catalog: the documentation site's check pages and index,
`ad-doctor explain -f markdown`, and the SARIF help text.
"""

from __future__ import annotations

import html
import json
import re

from . import catalog
from .model import CATEGORIES

ATTACK = "https://attack.mitre.org/techniques/{}/"
KIND_LABEL = {"vendor": "Microsoft and vendors", "spec": "Specifications",
              "research": "Research", "tool": "Tools"}  # fmt: skip
SOURCE_LABEL = {
    "ldap": "LDAP",
    "sysvol": "SYSVOL (SMB)",
    "probe-ldap": "LDAP probe",
    "probe-ldaps": "LDAPS probe",
    "probe-smb": "SMB probe",
    "probe-http": "HTTP probe",
    "probe-winreg": "CA registry probe",
    "derived": "derived from other findings",
}
# links between pages of the site: "AD-KRB-005.md", "../ci.md#accepted-risks"
_CHECK_LINK = re.compile(r"\]\((AD-[A-Z]+-\d{3})\.md(#[\w-]+)?\)")
_PAGE_LINK = re.compile(r"\]\(\.\./([\w-]+)\.md(#[\w-]+)?\)")


def attack_url(technique: str) -> str:
    return ATTACK.format(technique.replace(".", "/"))


def category(check_id: str) -> str:
    return CATEGORIES[check_id.split("-")[1]]


def absolute_links(md: str) -> str:
    """Rewrite site-relative links so the text works outside the site (SARIF, reports)."""
    md = _CHECK_LINK.sub(lambda m: f"]({catalog.DOCS_URL}/checks/{m[1]}/{m[2] or ''})", md)
    return _PAGE_LINK.sub(lambda m: f"]({catalog.DOCS_URL}/{m[1]}/{m[2] or ''})", md)


def _indent(text: str) -> str:
    return "\n".join(("    " + line) if line.strip() else "" for line in text.splitlines())


def _since(e: catalog.Entry) -> str:
    if e.since == "unreleased":
        return "*New in the next release.*"
    return f"*Available since {e.since or '0.1.0'}.*"


def check_page(e: catalog.Entry, title: str) -> str:
    sev = " ".join(f'<span class="sev sev-{s}">{s}</span>' for s in e.severities)
    meta = [sev, f"**{category(e.id)}**"]
    if e.mitre:
        meta.append("MITRE ATT&CK " + ", ".join(f"[{t}]({attack_url(t)})" for t in e.mitre))
    meta.append("Reads: " + ", ".join(SOURCE_LABEL[s] for s in e.data_sources))
    out = [
        "---",
        f"title: {json.dumps(f'{e.id}: {title}')}",
        f"description: {json.dumps(e.summary)}",
        "---",
        "",
        f"# {e.id}: {html.escape(title)}",
        "",
        " &nbsp; ".join(meta),
        "",
        f"> {e.summary}",
        "",
    ]
    if e.aliases:
        out += ["Also known as: " + ", ".join(f"`{a}`" for a in e.aliases), ""]
    out += ["## Why it matters", "", e.risk, "", "## How ad-doctor detects it", "", e.detection, ""]
    if e.attributes:
        out += ['??? info "Attributes and probes read"', "",
                _indent("\n".join(f"- `{a}`" for a in e.attributes)), ""]  # fmt: skip
    out += ["## Severity", "", e.severity_logic, ""]
    if e.false_positives:
        out += ["## False positives and limits", "", e.false_positives, ""]
    out += ["## Fix", "", e.remediation, ""]
    if e.verify:
        out += ["## Verify", "", "```bash", e.verify, "```", ""]
    out += [
        "To accept the risk instead, add an entry to the file passed with `--accept` "
        "(see [accepted risks](../ci.md#accepted-risks)):",
        "",
        "```toml",
        "[[accept]]",
        f'check = "{e.id}"',
        'objects = ["..."]        # optional; without it the whole check is accepted',
        'reason = "..."',
        "expires = 2027-03-31",
        "```",
        "",
    ]
    if e.related:
        out += ["## Related checks", "", *[f"- [{r}]({r}.md)" for r in e.related], ""]
    out += ["## References", ""]
    for kind, label in KIND_LABEL.items():
        refs = [r for r in e.references if r.kind == kind]
        if refs:
            out += [f"**{label}**", "", *[f"- [{r.title}]({r.url})" for r in refs], ""]
    if e.mitre:
        out += ["**MITRE ATT&CK**", "", *[f"- [{t}]({attack_url(t)})" for t in e.mitre], ""]
    out += [_since(e), ""]
    return "\n".join(out)


def stub_page(check_id: str, title: str) -> str:
    """Placeholder for a check without a catalog entry (gen_docs.py --allow-missing only)."""
    return "\n".join([
        f"# {check_id}: {html.escape(title)}",
        "",
        '!!! warning "Not documented yet"',
        "",
        "    `ad-doctor checks` lists this check; its catalog entry is still being written.",
        "",
    ])  # fmt: skip


def _count(rows: list[tuple[str, str, tuple[str, ...], str]]) -> str:
    invariants = sum(1 for r in rows if r[0].startswith("AD-INV-"))
    checks = len(rows) - invariants
    return f"{checks} checks and {invariants} invariants" if invariants else f"{checks} checks"


def index_page(rows: list[tuple[str, str, tuple[str, ...], str]]) -> str:
    """rows: (id, title, severities, summary), in registry order."""
    cats = sorted({category(r[0]) for r in rows})
    opts = "".join(f'<option value="{html.escape(c)}">{html.escape(c)}</option>' for c in cats)
    body = []
    for cid, title, sevs, summary in rows:
        cat = category(cid)
        top = max(sevs, key=catalog.SEVERITIES.index) if sevs else "info"
        body.append(
            f'<tr data-category="{html.escape(cat)}" data-severity="{" ".join(sevs)}">'
            f'<td><a href="{cid}/"><code>{cid}</code></a></td>'
            f"<td>{html.escape(title)}<br><small>{html.escape(summary)}</small></td>"
            f"<td>{html.escape(cat)}</td>"
            f'<td><span class="sev sev-{top}">{" / ".join(sevs) or "?"}</span></td></tr>'
        )
    return "\n".join([
        "---",
        "title: Check catalog",
        "hide: [toc]",
        "---",
        "",
        "# Check catalog",
        "",
        f"{_count(rows)}. Every finding in a report links to its page here, and "
        "`ad-doctor explain <ID>` prints the same text offline.",
        "",
        '<div class="catalog-filter" markdown="0">',
        '<input id="cf-text" type="search" placeholder="Filter by ID, title or text" '
        'aria-label="Filter checks">',
        f'<select id="cf-cat" aria-label="Category"><option value="">All categories</option>'
        f"{opts}</select>",
        '<select id="cf-sev" aria-label="Severity"><option value="">Any severity</option>'
        "<option>high</option><option>medium</option><option>low</option>"
        "<option>info</option></select>",
        '<span id="cf-count"></span>',
        "</div>",
        "",
        '<table id="catalog" markdown="0">',
        "<thead><tr><th>ID</th><th>Finding</th><th>Category</th><th>Severity</th></tr></thead>",
        "<tbody>",
        *body,
        "</tbody></table>",
        "",
    ])  # fmt: skip
