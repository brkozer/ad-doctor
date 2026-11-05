"""Per-check documentation: one TOML file per check ID, shipped in the wheel.

The catalog holds everything about a check that is not code: the long explanation,
severity rules, remediation steps, references and MITRE ATT&CK techniques. The code keeps
the ID, the title and the one-line runtime remediation. `ad-doctor explain`, the SARIF,
HTML, Markdown and JUnit reports and the documentation site all read it from here.

Files are read lazily (on the first `load()`) through importlib.resources, so importing
the package costs nothing and an installed wheel or zipapp works the same as a checkout.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

# The published site. Nothing is fetched from it: it only appears as links (SARIF helpUri,
# HTML report, `explain`), so offline use is unaffected.
DOCS_URL = "https://brkozer.github.io/ad-doctor"
SEVERITIES = ("info", "low", "medium", "high")
REFERENCE_KINDS = ("vendor", "spec", "research", "tool")
DATA_SOURCES = ("ldap", "sysvol", "probe-ldap", "probe-ldaps", "probe-smb", "probe-http",
                "probe-winreg", "derived")  # fmt: skip
SUMMARY_MAX = 200

_ID = re.compile(r"^AD-[A-Z]+-\d{3}$")
_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
_ALIAS = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_SINCE = re.compile(r"^(\d+\.\d+\.\d+|unreleased)$")

_REQUIRED_TEXT = ("id", "summary", "severity_logic", "risk", "detection", "remediation")
_OPTIONAL_TEXT = ("false_positives", "verify", "since")
_REQUIRED_LISTS = ("severities", "mitre", "data_sources")
_OPTIONAL_LISTS = ("attributes", "related", "aliases")
_KEYS = {*_REQUIRED_TEXT, *_OPTIONAL_TEXT, *_REQUIRED_LISTS, *_OPTIONAL_LISTS, "references"}


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Reference:
    title: str
    url: str
    kind: str


@dataclass(frozen=True)
class Entry:
    id: str
    summary: str
    severities: tuple[str, ...]
    severity_logic: str
    mitre: tuple[str, ...]
    data_sources: tuple[str, ...]
    risk: str
    detection: str
    remediation: str
    references: tuple[Reference, ...]
    aliases: tuple[str, ...] = ()
    attributes: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    false_positives: str = ""
    verify: str = ""
    since: str = ""

    @property
    def url(self) -> str:
        return f"{DOCS_URL}/checks/{self.id}/"

    @property
    def top_severity(self) -> str:
        return max(self.severities, key=SEVERITIES.index)


def _text(data: dict[str, Any], key: str, source: str, required: bool) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise CatalogError(f"{source}: {key} must be a string")
    value = value.strip()
    if required and not value:
        raise CatalogError(f"{source}: {key} is required")
    return value


def _strings(data: dict[str, Any], key: str, source: str, required: bool) -> tuple[str, ...]:
    if required and key not in data:
        raise CatalogError(f"{source}: {key} is required")
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise CatalogError(f"{source}: {key} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise CatalogError(f"{source}: duplicate value in {key}")
    return tuple(value)


def _references(data: dict[str, Any], source: str) -> tuple[Reference, ...]:
    refs = data.get("references")
    if not isinstance(refs, list) or not refs:
        raise CatalogError(f"{source}: at least one [[references]] entry is required")
    out = []
    for r in refs:
        if not isinstance(r, dict) or set(r) != {"title", "url", "kind"}:
            raise CatalogError(f"{source}: a reference needs exactly title, url and kind: {r}")
        title, url, kind = r["title"], r["url"], r["kind"]
        if not (isinstance(title, str) and title.strip()):
            raise CatalogError(f"{source}: reference without a title: {r}")
        if not (isinstance(url, str) and url.startswith("https://")):
            raise CatalogError(f"{source}: reference URL must be https: {url}")
        if "attack.mitre.org" in url:
            raise CatalogError(f"{source}: MITRE links are generated from `mitre`: {url}")
        if kind not in REFERENCE_KINDS:
            raise CatalogError(f"{source}: reference kind must be one of {REFERENCE_KINDS}")
        out.append(Reference(title.strip(), url, kind))
    if len({r.url for r in out}) != len(out):
        raise CatalogError(f"{source}: duplicate reference URL")
    return tuple(out)


def parse(data: dict[str, Any], source: str) -> Entry:
    """Validate one TOML document against the schema (see CONTRIBUTING.md)."""
    if unknown := sorted(set(data) - _KEYS):
        raise CatalogError(f"{source}: unknown keys {', '.join(unknown)}")
    text = {k: _text(data, k, source, True) for k in _REQUIRED_TEXT}
    text |= {k: _text(data, k, source, False) for k in _OPTIONAL_TEXT}
    lists = {k: _strings(data, k, source, True) for k in _REQUIRED_LISTS}
    lists |= {k: _strings(data, k, source, False) for k in _OPTIONAL_LISTS}

    if not _ID.match(text["id"]):
        raise CatalogError(f"{source}: malformed id {text['id']!r}")
    if len(text["summary"]) > SUMMARY_MAX or "\n" in text["summary"]:
        raise CatalogError(f"{source}: summary must be one line of at most {SUMMARY_MAX} chars")
    sev = lists["severities"]
    if not sev or any(s not in SEVERITIES for s in sev):
        raise CatalogError(f"{source}: severities must be a non-empty subset of {SEVERITIES}")
    if list(sev) != sorted(sev, key=SEVERITIES.index):
        raise CatalogError(f"{source}: list severities from lowest to highest")
    if bad := [t for t in lists["mitre"] if not _MITRE.match(t)]:
        raise CatalogError(f"{source}: malformed MITRE technique {bad}")
    if not lists["data_sources"] or (
        bad := [d for d in lists["data_sources"] if d not in DATA_SOURCES]
    ):
        raise CatalogError(f"{source}: data_sources must be a non-empty subset of {DATA_SOURCES}")
    if bad := [r for r in lists["related"] if not _ID.match(r) or r == text["id"]]:
        raise CatalogError(f"{source}: bad related IDs {bad}")
    if bad := [a for a in lists["aliases"] if not _ALIAS.match(a)]:
        raise CatalogError(f"{source}: aliases must be lower-case words: {bad}")
    if text["since"] and not _SINCE.match(text["since"]):
        raise CatalogError(f"{source}: since must be a version (0.1.0) or 'unreleased'")
    return Entry(
        id=text["id"],
        summary=text["summary"],
        severities=sev,
        severity_logic=text["severity_logic"],
        mitre=lists["mitre"],
        data_sources=lists["data_sources"],
        risk=text["risk"],
        detection=text["detection"],
        remediation=text["remediation"],
        references=_references(data, source),
        aliases=lists["aliases"],
        attributes=lists["attributes"],
        related=lists["related"],
        false_positives=text["false_positives"],
        verify=text["verify"],
        since=text["since"],
    )


@cache
def load() -> dict[str, Entry]:
    """Every catalog entry, keyed by check ID. Raises CatalogError on a malformed file."""
    entries: dict[str, Entry] = {}
    for f in resources.files(__name__).iterdir():
        if not f.name.endswith(".toml"):
            continue
        try:
            data = tomllib.loads(f.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise CatalogError(f"{f.name}: {exc}") from exc
        e = parse(data, f.name)
        if f.name != f"{e.id}.toml":
            raise CatalogError(f"{f.name}: id is {e.id}")
        entries[e.id] = e
    return dict(sorted(entries.items()))


def get(check_id: str) -> Entry | None:
    return load().get(check_id)


def find(query: str) -> Entry | None:
    """Look up by ID (any case) or alias: 'AD-ADCS-001', 'ad-adcs-001', 'esc1'."""
    q = query.strip().lower()
    return next((e for e in load().values() if e.id.lower() == q or q in e.aliases), None)
