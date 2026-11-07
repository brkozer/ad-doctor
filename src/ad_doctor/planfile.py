"""The plan file: changes a team decided to make, kept in the repository and checked
against every new snapshot.

    schema = 1
    [plan]
    domain = "lab.test"
    domain_sid = "S-1-5-21-..."
    made_against = 2026-11-06T18:58:00Z       # collected_at of the snapshot
    made_by = "ad-doctor 0.2.0 plan"
    goal = "exposure"

    [assume]
    tier0 = ["SYNC01$"]                        # nodes treated as tier 0, not changes

    [[change]]
    id = "c:5d1e0a7b2c44"                      # checksum over kind and identity fields
    kind = "adminsdholder-ace"
    trustee = "S-1-5-21-...-1117"
    reason = "helpdesk needs password reset only"    # optional, like ticket, owner, due

    [[keep]]                                   # never proposed while it holds
    kind = "ace"
    object = "dc=lab,dc=test"
    trustee = "S-1-5-21-...-1137"
    reason = "Entra Connect needs DCSync"
    expires = 2027-06-30

    [expect]                                   # checked by whatif --check
    closes_all = true
    max_exposed_percent = 0
    max_holders = 2

The identity fields decide; an `id` that does not match them means the file was edited.
Results are never stored here. The writer escapes strings like the viewer's tomlString,
so a plan written by the page has the same bytes.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from . import changes
from .provenance import Prim

SCHEMA = 1
EXPECT_KEYS = {"closes_all": bool, "max_exposed_percent": int, "max_holders": int}
OPTIONAL = ("label", "reason", "ticket", "owner")


class PlanError(Exception):
    pass


@dataclass
class Entry:
    """A [[change]] or [[keep]]: kind and identity fields, and what people add."""

    values: dict[str, str]
    id: str = ""
    label: str = ""
    reason: str = ""
    ticket: str = ""
    owner: str = ""
    due: date | None = None
    expires: date | None = None

    @property
    def prim(self) -> Prim:
        return changes.prim_of(self.values)

    @property
    def expected_id(self) -> str:
        return changes.change_id(self.prim)


@dataclass
class PlanFile:
    domain: str = ""
    domain_sid: str = ""
    made_against: datetime | None = None
    made_by: str = ""
    goal: str = "exposure"
    sources: list[str] = field(default_factory=list)  # `from`
    allow: list[str] = field(default_factory=list)
    tier0: list[str] = field(default_factory=list)
    changes: list[Entry] = field(default_factory=list)
    keeps: list[Entry] = field(default_factory=list)
    expect: dict[str, bool | int] = field(default_factory=dict)


def entry_for(prim: Prim, label: str = "") -> Entry:
    f = changes.fields(prim)
    return Entry(f, changes.change_id(prim), label)


def _entry(item: object, where: str, keep: bool) -> Entry:
    if not isinstance(item, dict):
        raise PlanError(f"{where}: not a table")
    try:
        prim = changes.prim_of(item)
    except ValueError as exc:
        raise PlanError(f"{where}: {exc}") from exc
    e = Entry(changes.fields(prim))
    for key in ("id", *OPTIONAL):
        value = item.get(key, "")
        if not isinstance(value, str):
            raise PlanError(f"{where}: {key} must be a string")
        setattr(e, key, value)
    for key in ("due", "expires"):
        value = item.get(key)
        if value is not None and (not isinstance(value, date) or isinstance(value, datetime)):
            raise PlanError(f"{where}: {key} must be a date like 2027-03-31")
        setattr(e, key, value)
    if keep and (e.expires is None or not e.reason):
        raise PlanError(f"{where}: a keep needs reason and expires, as in the accept file")
    return e


def _strings(value: object, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PlanError(f"{where} must be a list of strings")
    return list(value)


def loads(text: str, name: str = "plan") -> PlanFile:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PlanError(f"{name}: {exc}") from exc
    if data.get("schema", SCHEMA) != SCHEMA:
        raise PlanError(f"{name}: schema {data.get('schema')!r} is not {SCHEMA}")
    head = data.get("plan", {})
    if not isinstance(head, dict):
        raise PlanError(f"{name}: [plan] must be a table")
    made = head.get("made_against")
    if made is not None and not isinstance(made, datetime):
        raise PlanError(f"{name}: made_against must be a date and time")
    if isinstance(made, datetime) and made.tzinfo is None:
        made = made.replace(tzinfo=UTC)
    goal = head.get("goal", "exposure")
    if goal not in ("exposure", "all-paths", "from"):
        raise PlanError(f"{name}: goal is exposure, all-paths or from")
    plan = PlanFile(
        domain=str(head.get("domain", "")),
        domain_sid=str(head.get("domain_sid", "")),
        made_against=made,
        made_by=str(head.get("made_by", "")),
        goal=goal,
        sources=_strings(head.get("from"), f"{name}: from"),
        allow=_strings(head.get("allow"), f"{name}: allow"),
        tier0=_strings(data.get("assume", {}).get("tier0"), f"{name}: [assume] tier0"),
    )
    for i, item in enumerate(data.get("change", []), 1):
        plan.changes.append(_entry(item, f"{name}: change {i}", keep=False))
    for i, item in enumerate(data.get("keep", []), 1):
        plan.keeps.append(_entry(item, f"{name}: keep {i}", keep=True))
    expect = data.get("expect", {})
    if not isinstance(expect, dict):
        raise PlanError(f"{name}: [expect] must be a table")
    for key, value in expect.items():
        kind = EXPECT_KEYS.get(key)
        if kind is None:
            raise PlanError(f"{name}: unknown [expect] key {key!r}")
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise PlanError(f"{name}: [expect] {key} must be {kind.__name__}")
        assert isinstance(value, (bool, int))
        plan.expect[key] = value
    return plan


def load(path: Path) -> PlanFile:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"{path}: {exc}") from exc
    return loads(text, str(path))


def toml_string(value: str) -> str:
    """A TOML basic string, escaped exactly like the viewer's tomlString."""
    out = ['"']
    for ch in value:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif c < 0x20 or c == 0x7F:
            out.append(f"\\u{c:04x}")
        elif 0xD800 <= c <= 0xDFFF:
            out.append("�")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _list(values: list[str]) -> str:
    return "[" + ", ".join(toml_string(v) for v in values) + "]"


def _entry_lines(table: str, e: Entry, with_id: bool) -> list[str]:
    lines = ["", f"[[{table}]]"]
    if with_id:
        lines.append(f"id = {toml_string(e.id or e.expected_id)}")
    for key, value in e.values.items():
        lines.append(f"{key} = {toml_string(value)}")
    for key in OPTIONAL:
        value = getattr(e, key)
        if value:
            lines.append(f"{key} = {toml_string(value)}")
    if e.due is not None:
        lines.append(f"due = {e.due.isoformat()}")
    if e.expires is not None:
        lines.append(f"expires = {e.expires.isoformat()}")
    return lines


def dumps(plan: PlanFile) -> str:
    lines = [
        f"# ad-doctor plan for {plan.domain or 'a domain'}: changes to make in AD, checked "
        "with `ad-doctor whatif SNAPSHOT --plan FILE --check`",
        f"schema = {SCHEMA}",
        "",
        "[plan]",
        f"domain = {toml_string(plan.domain)}",
        f"domain_sid = {toml_string(plan.domain_sid)}",
    ]
    if plan.made_against is not None:
        made = plan.made_against.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"made_against = {made}")
    lines.append(f"made_by = {toml_string(plan.made_by)}")
    lines.append(f"goal = {toml_string(plan.goal)}")
    if plan.sources:
        lines.append(f"from = {_list(plan.sources)}")
    if plan.allow:
        lines.append(f"allow = {_list(plan.allow)}")
    if plan.tier0:
        lines += ["", "[assume]", f"tier0 = {_list(plan.tier0)}"]
    for e in plan.changes:
        lines += _entry_lines("change", e, with_id=True)
    for e in plan.keeps:
        lines += _entry_lines("keep", e, with_id=False)
    if plan.expect:
        lines += ["", "[expect]"]
        for key in EXPECT_KEYS:
            if key in plan.expect:
                value = plan.expect[key]
                text = str(value).lower() if isinstance(value, bool) else str(value)
                lines.append(f"{key} = {text}")
    return "\n".join(lines) + "\n"
