"""What a run could say about each check: judged, not applicable, or not evaluated and why.

A snapshot records no status per check. Its notes are the record that exists in snapshots
from every version, so the notes feed this module: a note that names a check, or that matches
NOTE_RULES, says that check could not judge everything it covers. A few gaps leave no note
(`DATA_GAPS`), mostly a probe that holds None. A check that found something is judged whatever
the notes say, and then counts as partial.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .checks import REGISTRY, ca_unjudged
from .invariants import IDS as INVARIANTS
from .model import CATEGORIES, CaConfig, Snapshot

JUDGED, NOT_APPLICABLE, NOT_EVALUATED = "judged", "not_applicable", "not_evaluated"
UNREADABLE, OLDER_SNAPSHOT, SWITCHED_OFF = "unreadable", "older_snapshot", "switched_off"
REASON_TEXT = {
    UNREADABLE: "data unreadable",
    OLDER_SNAPSHOT: "older snapshot",
    SWITCHED_OFF: "switched off",
}
# when several notes hold a check back, the one the reader can act on first
_REASON_RANK = (SWITCHED_OFF, OLDER_SNAPSHOT, UNREADABLE)


def _ids(prefix: str, *numbers: int) -> tuple[str, ...]:
    return tuple(f"AD-{prefix}-{n:03}" for n in numbers)


LOCAL_GROUP_CHECKS = _ids("GPO", 5, 6, 7)
SYSVOL_CHECKS = (*_ids("GPP", 1, 2), *_ids("GPO", 3), *LOCAL_GROUP_CHECKS)
REGISTRY_POL_CHECKS = _ids("GPO", 9, 10, 11, 12)
POLICY_FILE_CHECKS = (*_ids("GPO", 13, 14, 15, 16), "AD-ADCS-020")
GPO_APPLIED_CHECKS = (
    *_ids("GPO", 3, 5, 6, 7, 8),
    *REGISTRY_POL_CHECKS,
    *POLICY_FILE_CHECKS,
)
ALL_GPO_CHECKS = (*GPO_APPLIED_CHECKS, *_ids("GPO", 1, 2, 4))
CA_CONFIG_CHECKS = (*_ids("ADCS", 12, 13, 14, 15, 16, 18), "AD-CHAIN-004")
ENROLLMENT_CHECKS = ("AD-ADCS-010", "AD-ADCS-019", "AD-CHAIN-003")
ALL_ADCS_CHECKS = (
    *(c.id for c in REGISTRY if c.id.startswith("AD-ADCS-")),
    "AD-CHAIN-003",
    "AD-CHAIN-004",
)
TRUST_CHECKS = _ids("INF", 6, 15, 16, 17)

# A note names a check when the check could not judge all it covers. Two forms only state
# what a check is for: "AD-POL-001 judges the default ..." and a closing "(AD-GPO-008)".
CHECK_IN_NOTE = re.compile(r"(?<!\()\bAD-[A-Z]+-\d+\b(?! judges )")
# written by `accept.apply`: about the acceptance file, not about what a check could read
_ACCEPTANCE_NOTE = "acceptance of "
OLDER_NOTE = "snapshot from an older version"

# Notes that name no check, or name it in a shorthand, and the checks they hold back.
NOTE_RULES: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = tuple(
    (re.compile(p), c)
    for p, c in (
        (r"^SYSVOL (not checked|files not readable)", SYSVOL_CHECKS),
        (r"malformed XML, not evaluated$", LOCAL_GROUP_CHECKS),
        (r"GPOs set local groups in the user context", LOCAL_GROUP_CHECKS),
        (r"local group settings in GPOs reaching read-only DCs", LOCAL_GROUP_CHECKS),
        (r"name principals that could not be resolved", LOCAL_GROUP_CHECKS),
        (r"AD-GPO-009 to -012 do not evaluate", REGISTRY_POL_CHECKS),
        (r"(Registry\.pol: over \d+ bytes|not a valid Registry\.pol)", REGISTRY_POL_CHECKS),
        (r"^Registry\.pol files not readable", REGISTRY_POL_CHECKS),
        (r"(audit\.csv|Registry\.xml): over \d+ bytes", POLICY_FILE_CHECKS),
        (r"(not a valid audit\.csv|not valid Registry\.xml)", POLICY_FILE_CHECKS),
        (r"^audit\.csv or Registry\.xml not readable", POLICY_FILE_CHECKS),
        (r"^GPO from another domain linked at", GPO_APPLIED_CHECKS),
        (r"^CA configuration (\(|on )", CA_CONFIG_CHECKS),
        (
            r"uses the policy module .*ESC6 and ESC16",
            ("AD-ADCS-012", "AD-ADCS-015", "AD-CHAIN-004"),
        ),
        (
            r"^LDAP signing and channel binding not probed",
            ("AD-INF-005", "AD-INF-010", "AD-CHAIN-001"),
        ),
        (r"LDAP signing probe (inconclusive|failed)", ("AD-INF-005",)),
        (r"^SMB probes did not run", ("AD-INF-008", "AD-INF-009")),
        (r": not probed \(", _ids("INF", 5, 8, 9, 10)),
        (r"^enrollment URL .* not probed", ("AD-ADCS-019",)),
        (r"^http://.* not probed", ("AD-ADCS-010", "AD-CHAIN-003")),
        (r"^https://.* not probed", ("AD-ADCS-019",)),
        (r"fine-grained password policy links: only the first", ("AD-POL-003",)),
        (r"resource-based delegation edges", ("AD-PATH-001",)),
        # a search that failed says which part of the directory it left out
        (r"(CN=Policies,CN=System|gPLink).*(failed|not visible)", ALL_GPO_CHECKS),
        (
            r"(CN=Enrollment Services|CN=Certificate Templates|CN=OID|Public Key Services)"
            r".*(failed|not visible)",
            ALL_ADCS_CHECKS,
        ),
        (r"trustedDomain.*(failed|not visible)", TRUST_CHECKS),
    )
)
_SEARCH_FAILURE = re.compile(r"^search .* failed|is not visible to this account$")
_NOT_APPLICABLE_NOTES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AD CS not installed", ALL_ADCS_CHECKS),
    (
        "no enterprise CA found",
        (*CA_CONFIG_CHECKS, *ENROLLMENT_CHECKS),
    ),
)


@dataclass
class CheckStatus:
    id: str
    title: str
    category: str
    status: str
    # judged: "finding", "accepted" or "no_finding"
    outcome: str | None = None
    # not evaluated, or judged in part: why
    reason: str | None = None
    # the notes behind the status; a judged check with notes judged only part of what it covers
    notes: list[str] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        return self.status == JUDGED and self.outcome != "no_finding" and bool(self.notes)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
        }
        if self.outcome is not None:
            out["outcome"] = self.outcome
        if self.reason is not None:
            out["reason"] = self.reason
        if self.notes:
            out["notes"] = self.notes
        if self.partial:
            out["partial"] = True
        return out


def named_checks(note: str) -> list[str]:
    """Check IDs a note names as not fully judged."""
    if note.startswith(_ACCEPTANCE_NOTE):
        return []
    return list(dict.fromkeys(CHECK_IN_NOTE.findall(note)))


def note_checks(note: str) -> list[str]:
    """Checks a note holds back: those it names and those NOTE_RULES ties it to."""
    found = named_checks(note)
    for pattern, ids in NOTE_RULES:
        if pattern.search(note):
            found += [i for i in ids if i not in found]
    return found


def note_reason(note: str, sysvol_off: bool = False) -> str:
    if note.startswith(OLDER_NOTE):
        return OLDER_SNAPSHOT
    if "by choice" in note or "--no-" in note or (sysvol_off and "SYSVOL was not read" in note):
        return SWITCHED_OFF
    return UNREADABLE


def note_gaps(notes: Iterable[str]) -> dict[str, list[str]]:
    """Check ID -> the notes that say it could not judge everything it covers."""
    out: dict[str, list[str]] = {}
    for note in notes:
        for check_id in note_checks(note):
            out.setdefault(check_id, []).append(note)
    return out


def unattributed(notes: Iterable[str]) -> list[str]:
    """Failed searches that no rule ties to a check: something is unknown, but not what."""
    return [n for n in notes if _SEARCH_FAILURE.search(n) and not note_checks(n)]


# --- gaps a snapshot shows without a note ------------------------------------------------


def _unknown(snap: Snapshot, attr: str, fallback: bool | None) -> bool:
    values = [getattr(d, attr) for d in snap.probes.dcs] if snap.probes.dcs else [fallback]
    return None in values


def _ldap_unknown(snap: Snapshot) -> bool:
    return _unknown(snap, "ldap_signing_required", snap.ldap_signing_required)


def _channel_unknown(snap: Snapshot) -> bool:
    return _unknown(
        snap, "ldaps_channel_binding_required", snap.probes.ldaps_channel_binding_required
    )


def _spooler_unknown(snap: Snapshot) -> bool:
    return _unknown(snap, "spooler", snap.probes.spooler_on_dc)


def _krbtgt_unread(snap: Snapshot) -> bool:
    krbtgt = next((a for a in snap.accounts if a.sam.lower() == "krbtgt"), None)
    return krbtgt is not None and krbtgt.password_changed is None


def _sysvol_unread(snap: Snapshot) -> bool:
    return bool(snap.gpos) and not snap.gpo_settings and not snap.local_groups_collected


def _no_ca_config(snap: Snapshot) -> bool:
    return bool(snap.ca_hosts) and not snap.probes.ca_configs


def _no_probe_ran(snap: Snapshot) -> bool:
    return not snap.probes.dcs and not snap.probes.web_enrollment_ntlm


def _ca_part(snap: Snapshot, part: str) -> bool:
    return any(_part_unjudged(c, part) for c in snap.probes.ca_configs)


def _part_unjudged(c: CaConfig, part: str) -> bool:
    if c.error:
        return True
    if part == "audit":
        return c.audit_checked and c.audit_filter is None and not c.audit_absent
    return any(esc == part for _, esc in ca_unjudged(c))


_ESC_CHECKS = {"ESC6": "AD-ADCS-012", "ESC7": "AD-ADCS-013", "ESC11": "AD-ADCS-014",
               "ESC16": "AD-ADCS-015", "audit": "AD-ADCS-018"}  # fmt: skip

DATA_GAPS: tuple[tuple[tuple[str, ...], Callable[[Snapshot], bool], str], ...] = (
    (("AD-KRB-001",), _krbtgt_unread, "the krbtgt password date was not readable"),
    (("AD-INF-002",), lambda s: s.recycle_bin is None, "the Recycle Bin state was not readable"),
    (("AD-INF-011",), lambda s: not s.backup_checked, "the backup time was not readable"),
    (("AD-INF-005",), _ldap_unknown, "LDAP signing has no probe result"),
    (("AD-INF-008",), lambda s: _unknown(s, "smb_signing_required", s.probes.smb_signing_required),
     "SMB signing has no probe result"),
    (("AD-INF-009",), _spooler_unknown, "the Print Spooler has no probe result"),
    (("AD-INF-010",), _channel_unknown, "LDAPS channel binding has no probe result"),
    (("AD-INF-013",), lambda s: not s.probes.dcs, "no DC was probed"),
    (("AD-CHAIN-001",),
     lambda s: s.policy.machine_account_quota > 0 and (_ldap_unknown(s) or _channel_unknown(s)),
     "LDAP signing or channel binding has no probe result"),
    (("AD-ADCS-010", "AD-ADCS-019", "AD-CHAIN-003"),
     lambda s: bool(s.ca_hosts) and _no_probe_ran(s), "no web enrollment probe ran"),
    (CA_CONFIG_CHECKS, _no_ca_config, "no CA configuration in the snapshot"),
    (SYSVOL_CHECKS, _sysvol_unread, "SYSVOL was not read"),
    (LOCAL_GROUP_CHECKS, lambda s: not s.local_groups_collected and not _sysvol_unread(s),
     "local group settings were not collected"),
    *(((check_id,), (lambda p: lambda s: _ca_part(s, p))(part), f"{part} not read on every CA")
      for part, check_id in _ESC_CHECKS.items()),
)  # fmt: skip


def data_gaps(snap: Snapshot) -> dict[str, str]:
    out: dict[str, str] = {}
    for ids, unknown, why in DATA_GAPS:
        if unknown(snap):
            for check_id in ids:
                out.setdefault(check_id, why)
    return out


# --- not applicable ----------------------------------------------------------------------


def _no_2025(snap: Snapshot) -> bool:
    """dMSAs need a Windows Server 2025 DC; an unreadable OS proves nothing."""
    dcs = [a for a in snap.accounts if a.is_dc]
    return bool(dcs) and all(a.os for a in dcs) and not snap.has_2025


def not_applicable(snap: Snapshot, use_data: bool) -> dict[str, str]:
    """Check ID -> why the snapshot shows it has nothing to judge. Only a proven absence
    counts: anything less stays judged or not evaluated."""
    out: dict[str, str] = {}
    for note in snap.notes:
        for start, ids in _NOT_APPLICABLE_NOTES:
            if note.startswith(start):
                out.update(dict.fromkeys(ids, note))
    if use_data:
        if not snap.trusts:
            out.update(dict.fromkeys(TRUST_CHECKS, "the domain has no trusts"))
        if _no_2025(snap):
            why = "no Windows Server 2025 DC, so no dMSA can exist"
            out.update(dict.fromkeys(("AD-INF-007", "AD-ACL-009"), why))
    return out


# --- the status of every check -----------------------------------------------------------


def _category(check_id: str) -> str:
    return CATEGORIES[check_id.split("-")[1]]


def compute(
    snap: Snapshot,
    fired: Iterable[str],
    accepted: Iterable[str] = (),
    ran: Iterable[str] | None = None,
    use_data: bool = True,
) -> dict[str, CheckStatus]:
    """Every check of this run by ID. `fired` and `accepted` are the check IDs behind the
    findings; `ran` the IDs that ran, or None for every registered check. `use_data` is False
    for a JSON report, which has only the notes of a snapshot."""
    found, signed_off = set(fired), set(accepted)
    wanted = None if ran is None else set(ran)
    titles = {c.id: c.title for c in REGISTRY}
    gaps = note_gaps(snap.notes)
    sysvol_off = any(n.startswith("SYSVOL not checked by choice") for n in snap.notes)
    data = data_gaps(snap) if use_data else {}
    absent = not_applicable(snap, use_data)
    out: dict[str, CheckStatus] = {}
    extra = (found | signed_off | (wanted or set())) - titles.keys()
    for check_id in sorted(titles.keys() | extra):
        title = titles.get(check_id) or INVARIANTS.get(check_id, check_id)
        st = CheckStatus(check_id, title, _category(check_id), JUDGED)
        notes = list(gaps.get(check_id, ()))
        why_data = data.get(check_id)
        held_back = notes or ([why_data] if why_data else [])
        reasons = [note_reason(n, sysvol_off) for n in notes] or ([UNREADABLE] if why_data else [])
        if check_id in found or check_id in signed_off:
            st.outcome = "finding" if check_id in found else "accepted"
            st.notes = held_back
            st.reason = _pick(reasons)
        elif wanted is not None and check_id not in wanted:
            st.status, st.reason = NOT_EVALUATED, SWITCHED_OFF
            st.notes = ["not selected by --only"]
        elif held_back:
            st.status, st.reason, st.notes = NOT_EVALUATED, _pick(reasons), held_back
        elif check_id in absent:
            st.status, st.notes = NOT_APPLICABLE, [absent[check_id]]
        else:
            st.outcome = "no_finding"
        out[check_id] = st
    return out


def _pick(reasons: list[str]) -> str | None:
    return next((r for r in _REASON_RANK if r in reasons), None)


def from_report(data: dict[str, Any]) -> dict[str, CheckStatus] | None:
    """The statuses a JSON report recorded (schema 3); None when it has none."""
    rows = data.get("check_status")
    if not isinstance(rows, list):
        return None
    return {
        str(r["id"]): CheckStatus(
            id=str(r["id"]),
            title=str(r.get("title", r["id"])),
            category=str(r.get("category", "")),
            status=str(r.get("status", NOT_EVALUATED)),
            outcome=None if r.get("outcome") is None else str(r["outcome"]),
            reason=None if r.get("reason") is None else str(r["reason"]),
            notes=[str(n) for n in r.get("notes", [])],
        )
        for r in rows
        if isinstance(r, dict) and "id" in r
    }


def unevaluated(statuses: dict[str, CheckStatus]) -> set[str]:
    return {c for c, s in statuses.items() if s.status == NOT_EVALUATED}


def summary(statuses: dict[str, CheckStatus], notes: Iterable[str]) -> dict[str, Any]:
    """Counts, and whether the score is only a minimum. A check that was not evaluated adds
    nothing to the score, so with one the score says at least this and no better."""
    by_status = [s.status for s in statuses.values()]
    by_category: dict[str, int] = {}
    for s in statuses.values():
        if s.status == NOT_EVALUATED:
            by_category[s.category] = by_category.get(s.category, 0) + 1
    loose = unattributed(notes)
    return {
        JUDGED: by_status.count(JUDGED),
        NOT_APPLICABLE: by_status.count(NOT_APPLICABLE),
        NOT_EVALUATED: by_status.count(NOT_EVALUATED),
        "partial": sum(s.partial for s in statuses.values()),
        "score_is_minimum": bool(by_status.count(NOT_EVALUATED) or loose),
        "by_category": by_category,
        "unattributed_notes": loose,
    }
