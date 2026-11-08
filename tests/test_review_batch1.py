"""Regression tests for the review findings on the batch 1 checks."""

from __future__ import annotations

import json
from typing import Any
from xml.etree import ElementTree

import ldap3
import pytest
from ldap3.core.exceptions import LDAPNoSuchObjectResult

from ad_doctor import redact, report, sd
from ad_doctor.checks import run_all
from ad_doctor.collect import _blank_name_notes, _sysvol_unseen_notes
from ad_doctor.model import Dmsa, Severity, Snapshot, invisible_chars
from ad_doctor.report import Report, render_junit, render_sarif
from ad_doctor.sd import Ace
from tests.test_checks import computer, ids, only, snapshot, user
from tests.test_health import BASE, CONFIG, DOMAIN, FRS_DN, GLOBAL, OC, SUBS, Stub, ent
from tests.test_health import topology_routes as _topology_routes
from tests.test_identity_cloud import DOM, HELPDESK, PSO_BASE, PSO_KEY, SID
from tests.test_identity_cloud import admin_snapshot as _admin_snapshot
from tests.test_identity_cloud import dmsa as _dmsa
from tests.test_identity_cloud import dmsa_snapshot as _dmsa_snapshot
from tests.test_identity_cloud import pso as _pso

ADMIN_SID = f"{SID}-1500"
ADMIN = f"CN=alice.adm,CN=Users,{DOM}"
LINKS = f"CN=Inter-Site Transports,{BASE}"
SUBNETS = f"CN=Subnets,{BASE}"
DC2 = f"CN=DC2,OU=Domain Controllers,{DOMAIN}"
DC1 = f"CN=DC1,OU=Domain Controllers,{DOMAIN}"


def round_trip(snap: Snapshot) -> Snapshot:
    return Snapshot.from_json(json.loads(json.dumps(snap.to_json())))


def raw(snap: Snapshot) -> dict[str, Any]:
    return json.loads(json.dumps(snap.to_json()))  # type: ignore[no-any-return]


# --- AD-ACL-009: tier-0 members are not outsiders ---------------------------------------------


def tier0_user_snapshot(item: Dmsa) -> Snapshot:
    snap = _dmsa_snapshot(item)
    snap.accounts.append(user("alice.adm", sid=ADMIN_SID))
    snap.privileged["Domain Admins"].append(ADMIN)
    return snap


@pytest.mark.parametrize(
    "fields",
    [
        {"owner": ADMIN_SID, "aces": []},
        {"aces": [Ace(ADMIN_SID, sd.GENERIC_ALL)]},
        {"aces": [], "readers": [ADMIN_SID]},
    ],
    ids=["owner", "control", "reader"],
)
def test_a_domain_admin_user_is_not_outside_tier0(fields: dict[str, Any]) -> None:
    assert "AD-ACL-009" not in ids(run_all(tier0_user_snapshot(_dmsa(**fields))))


def test_a_user_outside_tier0_is_still_reported_next_to_a_tier0_user() -> None:
    snap = tier0_user_snapshot(_dmsa(owner=ADMIN_SID, aces=[Ace(HELPDESK, sd.GENERIC_ALL)]))
    f = only(snap, "AD-ACL-009")
    assert f.severity is Severity.MEDIUM and "helpdesk (control)" in f.objects[0]
    assert ADMIN_SID not in f.objects[0]


# --- AD-ACL-009: a link known only from the old account ---------------------------------------


def test_dmsa_without_its_link_stays_unknown_when_the_old_account_points_at_it() -> None:
    item = _dmsa(preceded_by=None, owner=HELPDESK, aces=[])
    snap = _dmsa_snapshot(item)
    snap.accounts[-1].superseded_by = item.dn
    f = only(snap, "AD-ACL-009")
    assert f.severity is Severity.LOW
    assert f.objects == [
        "svc_old: replaced by dmsa1; dMSA not readable, who controls it is unknown"
    ]


def test_dmsa_seen_from_both_sides_is_not_reported_twice() -> None:
    item = _dmsa()
    snap = _dmsa_snapshot(item)
    snap.accounts[-1].superseded_by = item.dn
    assert len(only(snap, "AD-ACL-009").objects) == 1


# --- AD-INF-021 and AD-ACC-016: no readable sAMAccountName --------------------------------------


def blank(name: str, **kw: Any) -> Any:
    a = user(name, sid=f"{SID}-{2000 + len(name)}", **kw)
    a.sam = ""
    return a


def test_unreadable_names_are_not_a_shared_name() -> None:
    snap = round_trip(snapshot(blank("x1"), blank("x22")))
    assert "AD-INF-021" not in ids(run_all(snap))


def test_real_shared_name_is_still_reported_next_to_unreadable_ones() -> None:
    twin = user("bob", sid=f"{SID}-1601")
    twin.dn = f"CN=bob2,CN=Users,{DOM}"
    snap = snapshot(blank("x1"), blank("x22"), user("bob", sid=f"{SID}-1600"), twin)
    assert len(only(snap, "AD-INF-021").objects) == 1


def test_unreadable_name_gives_no_host_name_mismatch() -> None:
    pc = computer("PC", dns_host="pc.lab.test")
    pc.sam = ""
    assert "AD-ACC-016" not in ids(run_all(snapshot(pc)))


def test_unreadable_names_are_counted_in_a_note() -> None:
    assert _blank_name_notes(snapshot().accounts) == []
    notes = _blank_name_notes(snapshot(blank("x1"), blank("x22")).accounts)
    assert len(notes) == 1 and notes[0].startswith("2 account(s)")
    assert "AD-INF-021" in notes[0]


# --- AD-ACC-016: snapshots redacted by an earlier version ---------------------------------------


def old_redacted() -> dict[str, Any]:
    """The shape 0.2.1 wrote: redacted, no marker, unrelated tokens for the two names."""
    data = raw(snapshot(computer("WS01", dns_host="xebb90276.lab.test")))
    data["redacted"] = True
    del data["host_names_comparable"]
    return data


def test_old_redaction_does_not_report_host_names_and_says_so() -> None:
    snap = Snapshot.from_json(old_redacted())
    assert "AD-ACC-016" not in ids(run_all(snap))
    assert any("dNSHostName part of AD-ACC-016" in n for n in snap.notes)


def test_current_redaction_keeps_the_host_name_part() -> None:
    data = raw(snapshot(computer("WS01", dns_host="other.lab.test")))
    back = Snapshot.from_json(redact.redact(data, b"k"))
    assert back.host_names_comparable and "AD-ACC-016" in ids(run_all(back))
    assert not any("dNSHostName part" in n for n in back.notes)


def test_redacting_an_old_redacted_file_again_does_not_compare_its_names() -> None:
    back = Snapshot.from_json(redact.redact(old_redacted(), b"k"))
    assert not back.host_names_comparable and "AD-ACC-016" not in ids(run_all(back))


def test_unredacted_older_snapshot_still_compares_host_names() -> None:
    data = raw(snapshot(computer("WS01", dns_host="other.lab.test")))
    del data["host_names_comparable"]
    snap = Snapshot.from_json(data)
    assert snap.host_names_comparable and "AD-ACC-016" in ids(run_all(snap))


# --- JUnit and SARIF: not judged is not passing -------------------------------------------------

NOTES = [
    "no fine-grained password policy visible (none exist, or this account cannot read them); "
    "AD-POL-001 judges the default domain policy only and AD-POL-003 not judged",
    "snapshot from an older version: AD-INF-016 and the AES part of AD-INF-015 not evaluated",
    "no GPO reaching a DC sets VulnerableChannelAllowList; a value set in a DC's own registry "
    "cannot be seen by this scan (AD-GPO-008)",
    "SYSVOL not checked: <needs> credentials",
]
RAN = ["AD-POL-001", "AD-POL-003", "AD-INF-015", "AD-INF-016", "AD-GPO-008", "AD-KRB-001"]


def junit(snap: Snapshot, ran: list[str]) -> ElementTree.Element:
    return ElementTree.fromstring(render_junit(Report(snap, run_all(snap)), ran))


def case(root: ElementTree.Element, check_id: str) -> ElementTree.Element:
    return next(c for c in root if c.attrib.get("name", "").startswith(check_id))


def test_not_judged_checks_are_skipped_with_the_note() -> None:
    root = junit(snapshot(notes=list(NOTES)), RAN)
    skipped = {c.attrib["name"].split()[0] for c in root if c.find("skipped") is not None}
    assert skipped == {"AD-POL-003", "AD-INF-015", "AD-INF-016"}
    assert root.attrib["skipped"] == "3" and root.attrib["tests"] == "6"
    message = case(root, "AD-POL-003").find("skipped")
    assert message is not None and "AD-POL-003 not judged" in message.attrib["message"]


def test_a_check_that_says_what_it_covers_still_passes() -> None:
    root = junit(snapshot(notes=list(NOTES)), RAN)
    assert not list(case(root, "AD-POL-001")) and not list(case(root, "AD-GPO-008"))


def test_a_finding_beats_a_note_saying_part_was_not_judged() -> None:
    weak = _admin_snapshot(_pso(min_length=8), notes=["x: AD-POL-003 did not judge the missing"])
    root = junit(weak, ["AD-POL-003"])
    assert case(root, "AD-POL-003").find("failure") is not None
    assert root.attrib["failures"] == "1" and root.attrib["skipped"] == "0"


def test_every_note_is_in_system_out() -> None:
    root = junit(snapshot(notes=list(NOTES)), ["AD-KRB-001"])
    out = root.find("system-out")
    assert out is not None and out.text == "\n".join(NOTES)


def test_no_notes_no_system_out() -> None:
    assert junit(snapshot(), ["AD-KRB-001"]).find("system-out") is None


def test_older_snapshot_is_not_green_in_junit() -> None:
    data = raw(snapshot())
    for key in ("psos_checked", "dmsas_checked", "krbtgt_links_checked"):
        del data[key]
    root = junit(Snapshot.from_json(data), ["AD-POL-003", "AD-ACL-009", "AD-KRB-007"])
    assert root.attrib["skipped"] == "3"


def test_sarif_carries_the_notes() -> None:
    snap = snapshot(notes=list(NOTES))
    run = json.loads(render_sarif(Report(snap, [])))["runs"][0]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    got = invocation["toolConfigurationNotifications"]
    assert [n["message"]["text"] for n in got] == NOTES
    assert got[0]["level"] == "warning" and got[0]["properties"]["notJudged"] == ["AD-POL-003"]
    assert got[1]["properties"]["notJudged"] == ["AD-INF-015", "AD-INF-016"]
    assert got[3]["level"] == "note" and "properties" not in got[3]


def test_not_judged_keeps_the_notes_per_check() -> None:
    snap = snapshot(notes=["a: AD-INF-019 not judged", "b: AD-INF-019 not judged"])
    assert report.not_judged(Report(snap, [])) == {"AD-INF-019": snap.notes}


# --- AD-INF-019 ---------------------------------------------------------------------------------


def sysvol(*dcs: Any, **kw: Any) -> Snapshot:
    return snapshot(*dcs, sysvol_replication_checked=True, **kw)


def registered(name: str) -> Any:
    a = computer(name, 0x2000)
    a.dn = DC1 if name == "DC1" else DC2
    return a


def test_dc_with_no_visible_subscription_is_counted_in_a_note() -> None:
    snap = sysvol(registered("DC1"), registered("DC2"), sysvol_dfsr_dcs=[DC1])
    snap.accounts = [a for a in snap.accounts if a.sam != "DC01$"]
    notes = _sysvol_unseen_notes(snap)
    assert len(notes) == 1 and notes[0].startswith("1 registered DC(s)")
    assert "AD-INF-019 not judged" in notes[0]


def test_partly_visible_subscriptions_still_count_as_checked() -> None:
    # only DC1's subscription comes back, with the state unset
    flags, frs, dfsr, checked = Stub({SUBS: [ent(FRS_DN, **OC)]})._sysvol_replication(DOMAIN)
    assert checked and flags is None and frs == [DC1] and not dfsr


@pytest.mark.parametrize("flags", [16, 32, 48])
def test_a_later_state_answers_for_every_dc(flags: int) -> None:
    snap = sysvol(registered("DC2"), sysvol_dfsr_flags=flags)
    assert _sysvol_unseen_notes(snap) == []


def test_every_dc_seen_needs_no_note() -> None:
    snap = sysvol(registered("DC1"), sysvol_dfsr_dcs=[DC1], sysvol_frs_dcs=[DC1])
    snap.accounts = [a for a in snap.accounts if a.sam != "DC01$"]
    assert _sysvol_unseen_notes(snap) == []


def test_entra_object_is_not_a_dc_without_a_subscription() -> None:
    entra = computer("AZUREADKERBEROS", 0x4001000, entra_kerberos=True)
    snap = sysvol(registered("DC1"), entra, sysvol_dfsr_dcs=[DC1])
    snap.accounts = [a for a in snap.accounts if a.sam != "DC01$"]
    assert _sysvol_unseen_notes(snap) == []


def test_not_checked_leaves_the_note_to_the_collector() -> None:
    assert _sysvol_unseen_notes(snapshot()) == []


def both_subscriptions(flags: int | None) -> Snapshot:
    return sysvol(
        registered("DC1"),
        sysvol_dfsr_flags=flags,
        sysvol_frs_dcs=[DC1],
        sysvol_dfsr_dcs=[DC1],
    )


def test_start_state_with_both_subscriptions_says_frs_still_serves() -> None:
    f = only(both_subscriptions(0), "AD-INF-019")
    assert f.severity is Severity.MEDIUM
    assert "Start state" in f.detail and "could not be read" not in f.detail


def test_unread_state_with_both_subscriptions_stays_a_low_review() -> None:
    f = only(both_subscriptions(None), "AD-INF-019")
    assert f.severity is Severity.LOW and "could not be read" in f.detail


# --- AD-POL-003 ---------------------------------------------------------------------------------


PARTIAL = {
    "msDS-PasswordSettingsPrecedence": [b"1"],
    "msDS-PasswordComplexityEnabled": [b"TRUE"],
    "msDS-LockoutThreshold": [b"0"],
    "msDS-PasswordReversibleEncryptionEnabled": [b"FALSE"],
}


def test_policy_with_only_its_precedence_is_counted_in_a_note() -> None:
    entry = ent(f"CN=P,{PSO_BASE}", name=[b"P"], **{"msDS-PasswordSettingsPrecedence": [b"1"]})
    c = Stub({PSO_KEY: [entry]})
    psos, unread, visible = c._psos(DOM)
    assert visible and unread == 0 and len(psos) == 1
    assert any(n.startswith("1 fine-grained") and "AD-POL-003" in n for n in c.notes)


def test_partly_read_policy_still_reports_what_was_read() -> None:
    c = Stub({PSO_KEY: [ent(f"CN=P,{PSO_BASE}", name=[b"P"], **PARTIAL)]})
    psos, _, _ = c._psos(DOM)
    assert any("only part" in n for n in c.notes)
    assert psos[0].min_length is None and psos[0].lockout_threshold == 0


def test_fully_read_policy_has_no_note() -> None:
    attrs = {**PARTIAL, "msDS-MinimumPasswordLength": [b"14"]}
    c = Stub({PSO_KEY: [ent(f"CN=P,{PSO_BASE}", name=[b"P"], **attrs)]})
    c._psos(DOM)
    assert c.notes == []


# --- AD-ACC-016: invisible characters -----------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [0x180B, 0x180C, 0x180D, 0x180F, 0x2065, 0xFFF0, 0xFFF8, 0xE0000, 0xE0FFF, 0x1BCA0, 0x1D173],
)
def test_default_ignorable_code_points_are_invisible(code: int) -> None:
    assert invisible_chars(f"HTTP/a{chr(code)}b") == chr(code)
    snap = snapshot(user("svc", spns=[f"HTTP/a{chr(code)}b"]), upn_checked=True)
    assert f"<U+{code:04X}>" in only(snap, "AD-ACC-016").objects[0]


def test_visible_neighbours_of_the_ranges_stay_visible() -> None:
    assert invisible_chars("᠐᠊\U000e1000") == ""


# --- AD-INF-020 ---------------------------------------------------------------------------------


class Hidden(Stub):
    """Stub in which some bases answer noSuchObject, as an object hidden by its ACL does."""

    hidden: tuple[str, ...] = ()

    def search(
        self,
        base: str,
        flt: str,
        attrs: list[str],
        scope: str = ldap3.SUBTREE,
        controls: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        if base in self.hidden:
            raise LDAPNoSuchObjectResult()
        return super().search(base, flt, attrs, scope, controls)


def topology(*hidden: str) -> Hidden:
    c = Hidden(_topology_routes())
    c.hidden = hidden
    return c


def test_hidden_site_links_are_not_judged_and_not_reported() -> None:
    c = topology(LINKS)
    got, _, checked = c._site_topology(CONFIG)
    assert checked and [s.linked for s in got] == [None, None]
    assert any("site links not readable" in n for n in c.notes)
    assert any(LINKS in n for n in c.notes)


def test_hidden_subnets_container_is_not_judged() -> None:
    c = topology(SUBNETS)
    assert c._site_topology(CONFIG) == ([], [], False)
    assert any("AD-INF-020" in n for n in c.notes)


def test_attempt_still_reads_a_missing_optional_base_as_empty() -> None:
    c = Hidden({})
    c.hidden = ("X",)
    assert c.attempt("X", "(objectClass=*)", []) == []
    assert c.notes == []


def test_global_settings_route_is_not_touched_by_must_exist() -> None:
    c = Hidden({SUBS: [ent(FRS_DN, **OC)]})
    c.hidden = (GLOBAL[0],)
    assert c._sysvol_replication(DOMAIN) == (None, [DC1], [], True)
