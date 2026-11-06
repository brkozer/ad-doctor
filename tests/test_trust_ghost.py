"""Trust hygiene (AD-INF-015, -016, -017) and ghost SPNs in delegation (AD-DEL-005)."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest

from ad_doctor import redact
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector
from ad_doctor.model import UAC, Account, Severity, Snapshot, Trust

from .test_checks import NORMAL, NOW, computer, ids, only, snapshot, user

FOREST, QUARANTINED, WITHIN_FOREST, SELECTIVE, AES_KEYS = 0x8, 0x4, 0x20, 0x10, 0x100
INBOUND, OUTBOUND, BOTH = 1, 2, 3
HOST_MAP = ["host=cifs,http,rpcss"]


def trust(name: str = "partner.test", **kw: Any) -> Trust:
    fields: dict[str, Any] = {
        "direction": BOTH,
        "trust_type": 2,
        "attributes": QUARANTINED,
        "enc_types": 0x18,
        "when_changed": NOW - timedelta(days=5),
    }
    return Trust(name=name, **{**fields, **kw})


def with_trusts(*trusts: Trust, checked: bool = True) -> Snapshot:
    return snapshot(trusts=list(trusts), trust_details_checked=checked)


def test_healthy_trust_stays_quiet() -> None:
    assert not ids(run_all(with_trusts(trust()))) & {"AD-INF-015", "AD-INF-016", "AD-INF-017"}


# --- AD-INF-015 ---------------------------------------------------------------------------


def test_downlevel_trust_in_any_direction() -> None:
    f = only(with_trusts(trust(trust_type=1, direction=OUTBOUND, enc_types=None)), "AD-INF-015")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["partner.test (downlevel, NT4 style)"]


def test_encryption_types_without_aes() -> None:
    f = only(with_trusts(trust(enc_types=0x4)), "AD-INF-015")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["partner.test (no AES, encryption types 0x4)"]


@pytest.mark.parametrize("value", [None, 0])
def test_aes_not_set_is_low(value: int | None) -> None:
    f = only(with_trusts(trust(enc_types=value)), "AD-INF-015")
    assert f.severity is Severity.LOW
    assert f.objects == ["partner.test (AES not set on the trust)"]


def test_worst_trust_sets_the_grade() -> None:
    f = only(
        with_trusts(trust("a.test", enc_types=None), trust("b.test", enc_types=4)), "AD-INF-015"
    )
    assert f.severity is Severity.MEDIUM
    assert len(f.objects) == 2


@pytest.mark.parametrize(
    "kw",
    [
        {"enc_types": 0x8},
        {"enc_types": 0x10},
        {"enc_types": 0x1C},
        {"enc_types": None, "attributes": QUARANTINED | AES_KEYS},
        {"enc_types": None, "direction": OUTBOUND},
        {"enc_types": 4, "direction": OUTBOUND},
        {"enc_types": None, "trust_type": 5},
    ],
)
def test_aes_quiet(kw: dict[str, Any]) -> None:
    assert "AD-INF-015" not in ids(run_all(with_trusts(trust(**kw))))


def test_entra_realm_is_not_judged_by_name_either() -> None:
    snap = with_trusts(
        trust(
            "Kerberos.MicrosoftOnline.com",
            enc_types=None,
            when_changed=NOW - timedelta(days=400),
        )
    )
    assert not ids(run_all(snap)) & {"AD-INF-015", "AD-INF-016"}


def test_older_snapshot_judges_only_the_downlevel_part() -> None:
    old = [trust("a.test", enc_types=None), trust("b.test", trust_type=1, enc_types=None)]
    f = only(with_trusts(*old, checked=False), "AD-INF-015")
    assert f.objects == ["b.test (downlevel, NT4 style)"]


# --- AD-INF-016 ---------------------------------------------------------------------------


def test_stale_trust_shows_a_stable_date() -> None:
    changed = NOW - timedelta(days=41)
    f = only(with_trusts(trust(when_changed=changed)), "AD-INF-016")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [f"partner.test (last changed {changed.date().isoformat()})"]


def test_exactly_forty_days_is_not_stale() -> None:
    snap = with_trusts(trust(when_changed=NOW - timedelta(days=40)))
    assert "AD-INF-016" not in ids(run_all(snap))


def test_unknown_date_is_not_judged() -> None:
    assert "AD-INF-016" not in ids(run_all(with_trusts(trust(when_changed=None))))


def test_realm_trust_alone_is_low() -> None:
    old = NOW - timedelta(days=400)
    f = only(with_trusts(trust(trust_type=3, when_changed=old)), "AD-INF-016")
    assert f.severity is Severity.LOW
    assert "realm trust" in f.objects[0] and "review" in f.objects[0]


def test_windows_trust_lifts_the_grade_over_a_realm_trust() -> None:
    old = NOW - timedelta(days=400)
    snap = with_trusts(trust("a.test", trust_type=3, when_changed=old), trust(when_changed=old))
    assert only(snap, "AD-INF-016").severity is Severity.MEDIUM


# --- AD-INF-017 ---------------------------------------------------------------------------


@pytest.mark.parametrize("direction", [OUTBOUND, BOTH])
def test_outgoing_forest_trust_without_selective_auth(direction: int) -> None:
    f = only(with_trusts(trust(attributes=FOREST, direction=direction)), "AD-INF-017")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["partner.test"]


@pytest.mark.parametrize(
    "kw",
    [
        {"attributes": FOREST | SELECTIVE},
        {"attributes": FOREST, "direction": INBOUND},
        {"attributes": FOREST | WITHIN_FOREST},
        {"attributes": QUARANTINED},
        {"attributes": FOREST, "trust_type": 3},
    ],
)
def test_selective_auth_quiet(kw: dict[str, Any]) -> None:
    assert "AD-INF-017" not in ids(run_all(with_trusts(trust(**kw))))


# --- trust collection and snapshots -------------------------------------------------------


def collector(entries: list[dict[str, list[Any]]]) -> Collector:
    c = Collector.__new__(Collector)
    c.notes = []
    c.search = lambda *args, **kwargs: entries  # type: ignore[method-assign]
    return c


def test_collector_reads_encryption_types_and_date() -> None:
    entry = {
        "trustpartner": ["partner.test"],
        "trustdirection": ["3"],
        "trusttype": ["2"],
        "trustattributes": ["8"],
        "msds-supportedencryptiontypes": ["24"],
        "whenchanged": ["20261001120000.0Z"],
    }
    c = collector([entry])
    t = c._trusts("DC=lab,DC=test")[0]
    assert t.enc_types == 24
    assert t.when_changed is not None and t.when_changed.date().isoformat() == "2026-10-01"
    assert not c.notes


def test_collector_keeps_unset_and_notes_an_unreadable_date() -> None:
    entry = {"trustpartner": ["partner.test"], "trustdirection": ["3"], "trusttype": ["2"]}
    c = collector([entry])
    t = c._trusts("DC=lab,DC=test")[0]
    assert t.enc_types is None and t.when_changed is None
    assert c.notes == ["whenChanged of trust partner.test not readable: AD-INF-016 not judged"]


def test_collector_reads_spn_mappings_and_notes_a_miss() -> None:
    assert collector([{"spnmappings": HOST_MAP}])._spn_mappings("CN=Configuration") == HOST_MAP
    c = collector([])
    assert c._spn_mappings("CN=Configuration") == []
    assert "AD-DEL-005" in c.notes[0]


def test_trust_fields_survive_json() -> None:
    snap = snapshot(trusts=[trust()], trust_details_checked=True, spn_mappings=HOST_MAP)
    back = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert back.trusts == snap.trusts
    assert back.trust_details_checked and back.spn_mappings == HOST_MAP
    assert not any("AD-INF-016" in n or "AD-DEL-005" in n for n in back.notes)


def test_older_snapshot_loads_and_says_what_was_not_evaluated() -> None:
    data = json.loads(json.dumps(snapshot(trusts=[trust()]).to_json()))
    del data["trust_details_checked"], data["spn_mappings"]
    for t in data["trusts"]:
        del t["enc_types"], t["when_changed"]
    snap = Snapshot.from_json(data)
    assert snap.trusts[0].when_changed is None and not snap.trust_details_checked
    assert any("AD-INF-016" in n for n in snap.notes)
    assert any("AD-DEL-005" in n for n in snap.notes)


# --- AD-DEL-005 ---------------------------------------------------------------------------


def delegating(*targets: str, uac: int = NORMAL) -> Account:
    return user("svc_app", uac, allowed_to_delegate_to=list(targets))


def fs01(**kw: Any) -> Account:
    spns = ["HOST/fs01.lab.test", "HOST/FS01"]
    return computer(
        "FS01", UAC.WORKSTATION_TRUST_ACCOUNT, spns=spns, dns_host="fs01.lab.test", **kw
    )


def targets(*accounts: Account, mappings: list[str] | None = None) -> Snapshot:
    return snapshot(*accounts, spn_mappings=HOST_MAP if mappings is None else mappings)


def test_no_delegation_stays_quiet() -> None:
    assert "AD-DEL-005" not in ids(run_all(targets(fs01())))


@pytest.mark.parametrize(
    "target",
    [
        "HOST/fs01.lab.test",
        "host/FS01.LAB.TEST",
        "cifs/fs01.lab.test",  # through sPNMappings
        "CIFS/FS01",
        "http/fs01.lab.test",
        "cifs/fs01.lab.test.",
    ],
)
def test_host_aliases_are_no_false_positive(target: str) -> None:
    assert "AD-DEL-005" not in ids(run_all(targets(delegating(target), fs01())))


def test_custom_mapping_counts() -> None:
    sql = user("svc_sql", NORMAL, spns=["sqlhost/db.lab.test"])
    snap = targets(
        delegating("report/db.lab.test"), sql, mappings=[*HOST_MAP, "sqlhost=report,etl"]
    )
    assert "AD-DEL-005" not in ids(run_all(snap))


def test_spn_on_a_user_or_managed_account_counts_without_a_computer() -> None:
    web = user("svc_web", NORMAL, spns=["http/portal.lab.test"])
    gmsa = computer("gmsa1", 0x1000, spns=["MSSQLSvc/db.lab.test:1433"], managed=True)
    snap = targets(delegating("http/portal.lab.test", "MSSQLSvc/db.lab.test:1433"), web, gmsa)
    assert "AD-DEL-005" not in ids(run_all(snap))


def test_disabled_holder_still_holds_the_spn() -> None:
    off = user("svc_old", NORMAL | UAC.ACCOUNTDISABLE, spns=["http/app.lab.test"])
    assert "AD-DEL-005" not in ids(run_all(targets(delegating("http/app.lab.test"), off)))


def test_disabled_delegating_account_is_skipped() -> None:
    account = delegating("cifs/gone.lab.test", uac=NORMAL | UAC.ACCOUNTDISABLE)
    assert "AD-DEL-005" not in ids(run_all(targets(account)))


def test_krbtgt_is_left_to_ad_del_004() -> None:
    found = run_all(targets(delegating("krbtgt/LAB.TEST")))
    assert "AD-DEL-004" in ids(found) and "AD-DEL-005" not in ids(found)


@pytest.mark.parametrize("target", ["cifs/gone.lab.test", "cifs/GONE", "http/gone.lab.test:8080"])
def test_ghost_host_kerberos_only_is_medium(target: str) -> None:
    f = only(targets(delegating(target)), "AD-DEL-005")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [f"svc_app -> {target} (no computer object)"]


def test_ghost_host_with_protocol_transition_is_high() -> None:
    account = delegating("cifs/gone.lab.test", uac=NORMAL | UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)
    f = only(targets(account), "AD-DEL-005")
    assert f.severity is Severity.HIGH
    assert f.objects == ["svc_app -> cifs/gone.lab.test (no computer object, protocol transition)"]
    assert "servicePrincipalName" in f.detail


def test_ghost_does_not_depend_on_mappings() -> None:
    snap = targets(delegating("cifs/gone.lab.test"), mappings=[])
    assert only(snap, "AD-DEL-005").severity is Severity.MEDIUM


def test_host_exists_but_nothing_holds_the_spn_is_graded_by_the_account() -> None:
    f = only(targets(delegating("MSSQLSvc/fs01.lab.test:1433"), fs01()), "AD-DEL-005")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [
        "svc_app -> MSSQLSvc/fs01.lab.test:1433 (no account holds it, the host exists)"
    ]


def test_prestaged_computer_counts_as_a_host() -> None:
    bare = computer("NEW01", UAC.WORKSTATION_TRUST_ACCOUNT)
    f = only(targets(delegating("cifs/new01.lab.test"), bare), "AD-DEL-005")
    assert "the host exists" in f.objects[0]


def test_without_mappings_a_target_on_a_known_host_is_not_judged() -> None:
    snap = targets(delegating("cifs/fs01.lab.test"), fs01(), mappings=[])
    assert "AD-DEL-005" not in ids(run_all(snap))


@pytest.mark.parametrize("target", ["cifs/fs01.child.lab.test", "cifs/10.0.0.5"])
def test_only_what_may_be_this_domain_gets_review_wording(target: str) -> None:
    f = only(targets(delegating(target)), "AD-DEL-005")
    assert f.severity is Severity.LOW
    assert f.objects == [f"svc_app -> {target} (not in this domain's snapshot, review)"]


def test_entry_that_cannot_be_parsed_is_reported() -> None:
    f = only(targets(delegating("cifs")), "AD-DEL-005")
    assert f.objects == ["svc_app -> cifs (cannot be parsed, review)"]


# --- redaction ----------------------------------------------------------------------------


def test_redaction_hides_ghost_hosts_and_keeps_the_findings() -> None:
    snap = targets(
        delegating(
            "cifs/gone.lab.test",
            "cifs/fs.partner.test",
            "cifs/fs.child.lab.test",
            "cifs/fs01.lab.test",
        ),
        fs01(),
        user("svc_web", NORMAL, spns=["http/portal.intranet.test:8080"]),
    )
    snap.trusts.append(trust(enc_types=None, when_changed=NOW - timedelta(days=90)))
    data = json.loads(json.dumps(snap.to_json()))
    out = redact.redact(data, b"k")
    text = json.dumps(out)
    for word in ("gone", "partner", "portal", "intranet", "fs01", "lab.test"):
        assert word not in text.lower(), word
    assert "8080" in text
    before = [(f.check_id, f.severity, len(f.objects)) for f in run_all(snap)]
    after = [(f.check_id, f.severity, len(f.objects)) for f in run_all(Snapshot.from_json(out))]
    assert after == before
    wording = next(f for f in run_all(Snapshot.from_json(out)) if f.check_id == "AD-DEL-005")
    assert sum("review" in o for o in wording.objects) == 1
