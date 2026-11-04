from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ad_doctor.checks import REGISTRY, run_all
from ad_doctor.cli import main
from ad_doctor.collect import sid_to_str
from ad_doctor.model import UAC, Account, DomainPolicy, Finding, Severity, Snapshot

NOW = datetime(2026, 11, 1, tzinfo=UTC)
NORMAL = 0x200
DC_DN = "CN=Users,DC=lab,DC=test"


def user(sam: str, uac: int = NORMAL, **kw: object) -> Account:
    defaults: dict[str, object] = {"pwd_last_set": NOW - timedelta(days=10), "last_logon": NOW}
    defaults.update(kw)
    return Account(dn=f"CN={sam},{DC_DN}", sam=sam, uac=uac, **defaults)  # type: ignore[arg-type]


def computer(sam: str, uac: int = 0x1000, **kw: object) -> Account:
    defaults: dict[str, object] = {"laps": True, "last_logon": NOW}
    defaults.update(kw)
    return Account(
        dn=f"CN={sam},CN=Computers,DC=lab,DC=test",
        sam=f"{sam}$",
        uac=uac,
        is_computer=True,
        **defaults,  # type: ignore[arg-type]
    )


def snapshot(*accounts: Account, **kw: object) -> Snapshot:
    """A clean domain: every check should pass on it."""
    base = Snapshot(
        domain="lab.test",
        domain_dn="DC=lab,DC=test",
        domain_sid="S-1-5-21-1-2-3",
        collected_at=NOW,
        policy=DomainPolicy(
            min_pwd_length=14,
            pwd_complexity=True,
            lockout_threshold=5,
            max_pwd_age_days=None,
            machine_account_quota=0,
            functional_level=10,
        ),
        accounts=[
            user("krbtgt", NORMAL | UAC.ACCOUNTDISABLE, pwd_last_set=NOW - timedelta(days=30)),
            user("Guest", NORMAL | UAC.ACCOUNTDISABLE),
            computer("DC01", 0x2000 | UAC.TRUSTED_FOR_DELEGATION, laps=False),
            *accounts,
        ],
        privileged={"Domain Admins": []},
        protected_users=[],
    )
    return replace(base, **kw)  # type: ignore[arg-type]


def ids(findings: list[Finding]) -> set[str]:
    return {f.check_id for f in findings}


def only(snap: Snapshot, check_id: str) -> Finding:
    found = [f for f in run_all(snap) if f.check_id == check_id]
    assert found, f"{check_id} did not fire"
    return found[0]


def test_clean_domain_has_no_findings() -> None:
    assert run_all(snapshot(user("alice"), computer("WS01"))) == []


def test_check_ids_are_unique() -> None:
    assert len({c.id for c in REGISTRY}) == len(REGISTRY)


def test_old_krbtgt() -> None:
    snap = snapshot()
    snap.accounts[0].pwd_last_set = NOW - timedelta(days=400)
    f = only(snap, "AD-KRB-001")
    assert f.severity is Severity.HIGH
    assert "400 days" in f.detail


def test_asrep_roastable_ignores_disabled() -> None:
    snap = snapshot(
        user("svc_legacy", NORMAL | UAC.DONT_REQ_PREAUTH),
        user("old", NORMAL | UAC.DONT_REQ_PREAUTH | UAC.ACCOUNTDISABLE),
    )
    assert only(snap, "AD-KRB-002").objects == ["svc_legacy"]


def test_kerberoastable_privileged_is_high() -> None:
    sql = user("svc_sql", spns=["MSSQLSvc/db01.lab.test:1433"])
    web = user("svc_web", spns=["HTTP/web01.lab.test"])
    snap = snapshot(sql, web, privileged={"Domain Admins": [sql.dn]})
    f = only(snap, "AD-KRB-003")
    assert f.severity is Severity.HIGH
    assert f.objects == ["svc_sql", "svc_web"]
    assert "svc_sql" in f.detail


def test_kerberoastable_unprivileged_is_medium() -> None:
    snap = snapshot(user("svc_web", spns=["HTTP/web01.lab.test"]))
    assert only(snap, "AD-KRB-003").severity is Severity.MEDIUM


def test_unconstrained_delegation_excludes_dcs() -> None:
    snap = snapshot(computer("APP01", 0x1000 | UAC.TRUSTED_FOR_DELEGATION))
    assert only(snap, "AD-DEL-001").objects == ["APP01$"]


def test_protocol_transition_lists_targets() -> None:
    snap = snapshot(
        user(
            "svc_iis",
            NORMAL | UAC.TRUSTED_TO_AUTH_FOR_DELEGATION,
            allowed_to_delegate_to=["cifs/fs01.lab.test"],
        )
    )
    assert only(snap, "AD-DEL-002").objects == ["svc_iis -> cifs/fs01.lab.test"]


def test_rbcd() -> None:
    assert only(snapshot(computer("FS01", rbcd=True)), "AD-DEL-003").objects == ["FS01$"]


@pytest.mark.parametrize(
    ("flag", "check_id"),
    [
        (UAC.PASSWD_NOTREQD, "AD-ACC-001"),
        (UAC.ENCRYPTED_TEXT_PWD_ALLOWED, "AD-ACC-002"),
        (UAC.USE_DES_KEY_ONLY, "AD-KRB-004"),
    ],
)
def test_uac_flag_checks(flag: UAC, check_id: str) -> None:
    snap = snapshot(user("bob", NORMAL | flag))
    assert only(snap, check_id).objects == ["bob"]


def test_privileged_never_expires_and_delegable() -> None:
    admin = user("adm_bob", NORMAL | UAC.DONT_EXPIRE_PASSWORD)
    snap = snapshot(admin, privileged={"Domain Admins": [admin.dn]})
    assert ids(run_all(snap)) >= {"AD-ACC-003", "AD-PRIV-002"}


def test_protected_users_member_is_not_delegable() -> None:
    admin = user("adm_bob")
    snap = snapshot(admin, privileged={"Domain Admins": [admin.dn]}, protected_users=[admin.dn])
    assert "AD-PRIV-002" not in ids(run_all(snap))


def test_guest_enabled() -> None:
    snap = snapshot()
    snap.accounts[1].uac = NORMAL
    assert only(snap, "AD-ACC-004").objects == ["Guest"]


def test_stale_users() -> None:
    snap = snapshot(
        user("gone", last_logon=NOW - timedelta(days=200)),
        user("never", last_logon=None, pwd_last_set=NOW - timedelta(days=365)),
        user("new", last_logon=None, pwd_last_set=NOW - timedelta(days=3)),
    )
    assert only(snap, "AD-ACC-005").objects == ["gone", "never"]


def test_large_admin_group() -> None:
    members = [f"CN=a{i},{DC_DN}" for i in range(7)]
    assert only(snapshot(privileged={"Domain Admins": members}), "AD-PRIV-001").objects == [
        "Domain Admins"
    ]


def test_password_policy() -> None:
    snap = snapshot()
    snap.policy.min_pwd_length = 7
    snap.policy.lockout_threshold = 0
    f = only(snap, "AD-POL-001")
    assert "minimum length 7" in f.detail
    assert "no account lockout" in f.detail


def test_machine_account_quota() -> None:
    snap = snapshot()
    snap.policy.machine_account_quota = 10
    assert "10" in only(snap, "AD-POL-002").detail


def test_laps_missing_skips_dcs() -> None:
    snap = snapshot(computer("WS02", laps=False))
    assert only(snap, "AD-SEC-001").objects == ["WS02$"]


def test_results_sorted_by_severity() -> None:
    snap = snapshot(
        computer("WS02", laps=False), user("x", NORMAL | UAC.ENCRYPTED_TEXT_PWD_ALLOWED)
    )
    sev = [f.severity for f in run_all(snap)]
    assert sev == sorted(sev, reverse=True)


def test_only_filter() -> None:
    snap = snapshot(computer("WS02", laps=False), user("x", NORMAL | UAC.PASSWD_NOTREQD))
    assert ids(run_all(snap, ["ad-sec-001"])) == {"AD-SEC-001"}


def test_sid_to_str() -> None:
    raw = bytes.fromhex("010400000000000515000000a065cf7e78aba4b0e3eb5c7a")
    assert sid_to_str(raw).startswith("S-1-5-21-")
    assert sid_to_str(raw).count("-") == 6


def test_snapshot_roundtrip_and_analyze_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap = snapshot(user("svc", NORMAL | UAC.DONT_REQ_PREAUTH))
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap.to_json()))
    assert Snapshot.from_json(json.loads(path.read_text())) == snap

    assert main(["analyze", str(path), "-f", "json", "--fail-on", "high"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert [f["id"] for f in out["findings"]] == ["AD-KRB-002"]
