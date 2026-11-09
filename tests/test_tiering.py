"""Tier-0 logon restrictions, authentication policy silos and change history from replication
metadata: AD-PRIV-013, -014, -015, AD-ACL-010 and AD-ACC-017."""

from __future__ import annotations

import itertools
import json
from datetime import timedelta
from typing import Any

from ad_doctor import coverage, gpo_scope, redact
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector, _member_additions
from ad_doctor.gpo_scope import CSE_SECURITY, DENY_LOGON_RIGHTS
from ad_doctor.model import (
    SILO_LEVEL,
    Account,
    AuthPolicy,
    AuthSilo,
    DirObject,
    GpLink,
    Gpo,
    GpoSettings,
    MemberChange,
    Severity,
    SidHistoryChange,
    Snapshot,
)

from .test_checks import NOW, ids, only, snapshot, user
from .test_gpo_local import APPLY, HEAD, ISOLATED, LAB, READ, dc, host, raw

DOM = "S-1-5-21-1-2-3"
DA = f"{DOM}-512"
CONFIG = "CN=Configuration,DC=lab,DC=test"
ROOT = f"CN=AuthN Policy Configuration,CN=Services,{CONFIG}"
SILOS = f"CN=AuthN Silos,{ROOT}"
POLICIES = f"CN=AuthN Policies,{ROOT}"
DENY_ALL = {key: [DA] for key in DENY_LOGON_RIGHTS}
ADMIN_SID = f"{DOM}-1500"
LOGON, RDP, BATCH, SERVICE = DENY_LOGON_RIGHTS
OLD = NOW - timedelta(days=400)
counter = itertools.count(1)


def admin(name: str = "admin1", rid: int = 1500) -> Account:
    return user(name, sid=f"{DOM}-{rid}")


def member(ou: str = LAB, name: str = "HOST1", rid: int = 3000) -> Account:
    return host(name, ou, rid, os="Windows Server 2022 Standard")


def gpo(
    rights: dict[str, list[str]] | None,
    *links: tuple[str, bool],
    **kw: Any,
) -> tuple[Gpo, GpoSettings | None]:
    number = next(counter)
    made = Gpo(
        name=f"GPO{number}",
        guid="{" + f"{number:036d}" + "}",
        linked_to=[],
        aces=[READ, APPLY],
        links=[GpLink(c, "ou", True, enforced, i) for i, (c, enforced) in enumerate(links)],
        machine_version=1,
        machine_extensions=[CSE_SECURITY],
        **kw,
    )
    return made, None if rights is None else GpoSettings(privileges=rights)


def domain_admins(*members: Account) -> DirObject:
    return DirObject(
        dn=f"CN=Domain Admins,CN=Users,{HEAD}",
        name="Domain Admins",
        kind="group",
        sid=DA,
        members=[a.dn for a in members],
    )


def world(
    *gpos: tuple[Gpo, GpoSettings | None], hosts: tuple[Account, ...] = (), **kw: Any
) -> Snapshot:
    a1 = kw.pop("admin", None) or admin()
    return snapshot(
        a1,
        *hosts,
        privileged={"Domain Admins": [a1.dn]},
        objects=[domain_admins(a1), *kw.pop("objects", [])],
        gpos=[g for g, _ in gpos],
        gpo_settings={g.guid: s for g, s in gpos if s is not None},
        logon_rights_collected=True,
        site_count=1,
        **kw,
    )


# --- AD-PRIV-013 --------------------------------------------------------------------------


def test_no_deny_on_a_member_fires_medium() -> None:
    f = only(world(hosts=(member(),)), "AD-PRIV-013")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [
        "Lab: HOST1: not denied to every tier-0 account: local logon, RDP, batch, service"
    ]


def test_deny_of_the_group_covers_its_members_and_stays_quiet() -> None:
    snap = world(gpo(DENY_ALL, (LAB, False)), hosts=(member(),))
    assert "AD-PRIV-013" not in ids(run_all(snap))


def test_only_batch_and_service_missing_is_low() -> None:
    snap = world(
        gpo({LOGON: [DA], RDP: [DA]}, (LAB, False)),
        hosts=(member(),),
    )
    f = only(snap, "AD-PRIV-013")
    assert f.severity is Severity.LOW
    assert "batch, service" in f.objects[0]


def test_judged_per_ou_not_domain_wide() -> None:
    covered = member(LAB, "HOST1", 3000)
    open_one = member(ISOLATED, "HOST2", 3001)
    snap = world(
        gpo(DENY_ALL, (LAB, False)),
        hosts=(covered, open_one),
        objects=[DirObject(dn=ISOLATED, name="Isolated", kind="ou", gp_blocked=True)],
    )
    f = only(snap, "AD-PRIV-013")
    assert [o.split(":")[1] for o in f.objects] == [" HOST2"]


def test_a_later_gpo_defining_the_right_replaces_the_list() -> None:
    domain = gpo(DENY_ALL, (HEAD, False))
    ou = gpo({key: [] for key in DENY_LOGON_RIGHTS}, (LAB, False))
    f = only(world(domain, ou, hosts=(member(),)), "AD-PRIV-013")
    assert f.severity is Severity.MEDIUM


def test_a_later_gpo_that_defines_other_rights_changes_nothing() -> None:
    domain = gpo(DENY_ALL, (HEAD, False))
    ou = gpo({"SeBackupPrivilege": []}, (LAB, False))
    assert "AD-PRIV-013" not in ids(run_all(world(domain, ou, hosts=(member(),))))


def test_enforced_gpo_above_wins_over_the_ou() -> None:
    domain = gpo(DENY_ALL, (HEAD, True))
    ou = gpo({key: [] for key in DENY_LOGON_RIGHTS}, (LAB, False))
    assert "AD-PRIV-013" not in ids(run_all(world(domain, ou, hosts=(member(),))))


def test_gpo_excluded_by_security_filter_does_not_count() -> None:
    made, settings = gpo(DENY_ALL, (LAB, False))
    # no read or apply for computers: the GPO stops at the security filter
    made.aces = [READ]
    f = only(world((made, settings), hosts=(member(),)), "AD-PRIV-013")
    assert f.severity is Severity.MEDIUM


def test_token_is_followed_through_nesting_and_who_is_left_out_is_named() -> None:
    one, two = admin("admin1", 1500), admin("admin2", 1501)
    nested = DirObject(
        dn=f"CN=T0,{HEAD}", name="T0", kind="group", sid=f"{DOM}-1600", members=[one.dn]
    )
    snap = snapshot(
        one,
        two,
        member(),
        privileged={"Domain Admins": [one.dn, two.dn]},
        objects=[domain_admins(two), nested],
        gpos=[g := gpo({key: [f"{DOM}-1600"] for key in DENY_LOGON_RIGHTS}, (LAB, False))[0]],
        gpo_settings={
            g.guid: GpoSettings(privileges={key: [f"{DOM}-1600"] for key in DENY_LOGON_RIGHTS})
        },
        logon_rights_collected=True,
        site_count=1,
    )
    f = only(snap, "AD-PRIV-013")
    assert "left out: admin2" in f.objects[0]
    assert f.severity is Severity.MEDIUM


def test_unreadable_security_template_is_undecided_not_a_pass() -> None:
    snap = world(gpo(None, (LAB, False)), hosts=(member(),))
    f = only(snap, "AD-PRIV-013")
    assert f.severity is Severity.INFO
    assert "GptTmpl.inf of" in f.objects[0] and "not decided" in f.objects[0]


def test_unresolved_name_in_the_right_is_undecided() -> None:
    rights = {key: ["OTHER\\Tier0"] for key in DENY_LOGON_RIGHTS}
    f = only(world(gpo(rights, (LAB, False)), hosts=(member(),)), "AD-PRIV-013")
    assert f.severity is Severity.INFO


def test_a_named_group_resolved_by_the_collector_counts() -> None:
    settings = {"x": GpoSettings(privileges={LOGON: ["CORP\\T0"]})}
    routes = {
        (f"CN=Partitions,{CONFIG}", "(&(objectClass=crossRef)(nCName=DC=lab,DC=test))"): [
            raw("CN=LAB", nETBIOSName="LAB")
        ],
    }
    c = StubCollector(routes)
    c._principal_sid = lambda name, *a: DA if name == "CORP\\T0" else ""  # type: ignore[method-assign]
    out = c._resolve_deny_rights(settings, HEAD, CONFIG, "lab.test")
    assert out["x"].privileges[LOGON] == [DA]
    assert c.notes == []


def test_an_unresolved_name_gets_a_note_naming_the_check() -> None:
    routes: dict[tuple[str, str], list[dict[str, Any]]] = {}
    c = StubCollector(routes)
    c._principal_sid = lambda *a: ""  # type: ignore[method-assign]
    c._resolve_deny_rights(
        {"x": GpoSettings(privileges={RDP: ["ghost"]})}, HEAD, CONFIG, "lab.test"
    )
    assert any("AD-PRIV-013" in n and "ghost" in n for n in c.notes)


def test_dcs_and_tier0_hosts_are_not_judged() -> None:
    snap = world(hosts=(dc(),))
    assert "AD-PRIV-013" not in ids(run_all(snap))
    ca = member(LAB, "CA01", 3005)
    assert "AD-PRIV-013" not in ids(run_all(world(hosts=(ca,), ca_hosts=["CA01$"])))


def test_not_collected_does_not_judge_and_is_not_a_pass() -> None:
    snap = world(hosts=(member(),))
    snap.logon_rights_collected = False
    assert "AD-PRIV-013" not in ids(run_all(snap))
    got = coverage.compute(snap, [])
    assert got["AD-PRIV-013"].status == coverage.NOT_EVALUATED


def test_unreadable_sysvol_holds_the_check_back() -> None:
    assert "AD-PRIV-013" in coverage.note_checks("SYSVOL files not readable by this account: x")


def test_denied_accounts_reports_undecided_when_an_outcome_is_unknown() -> None:
    made, _ = gpo(DENY_ALL, (LAB, False))
    effective = gpo_scope.Effective(
        (gpo_scope.Outcome(True, [DA], made.name), gpo_scope.Outcome(False, unknown=True))
    )
    assert gpo_scope.denied_accounts(effective, {"a": {DA}}) == (None, [])


# --- AD-PRIV-014 --------------------------------------------------------------------------


def silo(
    a: Account,
    enforced: bool = True,
    user_policy: str = f"CN=P,{POLICIES}",
    members: bool = True,
    assigned: bool = True,
) -> AuthSilo:
    return AuthSilo(
        name="Tier0",
        dn=f"CN=Tier0,{SILOS}",
        enforced=enforced,
        members=[a.dn] if members else [],
        assigned=[a.dn] if assigned else [],
        user_policy=user_policy,
    )


def policy(enforced: bool = True, limits: bool = True) -> AuthPolicy:
    return AuthPolicy("P", f"CN=P,{POLICIES}", enforced, limits)


def silo_snap(*silos: AuthSilo, policies: tuple[AuthPolicy, ...] = (), **kw: Any) -> Snapshot:
    a1 = admin()
    return snapshot(
        a1,
        privileged={"Domain Admins": [a1.dn]},
        auth_silos=list(silos),
        auth_policies=list(policies),
        silos_checked=True,
        **kw,
    )


def test_no_silo_at_all_fires_low() -> None:
    f = only(silo_snap(), "AD-PRIV-014")
    assert f.severity is Severity.LOW
    assert f.objects == ["admin1"]


def test_fully_covered_stays_quiet() -> None:
    a1 = admin()
    assert "AD-PRIV-014" not in ids(run_all(silo_snap(silo(a1), policies=(policy(),))))


def test_builtin_administrator_is_left_out() -> None:
    root = user("Administrator", sid=f"{DOM}-500")
    snap = snapshot(root, privileged={"Domain Admins": [root.dn]}, silos_checked=True)
    assert "AD-PRIV-014" not in ids(run_all(snap))


def test_silo_gaps_are_named() -> None:
    a1 = admin()
    for made, policies, text in (
        (silo(a1, enforced=False), (policy(),), "audit mode"),
        (silo(a1), (policy(enforced=False),), "audit mode"),
        (silo(a1), (policy(limits=False),), "does not limit"),
        (silo(a1), (), "no user policy"),
        (silo(a1, assigned=False), (policy(),), "one side only"),
        (silo(a1, members=False), (policy(),), "one side only"),
    ):
        assert text in only(silo_snap(made, policies=policies), "AD-PRIV-014").objects[0]


def test_silo_that_is_not_the_accounts_means_in_no_silo() -> None:
    other = user("someone", sid=f"{DOM}-1700")
    f = only(silo_snap(silo(other), policies=(policy(),)), "AD-PRIV-014")
    assert f.objects == ["admin1: in no silo"]


def test_unread_silos_do_not_judge_and_below_2012r2_is_not_applicable() -> None:
    a1 = admin()
    snap = silo_snap()
    snap.silos_checked = False
    assert "AD-PRIV-014" not in ids(run_all(snap))
    assert coverage.compute(snap, [])["AD-PRIV-014"].status == coverage.NOT_EVALUATED
    old = silo_snap(silo(a1), policies=(policy(),))
    old.policy.functional_level = SILO_LEVEL - 1
    assert coverage.compute(old, [])["AD-PRIV-014"].status == coverage.NOT_APPLICABLE
    assert "AD-PRIV-014" not in ids(run_all(old))


class StubCollector(Collector):
    """`attempt`, `optional` and `_base` from a dict keyed by (base, filter)."""

    def __init__(self, routes: dict[tuple[str, str], Any], dacl: list[Any] | None = None) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.routes = routes
        self.acl = dacl or []

    def attempt(self, base: str, flt: str, attrs: list[str], **kw: Any) -> Any:
        return self.routes.get((base, flt), [])

    def optional(self, base: str, flt: str, attrs: list[str], **kw: Any) -> list[dict[str, Any]]:
        return self.routes.get((base, flt), [])  # type: ignore[no-any-return]

    def _base(self, dn: str, attrs: list[str]) -> list[dict[str, Any]]:
        return self.routes.get((dn, "base"), [])  # type: ignore[no-any-return]

    def _dacl(self, dn: str) -> list[Any]:
        return self.acl


def silo_routes(**kw: Any) -> dict[tuple[str, str], Any]:
    return {
        (SILOS, "(objectClass=*)"): [raw(SILOS)],
        (POLICIES, "(objectClass=msDS-AuthNPolicy)"): [],
        **kw.get("extra", {}),
    }


def test_silo_objects_are_read() -> None:
    adm_dn = f"CN=admin1,CN=Users,{HEAD}"
    extra = {
        (SILOS, "(objectClass=msDS-AuthNPolicySilo)"): [
            raw(
                f"CN=Tier0,{SILOS}",
                name="Tier0",
                **{
                    "msDS-AuthNPolicySiloEnforced": "TRUE",
                    "msDS-AuthNPolicySiloMembers": adm_dn,
                    "msDS-AssignedAuthNPolicySiloBL": adm_dn,
                    "msDS-UserAuthNPolicy": f"CN=P,{POLICIES}",
                },
            )
        ],
        (POLICIES, "(objectClass=msDS-AuthNPolicy)"): [
            raw(
                f"CN=P,{POLICIES}",
                name="P",
                **{
                    "msDS-AuthNPolicyEnforced": "TRUE",
                    "msDS-UserAllowedToAuthenticateFrom": "O:SY",
                },
            )
        ],
    }
    silos, policies, checked = StubCollector(silo_routes(extra=extra))._auth_silos(CONFIG, 10)
    assert checked
    assert silos[0].enforced and silos[0].members == [adm_dn] and silos[0].assigned == [adm_dn]
    assert policies[0].enforced and policies[0].limits_user_from


def test_refused_search_is_not_none_found() -> None:
    routes = silo_routes()
    routes[(SILOS, "(objectClass=msDS-AuthNPolicySilo)")] = None  # the search was refused
    c = StubCollector(routes)
    assert c._auth_silos(CONFIG, 10) == ([], [], False)
    assert any("AD-PRIV-014" in n for n in c.notes)


def test_hidden_container_is_unknown_above_2012r2_and_absent_below() -> None:
    c = StubCollector({})
    assert c._auth_silos(CONFIG, 10) == ([], [], False)
    assert any("AD-PRIV-014" in n for n in c.notes)
    assert StubCollector({})._auth_silos(CONFIG, SILO_LEVEL - 1) == ([], [], True)


def test_empty_list_only_counts_when_ordinary_users_may_list_the_container() -> None:
    from ad_doctor import sd

    open_acl = [sd.Ace("S-1-5-11", sd.LIST_CHILDREN)]
    assert StubCollector(silo_routes(), open_acl)._auth_silos(CONFIG, 10) == ([], [], True)
    c = StubCollector(silo_routes(), [])
    assert c._auth_silos(CONFIG, 10) == ([], [], False)
    assert any("AD-PRIV-014" in n and "list" in n for n in c.notes)


# --- replication metadata ---------------------------------------------------------------------


def value_row(dn: str, deleted: str, changed: str, attribute: str = "member") -> str:
    return (
        f"<DS_REPL_VALUE_META_DATA><pszAttributeName>{attribute}</pszAttributeName>"
        f"<pszObjectDn>{dn}</pszObjectDn><ftimeDeleted>{deleted}</ftimeDeleted>"
        f"<ftimeCreated>2020-01-01T00:00:00Z</ftimeCreated>"
        f"<ftimeLastOriginatingChange>{changed}</ftimeLastOriginatingChange>"
        "</DS_REPL_VALUE_META_DATA>"
    )


ZERO = "1601-01-01T00:00:00Z"


def test_member_additions_keep_only_live_member_rows() -> None:
    xml = (
        value_row("CN=a&amp;b,DC=x", ZERO, "2026-10-30T12:00:00Z")
        + value_row("CN=gone,DC=x", "2026-10-30T13:00:00Z", "2026-10-30T13:00:00Z")
        + value_row("CN=other,DC=x", ZERO, "2026-10-30T12:00:00Z", "msDS-KeyCredentialLink")
    )
    got = _member_additions(xml)
    assert [dn for dn, _ in got] == ["CN=a&b,DC=x"]
    assert got[0][1].isoformat().startswith("2026-10-30T12:00:00")


def metadata(attribute: str, when: str) -> str:
    return (
        "<DS_REPL_ATTR_META_DATA><pszAttributeName>"
        f"{attribute}</pszAttributeName><ftimeLastOriginatingChange>{when}"
        "</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>"
    )


def seeded_groups() -> list[DirObject]:
    nested = DirObject(dn=f"CN=T0,{HEAD}", name="T0", kind="group", sid=f"{DOM}-1600")
    return [
        DirObject(
            dn=f"CN=Domain Admins,{HEAD}",
            name="Domain Admins",
            kind="group",
            sid=DA,
            members=[nested.dn],
        ),
        DirObject(
            dn=f"CN=Administrators,{HEAD}", name="Administrators", kind="group", sid="S-1-5-32-544"
        ),
        nested,
    ]


def base_routes(entries: dict[str, str | None]) -> dict[tuple[str, str], Any]:
    routes: dict[tuple[str, str], Any] = {}
    for dn, value in entries.items():
        routes[(dn, "base")] = (
            [{"distinguishedname": [dn]}]
            if value is None
            else [
                raw(
                    dn,
                    **{
                        "msDS-ReplAttributeMetaData": metadata("x", ZERO),
                        "msDS-ReplValueMetaData": value,
                    },
                )
            ]
        )
    return routes


def test_member_changes_read_nested_tier0_groups() -> None:
    xml = value_row(f"CN=mallory,{HEAD}", ZERO, "2026-10-30T12:00:00Z")
    groups = seeded_groups()
    routes = base_routes({g.dn: xml for g in groups})
    changes, checked = StubCollector(routes)._member_changes(groups, DOM)
    assert checked
    assert sorted(c.group for c in changes) == ["Administrators", "Domain Admins", "T0"]


def test_member_changes_note_an_unreadable_group() -> None:
    groups = seeded_groups()
    routes = base_routes({g.dn: "" for g in groups})
    routes[(groups[0].dn, "base")] = [{"distinguishedname": [groups[0].dn]}]  # no metadata
    c = StubCollector(routes)
    _, checked = c._member_changes(groups, DOM)
    assert checked
    assert any("AD-PRIV-015" in n and "Domain Admins" in n for n in c.notes)
    assert coverage.note_checks(c.notes[0]) == ["AD-PRIV-015"]


def test_member_changes_without_the_seed_groups_is_unknown() -> None:
    c = StubCollector({})
    assert c._member_changes([], DOM) == ([], False)
    assert any("AD-PRIV-015" in n for n in c.notes)


def test_admin_sd_holder_change_read_and_unread() -> None:
    dn = f"CN=AdminSDHolder,CN=System,{HEAD}"
    xml = metadata("nTSecurityDescriptor", "2026-10-30T12:00:00Z")
    c = StubCollector({(dn, "base"): [raw(dn, **{"msDS-ReplAttributeMetaData": xml})]})
    when, checked = c._admin_sd_holder_change(HEAD)
    assert checked and when is not None and when.day == 30
    c = StubCollector({})
    assert c._admin_sd_holder_change(HEAD) == (None, False)
    assert any("AD-ACL-010" in n for n in c.notes)


def test_sid_history_reads_are_capped_and_unread_noted() -> None:
    from ad_doctor import collect as module

    accounts = [user(f"u{i}", sid_history=[f"{DOM}-9{i}"]) for i in range(3)]
    routes = base_routes({})
    xml = metadata("sIDHistory", "2026-10-30T12:00:00Z")
    routes[(accounts[0].dn, "base")] = [raw(accounts[0].dn, **{"msDS-ReplAttributeMetaData": xml})]
    routes[(accounts[1].dn, "base")] = [{"distinguishedname": [accounts[1].dn]}]
    saved = module.MAX_SID_HISTORY_READS
    module.MAX_SID_HISTORY_READS = 2
    try:
        c = StubCollector(routes)
        changes, checked = c._sid_history_changes(accounts)
    finally:
        module.MAX_SID_HISTORY_READS = saved
    assert checked and [x.dn for x in changes] == [accounts[0].dn]
    assert any("AD-ACC-017" in n and "first 2" in n for n in c.notes)
    assert any("AD-ACC-017" in n and accounts[1].sam in n for n in c.notes)


def change_snap(**kw: Any) -> Snapshot:
    return snapshot(domain_created=NOW - timedelta(days=4000), **kw)


def added(days: int) -> MemberChange:
    return MemberChange(
        "Domain Admins", DA, f"CN=mallory,CN=Users,{HEAD}", NOW - timedelta(days=days)
    )


def test_recent_addition_fires_low_with_the_date() -> None:
    f = only(change_snap(member_changes=[added(3)], member_changes_checked=True), "AD-PRIV-015")
    assert f.severity is Severity.LOW
    assert f.objects == [f"Domain Admins: mallory added {(NOW - timedelta(days=3)):%Y-%m-%d}"]


def test_additions_outside_the_window_or_in_the_first_day_do_not_fire() -> None:
    assert "AD-PRIV-015" not in ids(
        run_all(change_snap(member_changes=[added(40)], member_changes_checked=True))
    )
    young = snapshot(
        domain_created=NOW - timedelta(days=3),
        member_changes=[added(3)],
        member_changes_checked=True,
    )
    assert "AD-PRIV-015" not in ids(run_all(young))
    assert "AD-PRIV-015" in ids(
        run_all(
            snapshot(
                domain_created=NOW - timedelta(days=5),
                member_changes=[added(3)],
                member_changes_checked=True,
            )
        )
    )


def test_unread_member_metadata_does_not_judge() -> None:
    snap = change_snap(member_changes=[added(3)])
    assert "AD-PRIV-015" not in ids(run_all(snap))
    assert coverage.compute(snap, [])["AD-PRIV-015"].status == coverage.NOT_EVALUATED


def test_admin_sd_holder_recent_fires_medium_old_does_not() -> None:
    recent = change_snap(
        admin_sd_holder_changed=NOW - timedelta(days=2), admin_sd_holder_checked=True
    )
    assert only(recent, "AD-ACL-010").severity is Severity.MEDIUM
    old = change_snap(admin_sd_holder_changed=OLD, admin_sd_holder_checked=True)
    assert "AD-ACL-010" not in ids(run_all(old))


def test_admin_sd_holder_first_day_of_the_domain_is_the_install() -> None:
    snap = snapshot(
        domain_created=NOW - timedelta(days=3),
        admin_sd_holder_changed=NOW - timedelta(days=3, hours=-1),
        admin_sd_holder_checked=True,
    )
    assert "AD-ACL-010" not in ids(run_all(snap))


def test_admin_sd_holder_unread_does_not_judge() -> None:
    snap = change_snap(admin_sd_holder_changed=NOW)
    assert "AD-ACL-010" not in ids(run_all(snap))
    assert coverage.compute(snap, [])["AD-ACL-010"].status == coverage.NOT_EVALUATED


def sid_snap(history: str, changed: Any) -> Snapshot:
    a = user("migrated", sid_history=[history])
    return change_snap_with(a, changed)


def change_snap_with(a: Account, changed: Any) -> Snapshot:
    return snapshot(
        a,
        domain_created=NOW - timedelta(days=4000),
        sid_history_changes=[SidHistoryChange(a.dn, changed)],
        sid_history_checked=True,
    )


def test_recent_sid_history_is_low_from_another_domain() -> None:
    f = only(sid_snap("S-1-5-21-9-9-9-1200", NOW - timedelta(days=2)), "AD-ACC-017")
    assert f.severity is Severity.LOW
    assert f.objects[0].startswith("migrated: sIDHistory changed")


def test_recent_sid_history_of_the_same_domain_is_medium() -> None:
    f = only(sid_snap(f"{DOM}-1200", NOW - timedelta(days=2)), "AD-ACC-017")
    assert f.severity is Severity.MEDIUM
    assert "migrated" in f.detail


def test_old_sid_history_does_not_fire() -> None:
    assert "AD-ACC-017" not in ids(run_all(sid_snap(f"{DOM}-1200", OLD)))


def test_unread_sid_history_metadata_does_not_judge() -> None:
    a = user("migrated", sid_history=[f"{DOM}-1200"])
    snap = snapshot(a, sid_history_changes=[SidHistoryChange(a.dn, NOW)])
    assert "AD-ACC-017" not in ids(run_all(snap))
    assert coverage.compute(snap, [])["AD-ACC-017"].status == coverage.NOT_EVALUATED


def test_clean_with_everything_collected_has_no_new_finding() -> None:
    snap = snapshot(
        user("alice"),
        logon_rights_collected=True,
        silos_checked=True,
        member_changes_checked=True,
        admin_sd_holder_checked=True,
        sid_history_checked=True,
    )
    assert run_all(snap) == []


# --- round trip, older snapshots and redaction -----------------------------------------------


NEW = {"AD-PRIV-013", "AD-PRIV-014", "AD-PRIV-015", "AD-ACL-010", "AD-ACC-017"}


def full_snapshot() -> Snapshot:
    a1 = admin("secretadmin")
    a2 = user("migrateduser", sid_history=[f"{DOM}-1200"])
    return snapshot(
        a1,
        a2,
        member(),
        privileged={"Domain Admins": [a1.dn]},
        objects=[domain_admins(a1)],
        gpos=[],
        logon_rights_collected=True,
        site_count=1,
        auth_silos=[silo(a1, enforced=False)],
        auth_policies=[policy()],
        silos_checked=True,
        domain_created=NOW - timedelta(days=4000),
        member_changes=[
            MemberChange(
                "Domain Admins", f"CN=Domain Admins,{HEAD}", a1.dn, NOW - timedelta(days=2)
            )
        ],
        member_changes_checked=True,
        admin_sd_holder_changed=NOW - timedelta(days=1),
        admin_sd_holder_checked=True,
        sid_history_changes=[SidHistoryChange(a2.dn, NOW - timedelta(days=2))],
        sid_history_checked=True,
    )


def test_new_fields_survive_a_json_round_trip() -> None:
    before = run_all(full_snapshot())
    assert ids(before) >= NEW
    data = json.loads(json.dumps(full_snapshot().to_json()))
    after = run_all(Snapshot.from_json(data))
    assert [(f.check_id, f.severity, f.objects) for f in after] == [
        (f.check_id, f.severity, f.objects) for f in before
    ]


def test_older_snapshot_loads_and_says_not_evaluated() -> None:
    data = full_snapshot().to_json()
    for key in (
        "logon_rights_collected",
        "auth_silos",
        "auth_policies",
        "silos_checked",
        "domain_created",
        "member_changes",
        "member_changes_checked",
        "admin_sd_holder_changed",
        "admin_sd_holder_checked",
        "sid_history_changes",
        "sid_history_checked",
    ):
        del data[key]
    snap = Snapshot.from_json(data)
    assert NEW.isdisjoint(ids(run_all(snap)))
    got = coverage.compute(snap, [])
    for check in NEW:
        assert got[check].status == coverage.NOT_EVALUATED, check
        assert got[check].reason == coverage.OLDER_SNAPSHOT, check


def test_redaction_keeps_findings_and_drops_names() -> None:
    raw_data = full_snapshot().to_json()
    raw_data["auth_silos"][0]["name"] = "PrivilegedSiloName"
    text_before = json.dumps(raw_data)
    assert "secretadmin" in text_before and "PrivilegedSiloName" in text_before
    out = redact.redact(raw_data, b"key")
    text = json.dumps(out)
    for word in ("secretadmin", "migrateduser", "PrivilegedSiloName"):
        assert word not in text, word
    before = run_all(Snapshot.from_json(raw_data))
    after = run_all(Snapshot.from_json(out))
    assert {f.check_id for f in after} == {f.check_id for f in before}
    assert {f.check_id for f in after} >= NEW
