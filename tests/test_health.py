"""Domain controller and computer health: AD-ACC-014, -015, AD-INF-018 to -021."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult

from ad_doctor import redact
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector
from ad_doctor.fixes import FIXES
from ad_doctor.model import UAC, ConflictObject, Gmsa, Severity, Site, Snapshot, Subnet
from tests.test_checks import NOW, computer, ids, only, snapshot, user

CONFIG = "CN=Configuration,DC=lab,DC=test"
SITE_A = f"CN=Hq,CN=Sites,{CONFIG}"
SITE_B = f"CN=Branch,CN=Sites,{CONFIG}"
DC_INDEX = 2  # snapshot() puts the DC after krbtgt and Guest


def round_trip(snap: Snapshot) -> Snapshot:
    return Snapshot.from_json(json.loads(json.dumps(snap.to_json())))


def old(days: int) -> Any:
    return NOW - timedelta(days=days)


# --- AD-ACC-014 ---------------------------------------------------------------------------


def test_stale_computer_is_reported_with_a_dry_run_fix() -> None:
    snap = snapshot(computer("OLD01", last_logon=old(200), pwd_last_set=old(200)))
    f = only(snap, "AD-ACC-014")
    assert f.severity is Severity.LOW and f.objects == ["OLD01$"]
    assert FIXES["AD-ACC-014"](f, snap) == ["Disable-ADAccount 'OLD01$' -WhatIf"]


def test_stale_computer_uses_the_newest_date() -> None:
    # an old logon but a recent password change is a machine that is on the network
    snap = snapshot(computer("NEW", last_logon=old(200), pwd_last_set=old(5)))
    assert "AD-ACC-014" not in ids(run_all(snap))
    # never logged on and never set a password, but created long ago
    snap = snapshot(computer("PRE", last_logon=None, pwd_last_set=None, when_created=old(400)))
    assert only(snap, "AD-ACC-014").objects == ["PRE$"]


def test_stale_computer_skips_what_it_must_not_judge() -> None:
    gone = {"last_logon": old(300), "pwd_last_set": old(300)}
    snap = snapshot(
        computer("OFF", 0x1000 | UAC.ACCOUNTDISABLE, **gone),
        computer("GMSA", managed=True, **gone),
        computer("AZUREADSSOACC", **gone),
        computer("DC02", 0x2000, **gone),
        computer("BLANK", last_logon=None),  # nothing readable: unknown, not stale
    )
    assert "AD-ACC-014" not in ids(run_all(snap))


def test_a_rogue_dc_object_is_still_a_computer_here() -> None:
    gone = computer("FAKE", 0x2000, last_logon=old(300), pwd_last_set=old(300), rogue_dc=True)
    assert only(snapshot(gone), "AD-ACC-014").objects == ["FAKE$"]


# --- AD-INF-018 ---------------------------------------------------------------------------


def dc_snapshot(days: int | None, **kw: object) -> Snapshot:
    snap = snapshot()
    dc = snap.accounts[DC_INDEX]
    dc.pwd_last_set = None if days is None else old(days)
    for key, value in kw.items():
        setattr(dc, key, value)
    return snap


def test_dc_password_grades() -> None:
    low = only(dc_snapshot(60), "AD-INF-018")
    assert low.severity is Severity.LOW and low.objects == ["DC01$"] and "DC01$ 60" in low.detail
    assert "Review" in low.detail
    assert only(dc_snapshot(200), "AD-INF-018").severity is Severity.MEDIUM


def test_dc_password_counts_the_older_of_the_two_times() -> None:
    f = only(dc_snapshot(10, pwd_changed=old(200)), "AD-INF-018")
    assert f.severity is Severity.MEDIUM


def test_dc_password_quiet_when_young_unknown_or_not_a_real_dc() -> None:
    assert "AD-INF-018" not in ids(run_all(dc_snapshot(30)))
    assert "AD-INF-018" not in ids(run_all(dc_snapshot(None)))  # unreadable: not judged
    assert "AD-INF-018" not in ids(run_all(dc_snapshot(300, rogue_dc=True)))
    assert "AD-INF-018" not in ids(run_all(dc_snapshot(300, entra_kerberos=True)))
    assert "AD-INF-018" not in ids(run_all(dc_snapshot(300, uac=0x2000 | UAC.ACCOUNTDISABLE)))


# --- AD-ACC-015 ---------------------------------------------------------------------------


def test_gmsa_long_interval() -> None:
    snap = snapshot(gmsas=[Gmsa("long$", "CN=long,DC=lab,DC=test", [], 365)])
    f = only(snap, "AD-ACC-015")
    assert f.severity is Severity.LOW and f.objects == ["long$ (365 days)"]
    assert "Review" in f.detail


def test_gmsa_interval_quiet_at_default_and_when_unread() -> None:
    fine = [Gmsa("a$", "CN=a,DC=lab,DC=test", [], 30), Gmsa("b$", "CN=b,DC=lab,DC=test", [], None)]
    assert "AD-ACC-015" not in ids(run_all(snapshot(gmsas=fine)))


# --- AD-INF-019 ---------------------------------------------------------------------------

DC_DN = "CN=DC01,CN=Computers,DC=lab,DC=test"


def sysvol(flags: int | None, frs: list[str], dfsr: list[str], checked: bool = True) -> Snapshot:
    return snapshot(
        sysvol_dfsr_flags=flags,
        sysvol_frs_dcs=frs,
        sysvol_dfsr_dcs=dfsr,
        sysvol_replication_checked=checked,
    )


def test_sysvol_fires_on_frs_and_on_unfinished_migration() -> None:
    assert only(sysvol(None, [DC_DN], []), "AD-INF-019").severity is Severity.MEDIUM
    assert only(sysvol(0, [DC_DN], []), "AD-INF-019").objects == ["DC01$"]
    assert only(sysvol(16, [DC_DN], [DC_DN]), "AD-INF-019").severity is Severity.MEDIUM
    redirected = only(sysvol(32, [], [DC_DN]), "AD-INF-019")
    assert redirected.severity is Severity.LOW and redirected.objects == ["lab.test"]
    mixed = only(sysvol(None, [DC_DN], [DC_DN]), "AD-INF-019")
    assert mixed.severity is Severity.LOW and "Review" in mixed.detail


def test_sysvol_quiet_on_dfsr_and_unknown() -> None:
    assert "AD-INF-019" not in ids(run_all(sysvol(48, [], [])))
    assert "AD-INF-019" not in ids(run_all(sysvol(48, [DC_DN], [])))  # leftover after the end
    assert "AD-INF-019" not in ids(run_all(sysvol(None, [], [DC_DN])))
    # unknown: no finding, the collector wrote a note
    assert "AD-INF-019" not in ids(run_all(sysvol(None, [DC_DN], [], checked=False)))
    # a subscription on a computer that is not a DC is not evidence about SYSVOL
    assert "AD-INF-019" not in ids(run_all(sysvol(None, ["CN=gone,DC=lab,DC=test"], [])))


# --- AD-INF-020 ---------------------------------------------------------------------------


def sites(
    all_sites: list[Site], subnets: list[Subnet] | None = None, checked: bool = True
) -> Snapshot:
    return snapshot(sites=all_sites, subnets=subnets or [], site_topology_checked=checked)


def test_sites_report_each_problem() -> None:
    snap = sites(
        [Site(SITE_A, 1, True), Site(SITE_B, 0, True), Site(f"CN=Far,CN=Sites,{CONFIG}", 1, False)],
        [Subnet("10.0.0.0/24", SITE_A), Subnet("10.1.0.0/24", "")],
    )
    f = only(snap, "AD-INF-020")
    assert f.severity is Severity.LOW and "Review" in f.detail
    assert f.objects == [
        "site Branch: no domain controller, no subnet",
        "site Far: no subnet, in no site link",
        "subnet 10.1.0.0/24: maps to no site",
    ]


def test_sites_quiet_on_a_default_domain_and_when_unknown() -> None:
    # one site, no subnets: the state of a new forest, and fine by Microsoft's guidance
    assert "AD-INF-020" not in ids(run_all(sites([Site(SITE_A, 1, True)])))
    assert "AD-INF-020" not in ids(
        run_all(sites([Site(SITE_B, 0, True)], [Subnet("10.1.0.0/24", "")], checked=False))
    )
    # no server seen anywhere proves nothing about any site
    assert "AD-INF-020" not in ids(run_all(sites([Site(SITE_A, 0, True)])))
    # the links were not read: "in no site link" cannot be said
    assert "AD-INF-020" not in ids(
        run_all(
            sites(
                [Site(SITE_A, 1, None), Site(SITE_B, 1, None)],
                [Subnet("10.0.0.0/24", SITE_A), Subnet("10.1.0.0/24", SITE_B)],
            )
        )
    )


# --- AD-INF-021 ---------------------------------------------------------------------------

CNF_DN = r"CN=bob\0ACNF:c93dad3e-4178-48aa-94c6-16237ba5aeaa,OU=West,DC=lab,DC=test"


def test_conflict_objects_are_listed() -> None:
    snap = snapshot(
        conflicts=[
            ConflictObject(CNF_DN, "cnf"),
            ConflictObject("CN=dup,OU=West,DC=lab,DC=test", "duplicate-sam"),
        ],
        conflicts_checked=True,
    )
    f = only(snap, "AD-INF-021")
    assert f.severity is Severity.LOW
    assert len(f.objects) == 2 and any("(cnf)" in o for o in f.objects)


def test_duplicate_accounts_are_found_in_the_snapshot() -> None:
    same_sid = f"{snapshot().domain_sid}-1105"
    a = user("one", sid=same_sid)
    b = user("two", sid=same_sid)
    f = only(snapshot(a, b), "AD-INF-021")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [f"SID {same_sid}: one, two"]
    c = user("Three")
    d = user("three")
    d.dn = "CN=three,OU=Other,DC=lab,DC=test"
    same_name = only(snapshot(c, d), "AD-INF-021")
    assert same_name.severity is Severity.LOW and same_name.objects[0].startswith("sAMAccountName")


def test_conflicts_quiet_when_none() -> None:
    assert "AD-INF-021" not in ids(run_all(snapshot(conflicts_checked=True)))
    assert "AD-INF-021" not in ids(run_all(snapshot(user("a", sid=""), user("b", sid=""))))


# --- the default domain stays clean ---------------------------------------------------------


def test_every_new_field_can_be_empty() -> None:
    snap = snapshot(
        user("alice"),
        computer("WS01"),
        sites=[Site(SITE_A, 1, True)],
        site_topology_checked=True,
        sysvol_dfsr_flags=48,
        sysvol_replication_checked=True,
        conflicts_checked=True,
    )
    assert run_all(snap) == []


# --- collection -----------------------------------------------------------------------------


class Stub(Collector):
    """A collector whose searches come from a table; refused ones raise."""

    def __init__(self, routes: dict[tuple[str, str], list[dict[str, Any]]]) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.routes = routes
        self.refused: set[tuple[str, str]] = set()

    def search(
        self,
        base: str,
        flt: str,
        attrs: list[str],
        scope: str = ldap3.SUBTREE,
        controls: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        if (base, flt) in self.refused:
            raise LDAPInsufficientAccessRightsResult()
        return self.routes.get((base, flt), [])


def ent(dn: str, **attrs: list[Any]) -> dict[str, Any]:
    return {"distinguishedname": [dn], **{k.lower(): v for k, v in attrs.items()}}


OC = {"objectClass": [b"top"]}
SERVER = f"CN=DC1,CN=Servers,{SITE_A}"
BASE = f"CN=Sites,{CONFIG}"


def topology_routes() -> dict[tuple[str, str], list[dict[str, Any]]]:
    return {
        (BASE, "(objectClass=site)"): [ent(SITE_A, **OC), ent(SITE_B, **OC)],
        (BASE, "(objectClass=server)"): [ent(SERVER, **OC)],
        (f"CN=Subnets,{BASE}", "(objectClass=subnet)"): [
            ent(f"CN=10.0.0.0/24,CN=Subnets,{BASE}", siteObject=[SITE_A.encode()], **OC),
            ent(f"CN=10.1.0.0/24,CN=Subnets,{BASE}", **OC),
        ],
        (f"CN=Inter-Site Transports,{BASE}", "(objectClass=siteLink)"): [
            ent(f"CN=L,{BASE}", siteList=[SITE_A.encode()], **OC)
        ],
    }


def test_site_topology_is_read() -> None:
    got, nets, checked = Stub(topology_routes())._site_topology(CONFIG)
    assert checked
    assert got == [Site(SITE_A, 1, True), Site(SITE_B, 0, False)]
    assert nets == [Subnet("10.0.0.0/24", SITE_A), Subnet("10.1.0.0/24", "")]


def test_site_topology_unreadable_parts_say_so() -> None:
    routes = topology_routes()
    routes[(f"CN=Subnets,{BASE}", "(objectClass=subnet)")][1] = ent(
        f"CN=10.1.0.0/24,CN=Subnets,{BASE}"
    )
    c = Stub(routes)
    assert c._site_topology(CONFIG) == ([], [], False)
    assert any("AD-INF-020" in n for n in c.notes)
    # a site link we cannot read: sites are read, "linked" stays unknown
    routes = topology_routes()
    routes[(f"CN=Inter-Site Transports,{BASE}", "(objectClass=siteLink)")] = [ent(f"CN=L,{BASE}")]
    c = Stub(routes)
    got, _, checked = c._site_topology(CONFIG)
    assert checked and [s.linked for s in got] == [None, None]
    assert any("site links not readable" in n for n in c.notes)
    # refused search
    routes = topology_routes()
    c = Stub(routes)
    c.refused.add((BASE, "(objectClass=server)"))
    assert c._site_topology(CONFIG) == ([], [], False)
    # no site at all readable
    c = Stub({})
    assert c._site_topology(CONFIG) == ([], [], False)


DOMAIN = "DC=lab,DC=test"
DC = f"CN=DC1,OU=Domain Controllers,{DOMAIN}"
FRS_DN = f"CN=Domain System Volume (SYSVOL share),CN=NTFRS Subscriptions,{DC}"
DFSR_DN = f"CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,{DC}"
GLOBAL = (f"CN=DFSR-GlobalSettings,CN=System,{DOMAIN}", "(objectClass=*)")
SUBS = (DOMAIN, "(|(objectClass=nTFRSSubscriber)(objectClass=msDFSR-Subscription))")


def test_sysvol_state_is_read() -> None:
    routes = {GLOBAL: [ent(GLOBAL[0], **{"msDFSR-Flags": [b"48"]})], SUBS: [ent(DFSR_DN, **OC)]}
    assert Stub(routes)._sysvol_replication(DOMAIN) == (48, [], [DC], True)
    routes = {SUBS: [ent(FRS_DN, **OC)]}
    assert Stub(routes)._sysvol_replication(DOMAIN) == (None, [DC], [], True)


def test_sysvol_state_unknown_says_so() -> None:
    # flags 0 with no subscription visible proves nothing
    routes = {GLOBAL: [ent(GLOBAL[0], **{"msDFSR-Flags": [b"0"]})]}
    c = Stub(routes)
    assert c._sysvol_replication(DOMAIN) == (0, [], [], False)
    assert any("AD-INF-019 not judged" in n for n in c.notes)
    c = Stub({})
    c.refused.update({GLOBAL, SUBS})
    assert c._sysvol_replication(DOMAIN) == (None, [], [], False)


def test_conflicts_need_the_line_feed() -> None:
    cnf = (DOMAIN, "(name=*CNF:*)")
    routes = {
        cnf: [
            ent(CNF_DN, name=[b"bob\nCNF:c93dad3e-4178-48aa-94c6-16237ba5aeaa"]),
            ent(f"CN=CNF: review,{DOMAIN}", name=[b"CNF: review"]),
        ],
        (DOMAIN, "(sAMAccountName=$DUPLICATE-*)"): [
            ent(f"CN=dup,{DOMAIN}", sAMAccountName=[b"$DUPLICATE-1f4"])
        ],
    }
    found, checked = Stub(routes)._conflicts(DOMAIN, CONFIG)
    assert checked
    assert found == [
        ConflictObject(CNF_DN, "cnf"),
        ConflictObject(f"CN=dup,{DOMAIN}", "duplicate-sam"),
    ]


def test_conflicts_refused_are_not_clean() -> None:
    c = Stub({})
    c.refused.add((CONFIG, "(name=*CNF:*)"))
    found, checked = c._conflicts(DOMAIN, CONFIG)
    assert not checked and not found
    assert any("AD-INF-021" in n for n in c.notes)


def test_unread_gmsa_interval_says_so() -> None:
    gmsa = (DOMAIN, "(objectClass=msDS-GroupManagedServiceAccount)")
    routes = {gmsa: [ent(f"CN=g,{DOMAIN}", sAMAccountName=[b"g$"])]}
    c = Stub(routes)
    assert c._gmsas(DOMAIN)[0].interval_days is None
    assert any("AD-ACC-015" in n for n in c.notes)
    routes = {
        gmsa: [
            ent(
                f"CN=g,{DOMAIN}",
                sAMAccountName=[b"g$"],
                **{"msDS-ManagedPasswordInterval": [b"60"]},
            )
        ]
    }
    assert Stub(routes)._gmsas(DOMAIN)[0].interval_days == 60


# --- snapshots ------------------------------------------------------------------------------

DIRTY = {
    "gmsas": [Gmsa("svc$", "CN=svc,OU=Tier1,DC=lab,DC=test", [], 365)],
    "sites": [Site(SITE_A, 1, True), Site(SITE_B, 0, True)],
    "subnets": [Subnet("10.1.2.0/24", ""), Subnet("10.9.9.0/24", SITE_A)],
    "site_topology_checked": True,
    "sysvol_dfsr_flags": None,
    "sysvol_frs_dcs": [DC_DN],
    "sysvol_replication_checked": True,
    "conflicts": [ConflictObject(CNF_DN.replace("bob", "secretname"), "cnf")],
    "conflicts_checked": True,
}


def test_new_fields_survive_a_round_trip_and_stay_found() -> None:
    snap = snapshot(**DIRTY)
    assert round_trip(snap) == snap


def test_redaction_keeps_findings_and_hides_names() -> None:
    snap = snapshot(**DIRTY)
    data = json.loads(json.dumps(snap.to_json()))
    out = redact.redact(data, b"k")
    text = json.dumps(out)
    for secret in ("Branch", "Hq", "secretname", "West", "10.1.2", "10.9.9"):
        assert secret not in text, secret
    assert len({s["name"] for s in out["subnets"]}) == 2
    back = Snapshot.from_json(out)
    for check_id in ("AD-ACC-015", "AD-INF-019", "AD-INF-020", "AD-INF-021"):
        assert check_id in ids(run_all(back)), check_id
    assert only(back, "AD-INF-020").objects.__len__() == only(snap, "AD-INF-020").objects.__len__()


def test_older_snapshot_loads_and_says_what_was_not_evaluated() -> None:
    data = json.loads(json.dumps(snapshot(**DIRTY).to_json()))
    for key in ("sites", "subnets", "site_topology_checked", "sysvol_dfsr_flags"):
        del data[key]
    for key in ("sysvol_frs_dcs", "sysvol_dfsr_dcs", "sysvol_replication_checked", "conflicts"):
        del data[key]
    del data["conflicts_checked"]
    for g in data["gmsas"]:
        del g["interval_days"]
    snap = Snapshot.from_json(data)
    text = " ".join(snap.notes)
    for check_id in ("AD-INF-019", "AD-INF-020", "AD-INF-021", "AD-ACC-015"):
        assert check_id in text, check_id
    assert not {"AD-ACC-015", "AD-INF-019", "AD-INF-020"} & ids(run_all(snap))
