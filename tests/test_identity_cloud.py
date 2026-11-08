"""Identity collisions, password policy settings, dMSA control and Entra Kerberos:
AD-ACC-016, AD-POL-003, AD-ACL-009, AD-KRB-007."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from ad_doctor import redact, sd
from ad_doctor.checks import run_all
from ad_doctor.collect import is_entra_kerberos
from ad_doctor.model import (
    UAC,
    DirObject,
    Dmsa,
    Pso,
    Severity,
    Snapshot,
    dns_host_matches,
    invisible_chars,
)
from ad_doctor.sd import Ace
from tests.test_checks import NOW, computer, ids, only, snapshot, user
from tests.test_health import Stub, ent

DOM = "DC=lab,DC=test"
SID = "S-1-5-21-1-2-3"
HELPDESK = f"{SID}-1105"
PSO_BASE = f"CN=Password Settings Container,CN=System,{DOM}"
PSO_KEY = (PSO_BASE, "(objectClass=msDS-PasswordSettings)")
DMSA_KEY = (DOM, "(objectClass=msDS-DelegatedManagedServiceAccount)")


def round_trip(snap: Snapshot) -> Snapshot:
    return Snapshot.from_json(json.loads(json.dumps(snap.to_json())))


def old(days: int) -> Any:
    return NOW - timedelta(days=days)


# --- AD-ACC-016 ---------------------------------------------------------------------------


def identity(*accounts: Any, **kw: Any) -> Snapshot:
    return snapshot(*accounts, upn_checked=True, **kw)


def test_bare_upn_equal_to_another_sam_is_reviewed() -> None:
    f = only(identity(user("attacker", upn="DomainAdmin1"), user("domainadmin1")), "AD-ACC-016")
    assert f.severity is Severity.LOW and "Review" in f.detail
    assert f.objects == ["attacker: UPN DomainAdmin1 is the sAMAccountName of domainadmin1"]


def test_ordinary_upns_stay_quiet() -> None:
    snap = identity(
        user("alice", upn="alice@lab.test"),  # its own name
        user("bob", upn="alice2@lab.test"),
        user("carol", upn="carol"),  # bare, but the account's own name
    )
    assert "AD-ACC-016" not in ids(run_all(snap))


def test_upn_with_a_suffix_is_not_compared_by_its_first_part() -> None:
    assert "AD-ACC-016" not in ids(
        run_all(identity(user("a", upn="target@lab.test"), user("target")))
    )


def test_upn_not_collected_is_not_judged() -> None:
    snap = snapshot(user("a", upn="target"), user("target"))  # upn_checked False
    assert "AD-ACC-016" not in ids(run_all(snap))


def test_invisible_unicode_in_an_spn_is_shown_escaped() -> None:
    f = only(identity(user("svc", spns=["cifs/SERVERB​"])), "AD-ACC-016")
    assert f.objects == ["svc: SPN cifs/SERVERB<U+200B>"]


def test_visible_spns_stay_quiet() -> None:
    snap = identity(user("svc", spns=["HTTP/web01.lab.test", "MSSQLSvc/süd.lab.test:1433"]))
    assert "AD-ACC-016" not in ids(run_all(snap))


def test_invisible_chars() -> None:
    assert invisible_chars("cifs/host") == ""
    assert invisible_chars("a b") == ""  # a plain space is visible
    assert invisible_chars("a bㅤc️") == " ㅤ️"
    assert invisible_chars("ümlaut") == ""
    assert invisible_chars("x\ty") == "\t"


def test_dns_host_name_of_another_computer_is_named() -> None:
    f = only(identity(computer("PC01", dns_host="dc01.lab.test")), "AD-ACC-016")
    assert f.severity is Severity.LOW
    assert f.objects == ["PC01$: dNSHostName dc01.lab.test (the name of DC01$)"]


def test_dns_host_mismatch_without_an_owner() -> None:
    f = only(identity(computer("PC01", dns_host="old-name.lab.test")), "AD-ACC-016")
    assert f.objects == ["PC01$: dNSHostName old-name.lab.test"]


def test_dns_host_matches_rules() -> None:
    assert dns_host_matches("pc01.lab.test", "PC01$")
    assert dns_host_matches("PC01", "pc01$")
    assert not dns_host_matches("pc02.lab.test", "PC01$")
    # sAMAccountName keeps 15 characters, the DNS name keeps them all
    assert dns_host_matches("averylongcomputername.lab.test", "AVERYLONGCOMPUT$")
    assert not dns_host_matches("averylong.lab.test", "AVERYLONG2$")


def test_dns_host_skips_what_it_must_not_judge() -> None:
    snap = identity(
        computer("OFF", 0x1000 | UAC.ACCOUNTDISABLE, dns_host="other.lab.test"),
        computer("GMSA", managed=True, dns_host="other.lab.test"),
        computer("ENTRA", 0x4001000, entra_kerberos=True, dns_host="other.lab.test"),
        computer("NODNS"),  # no value: unknown, not a mismatch
        computer("GOOD", dns_host="good.lab.test"),
    )
    assert "AD-ACC-016" not in ids(run_all(snap))


def test_identity_redaction_keeps_findings_and_hides_names() -> None:
    snap = identity(
        user("attacker", upn="domainadmin1"),
        user("domainadmin1", upn="domainadmin1@corp.example"),
        user("svc", spns=["cifs/secrethost​.lab.test"]),
        computer("PC01", dns_host="dc01.lab.test"),
        computer("GOOD01", dns_host="good01.lab.test"),
        computer("AVERYLONGCOMPUT", dns_host="averylongcomputername.lab.test"),
    )
    out = redact.redact(json.loads(json.dumps(snap.to_json())), b"k")
    text = json.dumps(out)
    for secret in ("attacker", "domainadmin1", "corp.example", "secrethost", "GOOD01", "good01"):
        assert secret.lower() not in text.lower(), secret
    back = Snapshot.from_json(out)
    f = only(back, "AD-ACC-016")
    # the same three findings: the two good computers must not become mismatches
    assert len(f.objects) == 3
    assert sum("UPN" in o for o in f.objects) == 1
    assert sum("<U+200B>" in o for o in f.objects) == 1
    assert sum("dNSHostName" in o for o in f.objects) == 1


# --- AD-POL-003 ---------------------------------------------------------------------------

ADMIN_DN = f"CN=admin1,CN=Users,{DOM}"
ADMINS_DN = f"CN=Tier0,OU=Groups,{DOM}"
NESTED_DN = f"CN=Nested,OU=Groups,{DOM}"


def pso(name: str = "Admins", precedence: int = 1, **kw: Any) -> Pso:
    settings: dict[str, Any] = {
        "min_length": 14,
        "complexity": True,
        "lockout_threshold": 5,
        "reversible": False,
        "applies_to": [ADMINS_DN],
    }
    settings.update(kw)
    return Pso(name=name, dn=f"CN={name},{PSO_BASE}", precedence=precedence, **settings)


def group(dn: str, members: list[str], sid: str = "") -> DirObject:
    return DirObject(dn=dn, name=dn.split(",")[0][3:], kind="group", sid=sid, members=members)


def admin_snapshot(*psos: Pso, members: list[str] | None = None, **kw: Any) -> Snapshot:
    groups = [group(ADMINS_DN, [ADMIN_DN] if members is None else members)]
    groups.append(group(NESTED_DN, [ADMINS_DN]))
    return snapshot(
        _admin(),
        privileged={"Domain Admins": [ADMIN_DN]},
        psos=list(psos),
        psos_visible=bool(psos),
        psos_checked=True,
        objects=groups,
        **kw,
    )


def _admin(**kw: Any) -> Any:
    a = user("admin1", **kw)
    assert a.dn == ADMIN_DN
    return a


def test_weak_pso_in_force_for_an_admin_is_medium() -> None:
    f = only(admin_snapshot(pso(min_length=8)), "AD-POL-003")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["Admins: minimum length 8; in force for admin1"]
    assert f.key(f.objects[0]) == "Admins"


def test_every_weakness_is_named() -> None:
    f = only(
        admin_snapshot(pso(min_length=6, complexity=False, lockout_threshold=0, reversible=True)),
        "AD-POL-003",
    )
    for word in ("minimum length 6", "complexity off", "no lockout", "reversible"):
        assert word in f.objects[0], word


def test_strong_pso_stays_quiet() -> None:
    assert "AD-POL-003" not in ids(run_all(admin_snapshot(pso())))


def test_weak_pso_for_ordinary_users_is_a_low_review() -> None:
    weak = pso("Users", min_length=8, applies_to=[f"CN=Staff,OU=Groups,{DOM}"])
    f = only(admin_snapshot(weak), "AD-POL-003")
    assert f.severity is Severity.LOW and "Review" in f.detail
    assert f.objects == ["Users: minimum length 8"]


def test_lower_precedence_wins_for_an_admin() -> None:
    strong = pso("Strong", precedence=1)
    weak = pso("Weak", precedence=5, min_length=8)
    f = only(admin_snapshot(strong, weak), "AD-POL-003")
    assert f.severity is Severity.LOW
    assert f.objects == ["Weak: minimum length 8"]


def test_direct_link_beats_a_group_link() -> None:
    direct = pso("Direct", precedence=9, applies_to=[ADMIN_DN])
    group_link = pso("Group", precedence=1, min_length=8)
    f = only(admin_snapshot(direct, group_link), "AD-POL-003")
    assert f.severity is Severity.LOW  # the weak group policy is not the one in force


def test_nested_and_primary_groups_count() -> None:
    nested = pso("N", applies_to=[NESTED_DN], min_length=8)
    assert only(admin_snapshot(nested), "AD-POL-003").severity is Severity.MEDIUM
    # member of nothing, but the primary group carries the link
    primary = group(f"CN=Prim,OU=Groups,{DOM}", [], sid=f"{SID}-1200")
    snap = snapshot(
        _admin(primary_group=1200),
        privileged={"Domain Admins": [ADMIN_DN]},
        psos=[pso("P", applies_to=[primary.dn], min_length=8)],
        psos_checked=True,
        objects=[primary],
    )
    assert only(snap, "AD-POL-003").severity is Severity.MEDIUM


def test_tie_needs_every_tied_policy_to_be_weak() -> None:
    weak = pso("Weak", min_length=8)
    strong = pso("Strong")  # the same precedence: Windows breaks this by GUID
    f = only(admin_snapshot(weak, strong), "AD-POL-003")
    assert f.severity is Severity.LOW
    both = pso("Weak2", min_length=9)
    assert only(admin_snapshot(weak, both), "AD-POL-003").severity is Severity.MEDIUM


def test_pso_with_no_effect_is_not_reported() -> None:
    assert "AD-POL-003" not in ids(run_all(admin_snapshot(pso(min_length=8, applies_to=[]))))
    weak = pso(min_length=8, not_global=[ADMINS_DN])  # linked to a domain-local group
    assert "AD-POL-003" not in ids(run_all(admin_snapshot(weak)))


def test_unreadable_pso_lowers_the_finding() -> None:
    f = only(admin_snapshot(pso(min_length=8), psos_unreadable=1), "AD-POL-003")
    assert f.severity is Severity.LOW and "could not be read" in f.detail


def test_no_pso_readable_is_silent_with_a_note() -> None:
    c = Stub({})
    assert c._psos(DOM) == ([], 0, False)
    assert any("AD-POL-003" in n and "fine-grained" in n for n in c.notes)
    assert "AD-POL-003" not in ids(run_all(admin_snapshot()))


def test_psos_are_read_with_group_types() -> None:
    routes = {
        PSO_KEY: [
            ent(
                f"CN=A,{PSO_BASE}",
                name=[b"A"],
                **{
                    "msDS-PasswordSettingsPrecedence": [b"3"],
                    "msDS-MinimumPasswordLength": [b"8"],
                    "msDS-PasswordComplexityEnabled": [b"FALSE"],
                    "msDS-LockoutThreshold": [b"0"],
                    "msDS-PasswordReversibleEncryptionEnabled": [b"TRUE"],
                    "msDS-PSOAppliesTo": [ADMINS_DN.encode(), NESTED_DN.encode()],
                },
            ),
            # came back without its settings
            ent(f"CN=B,{PSO_BASE}", name=[b"B"]),
        ],
        (ADMINS_DN, "(objectClass=group)"): [ent(ADMINS_DN, groupType=[b"-2147483646"])],
        (NESTED_DN, "(objectClass=group)"): [ent(NESTED_DN, groupType=[b"-2147483644"])],
    }
    c = Stub(routes)
    psos, unread, visible = c._psos(DOM)
    assert visible and unread == 1
    assert psos == [
        Pso(
            name="A",
            dn=f"CN=A,{PSO_BASE}",
            precedence=3,
            min_length=8,
            complexity=False,
            lockout_threshold=0,
            reversible=True,
            applies_to=[ADMINS_DN, NESTED_DN],
            not_global=[NESTED_DN],
        )
    ]
    assert any("without their settings" in n for n in c.notes)


# --- AD-ACL-009 ---------------------------------------------------------------------------

SVC_DN = f"CN=svc_old,CN=Users,{DOM}"
DMSA_DN = f"CN=dmsa1,CN=Managed Service Accounts,{DOM}"
CONTROL = Ace(HELPDESK, sd.GENERIC_ALL)


def dmsa(**kw: Any) -> Dmsa:
    values: dict[str, Any] = {
        "preceded_by": SVC_DN,
        "state": 2,
        "owner": f"{SID}-512",
        "aces": [CONTROL],
        "acl_read": True,
    }
    values.update(kw)
    return Dmsa(name="dmsa1$", dn=DMSA_DN, **values)


def dmsa_snapshot(*items: Dmsa, privileged: bool = True, **kw: Any) -> Snapshot:
    return snapshot(
        user("svc_old"),
        privileged={"Domain Admins": [SVC_DN] if privileged else []},
        dmsas=list(items),
        dmsas_checked=True,
        principals={HELPDESK: "helpdesk"},
        **kw,
    )


def test_control_over_a_dmsa_that_replaced_tier0_is_medium() -> None:
    f = only(dmsa_snapshot(dmsa()), "AD-ACL-009")
    assert f.severity is Severity.MEDIUM and "Review" in f.detail
    assert f.objects == ["dmsa1$: replaces svc_old; held by helpdesk (control)"]


def test_owner_and_attribute_writers_count() -> None:
    aces = [Ace(HELPDESK, sd.WRITE_PROPERTY, sd.GROUP_MSA_MEMBERSHIP)]
    f = only(dmsa_snapshot(dmsa(aces=aces)), "AD-ACL-009")
    assert "helpdesk (writes its links)" in f.objects[0]
    f = only(dmsa_snapshot(dmsa(aces=[], owner=HELPDESK)), "AD-ACL-009")
    assert "helpdesk (owner)" in f.objects[0]
    aces = [Ace(HELPDESK, sd.WRITE_PROPERTY, sd.MANAGED_ACCOUNT_PRECEDED_BY)]
    assert "writes its links" in only(dmsa_snapshot(dmsa(aces=aces)), "AD-ACL-009").objects[0]


def test_uncertain_cases_are_low_reviews() -> None:
    assert only(dmsa_snapshot(dmsa(state=1)), "AD-ACL-009").severity is Severity.LOW
    f = only(dmsa_snapshot(dmsa(), privileged=False), "AD-ACL-009")
    assert f.severity is Severity.LOW and "Review" in f.detail


def test_tier0_and_standalone_dmsas_stay_quiet() -> None:
    assert "AD-ACL-009" not in ids(run_all(dmsa_snapshot(dmsa(aces=[]))))
    tier0 = dmsa(aces=[Ace(f"{SID}-512", sd.GENERIC_ALL)])
    assert "AD-ACL-009" not in ids(run_all(dmsa_snapshot(tier0)))
    standalone = dmsa(preceded_by=None, state=3)
    assert "AD-ACL-009" not in ids(run_all(dmsa_snapshot(standalone)))


def test_service_hosts_may_be_listed_as_users() -> None:
    host = computer("APP01", sid=f"{SID}-2000")
    snap = snapshot(
        host,
        user("svc_old"),
        privileged={"Domain Admins": [SVC_DN]},
        dmsas=[dmsa(aces=[], readers=[f"{SID}-2000"])],
        dmsas_checked=True,
    )
    assert "AD-ACL-009" not in ids(run_all(snap))
    f = only(dmsa_snapshot(dmsa(aces=[], readers=[HELPDESK])), "AD-ACL-009")
    # listed as a user of the account, which a group of hosts also is: a review
    assert "allowed to use it" in f.objects[0] and f.severity is Severity.LOW


def test_a_migrating_account_keeps_its_rights_on_the_dmsa() -> None:
    svc_sid = f"{SID}-1500"
    svc = user("svc_old", sid=svc_sid)
    in_progress = dmsa(
        state=1, aces=[Ace(svc_sid, sd.WRITE_PROPERTY, sd.GROUP_MSA_MEMBERSHIP)], readers=[svc_sid]
    )
    snap = snapshot(svc, dmsas=[in_progress], dmsas_checked=True)
    assert "AD-ACL-009" not in ids(run_all(snap))
    # after the migration the same right is not by design
    done = dmsa(state=2, aces=[Ace(svc_sid, sd.WRITE_PROPERTY, sd.GROUP_MSA_MEMBERSHIP)])
    assert only(snapshot(svc, dmsas=[done], dmsas_checked=True), "AD-ACL-009")


def test_hidden_dmsa_is_reported_as_unknown_at_low() -> None:
    old_account = user("svc_old", superseded_by=DMSA_DN)
    snap = snapshot(old_account, privileged={"Domain Admins": [SVC_DN]}, dmsas_checked=True)
    f = only(snap, "AD-ACL-009")
    assert f.severity is Severity.LOW
    assert f.objects == [
        "svc_old: replaced by dmsa1; dMSA not readable, who controls it is unknown"
    ]
    # seen from both sides: judged by its ACL, not repeated as unknown
    snap = snapshot(
        old_account,
        privileged={"Domain Admins": [SVC_DN]},
        dmsas=[dmsa(aces=[])],
        dmsas_checked=True,
    )
    assert "AD-ACL-009" not in ids(run_all(snap))


def test_dmsa_without_a_descriptor_is_not_judged() -> None:
    assert "AD-ACL-009" not in ids(run_all(dmsa_snapshot(dmsa(acl_read=False))))
    routes = {DMSA_KEY: [ent(DMSA_DN, sAMAccountName=[b"dmsa1$"])]}
    c = Stub(routes)
    c.dmsa_seen = True
    found, checked = c._dmsas(DOM)
    assert checked and not found[0].acl_read
    assert any("AD-ACL-009 not judged" in n for n in c.notes)


def test_dmsa_search_refused_is_not_clean() -> None:
    c = Stub({})
    c.dmsa_seen = True
    c.refused.add(DMSA_KEY)
    assert c._dmsas(DOM) == ([], False)
    assert any("AD-ACL-009" in n for n in c.notes)


def test_no_dmsa_seen_skips_the_search() -> None:
    c = Stub({})
    c.dmsa_seen = False
    assert c._dmsas(DOM) == ([], True)


# --- AD-KRB-007 ---------------------------------------------------------------------------

ENTRA_DN = f"CN=AzureADKerberos,OU=Domain Controllers,{DOM}"
KEY_DN = f"CN=krbtgt_AzureAD,CN=Users,{DOM}"


def entra(days: int = 10, sam: str = "krbtgt_AzureAD") -> tuple[Any, Any]:
    key = user(sam, pwd_last_set=old(days))
    key.dn = KEY_DN
    obj = computer("AzureADKerberos", 0x4001000, entra_kerberos=True, krbtgt_link=KEY_DN)
    obj.dn = ENTRA_DN
    return obj, key


def krb(*accounts: Any) -> Snapshot:
    return snapshot(*accounts, krbtgt_links_checked=True)


def test_old_entra_key_is_a_low_review() -> None:
    f = only(krb(*entra(days=400)), "AD-KRB-007")
    assert f.severity is Severity.LOW and "Review" in f.detail
    assert f.objects == ["krbtgt_AzureAD: key of the Entra Kerberos object AzureADKerberos$"]
    assert "krbtgt_AzureAD 400" in f.detail


def test_recent_key_stays_quiet() -> None:
    assert "AD-KRB-007" not in ids(run_all(krb(*entra(days=30))))


def test_key_with_no_readable_date_is_not_judged() -> None:
    obj, key = entra()
    key.pwd_last_set = None
    assert "AD-KRB-007" not in ids(run_all(krb(obj, key)))


def test_only_the_structure_counts_as_the_object() -> None:
    assert is_entra_kerberos(ENTRA_DN, 0x4001000, KEY_DN)
    assert not is_entra_kerberos(f"CN=AzureADKerberos,OU=Lab,{DOM}", 0x4001000, KEY_DN)
    assert not is_entra_kerberos(ENTRA_DN, 0x1000, KEY_DN)
    assert not is_entra_kerberos(ENTRA_DN, 0x4001000, "")
    f = only(krb(computer("AzureADKerberos")), "AD-KRB-007")
    assert f.objects == [
        "AzureADKerberos$: named like the Entra Kerberos object, not built like it"
    ]


def test_a_name_alone_gives_no_key_age() -> None:
    orphan = user("krbtgt_AzureAD", pwd_last_set=old(900))
    f = only(krb(orphan), "AD-KRB-007")
    assert f.objects == ["krbtgt_AzureAD: named like its key account, linked from no such object"]
    assert "900" not in f.detail


def test_older_snapshot_is_not_judged() -> None:
    snap = snapshot(computer("AzureADKerberos"))  # krbtgt_links_checked False
    assert "AD-KRB-007" not in ids(run_all(snap))


def test_entra_notes_say_when_the_key_is_unknown() -> None:
    from ad_doctor.collect import _entra_kerberos_notes

    obj, key = entra()
    key.pwd_last_set = None
    assert any("AD-KRB-007" in n for n in _entra_kerberos_notes([obj, key]))
    assert any("AD-KRB-007" in n for n in _entra_kerberos_notes([obj]))
    assert _entra_kerberos_notes([*entra()]) == []


def test_entra_redaction_keeps_the_fixed_names_and_the_finding() -> None:
    obj, key = entra(days=400)
    snap = krb(obj, key, computer("secretpc", dns_host="secretpc.lab.test"))
    out = redact.redact(json.loads(json.dumps(snap.to_json())), b"k")
    assert "secretpc" not in json.dumps(out)
    back = Snapshot.from_json(out)
    assert only(back, "AD-KRB-007").objects == [
        "krbtgt_AzureAD: key of the Entra Kerberos object AzureADKerberos$"
    ]


# --- snapshots ------------------------------------------------------------------------------


def dirty() -> Snapshot:
    return admin_snapshot(pso(min_length=8), dmsas=[dmsa()], dmsas_checked=True, upn_checked=True)


def test_new_fields_survive_a_round_trip() -> None:
    snap = dirty()
    assert round_trip(snap) == snap


def test_pso_and_dmsa_redaction_keeps_findings_and_hides_names() -> None:
    snap = replace_names(dirty())
    out = redact.redact(json.loads(json.dumps(snap.to_json())), b"k")
    text = json.dumps(out)
    for secret in ("PrivilegedPso", "Tier0Secret", "dmsa_secret", SID):
        assert secret not in text, secret
    back = Snapshot.from_json(out)
    for check_id in ("AD-POL-003", "AD-ACL-009"):
        assert only(back, check_id).severity is only(snap, check_id).severity, check_id


def replace_names(snap: Snapshot) -> Snapshot:
    data = json.dumps(snap.to_json()).replace("Admins", "PrivilegedPso")
    return Snapshot.from_json(
        json.loads(data.replace("Tier0", "Tier0Secret").replace("dmsa1", "dmsa_secret"))
    )


def test_older_snapshot_loads_and_says_what_was_not_evaluated() -> None:
    data = json.loads(json.dumps(dirty().to_json()))
    for key in ("psos", "psos_unreadable", "psos_checked", "dmsas", "dmsas_checked"):
        del data[key]
    del data["upn_checked"]
    del data["krbtgt_links_checked"]
    for a in data["accounts"]:
        for key in ("upn", "krbtgt_link", "superseded_by"):
            del a[key]
    snap = Snapshot.from_json(data)
    text = " ".join(snap.notes)
    for check_id in ("AD-ACC-016", "AD-POL-003", "AD-ACL-009", "AD-KRB-007"):
        assert check_id in text, check_id
    assert not {"AD-POL-003", "AD-ACL-009", "AD-KRB-007"} & ids(run_all(snap))


def test_account_attributes_are_read() -> None:
    routes: dict[tuple[str, str], list[dict[str, Any]]] = {}
    c = Stub(routes)
    e = ent(
        f"CN=a,{DOM}",
        sAMAccountName=[b"a"],
        userAccountControl=[b"512"],
        objectClass=[b"user"],
        userPrincipalName=[b"a@lab.test"],
        **{
            "msDS-KrbTgtLink": [KEY_DN.encode()],
            "msDS-ManagedAccountPrecededByLinkBL": [DMSA_DN.encode()],
        },
    )
    a = c._account(e)
    assert a.upn == "a@lab.test" and a.krbtgt_link == KEY_DN and a.superseded_by == DMSA_DN
