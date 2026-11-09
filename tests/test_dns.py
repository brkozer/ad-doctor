"""Active Directory-integrated DNS zones: dnsprop, the collector and AD-DNS-001 to -003."""

from __future__ import annotations

import json
import struct
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult, LDAPNoSuchObjectResult

from ad_doctor import dnsprop, redact, sd
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector
from ad_doctor.fixes import FIXES
from ad_doctor.model import DnsZone, Severity, Snapshot
from ad_doctor.sd import Ace
from tests.test_acl_adcs import ace_bytes, descriptor, sid_bytes
from tests.test_checks import ids, only, snapshot, user

SID = "S-1-5-21-1-2-3"
ROOT_SID = "S-1-5-21-7-8-9"
DOMAIN_ADMINS = f"{SID}-512"
DNS_ADMINS = f"{SID}-1101"
HELPDESK = f"{SID}-1200"
AUTH_USERS = "S-1-5-11"
HEAD = "DC=lab,DC=test"
FORWARD = f"DC=lab.test,CN=MicrosoftDNS,DC=DomainDnsZones,{HEAD}"
REVERSE = f"DC=9.168.192.in-addr.arpa,CN=MicrosoftDNS,DC=DomainDnsZones,{HEAD}"
DEFAULT_ACES = [
    Ace(DOMAIN_ADMINS, sd.FULL_CONTROL),
    Ace("S-1-5-18", sd.FULL_CONTROL),
    Ace("S-1-5-9", 0xF017F),
    Ace(DNS_ADMINS, 0xF017F),
    Ace(AUTH_USERS, sd.CREATE_CHILD),
    Ace("S-1-1-0", 0x20094),
    Ace("S-1-5-32-544", 0xF01BD),
]


def value(prop: int, data: bytes, *, length: int | None = None, version: int = 1) -> bytes:
    """A dnsProperty value; NameLength and Name hold junk, as they do on a real DC."""
    size = len(data) if length is None else length
    return struct.pack("<5I", size, 0x130, 0, version, prop) + data + b"\x25\x02\x00\x00"


TYPE_PRIMARY = value(dnsprop.PROPERTY_ZONE_TYPE, b"\x01\x00\x00\x00")
UPDATE_SECURE = value(dnsprop.PROPERTY_ALLOW_UPDATE, b"\x02")
UPDATE_NONSECURE = value(dnsprop.PROPERTY_ALLOW_UPDATE, b"\x01")


def zone(name: str = "lab.test", dn: str = FORWARD, **kw: Any) -> DnsZone:
    base: dict[str, Any] = {
        "source": "DomainDnsZones",
        "zone_type": dnsprop.ZONE_TYPE_PRIMARY,
        "allow_update": dnsprop.UPDATE_SECURE,
        "acl_read": True,
        "owner": "S-1-5-18",
        "aces": list(DEFAULT_ACES),
    }
    return DnsZone(dn=dn, name=name, **{**base, **kw})


def dns_snapshot(*zones: DnsZone, **kw: Any) -> Snapshot:
    people = kw.pop("people", ())
    kw.setdefault("dns_admin_sids", [DNS_ADMINS])
    kw.setdefault("root_sid", SID)
    kw.setdefault("principals", {HELPDESK: "helpdesk", DNS_ADMINS: "DnsAdmins"})
    return snapshot(*people, dns_zones=list(zones), dns_zones_checked=True, **kw)


def round_trip(snap: Snapshot) -> Snapshot:
    return Snapshot.from_json(json.loads(json.dumps(snap.to_json())))


# --- dnsProperty ----------------------------------------------------------------------------


def test_parser_reads_type_and_update_setting() -> None:
    props = dnsprop.parse([value(0x10, b"\xa8\x00\x00\x00"), TYPE_PRIMARY, UPDATE_NONSECURE])
    assert props == dnsprop.ZoneProperties(1, 1)
    assert dnsprop.parse([TYPE_PRIMARY, UPDATE_SECURE]).allow_update == dnsprop.UPDATE_SECURE
    # a DWORD is accepted as well as the single byte Windows stores
    assert dnsprop.parse([value(2, b"\x01\x00\x00\x00")]).allow_update == 1


def test_parser_uses_the_documented_default_only_where_there_is_one() -> None:
    props = dnsprop.parse([value(1, b"", length=0), value(2, b"", length=0)])
    assert props == dnsprop.ZoneProperties(dnsprop.ZONE_TYPE_PRIMARY, None)


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\x01" * 19,  # shorter than the header
        struct.pack("<5I", 100, 0, 0, 1, 2) + b"\x01",  # claims more data than it holds
        struct.pack("<5I", 0xFFFFFFFF, 0, 0, 1, 2) + b"\x01",
        value(2, b"\x01", version=2),  # MUST be 1
        struct.pack("<5I", 1, 0, 1, 1, 2) + b"\x01",  # Flag MUST be 0
        value(2, b"\x03"),  # not one of the three values
        value(2, b"\x01\x00"),  # neither a byte nor a DWORD
        b"\x00" * 5000,  # beyond the bound
    ],
)
def test_malformed_values_are_unknown_never_a_setting(bad: bytes) -> None:
    assert dnsprop.parse([bad]).allow_update is None


def test_conflicting_and_excessive_values_are_unknown() -> None:
    assert dnsprop.parse([UPDATE_SECURE, UPDATE_NONSECURE]).allow_update is None
    assert dnsprop.parse([UPDATE_SECURE, UPDATE_SECURE]).allow_update == dnsprop.UPDATE_SECURE
    too_many = [TYPE_PRIMARY, UPDATE_NONSECURE] * dnsprop.MAX_VALUES
    assert dnsprop.parse(too_many) == dnsprop.ZoneProperties()


def test_parser_never_raises_on_noise() -> None:
    seed = bytes(range(256)) * 3
    for start in range(0, 200, 7):
        for size in range(0, 80, 11):
            dnsprop.parse([seed[start : start + size]])


# --- AD-DNS-001 -----------------------------------------------------------------------------


def test_nonsecure_forward_zone_is_high_with_a_dry_run_fix() -> None:
    snap = dns_snapshot(zone(allow_update=dnsprop.UPDATE_NONSECURE))
    f = only(snap, "AD-DNS-001")
    assert f.severity is Severity.HIGH and f.objects == ["lab.test (DomainDnsZones)"]
    assert FIXES["AD-DNS-001"](f, snap) == [
        "Set-DnsServerPrimaryZone -Name 'lab.test' -DynamicUpdate Secure -WhatIf"
    ]


def test_nonsecure_reverse_zone_only_is_medium() -> None:
    reverse = zone(
        "9.168.192.in-addr.arpa", REVERSE, reverse=True, allow_update=dnsprop.UPDATE_NONSECURE
    )
    assert only(dns_snapshot(reverse), "AD-DNS-001").severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "fields",
    [
        {"allow_update": dnsprop.UPDATE_SECURE},
        {"allow_update": dnsprop.UPDATE_OFF},
        {"allow_update": None},  # not readable: a note from the collector, not a pass or a hit
        {"zone_type": None, "allow_update": dnsprop.UPDATE_NONSECURE},
        {"zone_type": 3, "allow_update": dnsprop.UPDATE_NONSECURE},  # stub
        {"zone_type": 4, "allow_update": dnsprop.UPDATE_NONSECURE},  # conditional forwarder
    ],
)
def test_nonsecure_stays_quiet(fields: dict[str, Any]) -> None:
    assert "AD-DNS-001" not in ids(run_all(dns_snapshot(zone(**fields))))


# --- AD-DNS-002 -----------------------------------------------------------------------------


def test_default_acl_is_clean() -> None:
    assert not {"AD-DNS-001", "AD-DNS-002"} & ids(run_all(dns_snapshot(zone())))


@pytest.mark.parametrize(
    ("mask", "object_type"),
    [
        (sd.GENERIC_ALL, None),
        (sd.GENERIC_WRITE, None),
        (sd.WRITE_DAC, None),
        (sd.WRITE_OWNER, None),
        (sd.WRITE_PROPERTY, None),
        (sd.WRITE_PROPERTY, sd.DNS_PROPERTY),
        (sd.DELETE, None),
        (sd.DELETE_CHILD, None),
        (sd.DELETE_CHILD, sd.DNS_NODE_CLASS),
        (sd.DELETE_TREE, None),
    ],
)
def test_write_control_outside_tier0_is_reported(mask: int, object_type: str | None) -> None:
    snap = dns_snapshot(zone(aces=[*DEFAULT_ACES, Ace(HELPDESK, mask, object_type)]))
    f = only(snap, "AD-DNS-002")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["lab.test (DomainDnsZones): helpdesk"]


def test_broad_group_on_a_forward_zone_is_high_and_on_a_reverse_zone_medium() -> None:
    broad = Ace(AUTH_USERS, sd.GENERIC_ALL)
    forward = zone(aces=[*DEFAULT_ACES, broad])
    assert only(dns_snapshot(forward), "AD-DNS-002").severity is Severity.HIGH
    reverse = zone("9.168.192.in-addr.arpa", REVERSE, reverse=True, aces=[*DEFAULT_ACES, broad])
    assert only(dns_snapshot(reverse), "AD-DNS-002").severity is Severity.MEDIUM


def test_owner_outside_tier0_is_reported_and_a_dns_admin_is_not() -> None:
    f = only(dns_snapshot(zone(owner=HELPDESK)), "AD-DNS-002")
    assert f.objects == ["lab.test (DomainDnsZones): helpdesk (owner)"]
    member = user("dnsop", sid=f"{SID}-1300")
    snap = dns_snapshot(zone(owner=member.sid), people=[member], dns_admins=[member.dn])
    assert "AD-DNS-002" not in ids(run_all(snap))


def test_rights_on_the_records_count_when_inherited() -> None:
    inherited = [Ace(HELPDESK, sd.WRITE_PROPERTY, sd.DNS_RECORD, sd.DNS_NODE_CLASS)]
    f = only(dns_snapshot(zone(inheritable=inherited)), "AD-DNS-002")
    assert f.objects == ["lab.test (DomainDnsZones): helpdesk"]
    # an ACE that only user objects inherit does not reach a record
    other = [Ace(HELPDESK, sd.GENERIC_ALL, None, sd.USER_CLASS)]
    assert "AD-DNS-002" not in ids(run_all(dns_snapshot(zone(inheritable=other))))


def test_narrow_rights_are_not_write_control() -> None:
    aces = [
        *DEFAULT_ACES,
        Ace(HELPDESK, sd.READ_PROPERTY),
        Ace(HELPDESK, sd.CREATE_CHILD),
        Ace(HELPDESK, sd.WRITE_PROPERTY, sd.KEY_CREDENTIAL_LINK),
        Ace(HELPDESK, sd.DELETE_CHILD, sd.USER_CLASS),
    ]
    assert "AD-DNS-002" not in ids(run_all(dns_snapshot(zone(aces=aces))))


def test_unreadable_acl_is_not_judged() -> None:
    assert not {"AD-DNS-002", "AD-DNS-003"} & ids(
        run_all(dns_snapshot(zone(acl_read=False, aces=[], owner=HELPDESK)))
    )


def test_renamed_dnsadmins_is_listed_and_the_finding_says_so() -> None:
    f = only(dns_snapshot(zone(), dns_admin_sids=[]), "AD-DNS-002")
    assert "renamed" in f.detail and f.objects == ["lab.test (DomainDnsZones): DnsAdmins"]


FOREST = "DC=_msdcs.lab.test,CN=MicrosoftDNS,DC=ForestDnsZones,DC=root,DC=test"


def test_other_domain_on_a_forest_zone_is_not_judged() -> None:
    other = f"{ROOT_SID}-1101"
    forest = zone(
        "_msdcs.lab.test", FOREST, source="ForestDnsZones", aces=[Ace(other, sd.FULL_CONTROL)]
    )
    assert "AD-DNS-002" not in ids(run_all(dns_snapshot(forest, root_sid=ROOT_SID)))
    # with the forest root's DnsAdmins known, another group of the root domain can be judged
    known = [DNS_ADMINS, f"{ROOT_SID}-1101"]
    snap = dns_snapshot(
        zone(
            "_msdcs.lab.test",
            FOREST,
            source="ForestDnsZones",
            aces=[
                Ace(f"{ROOT_SID}-1101", sd.FULL_CONTROL),
                Ace(f"{ROOT_SID}-2000", sd.FULL_CONTROL),
            ],
        ),
        root_sid=ROOT_SID,
        dns_admin_sids=known,
    )
    assert only(snap, "AD-DNS-002").objects == [
        f"_msdcs.lab.test (ForestDnsZones): {ROOT_SID}-2000"
    ]
    # a domain zone is not forest-wide: the same principal is judged
    domain = zone(aces=[Ace(other, sd.FULL_CONTROL)])
    assert "AD-DNS-002" in ids(run_all(dns_snapshot(domain, root_sid=ROOT_SID)))


# --- AD-DNS-003 -----------------------------------------------------------------------------


def test_default_create_child_is_information_only() -> None:
    f = only(dns_snapshot(zone()), "AD-DNS-003")
    assert f.severity is Severity.INFO
    assert f.objects == ["lab.test (DomainDnsZones): Authenticated Users"]


def test_create_child_stays_quiet_when_narrowed_or_not_primary() -> None:
    narrowed = [a for a in DEFAULT_ACES if a.sid != AUTH_USERS]
    assert "AD-DNS-003" not in ids(run_all(dns_snapshot(zone(aces=narrowed))))
    assert "AD-DNS-003" not in ids(run_all(dns_snapshot(zone(zone_type=4))))
    # creating some other class is not creating a record
    other = [*narrowed, Ace(AUTH_USERS, sd.CREATE_CHILD, sd.USER_CLASS)]
    assert "AD-DNS-003" not in ids(run_all(dns_snapshot(zone(aces=other))))
    # one member's right is not the default for everyone
    single = [*narrowed, Ace(HELPDESK, sd.CREATE_CHILD)]
    assert "AD-DNS-003" not in ids(run_all(dns_snapshot(zone(aces=single))))


# --- snapshots ------------------------------------------------------------------------------

DIRTY = zone(
    allow_update=dnsprop.UPDATE_NONSECURE, aces=[*DEFAULT_ACES, Ace(HELPDESK, sd.WRITE_DAC)]
)
DIRTY_REVERSE = zone(
    "9.168.192.in-addr.arpa",
    REVERSE,
    reverse=True,
    allow_update=dnsprop.UPDATE_NONSECURE,
)


def test_zones_survive_a_round_trip() -> None:
    snap = dns_snapshot(DIRTY, DIRTY_REVERSE)
    assert round_trip(snap) == snap


def test_older_snapshot_says_not_evaluated_and_stays_quiet() -> None:
    data = json.loads(json.dumps(dns_snapshot(DIRTY).to_json()))
    for key in ("dns_zones", "dns_zones_checked", "dns_admin_sids"):
        del data[key]
    snap = Snapshot.from_json(data)
    assert any("AD-DNS-001" in n and "not evaluated" in n for n in snap.notes)
    assert not {"AD-DNS-001", "AD-DNS-002", "AD-DNS-003"} & ids(run_all(snap))


def test_redaction_hides_zone_names_and_keeps_findings() -> None:
    snap = dns_snapshot(DIRTY, DIRTY_REVERSE)
    out = redact.redact(json.loads(json.dumps(snap.to_json())), b"k")
    text = json.dumps(out)
    for secret in ("lab.test", "192.in-addr", "helpdesk", "1-2-3"):
        assert secret not in text, secret
    assert all("MicrosoftDNS,DC=DomainDnsZones" in z["dn"] for z in out["dns_zones"])
    assert all(z["source"] == "DomainDnsZones" for z in out["dns_zones"])
    back = Snapshot.from_json(out)
    found = {f.check_id: f for f in run_all(back)}
    assert found["AD-DNS-001"].severity is Severity.HIGH
    assert len(found["AD-DNS-001"].objects) == 2
    assert found["AD-DNS-002"].severity is Severity.MEDIUM
    assert len(found["AD-DNS-003"].objects) == 2


# --- the collector --------------------------------------------------------------------------

DOMAIN_ZONES = f"DC=DomainDnsZones,{HEAD}"
FOREST_ZONES = f"DC=ForestDnsZones,{HEAD}"
DACL = descriptor(ace_bytes(DOMAIN_ADMINS, sd.GENERIC_ALL), ace_bytes(AUTH_USERS, sd.CREATE_CHILD))


def entry(dn: str, **attrs: Any) -> dict[str, Any]:
    raw = {k: v if isinstance(v, list) else [v] for k, v in attrs.items()}
    return {"type": "searchResEntry", "dn": dn, "raw_attributes": raw}


def zone_entry(
    partition: str, name: str, *props: bytes, acl: bytes | None = DACL
) -> dict[str, Any]:
    attrs: dict[str, Any] = {"name": name.encode(), "dNSProperty": list(props)}
    if acl is not None:
        attrs["nTSecurityDescriptor"] = acl
    return entry(f"DC={name},CN=MicrosoftDNS,{partition}", **attrs)


class Fake:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes

    def paged_search(self, base: str, flt: str, **kw: Any) -> Iterator[dict[str, Any]]:
        if "DnsAdmins" in flt:
            yield entry(f"CN=DnsAdmins,CN=Users,{HEAD}", objectSid=sid_bytes(DNS_ADMINS))
            return
        found = self.routes.get(base)
        if isinstance(found, Exception):
            raise found
        if found is None:
            raise LDAPNoSuchObjectResult()
        yield from found


def collector(routes: dict[str, Any], contexts: tuple[str, ...]) -> Collector:
    info = SimpleNamespace(naming_contexts=list(contexts), other={})
    conn = SimpleNamespace(
        server=SimpleNamespace(info=info), extend=SimpleNamespace(standard=Fake(routes))
    )
    return Collector(conn)  # type: ignore[arg-type]


def container(partition: str) -> str:
    return f"CN=MicrosoftDNS,{partition}"


def test_collector_reads_all_three_locations() -> None:
    c = collector(
        {
            container(DOMAIN_ZONES): [
                zone_entry(DOMAIN_ZONES, "lab.test", TYPE_PRIMARY, UPDATE_SECURE)
            ],
            container(FOREST_ZONES): [
                zone_entry(FOREST_ZONES, "_msdcs.lab.test", TYPE_PRIMARY, UPDATE_NONSECURE),
                zone_entry(FOREST_ZONES, "..TrustAnchors", TYPE_PRIMARY, UPDATE_NONSECURE),
            ],
            container(f"CN=System,{HEAD}"): [
                zone_entry(f"CN=System,{HEAD}", "2.0.10.in-addr.arpa", TYPE_PRIMARY, UPDATE_SECURE),
                zone_entry(f"CN=System,{HEAD}", "RootDNSServers"),
            ],
        },
        (DOMAIN_ZONES, FOREST_ZONES),
    )
    zones, admins, checked = c._dns_zones(HEAD, HEAD, SID, SID)
    assert checked and admins == [DNS_ADMINS]
    found = {z.label: z for z in zones}
    assert sorted(found) == [
        "2.0.10.in-addr.arpa (domain partition)",
        "RootDNSServers (domain partition)",
        "_msdcs.lab.test (ForestDnsZones)",
        "lab.test (DomainDnsZones)",
    ]
    assert found["2.0.10.in-addr.arpa (domain partition)"].reverse
    assert not found["lab.test (DomainDnsZones)"].reverse
    assert found["_msdcs.lab.test (ForestDnsZones)"].allow_update == dnsprop.UPDATE_NONSECURE
    assert found["lab.test (DomainDnsZones)"].aces == [
        Ace(DOMAIN_ADMINS, sd.GENERIC_ALL),
        Ace(AUTH_USERS, sd.CREATE_CHILD),
    ]
    # root hints without properties are expected, and they are nothing to report
    assert not any("DNS zone" in n for n in c.notes)


def test_collector_notes_every_unread_zone() -> None:
    c = collector(
        {
            container(DOMAIN_ZONES): [
                zone_entry(DOMAIN_ZONES, "noprops.test"),
                zone_entry(DOMAIN_ZONES, "bad.test", b"\x01\x02", TYPE_PRIMARY),
                zone_entry(DOMAIN_ZONES, "noacl.test", TYPE_PRIMARY, UPDATE_SECURE, acl=None),
                zone_entry(
                    DOMAIN_ZONES, "badacl.test", TYPE_PRIMARY, UPDATE_SECURE, acl=b"\x01" * 24
                ),
            ],
            container(FOREST_ZONES): [],
        },
        (DOMAIN_ZONES, FOREST_ZONES),
    )
    zones, _, checked = c._dns_zones(HEAD, HEAD, SID, SID)
    assert checked and len(zones) == 4
    text = " ".join(c.notes)
    assert "2 DNS zone(s)" in text and "noprops.test" in text and "bad.test" in text
    assert "AD-DNS-001 did not judge" in text
    assert "noacl.test" in text and "badacl.test" in text and "AD-DNS-002" in text


def test_collector_says_what_it_could_not_read() -> None:
    # not on this DC, and the legacy container does not exist
    c = collector({}, ())
    zones, _, checked = c._dns_zones(HEAD, HEAD, SID, SID)
    assert zones == [] and not checked
    assert sum("holds no copy" in n for n in c.notes) == 2
    assert any("not judged" in n for n in c.notes)
    # refused where the partition is held: "could not ask", not "no zones"
    c = collector(
        {
            container(DOMAIN_ZONES): LDAPInsufficientAccessRightsResult(),
            container(FOREST_ZONES): LDAPNoSuchObjectResult(),
        },
        (DOMAIN_ZONES, FOREST_ZONES),
    )
    _, _, checked = c._dns_zones(HEAD, HEAD, SID, SID)
    assert not checked
    assert any("failed" in n for n in c.notes) and any("not visible" in n for n in c.notes)


def test_collector_keeps_one_partition_when_the_other_is_missing() -> None:
    c = collector(
        {
            container(DOMAIN_ZONES): [
                zone_entry(DOMAIN_ZONES, "lab.test", TYPE_PRIMARY, UPDATE_SECURE)
            ]
        },
        (DOMAIN_ZONES,),
    )
    zones, _, checked = c._dns_zones(HEAD, HEAD, SID, SID)
    assert checked and [z.name for z in zones] == ["lab.test"]
    assert any("ForestDnsZones" in n for n in c.notes)


def test_collector_notes_foreign_trustees_on_forest_zones() -> None:
    acl = descriptor(ace_bytes(f"{ROOT_SID}-1101", sd.GENERIC_ALL))
    c = collector(
        {
            container(DOMAIN_ZONES): [],
            container(FOREST_ZONES): [
                zone_entry(FOREST_ZONES, "z.test", TYPE_PRIMARY, UPDATE_SECURE, acl=acl)
            ],
        },
        (DOMAIN_ZONES, FOREST_ZONES),
    )
    c._dns_zones(HEAD, HEAD, SID, ROOT_SID)
    assert any("another domain" in n and "z.test" in n for n in c.notes)
