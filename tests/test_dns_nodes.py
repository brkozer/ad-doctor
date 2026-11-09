"""dnsNode records: the dnsRecord parser, the walk of the zones and AD-DNS-004 to -007."""

from __future__ import annotations

import json
import random
import struct
import tracemalloc
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult

from ad_doctor import dnsprop, redact, sd
from ad_doctor.checks import dns_lookup_hosts, run_all
from ad_doctor.collect import MAX_KEPT_DNS_NODES, Collector
from ad_doctor.model import DnsNode, DnsZone, Severity, Snapshot
from ad_doctor.sd import Ace
from tests.test_acl_adcs import ace_bytes, descriptor, sid_bytes
from tests.test_checks import NOW, computer, ids, only, snapshot, user
from tests.test_dns import (
    DNS_ADMINS,
    DOMAIN_ADMINS,
    FORWARD,
    HEAD,
    HELPDESK,
    SID,
    collector,
    dns_snapshot,
    entry,
    round_trip,
    zone,
)

MARKER = "1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"
OWN_NAME = "srv01.lab.test"


def record(kind: int = dnsprop.TYPE_A, data: bytes = b"\x0a\x00\x00\x01", **kw: Any) -> bytes:
    length = kw.get("length", len(data))
    version = kw.get("version", dnsprop.RECORD_VERSION)
    return struct.pack("<HHBBHIIII", length, kind, version, 0xF0, 0, 1, 0, 0, 0) + data


def fired(snap: Snapshot) -> set[str]:
    return set(ids(run_all(snap)))


def node(name: str = "*", kind: str = dnsprop.KIND_WILDCARD, **kw: Any) -> DnsNode:
    base: dict[str, Any] = {
        "zone": "lab.test",
        "source": "DomainDnsZones",
        "record_types": [dnsprop.TYPE_A],
        "tombstoned": False,
        "owner": HELPDESK,
    }
    return DnsNode(name=name, kind=kind, **{**base, **kw})


def records_snapshot(*nodes: DnsNode, **kw: Any) -> Snapshot:
    zones = kw.pop("zones", (zone(nodes_read=True),))
    return dns_snapshot(*zones, dns_nodes=list(nodes), dns_nodes_checked=True, **kw)


# --- dnsRecord ------------------------------------------------------------------------------


def test_record_type_reads_the_header() -> None:
    assert dnsprop.record_type(record()) == dnsprop.TYPE_A
    assert dnsprop.record_type(record(dnsprop.TYPE_AAAA, b"\x00" * 16)) == dnsprop.TYPE_AAAA
    assert dnsprop.record_type(record(dnsprop.TYPE_TOMBSTONE, b"\x00" * 8)) == 0


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x01",
        b"\x00" * 23,
        record(version=4),
        record(length=5),
        record(data=b"", length=1),
        b"\xff" * dnsprop.RECORD_HEADER.size,
        record(data=b"\x00" * (dnsprop.MAX_RECORD_BYTES + 1), length=0),
    ],
)
def test_record_type_refuses_what_does_not_fit(raw: bytes) -> None:
    assert dnsprop.record_type(raw) is None


def test_record_types_keeps_the_valid_values() -> None:
    assert dnsprop.record_types([b"junk", record(), record(dnsprop.TYPE_NS, b"x")]) == [1, 2]
    assert dnsprop.record_types([b"junk"]) is None
    assert dnsprop.record_types([]) is None


def test_record_types_is_bounded() -> None:
    values = [record(dnsprop.TYPE_NS, b"x")] * (dnsprop.MAX_RECORD_VALUES + 5)
    assert dnsprop.record_types([*values, record()]) == [dnsprop.TYPE_NS]


def test_parser_never_raises_on_random_bytes() -> None:
    rng = random.Random(1234)
    for _ in range(3000):
        raw = rng.randbytes(rng.randrange(60))
        assert dnsprop.record_type(raw) in (None, *range(0x10000))
        dnsprop.node_kind(raw.decode("latin-1"))


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        (f"srv1{MARKER}", dnsprop.KIND_MARSHALED),
        (f"srv1{MARKER}".lower(), dnsprop.KIND_MARSHALED),
        ("*", dnsprop.KIND_WILDCARD),
        ("*.branch", dnsprop.KIND_WILDCARD),
        ("wpad", dnsprop.KIND_WELL_KNOWN),
        ("WPAD.branch", dnsprop.KIND_WELL_KNOWN),
        ("isatap", dnsprop.KIND_WELL_KNOWN),
        ("autodiscover", dnsprop.KIND_WELL_KNOWN),
        ("srv01", None),
        ("wpad2", None),
        ("a*", None),
        ("uwhrcbaaaa", None),
        ("uwhrc-short-baaaa", None),
        ("*" * 300, None),
    ],
)
def test_node_kind(name: str, kind: str | None) -> None:
    assert dnsprop.node_kind(name) == kind


# --- AD-DNS-004 -----------------------------------------------------------------------------


def marshaled(**kw: Any) -> DnsNode:
    return node(f"srv1{MARKER}", dnsprop.KIND_MARSHALED, **kw)


def test_marshaled_name_is_high() -> None:
    f = only(records_snapshot(marshaled()), "AD-DNS-004")
    assert f.severity is Severity.HIGH and MARKER in f.objects[0]


def test_marshaled_name_counts_even_when_records_are_unreadable() -> None:
    f = only(records_snapshot(marshaled(record_types=None)), "AD-DNS-004")
    assert f.severity is Severity.HIGH


def test_tombstoned_marshaled_name_is_medium() -> None:
    snap = records_snapshot(marshaled(record_types=[0], tombstoned=True))
    f = only(snap, "AD-DNS-004")
    assert f.severity is Severity.MEDIUM and "(tombstoned)" in f.objects[0]


def test_one_live_marshaled_name_keeps_it_high() -> None:
    live = marshaled()
    gone = node(f"b{MARKER}", dnsprop.KIND_MARSHALED, tombstoned=True, record_types=[0])
    assert only(records_snapshot(live, gone), "AD-DNS-004").severity is Severity.HIGH


def test_marshaled_quiet_without_a_match() -> None:
    assert "AD-DNS-004" not in fired(records_snapshot())


# --- AD-DNS-005 -----------------------------------------------------------------------------


def test_wildcard_by_ordinary_account_is_high() -> None:
    f = only(records_snapshot(node()), "AD-DNS-005")
    assert f.severity is Severity.HIGH and f.objects == [
        "* in lab.test (DomainDnsZones): created by helpdesk"
    ]


def test_wildcard_alias_is_high() -> None:
    f = only(records_snapshot(node(record_types=[dnsprop.TYPE_CNAME])), "AD-DNS-005")
    assert f.severity is Severity.HIGH


def test_wildcard_by_ordinary_account_without_an_address_is_low() -> None:
    f = only(records_snapshot(node(record_types=[16])), "AD-DNS-005")
    assert f.severity is Severity.LOW and "no address record" in f.objects[0]


def test_wildcard_with_unreadable_records_is_low_and_says_so() -> None:
    f = only(records_snapshot(node(record_types=None)), "AD-DNS-005")
    assert f.severity is Severity.LOW and "records not readable" in f.objects[0]


def test_wildcard_with_unreadable_owner_is_low_and_says_so() -> None:
    f = only(records_snapshot(node(owner=None)), "AD-DNS-005")
    assert f.severity is Severity.LOW and "owner not readable" in f.objects[0]


def test_wildcard_owned_in_another_domain_is_low() -> None:
    other = f"S-1-5-21-4-5-6-{1105}"
    n = node(owner=other, source="ForestDnsZones")
    f = only(records_snapshot(n), "AD-DNS-005")
    assert f.severity is Severity.LOW and "another domain" in f.objects[0]


def test_wildcard_by_an_administrator_is_information() -> None:
    for owner in (DOMAIN_ADMINS, DNS_ADMINS, "S-1-5-18"):
        f = only(records_snapshot(node(owner=owner)), "AD-DNS-005")
        assert f.severity is Severity.INFO and "created by" in f.objects[0]


def test_tombstoned_wildcard_is_quiet() -> None:
    assert "AD-DNS-005" not in fired(records_snapshot(node(record_types=[0])))
    assert "AD-DNS-005" not in fired(records_snapshot(node(tombstoned=True)))


# --- AD-DNS-006 -----------------------------------------------------------------------------


def wpad(**kw: Any) -> DnsNode:
    return node("wpad", dnsprop.KIND_WELL_KNOWN, **kw)


def test_wpad_by_ordinary_account_is_high() -> None:
    f = only(records_snapshot(wpad()), "AD-DNS-006")
    assert f.severity is Severity.HIGH and "created by helpdesk" in f.objects[0]


def test_wpad_without_an_address_is_low() -> None:
    f = only(records_snapshot(wpad(record_types=[16])), "AD-DNS-006")
    assert f.severity is Severity.LOW and "no address record" in f.objects[0]


def test_wpad_with_unreadable_records_is_low() -> None:
    f = only(records_snapshot(wpad(record_types=None)), "AD-DNS-006")
    assert f.severity is Severity.LOW and "records not readable" in f.objects[0]


def test_wpad_owned_in_another_domain_is_low() -> None:
    n = wpad(owner="S-1-5-21-4-5-6-1105", source="ForestDnsZones")
    f = only(records_snapshot(n), "AD-DNS-006")
    assert f.severity is Severity.LOW and "another domain" in f.objects[0]


def test_wpad_by_an_administrator_or_unread_is_quiet() -> None:
    for owner in (DOMAIN_ADMINS, DNS_ADMINS, "S-1-5-18", None):
        assert "AD-DNS-006" not in fired(records_snapshot(wpad(owner=owner)))


def test_wpad_tombstoned_is_quiet() -> None:
    assert "AD-DNS-006" not in fired(records_snapshot(wpad(tombstoned=True)))


def test_host_really_called_wpad_is_quiet() -> None:
    host = computer("WPAD", sid=f"{SID}-2000")
    snap = records_snapshot(wpad(owner=f"{SID}-2000"), people=(host,))
    assert "AD-DNS-006" not in fired(snap)


def test_another_computer_owning_wpad_is_reported() -> None:
    host = computer("WS01", sid=f"{SID}-2000")
    snap = records_snapshot(wpad(owner=f"{SID}-2000"), people=(host,))
    assert only(snap, "AD-DNS-006").severity is Severity.HIGH


# --- AD-DNS-007 -----------------------------------------------------------------------------


def live_computer(*spns: str, **kw: Any) -> Any:
    return computer("SRV01", dns_host=OWN_NAME, spns=list(spns), **kw)


def ghost_snapshot(*people: Any, **kw: Any) -> Snapshot:
    kw.setdefault("dns_spn_hosts", [OWN_NAME])
    return records_snapshot(people=people, **kw)


def test_ghost_host_spn_on_a_computer_is_medium() -> None:
    f = only(ghost_snapshot(live_computer("HOST/old.lab.test")), "AD-DNS-007")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["SRV01$: HOST/old.lab.test (zone lab.test (DomainDnsZones))"]


def test_ghost_cifs_is_medium_and_other_classes_low() -> None:
    assert (
        only(ghost_snapshot(live_computer("cifs/old.lab.test")), "AD-DNS-007").severity
        is Severity.MEDIUM
    )
    assert (
        only(ghost_snapshot(live_computer("HTTP/old.lab.test")), "AD-DNS-007").severity
        is Severity.LOW
    )


def test_ghost_on_a_service_account_is_low() -> None:
    svc = user("svc_web", spns=["HOST/old.lab.test"])
    assert only(ghost_snapshot(svc), "AD-DNS-007").severity is Severity.LOW


def test_short_host_counts_for_host_classes_only() -> None:
    assert "AD-DNS-007" in fired(ghost_snapshot(live_computer("HOST/old")))
    assert "AD-DNS-007" not in fired(ghost_snapshot(live_computer("MyApp/old")))


def test_dns_record_present_is_quiet() -> None:
    host = live_computer("HOST/alias.lab.test")
    snap = ghost_snapshot(host, dns_spn_hosts=[OWN_NAME, "alias.lab.test"])
    assert "AD-DNS-007" not in fired(snap)


def test_short_host_with_a_record_is_quiet() -> None:
    snap = ghost_snapshot(live_computer("HOST/alias"), dns_spn_hosts=[OWN_NAME, "alias.lab.test"])
    assert "AD-DNS-007" not in fired(snap)


def test_the_computers_own_names_are_quiet() -> None:
    assert "AD-DNS-007" not in fired(
        ghost_snapshot(live_computer("HOST/SRV01", "HOST/srv01.lab.test"))
    )


def test_dead_computer_is_quiet() -> None:
    # no DNS record of its own: there is no host to relay to
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"), dns_spn_hosts=[])
    assert "AD-DNS-007" not in fired(snap)
    stale = live_computer("HOST/old.lab.test", last_logon=NOW - timedelta(days=200))
    assert "AD-DNS-007" not in fired(ghost_snapshot(stale))
    never = live_computer("HOST/old.lab.test", last_logon=None)
    assert "AD-DNS-007" not in fired(ghost_snapshot(never))


def test_disabled_account_and_krbtgt_are_quiet() -> None:
    off = live_computer("HOST/old.lab.test", uac=0x1002)
    assert "AD-DNS-007" not in fired(ghost_snapshot(off))
    krb = user("krbtgt", spns=["HOST/old.lab.test"])
    assert "AD-DNS-007" not in fired(ghost_snapshot(krb))


def test_host_outside_every_zone_is_quiet() -> None:
    assert "AD-DNS-007" not in fired(ghost_snapshot(live_computer("HOST/x.other.example")))


def test_ip_and_odd_hosts_are_quiet() -> None:
    assert "AD-DNS-007" not in fired(
        ghost_snapshot(live_computer("HOST/10.0.0.5", "HOST/[::1]", "HOST/bad name.lab"))
    )


def test_unlisted_zone_is_not_judged() -> None:
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"), zones=(zone(nodes_read=False),))
    assert "AD-DNS-007" not in fired(snap)


def test_zone_nobody_can_add_to_is_quiet() -> None:
    closed = zone(nodes_read=True, aces=[Ace(DOMAIN_ADMINS, sd.FULL_CONTROL)])
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"), zones=(closed,))
    assert "AD-DNS-007" not in fired(snap)


def test_unread_zone_acl_is_not_judged() -> None:
    blind = zone(nodes_read=True, acl_read=False, aces=[])
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"), zones=(blind,))
    assert "AD-DNS-007" not in fired(snap)


def test_nonsecure_zone_counts_even_without_an_acl() -> None:
    open_zone = zone(
        nodes_read=True, acl_read=False, aces=[], allow_update=dnsprop.UPDATE_NONSECURE
    )
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"), zones=(open_zone,))
    assert "AD-DNS-007" in fired(snap)


def test_secondary_zone_is_quiet() -> None:
    copy = zone(nodes_read=True, zone_type=2)
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"), zones=(copy,))
    assert "AD-DNS-007" not in fired(snap)


def test_longest_zone_decides() -> None:
    parent = zone(nodes_read=True)
    child = zone(
        name="sub.lab.test",
        dn=f"DC=sub.lab.test,CN=MicrosoftDNS,DC=DomainDnsZones,{HEAD}",
        nodes_read=True,
        aces=[Ace(DOMAIN_ADMINS, sd.FULL_CONTROL)],
    )
    snap = ghost_snapshot(live_computer("HOST/x.sub.lab.test"), zones=(parent, child))
    assert "AD-DNS-007" not in fired(snap)


def test_wildcard_covers_the_name() -> None:
    gone = ghost_snapshot(live_computer("HOST/old.lab.test"))
    gone.dns_nodes = [node(owner=DOMAIN_ADMINS)]
    assert "AD-DNS-007" not in fired(gone)


def test_tombstoned_wildcard_covers_nothing() -> None:
    snap = ghost_snapshot(live_computer("HOST/old.lab.test"))
    snap.dns_nodes = [node(owner=DOMAIN_ADMINS, tombstoned=True)]
    assert "AD-DNS-007" in fired(snap)


def test_delegated_subtree_is_quiet() -> None:
    snap = ghost_snapshot(live_computer("HOST/x.far.lab.test"), dns_delegations=["far.lab.test"])
    assert "AD-DNS-007" not in fired(snap)


def test_does_not_repeat_ad_del_005() -> None:
    # a delegation target no account holds is AD-DEL-005's, and never this check's
    svc = user("svc_app", allowed_to_delegate_to=["cifs/old.lab.test"])
    assert "AD-DNS-007" not in fired(ghost_snapshot(svc))


def test_lookup_hosts() -> None:
    host = live_computer("HOST/old.lab.test", "HOST/alias", "MyApp/x", "HOST/10.0.0.1")
    off = computer("OFF", uac=0x1002, spns=["HOST/off.lab.test"])
    assert dns_lookup_hosts([host, off], "lab.test") == {
        OWN_NAME,
        "old.lab.test",
        "alias.lab.test",
    }


# --- snapshots ------------------------------------------------------------------------------


def test_older_snapshot_says_not_evaluated() -> None:
    data = snapshot().to_json()
    for key in ("dns_nodes", "dns_nodes_checked", "dns_spn_hosts", "dns_delegations"):
        del data[key]
    snap = Snapshot.from_json(data)
    assert not snap.dns_nodes_checked and snap.dns_nodes == []
    assert any("AD-DNS-004 to AD-DNS-007" in n for n in snap.notes)
    assert not {"AD-DNS-004", "AD-DNS-005", "AD-DNS-006", "AD-DNS-007"} & set(fired(snap))


def test_quiet_when_records_were_not_read() -> None:
    snap = dns_snapshot(zone(), dns_nodes=[node()], dns_nodes_checked=False)
    assert "AD-DNS-005" not in fired(snap)


def test_round_trip_keeps_the_nodes() -> None:
    snap = records_snapshot(marshaled(), node(), wpad())
    copy = round_trip(snap)
    assert copy.dns_nodes == snap.dns_nodes and copy.dns_nodes_checked
    assert copy.dns_zones[0].nodes_read


def _redacted(snap: Snapshot) -> Snapshot:
    return Snapshot.from_json(redact.redact(json.loads(json.dumps(snap.to_json())), b"k"))


def test_redaction_keeps_the_findings() -> None:
    host = live_computer("HOST/old.lab.test")
    snap = ghost_snapshot(host, dns_spn_hosts=[OWN_NAME])
    snap.dns_nodes = [marshaled(), node(owner=DOMAIN_ADMINS, zone="elsewhere.test"), wpad()]
    before = fired(snap)
    copy = _redacted(snap)
    assert fired(copy) == before
    text = json.dumps(copy.to_json())
    assert MARKER.lower() not in text.lower()
    assert "wpad" not in text.lower() and "old.lab" not in text.lower()
    assert "elsewhere" not in text.lower()
    assert {n.kind for n in copy.dns_nodes} == set(dnsprop.NODE_KINDS)


def test_redaction_keeps_a_present_name_present() -> None:
    other = computer("OTHER", dns_host="other.lab.test")
    host = live_computer("HOST/other.lab.test", "HOST/alias.lab.test")
    snap = ghost_snapshot(host, other, dns_spn_hosts=[OWN_NAME, "other.lab.test", "alias.lab.test"])
    assert "AD-DNS-007" not in fired(snap)
    assert "AD-DNS-007" not in fired(_redacted(snap))


# --- the walk of the zones ------------------------------------------------------------------

DACL = descriptor(ace_bytes(DOMAIN_ADMINS, sd.GENERIC_ALL))


def owned_by(sid: str) -> bytes:
    data = bytearray(DACL)
    raw = sid_bytes(sid)
    struct.pack_into("<I", data, 4, len(data))
    return bytes(data) + raw


def node_entry(name: str, *records: bytes, zone_dn: str = FORWARD, **attrs: Any) -> dict[str, Any]:
    values: dict[str, Any] = {"name": name.encode(), "dnsRecord": list(records), **attrs}
    return entry(f"DC={name},{zone_dn}", **values)


def owner_entry(name: str, sid: str, zone_dn: str = FORWARD) -> dict[str, Any]:
    return entry(f"DC={name},{zone_dn}", nTSecurityDescriptor=owned_by(sid))


def scanning(routes: dict[str, Any]) -> Collector:
    return collector({**routes}, ())


def walk(
    c: Collector, zones: list[DnsZone] | None = None, *people: Any
) -> tuple[Any, bool, list[DnsZone]]:
    picked = zones if zones is not None else [zone(acl_read=True)]
    scan, checked = c._dns_nodes(picked, list(people), "lab.test")
    return scan, checked, picked


def test_walk_keeps_only_what_is_asked_about() -> None:
    star = f"DC=*,{FORWARD}"
    c = scanning(
        {
            FORWARD: [
                node_entry("srv01", record()),
                node_entry("old", record()),
                node_entry("noise", record()),
                node_entry("*", record()),
                node_entry("@", record(dnsprop.TYPE_NS, b"x")),
            ],
            star: [owner_entry("*", HELPDESK)],
        }
    )
    host = live_computer("HOST/old.lab.test")
    scan, checked, zones = walk(c, None, host)
    assert checked and zones[0].nodes_read
    assert scan.hosts == {OWN_NAME, "old.lab.test"}
    assert [n.name for _, n in scan.kept] == ["*"]
    assert scan.kept[0][1].owner == HELPDESK
    assert scan.kept[0][1].record_types == [dnsprop.TYPE_A]
    assert not c.notes


def test_walk_finds_names_and_flags() -> None:
    c = scanning(
        {
            FORWARD: [
                node_entry(f"a{MARKER}", record(0, b"\x00" * 8), dNSTombstoned=b"TRUE"),
                node_entry("wpad", b"junk"),
            ],
            f"DC=a{MARKER},{FORWARD}": [owner_entry(f"a{MARKER}", HELPDESK)],
            f"DC=wpad,{FORWARD}": [owner_entry("wpad", HELPDESK)],
        }
    )
    scan, _, _ = walk(c)
    found = {n.kind: n for _, n in scan.kept}
    assert found[dnsprop.KIND_MARSHALED].tombstoned is True
    assert found[dnsprop.KIND_MARSHALED].is_tombstoned
    assert found[dnsprop.KIND_WELL_KNOWN].record_types is None
    assert found[dnsprop.KIND_WELL_KNOWN].readable is False


def test_walk_finds_the_zone_apex() -> None:
    c = scanning({FORWARD: [node_entry("@", record())]})
    host = live_computer("ldap/lab.test")
    scan, _, _ = walk(c, None, host)
    assert scan.hosts == {"lab.test"}


def test_walk_records_delegations_only_above_a_wanted_host() -> None:
    c = scanning(
        {
            FORWARD: [
                node_entry("far", record(dnsprop.TYPE_NS, b"x")),
                node_entry("unrelated", record(dnsprop.TYPE_NS, b"x")),
            ],
        }
    )
    scan, _, _ = walk(c, None, live_computer("HOST/x.far.lab.test"))
    assert scan.delegations == {"far.lab.test"}


def test_walk_skips_reverse_zones_and_root_hints() -> None:
    reverse = zone(name="2.0.10.in-addr.arpa", dn="DC=reverse", reverse=True)
    hints = zone(name="RootDNSServers", dn="DC=hints")
    c = scanning({})
    _, checked, _ = walk(c, [reverse, hints])
    assert not checked and any("AD-DNS-004" in n for n in c.notes)


def test_walk_ignores_conflict_names_and_cleans_what_it_shows() -> None:
    c = scanning(
        {
            FORWARD: [
                entry(f"DC=x,{FORWARD}", name=b"wpad\ncnf:guid", dnsRecord=[record()]),
                entry(f"DC=e,{FORWARD}", name=b"wpad.\x1b[31m", dnsRecord=[record()]),
            ],
            f"DC=e,{FORWARD}": [entry(f"DC=e,{FORWARD}", nTSecurityDescriptor=owned_by(HELPDESK))],
        }
    )
    scan, _, _ = walk(c)
    assert [n.name for _, n in scan.kept] == ["wpad.?[31m"]


def test_walk_notes_a_zone_it_could_not_list() -> None:
    c = scanning({FORWARD: LDAPInsufficientAccessRightsResult()})
    _, checked, zones = walk(c)
    assert not checked and not zones[0].nodes_read
    assert any("could not be listed" in n and "AD-DNS-007" in n for n in c.notes)


def test_walk_notes_unread_owners_and_data() -> None:
    c = scanning(
        {
            FORWARD: [
                node_entry("*", record()),
                entry(f"DC=y,{FORWARD}", name=b"plain"),
            ],
            f"DC=*,{FORWARD}": [],
        }
    )
    scan, _, _ = walk(c)
    assert scan.kept[0][1].owner is None
    text = " ".join(c.notes)
    assert "owner of 1" in text and "1 of 2 DNS names came back without dnsRecord" in text


def test_walk_survives_an_owner_that_does_not_parse() -> None:
    c = scanning(
        {
            FORWARD: [node_entry("*", record())],
            f"DC=*,{FORWARD}": [entry(f"DC=*,{FORWARD}", nTSecurityDescriptor=b"\x01" * 24)],
        }
    )
    scan, checked, _ = walk(c)
    assert checked and scan.kept[0][1].owner is None


def test_walk_notes_zones_whose_permissions_are_unread() -> None:
    c = scanning({FORWARD: []})
    walk(c, [zone(acl_read=False, aces=[])])
    assert any("AD-DNS-007 did not judge" in n for n in c.notes)


def test_walk_caps_each_kind_separately() -> None:
    wildcards = [node_entry(f"*.a{i}", record()) for i in range(MAX_KEPT_DNS_NODES + 3)]
    late = node_entry(f"z{MARKER}", record())
    c = scanning({FORWARD: [*wildcards, late]})
    scan, _, _ = walk(c)
    assert scan.kept_by_kind[dnsprop.KIND_WILDCARD] == MAX_KEPT_DNS_NODES
    # a flood of wildcards cannot push the marshaled name out
    assert scan.kept_by_kind[dnsprop.KIND_MARSHALED] == 1
    assert scan.dropped[dnsprop.KIND_WILDCARD] == 3
    assert any("3 more DNS names" in n for n in c.notes)


def test_walk_of_a_large_zone_does_not_grow() -> None:
    size = 40_000

    class Stream:
        def paged_search(self, base: str, flt: str, **kw: Any) -> Iterator[dict[str, Any]]:
            if base != FORWARD:
                return
            payload = record(data=b"\x00" * 4)
            for i in range(size):
                yield {
                    "type": "searchResEntry",
                    "dn": f"DC=h{i},{FORWARD}",
                    "raw_attributes": {"name": [f"h{i}".encode()], "dnsRecord": [payload]},
                }

    c = collector({}, ())
    c.conn.extend.standard = Stream()  # type: ignore[attr-defined]
    tracemalloc.start()
    scan, checked, _ = walk(c)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert checked and scan.names_seen == size and not scan.kept
    assert peak < 1_000_000
