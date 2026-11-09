"""Forest scanning against a fake forest: the per-domain collector is stubbed, the listing,
the choice of DCs, the manifest and the group expansion are the real code."""

from __future__ import annotations

import gc
import json
import os
import socket
import ssl
import threading
import weakref
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError

from ad_doctor import collect, coverage, forest, rollup
from ad_doctor.cli import main
from ad_doctor.collect import BindRejected, CollectError, Target
from ad_doctor.model import Snapshot

from .test_acl_adcs import sid_bytes
from .test_checks import snapshot

ROOT = "DC=corp,DC=example"
CHILD = "DC=child,DC=corp,DC=example"
OTHER = "DC=other,DC=example"
CONFIG = f"CN=Configuration,{ROOT}"
PASSWORD = "canary-Pa55word"


def entry(dn: str, **attrs: Any) -> dict[str, Any]:
    def encode(v: Any) -> bytes:
        return v if isinstance(v, bytes) else str(v).encode()

    raw = {
        k: [encode(v) for v in (vs if isinstance(vs, list) else [vs])] for k, vs in attrs.items()
    }
    return {"type": "searchResEntry", "dn": dn, "raw_attributes": raw}


@dataclass
class Fake:
    """A forest: every host answers only for its own domain, as a real DC does."""

    seed: str = ROOT
    root: str = ROOT
    crossrefs: list[dict[str, Any]] = field(default_factory=list)
    sites: list[dict[str, Any]] = field(default_factory=list)
    hosts: dict[str, str] = field(default_factory=dict)
    objects: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    sids: dict[str, str] = field(default_factory=dict)
    unreachable: set[str] = field(default_factory=set)
    rejects: set[str] = field(default_factory=set)
    calls: list[Target] = field(default_factory=list)
    # the forest root SID each domain's collection was given
    root_sids: dict[str, str] = field(default_factory=dict)
    opened: int = 0
    closed: int = 0

    def domain(
        self,
        dn: str,
        sid: str,
        *hosts: str,
        netbios: str = "",
        flags: int = 3,
        dns_root: str | None = None,
        enabled: str | None = None,
    ) -> None:
        name = forest.dns_name(dn)
        attrs: dict[str, Any] = {"cn": netbios or name, "nCName": dn, "systemFlags": flags}
        attrs["dnsRoot"] = dns_root if dns_root is not None else name
        if netbios:
            attrs["nETBIOSName"] = netbios
        if enabled is not None:
            attrs["Enabled"] = enabled
        self.crossrefs.append(entry(f"CN={attrs['cn']},CN=Partitions,{CONFIG}", **attrs))
        self.sids[dn.lower()] = sid
        self.objects[dn.lower()] = {dn.lower(): entry(dn, objectSid=sid_bytes(sid))}
        for host in hosts:
            self.server(dn, host)

    def server(
        self, dn: str, host: str, read_only: bool = False, serves: str | None = None
    ) -> None:
        site = f"CN={host},CN=Servers,CN=HQ,CN=Sites,{CONFIG}"
        category = f"CN=NTDS-DSA{'-RO' if read_only else ''},CN=Schema,{CONFIG}"
        self.sites.append(entry(site, dNSHostName=host, objectClass=["server"]))
        self.sites.append(
            entry(
                f"CN=NTDS Settings,{site}",
                objectClass=["nTDSDSA"],
                objectCategory=category,
                **{"msDS-HasDomainNCs": dn},
            )
        )
        self.hosts[host] = serves or dn

    def add(self, domain: str, dn: str, **attrs: Any) -> None:
        self.objects[domain.lower()][dn.lower()] = entry(dn, **attrs)

    def group(self, domain: str, name: str, rid: int, *members: str) -> str:
        dn = f"CN={name},CN=Users,{domain}"
        sid = f"{self.sids[domain.lower()]}-{rid}"
        self.add(
            domain,
            dn,
            objectClass=["group"],
            objectSid=sid_bytes(sid),
            sAMAccountName=name,
            **({"member": list(members)} if members else {}),
        )
        return dn

    def user(self, domain: str, name: str, rid: int, uac: int = 512, **attrs: Any) -> str:
        dn = f"CN={name},CN=Users,{domain}"
        self.add(
            domain,
            dn,
            objectClass=["user"],
            objectSid=sid_bytes(f"{self.sids[domain.lower()]}-{rid}"),
            sAMAccountName=name,
            userAccountControl=uac,
            **attrs,
        )
        return dn

    def connect(self, target: Target) -> Any:
        self.calls.append(target)
        if target.host in self.rejects:
            raise BindRejected(f"bind to {target.host}: invalidCredentials")
        if target.host in self.unreachable or target.host not in self.hosts:
            raise CollectError(f"bind to {target.host}:{target.port} failed: unreachable")
        self.opened += 1
        return Conn(self, self.hosts[target.host])

    def read(self, conn: Any, target: Target, root_sid: str) -> Snapshot:
        dn = conn.domain
        self.root_sids[forest.dns_name(dn)] = root_sid
        return replace(
            snapshot(),
            domain=forest.dns_name(dn),
            domain_dn=dn,
            domain_sid=self.sids[dn.lower()],
            notes=[f"from {target.host}"],
        )


class Conn:
    def __init__(self, fake: Fake, domain: str) -> None:
        self.fake = fake
        self.domain = domain
        info = SimpleNamespace(
            other={
                "defaultNamingContext": [domain],
                "configurationNamingContext": [CONFIG],
                "rootDomainNamingContext": [fake.root] if fake.root else [],
            }
        )
        self.server = SimpleNamespace(info=info)
        self.extend = SimpleNamespace(standard=SimpleNamespace(paged_search=self.paged_search))

    def unbind(self) -> None:
        self.fake.closed += 1

    def paged_search(self, base: str, flt: str, **kw: Any) -> Iterator[dict[str, Any]]:
        fake = self.fake
        if base == f"CN=Partitions,{CONFIG}":
            yield {"type": "searchResRef", "uri": ["ldap://elsewhere/"]}
            yield from fake.crossrefs
            return
        if base == f"CN=Sites,{CONFIG}":
            want = "nTDSDSA" if "nTDSDSA" in flt else "server"
            for e in fake.sites:
                if want.encode() in e["raw_attributes"]["objectClass"]:
                    yield e
            return
        own = fake.objects[self.domain.lower()]
        if flt.startswith("(primaryGroupID="):
            rid = flt.split("=")[1].rstrip(")")
            for e in own.values():
                if e["raw_attributes"].get("primaryGroupID") == [rid.encode()]:
                    yield e
            return
        if flt.startswith("(objectSid="):
            sid = flt.split("=")[1].rstrip(")")
            for e in own.values():
                if e["raw_attributes"].get("objectSid") == [sid_bytes(sid)]:
                    yield e
            return
        hit = own.get(base.lower())
        if hit is None:
            # another domain's object: a DC answers with a referral and no entry
            yield {"type": "searchResRef", "uri": [f"ldap://other/{base}"]}
            return
        yield hit


TARGET = Target("dc1.corp.example", port=10389, user="CORP\\auditor", password=PASSWORD)


def holder_names(group: dict[str, Any]) -> set[str]:
    return {h["name"] for h in group["holders"]}


def two() -> Fake:
    f = Fake()
    f.domain(ROOT, "S-1-5-21-1-1-1", "dc1.corp.example", netbios="CORP")
    f.domain(CHILD, "S-1-5-21-2-2-2", "dc1.child.corp.example", netbios="CHILD")
    admin = f.user(ROOT, "Administrator", 500)
    f.group(ROOT, "Enterprise Admins", 519, admin)
    f.group(ROOT, "Schema Admins", 518, admin)
    # configuration, schema and application partitions are not domains
    f.crossrefs.append(entry("CN=Enterprise Configuration", cn="c", nCName=CONFIG, systemFlags=1))
    f.crossrefs.append(
        entry("CN=Enterprise Schema", cn="s", nCName=f"CN=Schema,{CONFIG}", systemFlags=1)
    )
    f.crossrefs.append(
        entry("CN=Dns", cn="d", nCName=f"DC=ForestDnsZones,{ROOT}", systemFlags=5, dnsRoot="x")
    )
    return f


def three() -> Fake:
    f = two()
    f.domain(OTHER, "S-1-5-21-3-3-3", "dc1.other.example", netbios="OTHER")
    return f


def run(fake: Fake, out: Path, **kw: Any) -> dict[str, Any]:
    return forest.run(TARGET, out, connector=fake.connect, read=fake.read, **kw)


def rows(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["domain"]: r for r in manifest["domains"]}


def analyzed(out: Path, manifest: dict[str, Any]) -> None:
    """A report file for each read domain, as `scan --forest` writes them."""
    for row in manifest["domains"]:
        if row["status"] == "read":
            (out / f"{row['stem']}{forest.REPORT_SUFFIX}").write_text(
                json.dumps(
                    {
                        "tool": "ad-doctor",
                        "domain": row["domain"],
                        "version": "x",
                        "collected_at": "2026-01-01T00:00:00+00:00",
                        "score": 1,
                        "grade": "A",
                        "findings": [
                            {
                                "id": "AD-X-001",
                                "title": "t",
                                "severity": "high",
                                "objects": ["a"],
                            }
                        ],
                        "checks": ["AD-X-001"],
                        "notes": [],
                        "accepted": [],
                    }
                ),
                encoding="utf-8",
            )


# --- listing the forest ----------------------------------------------------------------------


def test_two_domains_one_snapshot_each(tmp_path: Path) -> None:
    fake = two()
    out = tmp_path / "f"
    m = run(fake, out)
    assert m["complete"] is True
    assert list(rows(m)) == ["corp.example", "child.corp.example"]
    assert [p.name for p in sorted(out.iterdir())] == [
        "child.corp.example.snapshot.json",
        "corp.example.snapshot.json",
        "forest.json",
    ]
    assert m["root"] == "corp.example"
    child = Snapshot.from_json(
        json.loads((out / "child.corp.example.snapshot.json").read_text(encoding="utf-8"))
    )
    assert child.domain == "child.corp.example"
    assert child.notes == ["from dc1.child.corp.example"]


def test_only_domain_crossrefs_become_domains(tmp_path: Path) -> None:
    m = run(two(), tmp_path / "f")
    assert {r["dn"] for r in m["domains"]} == {ROOT, CHILD}


def test_three_domain_forest_with_an_unreachable_child(tmp_path: Path) -> None:
    fake = three()
    fake.unreachable.add("dc1.child.corp.example")
    out = tmp_path / "f"
    m = run(fake, out)
    assert m["complete"] is False
    row = rows(m)["child.corp.example"]
    assert row["status"] == "not_evaluated"
    assert "unreachable" in row["reason"]
    assert rows(m)["other.example"]["status"] == "read"
    assert not (out / "child.corp.example.snapshot.json").exists()
    analyzed(out, m)
    doc = rollup.build_forest(out)
    assert doc["forest"]["complete"] is False
    assert doc["forest"]["read"] == 2 and doc["forest"]["domains"] == 3
    assert doc["checks"][0]["not_judged"] == ["child.corp.example"]
    text = rollup.render_text(doc)
    assert "INCOMPLETE" in text and "2 of 3 domains read" in text
    assert "1/2 read, of 3 domains" not in text and "2/2 read, of 3 domains" in text
    assert "child.corp.example: bind" in text


def test_a_crossref_that_points_outside_is_a_referral_not_a_domain(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs.append(
        entry("CN=Ext", cn="Ext", nCName="DC=external,DC=test", systemFlags=0, dnsRoot="ldap.test")
    )
    out = tmp_path / "f"
    m = run(fake, out)
    assert m["referrals"] == [{"name": "Ext", "target": "ldap.test", "dn": "DC=external,DC=test"}]
    assert "external.test" not in rows(m)
    assert m["complete"] is True
    analyzed(out, m)
    assert "Ext: ldap.test" in rollup.render_text(rollup.build_forest(out))


def test_a_dc_that_serves_another_domain_is_not_collected(tmp_path: Path) -> None:
    fake = two()
    fake.server(CHILD, "aaa.child.corp.example", serves=ROOT)
    m = run(fake, tmp_path / "f")
    assert rows(m)["child.corp.example"]["status"] == "read"
    assert rows(m)["child.corp.example"]["dc"] == "dc1.child.corp.example"
    fake = two()
    fake.hosts["dc1.child.corp.example"] = ROOT
    m = run(fake, tmp_path / "g")
    row = rows(m)["child.corp.example"]
    assert row["status"] == "not_evaluated" and "serves" in row["reason"]
    assert m["complete"] is False


def test_writable_dcs_are_tried_before_read_only_ones(tmp_path: Path) -> None:
    fake = Fake()
    fake.domain(ROOT, "S-1-5-21-1-1-1", "dc1.corp.example")
    fake.domain(CHILD, "S-1-5-21-2-2-2")
    fake.server(CHILD, "aa-rodc.child.corp.example", read_only=True)
    fake.server(CHILD, "zz.child.corp.example")
    fake.user(ROOT, "a", 500)
    m = run(fake, tmp_path / "f")
    assert rows(m)["child.corp.example"]["dc"] == "zz.child.corp.example"


def test_a_refused_bind_stops_at_the_first_dc_of_that_domain(tmp_path: Path) -> None:
    fake = two()
    fake.server(CHILD, "dc0.child.corp.example")
    fake.rejects.add("dc0.child.corp.example")
    m = run(fake, tmp_path / "f")
    assert [t.host for t in fake.calls].count("dc1.child.corp.example") == 0
    assert "invalidCredentials" in rows(m)["child.corp.example"]["reason"]


def test_a_domain_with_many_dead_dcs_is_given_up_with_a_reason(tmp_path: Path) -> None:
    fake = two()
    fake.unreachable.add("dc1.child.corp.example")
    for i in range(8):
        fake.server(CHILD, f"dd{i}.child.corp.example")
        fake.unreachable.add(f"dd{i}.child.corp.example")
    m = run(fake, tmp_path / "f")
    tried = [t.host for t in fake.calls if t.host.endswith("child.corp.example")]
    assert len(tried) == forest.MAX_DC_TRIES
    assert "more domain controllers not tried" in rows(m)["child.corp.example"]["reason"]


def test_same_first_label_keeps_two_domains_apart(tmp_path: Path) -> None:
    fake = Fake()
    a, b = "DC=corp,DC=alpha,DC=example", "DC=corp,DC=beta,DC=example"
    fake.seed, fake.root = a, a
    fake.domain(a, "S-1-5-21-1-1-1", "dc.corp.alpha.example", netbios="CORP")
    fake.domain(b, "S-1-5-21-2-2-2", "dc.corp.beta.example", netbios="CORP2")
    fake.group(a, "Enterprise Admins", 519, fake.user(b, "joe", 1200))
    fake.group(a, "Schema Admins", 518, fake.user(a, "Administrator", 500))
    target = replace(TARGET, host="dc.corp.alpha.example")
    out = tmp_path / "f"
    m = forest.run(target, out, connector=fake.connect, read=fake.read)
    assert m["complete"] is True
    assert (out / "corp.alpha.example.snapshot.json").exists()
    assert (out / "corp.beta.example.snapshot.json").exists()
    analyzed(out, m)
    doc = rollup.build_forest(out)
    assert sorted(r["domain"] for r in doc["domains"]) == [
        "corp.alpha.example",
        "corp.beta.example",
    ]
    assert m["groups"]["Enterprise Admins"]["holders"][0]["domain"] == "corp.beta.example"


def test_a_child_dn_is_not_taken_for_its_parent() -> None:
    domains = [forest.Domain(ROOT, "corp.example"), forest.Domain(CHILD, "child.corp.example")]
    found = forest._domain_of(f"CN=x,CN=Users,{CHILD}", domains)
    assert found is not None and found.dn == CHILD
    root_user = forest._domain_of(f"CN=x,CN=Users,{ROOT}", domains)
    assert root_user is not None and root_user.dn == ROOT
    assert forest._domain_of("CN=x,DC=notcorp,DC=example", domains) is None


def test_hostile_directory_names_are_not_used_as_paths() -> None:
    for dn in ("DC=..,DC=..,DC=etc", "DC=a/b,DC=c", "DC=a b,DC=c", "DC=" + "x" * 300):
        stem = forest.file_stem(dn)
        assert stem.startswith("domain-") and "/" not in stem and ".." not in stem
    assert forest.file_stem("DC=Corp,DC=Example") == "corp.example"


def test_disabled_crossref_is_not_evaluated(tmp_path: Path) -> None:
    fake = two()
    fake.domain("DC=new,DC=example", "S-1-5-21-9-9-9", enabled="FALSE")
    m = run(fake, tmp_path / "f")
    row = rows(m)["new.example"]
    assert row["status"] == "not_evaluated" and "disabled" in row["reason"]
    assert m["complete"] is False
    assert not any(t.host == "new.example" for t in fake.calls)


def test_a_crossref_with_unreadable_flags_makes_the_result_partial(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs.append(entry("CN=Hidden", cn="Hidden"))
    m = run(fake, tmp_path / "f")
    assert m["partial"] is True and m["complete"] is False
    assert any("Hidden" in n for n in m["notes"])


def test_the_seed_domain_is_scanned_even_when_its_crossref_is_hidden(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs = fake.crossrefs[1:]  # drop the crossRef of the domain scanned first
    m = run(fake, tmp_path / "f")
    assert m["partial"] is True and m["complete"] is False
    assert rows(m)["corp.example"]["status"] == "read"


def test_no_crossrefs_is_an_error_not_an_empty_forest(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs = []
    with pytest.raises(CollectError, match="crossRef"):
        run(fake, tmp_path / "f")
    assert not (tmp_path / "f").exists()


def test_no_server_object_falls_back_to_the_dns_name(tmp_path: Path) -> None:
    fake = two()
    fake.domain("DC=lone,DC=example", "S-1-5-21-5-5-5")
    fake.hosts["lone.example"] = "DC=lone,DC=example"
    m = run(fake, tmp_path / "f")
    assert rows(m)["lone.example"]["dc"] == "lone.example"


def test_no_dc_known_at_all_is_not_evaluated(tmp_path: Path) -> None:
    fake = two()
    fake.domain("DC=lone,DC=example", "S-1-5-21-5-5-5", dns_root="")
    m = run(fake, tmp_path / "f")
    assert "no domain controller" in rows(m)["lone.example"]["reason"]


# --- the target each DC gets -----------------------------------------------------------------


def test_the_scanned_dc_keeps_its_target_and_others_get_standard_ports(tmp_path: Path) -> None:
    fake = two()
    run(fake, tmp_path / "f")
    seed = [t for t in fake.calls if t.host == "dc1.corp.example"]
    assert all(t == TARGET for t in seed)
    child = next(t for t in fake.calls if t.host == "dc1.child.corp.example")
    assert (child.port, child.smb_port, child.plain_port) == (389, 445, 389)
    assert child.password == PASSWORD and child.user == TARGET.user


def test_ldaps_and_switched_off_probes_carry_over() -> None:
    target = replace(TARGET, use_ssl=True, plain_port=0, http_port=0, https_port=0, smb_port=4445)
    other = forest._other_dc(target, "dc2")
    assert other.port == 636 and other.use_ssl and other.smb_port == 445
    assert (other.plain_port, other.http_port, other.https_port) == (0, 0, 0)


def test_forest_connections_do_not_chase_referrals(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = MagicMock(return_value=MagicMock())
    monkeypatch.setattr(collect.ldap3, "Connection", conn)
    forest._connector(Target("h"))
    assert conn.call_args.kwargs["auto_referrals"] is False
    collect.connect(Target("h"))
    assert conn.call_args.kwargs["auto_referrals"] is True


def test_refused_credentials_are_told_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a: Any, **kw: Any) -> None:
        raise LDAPInvalidCredentialsResult()

    monkeypatch.setattr(collect.ldap3, "Connection", refuse)
    with pytest.raises(BindRejected):
        collect.connect(Target("h", user="u@x", password="p"))


def test_a_socket_failure_is_not_a_refused_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    def down(*a: Any, **kw: Any) -> None:
        raise LDAPSocketOpenError("down")

    monkeypatch.setattr(collect.ldap3, "Connection", down)
    with pytest.raises(CollectError) as caught:
        collect.connect(Target("h", user="u@x", password="p"))
    assert not isinstance(caught.value, BindRejected)


def test_the_password_stays_out_of_everything_written(tmp_path: Path) -> None:
    fake = three()
    real = fake.connect

    def noisy(target: Target) -> Any:
        if target.host == "dc1.child.corp.example":
            raise CollectError(f"bind failed with {target.password}")
        return real(target)

    out = tmp_path / "f"
    m = forest.run(TARGET, out, connector=noisy, read=fake.read)
    assert PASSWORD not in json.dumps(m)
    for path in out.iterdir():
        assert PASSWORD not in path.read_text(encoding="utf-8")


# --- who holds the forest-root groups --------------------------------------------------------


def test_a_child_member_is_followed_into_its_domain(tmp_path: Path) -> None:
    fake = two()
    joe = fake.user(CHILD, "joe", 1100)
    fake.group(ROOT, "Enterprise Admins", 519, joe, f"CN=Administrator,CN=Users,{ROOT}")
    m = run(fake, tmp_path / "f")
    ea = m["groups"]["Enterprise Admins"]
    assert ea["status"] == "read"
    assert holder_names(ea) == {"joe", "Administrator"}
    assert next(h for h in ea["holders"] if h["name"] == "joe")["domain"] == "child.corp.example"
    assert holder_names(m["groups"]["Schema Admins"]) == {"Administrator"}


def test_nesting_crosses_domains_and_a_cycle_ends(tmp_path: Path) -> None:
    fake = two()
    joe = fake.user(CHILD, "joe", 1100)
    fake.user(ROOT, "ann", 1101)
    ann = f"CN=ann,CN=Users,{ROOT}"
    inner = fake.group(ROOT, "Inner", 1200, ann, f"CN=Mid,CN=Users,{CHILD}")
    mid = fake.group(CHILD, "Mid", 1201, joe, inner)
    fake.group(ROOT, "Enterprise Admins", 519, mid)
    m = run(fake, tmp_path / "f")
    ea = m["groups"]["Enterprise Admins"]
    assert ea["status"] == "read" and holder_names(ea) == {"joe", "ann"}
    assert next(h for h in ea["holders"] if h["name"] == "joe")["via"] == ["Mid"]
    assert next(h for h in ea["holders"] if h["name"] == "ann")["via"] == ["Mid", "Inner"]


def test_primary_group_members_are_holders(tmp_path: Path) -> None:
    fake = two()
    fake.user(ROOT, "hidden", 1300, primaryGroupID=519)
    m = run(fake, tmp_path / "f")
    ea = m["groups"]["Enterprise Admins"]
    assert "hidden" in holder_names(ea)
    assert next(h for h in ea["holders"] if h["name"] == "hidden")["primary_group"] is True


def test_foreign_principals_and_disabled_accounts_are_named(tmp_path: Path) -> None:
    fake = two()
    fsp = f"CN=S-1-5-21-77-77-77-1000,CN=ForeignSecurityPrincipals,{ROOT}"
    fake.add(
        ROOT,
        fsp,
        objectClass=["foreignSecurityPrincipal"],
        objectSid=sid_bytes("S-1-5-21-77-77-77-1000"),
    )
    off = fake.user(ROOT, "off", 1400, uac=514)
    fake.group(ROOT, "Enterprise Admins", 519, fsp, off)
    m = run(fake, tmp_path / "f")
    holders = {h["name"]: h for h in m["groups"]["Enterprise Admins"]["holders"]}
    assert holders["S-1-5-21-77-77-77-1000"]["kind"] == "foreign"
    assert holders["off"]["enabled"] is False


def test_a_member_in_an_unread_domain_is_not_silently_dropped(tmp_path: Path) -> None:
    fake = two()
    fake.unreachable.add("dc1.child.corp.example")
    fake.group(ROOT, "Enterprise Admins", 519, f"CN=joe,CN=Users,{CHILD}")
    m = run(fake, tmp_path / "f")
    ea = m["groups"]["Enterprise Admins"]
    assert ea["status"] == "partial" and not ea["holders"]
    assert ea["unresolved"] == [
        {"name": f"CN=joe,CN=Users,{CHILD}", "reason": "child.corp.example could not be read"}
    ]


def test_a_member_outside_the_forest_or_hidden_is_unresolved(tmp_path: Path) -> None:
    fake = two()
    fake.group(ROOT, "Enterprise Admins", 519, "CN=x,DC=elsewhere,DC=test", f"CN=gone,{ROOT}")
    m = run(fake, tmp_path / "f")
    reasons = {u["reason"] for u in m["groups"]["Enterprise Admins"]["unresolved"]}
    assert reasons == {
        "outside every domain of this forest",
        "not returned: hidden, or not readable",
    }
    assert m["complete"] is False


def test_a_group_with_no_visible_members_is_not_clean(tmp_path: Path) -> None:
    fake = two()
    fake.group(ROOT, "Enterprise Admins", 519)
    m = run(fake, tmp_path / "f")
    ea = m["groups"]["Enterprise Admins"]
    assert ea["status"] == "partial"
    assert "no members visible" in ea["unresolved"][0]["reason"]


def test_the_root_not_read_leaves_the_groups_not_evaluated(tmp_path: Path) -> None:
    fake = two()
    fake.seed = CHILD
    fake.unreachable.add("dc1.corp.example")
    target = replace(TARGET, host="dc1.child.corp.example")
    m = forest.run(target, tmp_path / "f", connector=fake.connect, read=fake.read)
    assert m["groups"]["Enterprise Admins"]["status"] == "not_evaluated"
    assert m["complete"] is False
    assert next(iter(rows(m))) == "child.corp.example"


def test_connections_are_closed(tmp_path: Path) -> None:
    fake = three()
    run(fake, tmp_path / "f")
    assert fake.opened == fake.closed


# --- the manifest and the run --------------------------------------------------------------


def test_a_run_cut_short_still_reads_as_incomplete(tmp_path: Path) -> None:
    fake = three()
    out = tmp_path / "f"

    def stop(snap: Snapshot, stem: str) -> None:
        if stem == "child.corp.example":
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run(fake, out, analyze=stop)
    data = json.loads((out / forest.MANIFEST).read_text(encoding="utf-8"))
    assert data["complete"] is False
    assert {r["domain"]: r["status"] for r in data["domains"]} == {
        "corp.example": "read",
        "child.corp.example": "read",
        "other.example": "pending",
    }
    assert "pending" in {r["status"] for r in data["domains"]}


def test_an_existing_scan_is_not_overwritten(tmp_path: Path) -> None:
    out = tmp_path / "f"
    run(two(), out)
    with pytest.raises(CollectError, match="already holds"):
        run(two(), out)


def test_files_are_private(tmp_path: Path) -> None:
    out = tmp_path / "f"
    run(two(), out)
    for path in out.iterdir():
        assert path.stat().st_mode & 0o077 == 0


def test_an_analysis_failure_does_not_lose_the_other_domains(tmp_path: Path) -> None:
    fake = two()

    def analyze(snap: Snapshot, stem: str) -> None:
        if stem == "corp.example":
            raise ValueError("boom")

    m = run(fake, tmp_path / "f", analyze=analyze)
    assert rows(m)["corp.example"]["status"] == "not_evaluated"
    assert "boom" in rows(m)["corp.example"]["reason"]
    assert rows(m)["child.corp.example"]["status"] == "read"


# --- the command line ------------------------------------------------------------------------


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> Fake:
    fake = three()
    monkeypatch.setattr(forest, "_connector", fake.connect)
    monkeypatch.setattr(forest, "_read", fake.read)
    monkeypatch.setenv("AD_DOCTOR_PASSWORD", PASSWORD)

    def no_prompt(*a: Any, **kw: Any) -> str:
        raise AssertionError("prompted for a password")

    monkeypatch.setattr("getpass.getpass", no_prompt)
    return fake


ARGS = ["dc1.corp.example", "--forest", "-u", "CORP\\auditor"]


def test_collect_forest_writes_snapshots_and_says_what_it_read(
    cli: Fake, tmp_path: Path, capsys: Any
) -> None:
    out = tmp_path / "f"
    assert main(["collect", *ARGS, "-o", str(out)]) == 0
    assert "3 of 3 domains read, complete" in capsys.readouterr().out
    assert (out / "other.example.snapshot.json").exists()


def test_collect_forest_incomplete_exits_3(cli: Fake, tmp_path: Path, capsys: Any) -> None:
    cli.unreachable.add("dc1.other.example")
    assert main(["collect", *ARGS, "-o", str(tmp_path / "f")]) == 3
    out = capsys.readouterr().out
    assert "2 of 3 domains read, INCOMPLETE" in out and "other.example: not evaluated" in out


def test_scan_forest_writes_reports_and_rolls_up(cli: Fake, tmp_path: Path, capsys: Any) -> None:
    out = tmp_path / "f"
    assert main(["scan", *ARGS, "-o", str(out), "-f", "markdown"]) == 0
    printed = capsys.readouterr().out
    assert "3 of 3 domains read, all domains read" in printed
    assert "Enterprise Admins (forest root corp.example): 1 holder" in printed
    assert (out / "child.corp.example.report.json").exists()
    assert (out / "child.corp.example.report.md").exists()
    # the report of a domain is the report of its snapshot
    snap_path = out / "child.corp.example.snapshot.json"
    again = tmp_path / "again.json"
    assert main(["analyze", str(snap_path), "-f", "json", "-o", str(again)]) == 0
    first = json.loads((out / "child.corp.example.report.json").read_text(encoding="utf-8"))
    assert first == json.loads(again.read_text(encoding="utf-8"))


def test_scan_forest_incomplete_exits_3_even_when_the_gate_fires(
    cli: Fake, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr("ad_doctor.cli._fails", lambda found, level: True)
    assert main(["scan", *ARGS, "-o", str(tmp_path / "whole"), "--fail-on", "high"]) == 2
    capsys.readouterr()
    cli.unreachable.add("dc1.other.example")
    assert main(["scan", *ARGS, "-o", str(tmp_path / "a")]) == 3
    assert "INCOMPLETE" in capsys.readouterr().out
    assert main(["scan", *ARGS, "-o", str(tmp_path / "b"), "--fail-on", "high"]) == 3


def test_rollup_forest_of_a_collect_run_says_reports_are_missing(
    cli: Fake, tmp_path: Path, capsys: Any
) -> None:
    out = tmp_path / "f"
    assert main(["collect", *ARGS, "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["rollup", "--forest", str(out)]) == 3
    printed = capsys.readouterr().out
    assert "0 of 3 domains read" in printed and "no report" in printed


def test_rollup_forest_after_analyzing_each_snapshot(
    cli: Fake, tmp_path: Path, capsys: Any
) -> None:
    out = tmp_path / "f"
    assert main(["collect", *ARGS, "-o", str(out)]) == 0
    for path in out.glob("*.snapshot.json"):
        name = path.name.replace(".snapshot.json", ".report.json")
        assert main(["analyze", str(path), "-f", "json", "-o", str(out / name)]) == 0
    capsys.readouterr()
    assert main(["rollup", "--forest", str(out), "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["forest"]["complete"] is True and doc["forest"]["read"] == 3
    assert main(["rollup", "--forest", str(out), "-f", "markdown"]) == 0
    assert "## Enterprise Admins" in capsys.readouterr().out


def test_rollup_forest_refuses_a_report_of_another_domain(
    tmp_path: Path,
) -> None:
    fake = two()
    out = tmp_path / "f"
    m = run(fake, out)
    analyzed(out, m)
    swap = out / "child.corp.example.report.json"
    data = json.loads(swap.read_text(encoding="utf-8"))
    data["domain"] = "corp.example"
    swap.write_text(json.dumps(data), encoding="utf-8")
    f = rollup.build_forest(out)["forest"]
    assert f["complete"] is False
    assert f["not_evaluated"][0]["domain"] == "child.corp.example"


def test_a_one_domain_forest_rolls_up_without_a_second_report(tmp_path: Path) -> None:
    fake = Fake()
    fake.domain(ROOT, "S-1-5-21-1-1-1", "dc1.corp.example")
    admin = fake.user(ROOT, "Administrator", 500)
    fake.group(ROOT, "Enterprise Admins", 519, admin)
    fake.group(ROOT, "Schema Admins", 518, admin)
    out = tmp_path / "f"
    m = run(fake, out)
    analyzed(out, m)
    doc = rollup.build_forest(out)
    assert doc["forest"]["complete"] is True and doc["notes"] == []


def test_rollup_forest_rejects_other_directories(tmp_path: Path, capsys: Any) -> None:
    assert main(["rollup", "--forest", str(tmp_path)]) == 1
    (tmp_path / forest.MANIFEST).write_text("{}", encoding="utf-8")
    assert main(["rollup", "--forest", str(tmp_path)]) == 1
    assert "not the result of a --forest run" in capsys.readouterr().err


def test_rollup_takes_a_forest_or_reports_not_both(tmp_path: Path, capsys: Any) -> None:
    assert main(["rollup", "--forest", str(tmp_path), str(tmp_path / "x.json")]) == 1
    assert "do not name reports" in capsys.readouterr().err


def test_rollup_without_anything_is_still_a_usage_error(capsys: Any) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["rollup"])
    assert caught.value.code == 2
    assert "REPORT" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flags",
    [
        ["--baseline", "x.json"],
        ["--accept", "x.toml"],
        ["--invariants", "x.toml"],
        ["--fixes", "x.ps1"],
        ["--preflight", "x.ps1"],
        ["--tier0", "JUMP$"],
        ["--tier0-file", "x.toml"],
    ],
)
def test_options_about_one_domain_are_refused(
    cli: Fake, tmp_path: Path, flags: list[str], capsys: Any
) -> None:
    out = tmp_path / "f"
    assert main(["scan", *ARGS, "-o", str(out), *flags]) == 1
    assert "--forest does not take" in capsys.readouterr().err
    assert not out.exists()
    assert not cli.calls


def test_scan_forest_needs_a_directory(cli: Fake, capsys: Any) -> None:
    assert main(["scan", *ARGS]) == 1
    assert "needs -o DIR" in capsys.readouterr().err


def test_no_flag_on_the_command_line_can_carry_a_password() -> None:
    import ad_doctor.cli as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert '"--password"' not in source and '"-p"' not in source
    assert "getpass" not in Path(forest.__file__).read_text(encoding="utf-8")


def test_without_the_flag_the_normal_path_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    seen: list[Target] = []

    def collected(target: Target) -> Snapshot:
        seen.append(target)
        return snapshot()

    def boom(*a: Any, **kw: Any) -> None:
        raise AssertionError("forest code ran")

    monkeypatch.setattr("ad_doctor.cli.collect", collected)
    monkeypatch.setattr(forest, "run", boom)
    out = tmp_path / "plain.json"
    assert main(["collect", "dc", "-o", str(out)]) == 0
    assert len(seen) == 1 and out.is_file()


def test_a_scan_read_as_text_is_never_called_clean_with_a_gap(tmp_path: Path) -> None:
    fake = three()
    fake.unreachable.add("dc1.child.corp.example")
    out = tmp_path / "f"
    m = run(fake, out)
    analyzed(out, m)
    doc = rollup.build_forest(out)
    assert "all domains read" not in rollup.render_text(doc)
    assert "all domains read" not in rollup.render_markdown(doc)
    assert "INCOMPLETE" in rollup.render_markdown(doc)


def test_the_rollup_prints_why_the_list_of_domains_is_short(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs.append(entry("CN=Hidden", cn="Hidden"))
    out = tmp_path / "f"
    m = run(fake, out)
    analyzed(out, m)
    doc = rollup.build_forest(out)
    assert "Forest notes:" in rollup.render_text(doc) and "Hidden" in rollup.render_text(doc)
    assert "## Forest notes" in rollup.render_markdown(doc)
    assert doc["forest"]["complete"] is False


def test_the_manifest_names_the_dcs_it_knew(tmp_path: Path) -> None:
    fake = two()
    fake.server(CHILD, "dc0.child.corp.example", read_only=True)
    m = run(fake, tmp_path / "f")
    assert rows(m)["child.corp.example"]["dcs"] == [
        "dc1.child.corp.example",
        "dc0.child.corp.example",
    ]


@pytest.mark.parametrize(
    ("fmt", "ext"),
    [("text", "txt"), ("html", "html"), ("sarif", "sarif"), ("junit", "xml")],
)
def test_every_report_format_is_written_per_domain(
    cli: Fake, tmp_path: Path, fmt: str, ext: str
) -> None:
    out = tmp_path / "f"
    assert main(["scan", *ARGS, "-o", str(out), "-f", fmt]) == 0
    assert (out / f"other.example.report.{ext}").stat().st_size > 0
    assert (out / "other.example.report.json").exists()


# --- the forest root's SID in other domains ---------------------------------------------------


ROOT_SID = "S-1-5-21-1-1-1"
CHILD_SEED = replace(TARGET, host="dc1.child.corp.example")


def from_child(fake: Fake, out: Path, **kw: Any) -> dict[str, Any]:
    fake.seed = CHILD
    return forest.run(CHILD_SEED, out, connector=fake.connect, read=fake.read, **kw)


def test_a_child_seed_gets_the_root_sid_from_a_dc_of_the_root(tmp_path: Path) -> None:
    fake = two()
    m = from_child(fake, tmp_path / "f")
    assert fake.root_sids == {"child.corp.example": ROOT_SID, "corp.example": ROOT_SID}
    assert m["complete"] is True and m["partial"] is False
    assert m["groups"]["Enterprise Admins"]["status"] == "read"


def test_the_root_sid_is_read_once_when_the_seed_is_the_root(tmp_path: Path) -> None:
    fake = three()
    run(fake, tmp_path / "f")
    assert set(fake.root_sids.values()) == {ROOT_SID}
    # the listing, the collection and the group step: no bind of its own for the SID
    assert [t.host for t in fake.calls].count("dc1.corp.example") == 3


def test_a_child_dc_that_refers_the_root_read_still_yields_the_root_sid(tmp_path: Path) -> None:
    """The real collector over a child DC, which answers a read of the root's DN with a
    referral (result 10): the SID found at a root DC reaches its tier 0."""
    fake = two()
    fake.seed = CHILD

    class HeadOnly(Conn):
        def paged_search(self, base: str, flt: str, **kw: Any) -> Iterator[dict[str, Any]]:
            # of a domain's own contents only its head: the root read below is what matters
            if base.lower() not in self.fake.objects or "Class=domain" in flt or "Class=*" in flt:
                yield from super().paged_search(base, flt, **kw)

    def connector(target: Target) -> Any:
        fake.connect(target)
        return HeadOnly(fake, fake.hosts[target.host])

    def info(conn: HeadOnly) -> HeadOnly:
        # the child's rootDSE names the root as the forest root
        conn.server.info.other["rootDomainNamingContext"] = [ROOT]
        return conn

    target = replace(
        CHILD_SEED, probes=False, sysvol=False, plain_port=0, http_port=0, https_port=0
    )
    out = tmp_path / "f"
    forest.run(target, out, connector=lambda t: info(connector(t)))
    doc = json.loads((out / "child.corp.example.snapshot.json").read_text(encoding="utf-8"))
    assert doc["domain_sid"] == "S-1-5-21-2-2-2"
    assert doc["root_sid"] == ROOT_SID
    assert not any("forest root SID not readable" in n for n in doc["notes"])
    assert f"{ROOT_SID}-519" in Snapshot.from_json(doc).tier0_sids()


def test_a_root_sid_that_cannot_be_read_is_not_a_complete_forest(tmp_path: Path) -> None:
    fake = two()
    fake.unreachable.add("dc1.corp.example")
    m = from_child(fake, tmp_path / "f")
    assert fake.root_sids == {"child.corp.example": ""}
    assert m["partial"] is True and m["complete"] is False
    assert any("SID of the forest root was not read" in n for n in m["notes"])


# --- one domain's failure stays that domain's ------------------------------------------------


def failing_on(fake: Fake, host: str, exc: Exception) -> forest.Connector:
    def connector(target: Target) -> Any:
        if target.host == host:
            raise exc
        return fake.connect(target)

    return connector


@pytest.mark.parametrize(
    "exc",
    [
        UnicodeEncodeError("idna", "x", 0, 1, "label too long"),
        UnicodeDecodeError("ascii", b"\x82", 0, 1, "ordinal not in range"),
        type("GSSError", (Exception,), {})("Server not found in Kerberos database"),
    ],
)
def test_any_failure_to_connect_leaves_the_other_domains_read(
    tmp_path: Path, exc: Exception
) -> None:
    fake = three()
    connector = failing_on(fake, "dc1.child.corp.example", exc)
    m = forest.run(TARGET, tmp_path / "f", connector=connector, read=fake.read)
    assert rows(m)["child.corp.example"]["status"] == "not_evaluated"
    assert rows(m)["other.example"]["status"] == "read"
    assert m["groups"]["Enterprise Admins"]["status"] == "read"
    assert m["complete"] is False


def test_a_failure_to_connect_moves_on_to_the_next_dc_of_that_domain(tmp_path: Path) -> None:
    fake = two()
    fake.server(CHILD, "dc0.child.corp.example")
    exc = UnicodeDecodeError("ascii", b"\x82", 0, 1, "bad reply")
    connector = failing_on(fake, "dc0.child.corp.example", exc)
    m = forest.run(TARGET, tmp_path / "f", connector=connector, read=fake.read)
    row = rows(m)["child.corp.example"]
    assert row["status"] == "read" and row["dc"] == "dc1.child.corp.example"
    assert any("read from dc1.child.corp.example, not dc0" in n for n in m["notes"])


def test_the_password_is_scrubbed_from_any_failure(tmp_path: Path) -> None:
    fake = two()
    connector = failing_on(fake, "dc1.child.corp.example", RuntimeError(f"bad {PASSWORD}"))
    m = forest.run(TARGET, tmp_path / "f", connector=connector, read=fake.read)
    assert PASSWORD not in json.dumps(m)
    assert "***" in rows(m)["child.corp.example"]["reason"]


def test_a_later_failure_in_the_group_step_is_a_note(tmp_path: Path) -> None:
    fake = two()
    joe = fake.user(CHILD, "joe", 1100)
    fake.group(ROOT, "Enterprise Admins", 519, joe)
    real = fake.connect
    seen: list[str] = []

    def connector(target: Target) -> Any:
        seen.append(target.host)
        if target.host == "dc1.child.corp.example" and seen.count(target.host) > 1:
            raise type("GSSError", (Exception,), {})("no ticket")
        return real(target)

    m = forest.run(TARGET, tmp_path / "f", connector=connector, read=fake.read)
    assert any("not reachable again for group members: no ticket" in n for n in m["notes"])
    assert m["groups"]["Enterprise Admins"]["status"] == "partial"


def test_a_broken_group_read_marks_the_group_and_ends_normally(tmp_path: Path) -> None:
    fake = two()
    original = forest._expand

    def expand(name: str, *a: Any, **kw: Any) -> dict[str, Any]:
        if name == "Enterprise Admins":
            raise UnicodeDecodeError("ascii", b"\x82", 0, 1, f"malformed {PASSWORD}")
        return original(name, *a, **kw)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(forest, "_expand", expand)
        m = run(fake, tmp_path / "f")
    assert m["groups"]["Enterprise Admins"]["status"] == "not_evaluated"
    assert PASSWORD not in json.dumps(m)
    assert m["groups"]["Schema Admins"]["status"] == "read"
    assert m["complete"] is False


def test_a_connection_that_breaks_on_close_costs_nothing(tmp_path: Path) -> None:
    fake = three()
    real = fake.connect

    def connector(target: Target) -> Any:
        conn = real(target)

        def unbind() -> None:
            raise LDAPSocketOpenError("gone")

        conn.unbind = unbind
        return conn

    m = forest.run(TARGET, tmp_path / "f", connector=connector, read=fake.read)
    assert m["complete"] is True


# --- read-only domain controllers ------------------------------------------------------------


def with_rodc(writable_up: bool) -> Fake:
    fake = Fake()
    fake.domain(ROOT, ROOT_SID, "dc1.corp.example")
    admin = fake.user(ROOT, "Administrator", 500)
    fake.group(ROOT, "Enterprise Admins", 519, admin)
    fake.group(ROOT, "Schema Admins", 518, admin)
    fake.domain(CHILD, "S-1-5-21-2-2-2")
    fake.server(CHILD, "aa-rw.child.corp.example")
    fake.server(CHILD, "zz-ro.child.corp.example", read_only=True)
    if not writable_up:
        fake.unreachable.add("aa-rw.child.corp.example")
    return fake


def test_a_domain_read_from_an_rodc_says_so_and_names_what_it_cannot_judge(tmp_path: Path) -> None:
    out = tmp_path / "f"
    m = run(with_rodc(writable_up=False), out)
    row = rows(m)["child.corp.example"]
    assert row["status"] == "read" and row["read_only"] is True
    assert any("read-only DC zz-ro.child.corp.example" in n for n in m["notes"])
    doc = json.loads((out / "child.corp.example.snapshot.json").read_text(encoding="utf-8"))
    note = next(n for n in doc["notes"] if "read-only DC" in n)
    assert coverage.note_checks(note) == ["AD-SEC-002"]


def test_a_domain_read_from_a_writable_dc_has_no_such_note(tmp_path: Path) -> None:
    out = tmp_path / "f"
    m = run(with_rodc(writable_up=True), out)
    assert rows(m)["child.corp.example"]["read_only"] is False
    assert rows(m)["corp.example"]["read_only"] is False
    doc = json.loads((out / "child.corp.example.snapshot.json").read_text(encoding="utf-8"))
    assert not any("read-only DC" in n for n in doc["notes"])


# --- memory ----------------------------------------------------------------------------------


def test_no_earlier_snapshot_is_alive_during_the_next_collection(tmp_path: Path) -> None:
    fake = three()
    earlier: list[weakref.ref[Snapshot]] = []
    alive: list[list[bool]] = []

    def read(conn: Any, target: Target, root_sid: str) -> Snapshot:
        gc.collect()
        alive.append([ref() is not None for ref in earlier])
        snap = fake.read(conn, target, root_sid)
        earlier.append(weakref.ref(snap))
        return snap

    forest.run(TARGET, tmp_path / "f", connector=fake.connect, read=read)
    assert alive == [[], [False], [False, False]]


# --- which hosts receive the credentials -----------------------------------------------------

BAD_HOSTS = [
    "127.0.0.1:3899",
    "127.0.0.1",
    "ldap://127.0.0.1:3898",
    "ldaps://dc1.child.corp.example",
    "dc1.child.corp.example:636",
    "dc1.child.corp.example/x",
    "[::1]",
    "a-rogue.attacker.example",
    "dc1.child.corp.example.attacker.example",
    "notchild.corp.example",
    "x" * 70 + ".child.corp.example",
    "dc1 .child.corp.example",
]


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_a_server_object_with_a_bad_host_gets_no_connection(tmp_path: Path, host: str) -> None:
    fake = two()
    fake.server(CHILD, host)
    fake.hosts[host] = CHILD
    m = run(fake, tmp_path / "f")
    assert host not in [t.host for t in fake.calls]
    row = rows(m)["child.corp.example"]
    assert row["status"] == "read" and row["dc"] == "dc1.child.corp.example"
    assert any(f"not connecting to {host}" in n for n in m["notes"])
    assert host not in row["dcs"]


@pytest.mark.parametrize("value", ["127.0.0.1:3899", "ldap://127.0.0.1:3898", "10.0.0.5"])
def test_a_crossref_with_a_bad_dnsroot_is_not_evaluated_and_named(
    tmp_path: Path, value: str
) -> None:
    fake = two()
    fake.domain("DC=evil,DC=attacker,DC=example", "S-1-5-21-9-9-9", dns_root=value)
    fake.hosts[value] = "DC=evil,DC=attacker,DC=example"
    m = run(fake, tmp_path / "f")
    assert value not in [t.host for t in fake.calls]
    row = rows(m)["evil.attacker.example"]
    assert row["status"] == "not_evaluated" and value in row["reason"]
    assert m["complete"] is False


def test_no_target_host_ever_carries_a_scheme_or_a_port(tmp_path: Path) -> None:
    fake = two()
    for host in BAD_HOSTS:
        fake.server(CHILD, host)
    fake.domain("DC=lone,DC=example", "S-1-5-21-5-5-5", dns_root="ldap://lone.example:389")
    run(fake, tmp_path / "f")
    assert all(":" not in t.host and "/" not in t.host for t in fake.calls)


def test_the_host_the_user_typed_is_not_vetted(tmp_path: Path) -> None:
    fake = two()
    fake.hosts["127.0.0.1"] = ROOT
    target = replace(TARGET, host="127.0.0.1")
    m = forest.run(target, tmp_path / "f", connector=fake.connect, read=fake.read)
    assert rows(m)["corp.example"]["dc"] == "127.0.0.1"


def test_a_seed_domain_stays_scanned_when_every_named_dc_is_refused(tmp_path: Path) -> None:
    fake = two()
    fake.hosts["127.0.0.1"] = ROOT
    fake.sites = [e for e in fake.sites if b"dc1.corp.example" not in e["dn"].encode()]
    fake.server(ROOT, "evil.attacker.example")
    target = replace(TARGET, host="127.0.0.1")
    m = forest.run(target, tmp_path / "f", connector=fake.connect, read=fake.read)
    assert rows(m)["corp.example"]["status"] == "read"
    assert "evil.attacker.example" not in [t.host for t in fake.calls]


def disjoint() -> Fake:
    fake = Fake()
    fake.domain(ROOT, ROOT_SID, "dc1.corp.example")
    admin = fake.user(ROOT, "Administrator", 500)
    fake.group(ROOT, "Enterprise Admins", 519, admin)
    fake.group(ROOT, "Schema Admins", 518, admin)
    fake.domain(CHILD, "S-1-5-21-2-2-2", "dc1.ad.internal")
    return fake


def test_a_disjoint_namespace_needs_the_opt_in(tmp_path: Path) -> None:
    fake = disjoint()
    m = run(fake, tmp_path / "f")
    row = rows(m)["child.corp.example"]
    assert row["status"] == "not_evaluated" and "--forest-allow-dns" in row["reason"]
    assert "dc1.ad.internal" not in [t.host for t in fake.calls]

    fake = disjoint()
    m = run(fake, tmp_path / "g", allow=["ad.internal", "corp.example"])
    assert rows(m)["child.corp.example"]["dc"] == "dc1.ad.internal"
    assert m["complete"] is True


def test_the_allowed_suffixes_replace_the_default_rule(tmp_path: Path) -> None:
    fake = three()
    m = run(fake, tmp_path / "f", allow=["corp.example"])
    row = rows(m)["other.example"]
    assert row["status"] == "not_evaluated" and "inside corp.example" in row["reason"]
    assert "dc1.other.example" not in [t.host for t in fake.calls]
    assert rows(m)["child.corp.example"]["status"] == "read"


def test_the_allow_option_reaches_the_run(cli: Fake, tmp_path: Path, capsys: Any) -> None:
    code = main(
        ["collect", *ARGS, "-o", str(tmp_path / "f"), "--forest-allow-dns", ".Corp.Example."]
    )
    assert code == 3
    assert "other.example: not evaluated" in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["ldap://corp.example", "corp.example:389", "10.0.0.5"])
def test_a_bad_allowed_suffix_is_refused_before_connecting(
    cli: Fake, tmp_path: Path, bad: str, capsys: Any
) -> None:
    assert main(["collect", *ARGS, "-o", str(tmp_path / "f"), "--forest-allow-dns", bad]) == 1
    assert "not a DNS name" in capsys.readouterr().err
    assert not cli.calls


# --- certificates of hosts the directory named ------------------------------------------------


def test_only_directory_named_hosts_get_the_ca_file(tmp_path: Path) -> None:
    fake = two()
    target = replace(TARGET, use_ssl=True)
    forest.run(target, tmp_path / "f", connector=fake.connect, read=fake.read, ca_file="ca.pem")
    assert {t.host: t.ca_file for t in fake.calls} == {
        "dc1.corp.example": None,
        "dc1.child.corp.example": "ca.pem",
    }


def test_connect_validates_only_with_a_ca_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = MagicMock()
    monkeypatch.setattr(collect.ldap3, "Server", server)
    monkeypatch.setattr(collect.ldap3, "Connection", MagicMock())
    collect.connect(Target("h", use_ssl=True))
    assert server.call_args.kwargs["tls"] is None
    pem = tmp_path / "ca.pem"
    pem.write_text("x", encoding="utf-8")
    collect.connect(Target("h", use_ssl=True, ca_file=str(pem)))
    tls = server.call_args.kwargs["tls"]
    assert tls.validate == ssl.CERT_REQUIRED and tls.ca_certs_file == str(pem)


def _self_signed(directory: Path, stem: str, name: str) -> tuple[str, str]:
    x509 = pytest.importorskip("cryptography.x509")
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{stem}.pem", directory / f"{stem}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class TlsListener:
    """Accepts one TLS connection and records whatever the client sends inside it."""

    def __init__(self, cert: str, key: str) -> None:
        self.received = b""
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(5)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        try:
            raw, _ = self.sock.accept()
            raw.settimeout(5)
            with self.context.wrap_socket(raw, server_side=True) as tls:
                self.received = tls.recv(4096)
        except (OSError, ssl.SSLError):
            pass

    def close(self) -> None:
        self.sock.close()
        self.thread.join(6)


@pytest.mark.parametrize("trusted", [True, False])
def test_a_bad_certificate_gets_no_password(tmp_path: Path, trusted: bool) -> None:
    """A real TLS handshake: a certificate for another name, then one from an unknown issuer."""
    cert, key = _self_signed(tmp_path, "server", "not-a-dc.attacker.example")
    other, _ = _self_signed(tmp_path, "other", "localhost")
    listener = TlsListener(cert, key)
    target = Target(
        "localhost",
        port=listener.port,
        use_ssl=True,
        user="auditor@corp.example",
        password=PASSWORD,
        ca_file=cert if trusted else other,
    )
    try:
        with pytest.raises(CollectError):
            collect.connect(target, auto_referrals=False)
    finally:
        listener.close()
    assert PASSWORD.encode() not in listener.received


def test_without_a_ca_file_any_certificate_is_taken(tmp_path: Path) -> None:
    """What the documentation says about --ldaps with no CA file."""
    cert, key = _self_signed(tmp_path, "server", "not-a-dc.attacker.example")
    listener = TlsListener(cert, key)
    target = Target(
        "localhost",
        port=listener.port,
        use_ssl=True,
        user="auditor@corp.example",
        password=PASSWORD,
    )
    try:
        with pytest.raises(CollectError):
            collect.connect(target, auto_referrals=False)
    finally:
        listener.close()
    assert PASSWORD.encode() in listener.received


def test_a_ca_file_needs_ldaps_and_must_exist(cli: Fake, tmp_path: Path, capsys: Any) -> None:
    pem = tmp_path / "ca.pem"
    pem.write_text("x", encoding="utf-8")
    assert main(["collect", *ARGS, "-o", str(tmp_path / "a"), "--forest-ca-file", str(pem)]) == 1
    assert "needs --ldaps" in capsys.readouterr().err
    missing = str(tmp_path / "gone.pem")
    code = main(
        ["collect", *ARGS, "--ldaps", "-o", str(tmp_path / "b"), "--forest-ca-file", missing]
    )
    assert code == 1
    assert "is not a file" in capsys.readouterr().err
    assert not cli.calls


def test_the_forest_options_need_forest(capsys: Any) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["collect", "dc", "-o", "x.json", "--forest-allow-dns", "corp.example"])
    assert caught.value.code == 2
    assert "need --forest" in capsys.readouterr().err


# --- a domain that is not what its name says ---------------------------------------------------


def test_two_dns_that_read_alike_get_different_files() -> None:
    assert forest.file_stem("DC=corp,DC=example") == "corp.example"
    for dn in ("DC=corp.example", "DC = corp,DC=example", "OU=corp,DC=example"):
        assert forest.file_stem(dn).startswith("domain-")
    assert forest.file_stem("DC=corp.example") != forest.file_stem("DC = corp,DC=example")


def test_a_rogue_server_object_cannot_stand_in_for_a_domain(tmp_path: Path) -> None:
    fake = two()
    fake.server(CHILD, "a-rogue.attacker.example")
    m = run(fake, tmp_path / "f")
    row = rows(m)["child.corp.example"]
    assert row["dc"] == "dc1.child.corp.example"
    assert "a-rogue.attacker.example" not in [t.host for t in fake.calls]
    assert any("a-rogue.attacker.example" in n for n in m["notes"])


@pytest.mark.parametrize("forged", ["DC=corp.example", "DC = corp,DC=example", "OU=x,DC=example"])
def test_a_crossref_that_is_no_domain_dn_cannot_replace_a_domain(
    tmp_path: Path, forged: str
) -> None:
    fake = two()
    fake.crossrefs.append(
        entry("CN=Forged", cn="Forged", nCName=forged, systemFlags=3, dnsRoot="corp.example")
    )
    out = tmp_path / "f"
    m = run(fake, out)
    row = next(r for r in m["domains"] if r["dn"] == forged)
    assert row["status"] == "not_evaluated" and "not a domain's" in row["reason"]
    assert m["complete"] is False
    assert sum(1 for t in fake.calls if t.host == "corp.example") == 0
    real = json.loads((out / "corp.example.snapshot.json").read_text(encoding="utf-8"))
    assert real["domain_dn"] == ROOT
    analyzed(out, m)
    assert "INCOMPLETE" in rollup.render_text(rollup.build_forest(out))


# --- a list of domains that is known to be short -----------------------------------------------


def test_a_domain_in_sites_with_no_crossref_makes_the_result_partial(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs = [c for c in fake.crossrefs if c["dn"] != f"CN=CHILD,CN=Partitions,{CONFIG}"]
    m = run(fake, tmp_path / "f")
    assert "child.corp.example" not in rows(m)
    assert m["partial"] is True and m["complete"] is False
    assert any(n.startswith("child.corp.example: domain controllers") for n in m["notes"])


def test_only_domain_contexts_of_a_dc_count_as_evidence(tmp_path: Path) -> None:
    fake = two()
    fake.sites.append(
        entry(
            f"CN=NTDS Settings,CN=x,CN=Servers,CN=HQ,CN=Sites,{CONFIG}",
            objectClass=["nTDSDSA"],
            objectCategory=f"CN=NTDS-DSA,CN=Schema,{CONFIG}",
            hasMasterNCs=[CONFIG, f"CN=Schema,{CONFIG}"],
        )
    )
    m = run(fake, tmp_path / "f")
    assert m["partial"] is False and m["complete"] is True


def test_a_forest_root_with_no_crossref_makes_the_result_partial(tmp_path: Path) -> None:
    fake = two()
    fake.crossrefs = [c for c in fake.crossrefs if c["dn"] != f"CN=CORP,CN=Partitions,{CONFIG}"]
    m = from_child(fake, tmp_path / "f")
    assert m["partial"] is True and m["complete"] is False
    assert any("the forest root, was not returned" in n for n in m["notes"])


# --- the output directory ----------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_an_existing_open_directory_is_noted_and_left_alone(tmp_path: Path) -> None:
    out = tmp_path / "shared"
    out.mkdir(mode=0o755)
    out.chmod(0o755)
    m = run(two(), out)
    assert out.stat().st_mode & 0o777 == 0o755
    assert any("open to other local users (mode 755)" in n for n in m["notes"])
    assert (out / forest.MANIFEST).stat().st_mode & 0o077 == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_a_directory_the_run_creates_is_owner_only(tmp_path: Path) -> None:
    out = tmp_path / "new"
    m = run(two(), out)
    assert out.stat().st_mode & 0o777 == 0o700
    assert not any("open to other local users" in n for n in m["notes"])
