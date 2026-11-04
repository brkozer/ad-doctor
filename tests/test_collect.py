"""Collector against a fake LDAP connection that answers like a small domain."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

from ldap3.core.exceptions import LDAPNoSuchObjectResult

from ad_doctor import sd
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector

from .test_acl_adcs import ace_bytes, descriptor, sid_bytes

DOMAIN = "DC=corp,DC=test"
CONFIG = f"CN=Configuration,{DOMAIN}"
PKS = f"CN=Public Key Services,CN=Services,{CONFIG}"
SID = "S-1-5-21-10-20-30"
GPO_DN = f"CN={{AAAA}},CN=Policies,CN=System,{DOMAIN}"
HELPDESK = f"{SID}-1200"


def entry(dn: str, **attrs: Any) -> dict[str, Any]:
    def encode(v: Any) -> bytes:
        return v if isinstance(v, bytes) else str(v).encode()

    raw = {
        k: [encode(v) for v in (vs if isinstance(vs, list) else [vs])] for k, vs in attrs.items()
    }
    return {"type": "searchResEntry", "dn": dn, "raw_attributes": raw}


USERS = [
    entry(
        f"CN=Administrator,CN=Users,{DOMAIN}",
        sAMAccountName="Administrator",
        objectClass=["user"],
        userAccountControl=0x10200,
        adminCount=1,
    ),
    entry(
        f"CN=legacy,CN=Users,{DOMAIN}",
        sAMAccountName="legacy",
        objectClass=["user"],
        userAccountControl=0x200 | 0x400000,
    ),
]
COMPUTERS = [
    entry(
        f"CN=OLD01,CN=Computers,{DOMAIN}",
        sAMAccountName="OLD01$",
        objectClass=["computer"],
        userAccountControl=0x1000,
        operatingSystem="Windows 7 Professional",
        sIDHistory=[sid_bytes(f"{SID}-512")],
    ),
]

ROUTES: dict[tuple[str, str], list[dict[str, Any]]] = {
    (DOMAIN, "(objectClass=domain)"): [
        entry(
            DOMAIN,
            objectSid=sid_bytes(SID),
            minPwdLength=14,
            pwdProperties=1,
            lockoutThreshold=5,
            maxPwdAge=0,
            **{"ms-DS-MachineAccountQuota": 0},
            **{"msDS-Behavior-Version": 7},
            gPLink=f"[LDAP://{GPO_DN};0]",
        )
    ],
    (DOMAIN, "(&(objectCategory=person)(objectClass=user))"): USERS,
    (DOMAIN, "(objectClass=computer)"): COMPUTERS,
    (DOMAIN, f"(objectSid={SID}-512)"): [entry(f"CN=Domain Admins,CN=Users,{DOMAIN}")],
    (DOMAIN, "member-of:CN=Domain Admins"): [USERS[0]],
    (f"CN=System,{DOMAIN}", "(objectClass=trustedDomain)"): [
        entry(
            f"CN=partner.test,CN=System,{DOMAIN}",
            trustPartner="partner.test",
            trustDirection=3,
            trustType=2,
            trustAttributes=0,
        )
    ],
    (GPO_DN, "(objectClass=groupPolicyContainer)"): [
        entry(
            GPO_DN,
            displayName="Default Domain Policy",
            name="{AAAA}",
            nTSecurityDescriptor=descriptor(ace_bytes(HELPDESK, sd.GENERIC_ALL)),
        )
    ],
    (DOMAIN, f"(objectSid={HELPDESK})"): [
        entry(f"CN=helpdesk,CN=Users,{DOMAIN}", sAMAccountName="helpdesk")
    ],
    (f"CN=Directory Service,CN=Windows NT,CN=Services,{CONFIG}", "(objectClass=*)"): [
        entry("CN=Directory Service", dSHeuristics="0000002")
    ],
    (f"CN=Partitions,{CONFIG}", "(objectClass=*)"): [entry("CN=Partitions")],
}


class FakeExtend:
    def paged_search(self, base: str, flt: str, **kw: Any) -> Iterator[dict[str, Any]]:
        if "memberOf:" in flt:
            group = flt.split(":=", 1)[1].split(",", 1)[0]
            yield from ROUTES.get((DOMAIN, f"member-of:{group}"), [])
            return
        if (base, flt) in ROUTES:
            yield from ROUTES[(base, flt)]
            return
        if base.startswith(("CN=Public Key Services", "CN=", "OU=")) and base != DOMAIN:
            raise LDAPNoSuchObjectResult()


def fake_conn() -> Any:
    info = SimpleNamespace(
        other={"defaultNamingContext": [DOMAIN], "configurationNamingContext": [CONFIG]}
    )
    return SimpleNamespace(
        server=SimpleNamespace(info=info),
        extend=SimpleNamespace(standard=FakeExtend()),
    )


def test_collector_builds_snapshot_and_checks_fire() -> None:
    snap = Collector(fake_conn()).snapshot()
    assert snap.domain == "corp.test"
    assert snap.domain_sid == SID
    assert {a.sam for a in snap.accounts} == {"Administrator", "legacy", "OLD01$"}
    old = next(a for a in snap.accounts if a.sam == "OLD01$")
    assert old.os == "Windows 7 Professional"
    assert old.sid_history == [f"{SID}-512"]
    assert snap.privileged["Domain Admins"] == [USERS[0]["dn"]]
    assert snap.gpos[0].linked_to == ["domain"]
    assert snap.principals[HELPDESK] == "helpdesk"
    assert snap.recycle_bin is False
    assert "AD CS not installed" in snap.notes

    found = {f.check_id: f.objects for f in run_all(snap)}
    assert found["AD-KRB-002"] == ["legacy"]
    assert found["AD-INF-001"] == ["OLD01$ (Windows 7 Professional)"]
    assert found["AD-ACC-007"] == ["OLD01$"]
    assert found["AD-INF-002"] == ["corp.test"]
    assert found["AD-INF-004"] == ["0000002"]
    assert found["AD-INF-006"] == ["partner.test (external, SID filtering disabled)"]
    assert found["AD-GPO-001"] == ["Default Domain Policy -> domain (helpdesk)"]
    assert "AD-ADCS-001" not in found
