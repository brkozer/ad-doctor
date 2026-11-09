"""Snapshots and helpers for the what-if tests.

`kitchen_sink()` holds at least one fact of every change kind that makes an edge, with the
SDProp and inheritance cases the provenance rules are about. `lab_snapshots()` returns the
snapshot files named in AD_DOCTOR_WHATIF_SNAPSHOTS (os.pathsep separated): the exhaustive
lab tests run on those and are skipped without them.
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import replace
from pathlib import Path

from ad_doctor import changes, paths, sd, whatif
from ad_doctor.model import DEFAULT_POLICY_MODULE, CaConfig, DirObject, Gmsa, Probes, Snapshot
from ad_doctor.sd import Ace

from .test_acl_adcs import template
from .test_checks import user
from .test_gpo_local import ADMINS, DC_OU, GUID_A, LAB, entry, gpo, gsnap, host, link

DOM = "S-1-5-21-1-2-3"
HEAD = "DC=lab,DC=test"
HELPDESK = f"{DOM}-1105"
OPS = f"{DOM}-1106"
OWNER = f"{DOM}-1107"
READER = f"{DOM}-1108"
OFFICER = f"{DOM}-1109"
NESTED = f"{DOM}-1700"
DA = f"{DOM}-512"
HOLDER = f"CN=AdminSDHolder,CN=System,{HEAD}"
TEAM_OU = f"OU=Team,{LAB}"


def kitchen_sink(inherited_bit: bool = True) -> Snapshot:
    """Every kind of change, SDProp copies and inherited copies (with the INHERITED_ACE
    flag kept unless `inherited_bit` is False)."""
    alice = user("alice", sid=f"{DOM}-3001", admin_count=True)
    alice.dn = f"CN=alice,{TEAM_OU}"
    bob = user("bob", sid=f"{DOM}-3002")
    bob.dn = f"CN=bob,{TEAM_OU}"
    carol = user("carol", sid=f"{DOM}-3003")
    helpdesk = user("helpdesk", sid=HELPDESK)
    ops = user("ops", sid=OPS)
    owner = user("owner", sid=OWNER)
    reader = user("reader", sid=READER)
    officer = user("officer", sid=OFFICER)
    ws = host("WS01", rid=2004)
    srv = host("SRV01", ou=TEAM_OU, rid=2005)
    full = Ace(HELPDESK, sd.GENERIC_ALL)
    reset_inh = Ace(OPS, sd.CONTROL_ACCESS, sd.RESET_PASSWORD, sd.USER_CLASS)
    copy = Ace(OPS, sd.CONTROL_ACCESS, sd.RESET_PASSWORD, None, inherited_bit)
    team = DirObject(TEAM_OU, "Team", "ou", inheritable=[reset_inh])
    nested = DirObject(
        f"CN=Nested,{TEAM_OU}",
        "Nested",
        "group",
        sid=NESTED,
        members=[alice.dn],
        aces=[Ace(OPS, sd.WRITE_PROPERTY, sd.MEMBER, None, inherited_bit)],
    )
    da = DirObject(
        f"CN=Domain Admins,CN=Users,{HEAD}",
        "Domain Admins",
        "group",
        sid=DA,
        members=[nested.dn],
        aces=[full, Ace(HELPDESK, sd.WRITE_OWNER)],  # the first is an SDProp copy
        dacl_protected=True,
    )
    holder = DirObject(HOLDER, "AdminSDHolder", "container", aces=[full], dacl_protected=True)
    bob_obj = DirObject(bob.dn, "bob", "user", sid=bob.sid, aces=[copy])
    owned = DirObject(f"CN=Owned,{LAB}", "Owned", "group", sid=f"{DOM}-1800", owner=OWNER)
    owned.members = [carol.dn]
    owned_in_da = replace(da, members=[*da.members, owned.dn])
    gm = Gmsa("svc_gmsa", f"CN=svc_gmsa,CN=Managed Service Accounts,{HEAD}", [READER])
    pki = [Ace(HELPDESK, sd.GENERIC_ALL)]
    ca = CaConfig(
        "lab-CA",
        "ca01.lab.test",
        aces=[Ace(OFFICER, sd.CA_OFFICER), Ace(OPS, sd.CA_MANAGE)],
    )
    esc1 = template("Esc1", enrollee_supplies_subject=True)
    esc4 = template("Esc4", aces=[Ace(HELPDESK, sd.WRITE_DAC)])
    snap = gsnap(
        alice,
        bob,
        carol,
        helpdesk,
        ops,
        owner,
        reader,
        officer,
        ws,
        srv,
        gpos=[gpo("LabLocalAdmins", GUID_A, link(LAB))],
        entries=[entry(GUID_A, ADMINS, f"{DOM}-3003")],
        objects=[team, nested, owned_in_da, holder, bob_obj, owned],
        privileged={"Domain Admins": [alice.dn, carol.dn]},
        templates=[esc1, esc4],
        acls={"PKI:NTAuthCertificates": pki, "AdminSDHolder": [full]},
        gmsas=[gm],
        probes=Probes(ca_configs=[ca]),
        ace_inheritance_checked=inherited_bit,
        principals={HELPDESK: "helpdesk", OPS: "ops", OWNER: "owner", READER: "reader"},
    )
    return snap


FOREIGN = "S-1-5-21-7-7-7-1104"
OID = "1.3.6.1.4.1.311.21.8.1.1.1"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"


def enroll(sid: str, right: str = sd.CERT_ENROLL) -> Ace:
    return Ace(sid, sd.CONTROL_ACCESS, right)


def adcs_snapshot() -> Snapshot:
    """ESC13 and ESC6 (with ESC16) on a path to tier 0, and the facts that keep edges out."""
    enrollee = user("esc_user", sid=f"{DOM}-3300")
    other = user("esc_other", sid=f"{DOM}-3301")
    esc6_user = user("esc6_user", sid=f"{DOM}-3302")
    linked_group = DirObject(f"CN=Linked,{LAB}", "Linked", "group", sid=f"{DOM}-3400")
    da = DirObject(
        f"CN=Domain Admins,CN=Users,{HEAD}",
        "Domain Admins",
        "group",
        sid=DA,
        aces=[Ace(linked_group.sid, sd.GENERIC_ALL)],
    )
    return gsnap(
        enrollee,
        other,
        esc6_user,
        gpos=[],
        entries=[],
        objects=[da, linked_group],
        privileged={"Domain Admins": []},
        templates=[
            template(
                "LinkedA",
                issuance_policies=[OID],
                aces=[enroll(enrollee.sid), enroll(other.sid)],
            ),
            template("LinkedB", issuance_policies=[OID], aces=[enroll(other.sid)]),
            template("Plain", aces=[enroll(esc6_user.sid)]),
        ],
        oid_group_links={OID: linked_group.dn},
        ca_hosts=["CA01$"],
        probes=Probes(
            ca_configs=[
                CaConfig(
                    "lab-CA",
                    "ca01.lab.test",
                    policy_module=DEFAULT_POLICY_MODULE,
                    edit_flags=sd.EDITF_ATTRIBUTESUBJECTALTNAME2,
                    disabled_extensions=[sd.SZOID_NTDS_CA_SECURITY_EXT],
                )
            ]
        ),
    )


def delegation_snapshot() -> Snapshot:
    """Every delegation and SID history edge, each on a path to tier 0, and the facts that
    keep other edges out."""
    admin = user("admin1", sid=f"{DOM}-3100")
    shielded = user("admin2", sid=f"{DOM}-3101")
    dc01 = host("DC02", DC_OU, 1000, 0x2000, spns=["HOST/dc02.lab.test", "ldap/dc02.lab.test"])
    app = host("APP01", rid=2100, spns=["HOST/app01.lab.test"], sid_history=[DA])
    app.rbcd = True
    kcd = user(
        "svc_kcd",
        0x200 | 0x1000000,  # protocol transition
        sid=f"{DOM}-3102",
        spns=["http/svc.lab.test"],
        allowed_to_delegate_to=["cifs/app01.lab.test", "ldap/dc02.lab.test"],
    )
    kerberos_only = user(
        "svc_krb",
        sid=f"{DOM}-3103",
        spns=["http/krb.lab.test"],
        allowed_to_delegate_to=["cifs/app01.lab.test"],
    )
    rbcd_user = user("svc_rbcd", sid=f"{DOM}-3104", spns=["http/rbcd.lab.test"])
    in_group = user("svc_grp", sid=f"{DOM}-3105", spns=["http/grp.lab.test"])
    migrated = user("migrated", sid=f"{DOM}-3106", sid_history=[DA])
    old = user("oldname", sid=f"{DOM}-3107", sid_history=[FOREIGN])
    group = DirObject(f"CN=Rbcd,{LAB}", "Rbcd", "group", sid=f"{DOM}-3200", members=[in_group.dn])
    app.rbcd_principals = [rbcd_user.sid, group.sid]
    da = DirObject(
        f"CN=Domain Admins,CN=Users,{HEAD}",
        "Domain Admins",
        "group",
        sid=DA,
        members=[admin.dn, shielded.dn],
        aces=[Ace(FOREIGN, sd.GENERIC_ALL)],
    )
    protected = DirObject(
        f"CN=Protected Users,CN=Users,{HEAD}",
        "Protected Users",
        "group",
        sid=f"{DOM}-525",
        members=[shielded.dn],
    )
    return gsnap(
        admin,
        shielded,
        dc01,
        app,
        kcd,
        kerberos_only,
        rbcd_user,
        in_group,
        migrated,
        old,
        gpos=[],
        entries=[],
        objects=[da, group, protected],
        privileged={"Domain Admins": [admin.dn, shielded.dn]},
        protected_users=[shielded.dn],
        spn_mappings=["host=cifs,http"],
    )


def tier0_change_snapshot() -> Snapshot:
    """Members who can leave tier 0: eve holds a right of her own on Domain Admins (a new
    holder once she leaves), prim stays because Domain Admins is her primary group, deep
    gets there through a nested group."""
    eve = user("eve", sid=f"{DOM}-3500")
    prim = user("prim", sid=f"{DOM}-3501", primary_group=512)
    deep = user("deep", sid=f"{DOM}-3502")
    team = DirObject(f"CN=Team,{LAB}", "Team", "group", sid=f"{DOM}-3503", members=[deep.dn])
    da = DirObject(
        f"CN=Domain Admins,CN=Users,{HEAD}",
        "Domain Admins",
        "group",
        sid=DA,
        members=[eve.dn, prim.dn, team.dn],
        aces=[Ace(eve.sid, sd.GENERIC_ALL)],
    )
    return gsnap(
        eve,
        prim,
        deep,
        gpos=[],
        entries=[],
        objects=[team, da],
        privileged={"Domain Admins": [eve.dn, prim.dn, deep.dn]},
    )


def lab_snapshots() -> list[Path]:
    value = os.environ.get("AD_DOCTOR_WHATIF_SNAPSHOTS", "")
    return [Path(p) for p in value.split(os.pathsep) if p]


def load(path: Path) -> Snapshot:
    return Snapshot.from_json(json.loads(path.read_text(encoding="utf-8")))


def rebuilt(snap: Snapshot, prov: object, removed: list[int]) -> paths.Graph:
    """paths.build on a changed copy of the snapshot (a JSON round trip, not deepcopy)."""
    copy = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert isinstance(prov, changes.Provenance)
    changes.apply(copy, prov, removed)
    return paths.build(copy)


def parity(snap: Snapshot, sets: list[list[int]], g: paths.Graph) -> dict[str, list[str]]:
    """For each set: equal, or the part of the signature that differs. Returns
    {"equal": [...], "differs": [...], "rebuild": [...]} keyed by change kinds."""
    assert g.prov is not None
    text = json.dumps(snap.to_json())
    out: dict[str, list[str]] = {"equal": [], "differs": [], "rebuild": []}
    for removed in sets:
        copy = Snapshot.from_json(json.loads(text))
        changes.apply(copy, g.prov, removed)
        want = whatif.signature(paths.build(copy))
        got = whatif.signature(whatif.masked(g, snap, removed))
        kinds = "+".join(sorted({g.prov.prims[p][0] for p in removed}))
        if not whatif.maskable(g.prov, removed):
            out["rebuild"].append(kinds)
            continue
        if got == want:
            out["equal"].append(kinds)
        else:
            diff = sorted(k for k in got if got[k] != want[k])
            out["differs"].append(f"{kinds}: {diff} {[g.prov.prims[p] for p in removed]}")
    return out


def random_sets(n_prims: int, count: int, seed: int, most: int = 8) -> list[list[int]]:
    rng = random.Random(seed)
    return [rng.sample(range(n_prims), rng.randint(1, min(most, n_prims))) for _ in range(count)]
