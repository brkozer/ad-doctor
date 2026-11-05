"""Round 5: local group membership set by Group Policy (Restricted Groups, GPP Local Groups),
its scope, the AD-GPO-005..007 checks, graph edges, OpenGraph kinds and redaction."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from ad_doctor import gpo_scope, opengraph, paths, sd, sysvol
from ad_doctor.checks import run_all, tier0_hosts
from ad_doctor.collect import Collector, machine_extensions, parse_gplink
from ad_doctor.gpo_scope import CSE_GROUPS, CSE_SECURITY
from ad_doctor.model import (
    UAC,
    Account,
    DirObject,
    GpLink,
    Gpo,
    GpoLocalGroup,
    GpoSettings,
    Severity,
    Snapshot,
)
from ad_doctor.redact import redact

from .test_acl_adcs import sid_bytes
from .test_checks import NOW, only, snapshot, user

DOM = "S-1-5-21-1-2-3"
HEAD = "DC=lab,DC=test"
LAB = f"OU=Lab,{HEAD}"
ISOLATED = f"OU=Isolated,{LAB}"
DC_OU = f"OU=Domain Controllers,{HEAD}"
DOMAIN_USERS = f"{DOM}-513"
DOMAIN_ADMINS = f"{DOM}-512"
SERVER_ADMINS = f"{DOM}-1200"
HELPDESK = f"{DOM}-1105"
ADMINS = "S-1-5-32-544"
RDU = "S-1-5-32-555"
AU = "S-1-5-11"
READ = sd.Ace(AU, 0x20094)  # what AD stores for "Read": READ_CONTROL, LIST, READ_PROP
APPLY = sd.Ace(AU, sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)
GUID_A = "{AAAAAAAA-0000-0000-0000-000000000001}"
GUID_B = "{BBBBBBBB-0000-0000-0000-000000000002}"
GUID_C = "{CCCCCCCC-0000-0000-0000-000000000003}"
GPTTMPL = rf"Policies\{GUID_A}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"


def host(name: str, ou: str = LAB, rid: int = 2000, uac: int = 0x1000, **kw: Any) -> Account:
    return Account(
        dn=f"CN={name},{ou}",
        sam=f"{name}$",
        uac=uac,
        is_computer=True,
        sid=f"{DOM}-{rid}",
        laps=True,
        last_logon=NOW,
        **kw,
    )


def dc(name: str = "DC02", rid: int = 1000, uac: int = 0x2000) -> Account:
    return host(name, DC_OU, rid, uac)


def link(container: str, kind: str = "ou", enabled: bool = True, enforced: bool = False) -> GpLink:
    return GpLink(container, kind, enabled, enforced, 0)


def gpo(name: str, guid: str, *links: GpLink, **kw: Any) -> Gpo:
    fields: dict[str, Any] = {
        "aces": [READ, APPLY],
        "machine_version": 1,
        "machine_extensions": [CSE_SECURITY, CSE_GROUPS],
    }
    fields.update(kw)
    return Gpo(name=name, guid=guid, linked_to=[], links=list(links), **fields)


def entry(
    guid: str, group: str, member: str, source: str = "restricted", **kw: Any
) -> GpoLocalGroup:
    fields: dict[str, Any] = {
        "gpo": guid,
        "source": source,
        "path": "p",
        "group_sid": group,
        "group_name": "g",
        "member_sid": member,
        "member_name": "m" if member else "",
        "action": "add",
    }
    fields.update(kw)
    return GpoLocalGroup(**fields)


def gsnap(
    *accounts: Account,
    gpos: list[Gpo],
    entries: list[GpoLocalGroup],
    objects: list[DirObject] | None = None,
    **kw: Any,
) -> Snapshot:
    base = [DirObject(HEAD, "lab.test", "domain"), DirObject(LAB, "Lab", "ou")]
    defaults: dict[str, Any] = {
        "gpos": gpos,
        "gpo_local_groups": entries,
        "local_groups_collected": True,
        "objects": base + (objects or []),
        "site_count": 1,
        "principals": {SERVER_ADMINS: "LabServerAdmins", HELPDESK: "helpdesk"},
    }
    defaults.update(kw)
    return snapshot(*accounts, **defaults)


def reached(snap: Snapshot) -> set[tuple[str, str]]:
    """(GPO name, computer or DCs) of every grant."""
    return {(g.gpo.name, g.computer.sam if g.computer else "DCs") for g in gpo_scope.grants(snap)}


# --- Restricted Groups (GptTmpl.inf [Group Membership]) ----------------------------------


def inf(*lines: str) -> str:
    return "[Unicode]\nUnicode=yes\n[Group Membership]\n" + "\n".join(lines) + "\n"


def test_restricted_groups_sid_forms() -> None:
    text = inf(
        f"*{SERVER_ADMINS}__Memberof = *{ADMINS}",
        f"*{RDU}__Members = *{DOM}-1201,*{DOM}-1202",
    )
    out = sysvol.parse_group_membership(text, GUID_A, GPTTMPL)
    assert [(x.group_sid, x.member_sid, x.action, x.replaces) for x in out] == [
        (ADMINS, SERVER_ADMINS, "add", False),
        (RDU, f"{DOM}-1201", "set", True),
        (RDU, f"{DOM}-1202", "set", True),
    ]
    assert {x.source for x in out} == {"restricted"} and out[0].path == GPTTMPL


def test_gpmc_shape_writes_an_empty_members_line() -> None:
    # GPMC writes both lines when only "This group is a member of" is filled in
    text = inf(f"*{SERVER_ADMINS}__Memberof = *{ADMINS}", f"*{SERVER_ADMINS}__Members =")
    out = sysvol.parse_group_membership(text, GUID_A, GPTTMPL)
    assert [(x.group_sid, x.member_sid, x.member_name, x.action, x.replaces) for x in out] == [
        (ADMINS, SERVER_ADMINS, f"*{SERVER_ADMINS}", "add", False),
        (SERVER_ADMINS, "", "", "set", True),
    ]


def test_restricted_groups_names_quotes_case_and_underscores() -> None:
    text = inf(
        r"ADLAB\LabAdmins__Memberof = Administrators",
        r'Remote Desktop Users__MEMBERS = "ADLAB\help_desk" , *S-1-5-11',
        "App_Admins__memberOf = BUILTIN\\Backup Operators",
        "Odd__Suffix = x",
        "no equals sign",
    )
    out = sysvol.parse_group_membership(text, GUID_A, GPTTMPL)
    got = [(x.group_sid, x.group_name, x.member_sid, x.member_name) for x in out]
    assert got == [
        (ADMINS, "Administrators", "", r"ADLAB\LabAdmins"),
        (RDU, "Remote Desktop Users", "", r"ADLAB\help_desk"),
        (RDU, "Remote Desktop Users", AU, "*S-1-5-11"),
        ("S-1-5-32-551", "BUILTIN\\Backup Operators", "", "App_Admins"),
    ]


def test_other_sections_are_not_group_membership() -> None:
    text = "[Privilege Rights]\nSeDebugPrivilege__Members = *S-1-5-11\n"
    assert sysvol.parse_group_membership(text, GUID_A, GPTTMPL) == []


@pytest.mark.parametrize(
    "data",
    [
        "﻿[Group Membership]\n*S-1-5-11__Memberof = *S-1-5-32-544\n".encode("utf-16-le"),
        "[Group Membership]\n*S-1-5-11__Memberof = *S-1-5-32-544\n".encode("utf-16-le"),
        b"\xef\xbb\xbf[Group Membership]\n*S-1-5-11__Memberof = *S-1-5-32-544\n",
    ],
    ids=["utf16-bom", "utf16-no-bom", "utf8-bom"],
)
def test_gpttmpl_encodings(data: bytes) -> None:
    out = sysvol.parse_group_membership(sysvol._decode(data), GUID_A, GPTTMPL)
    assert [(x.group_sid, x.member_sid) for x in out] == [(ADMINS, AU)]


# --- GPP Local Groups (Machine\Preferences\Groups\Groups.xml) -----------------------------


def groups_xml(*items: str) -> bytes:
    body = "".join(items)
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">{body}</Groups>'
    ).encode()


def group(
    props: str, members: str = "", attrs: str = "", filters: str | None = None, tag: str = "Group"
) -> str:
    f = "" if filters is None else f"<Filters>{filters}</Filters>"
    return (
        f'<{tag} clsid="{{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}}" name="x" {attrs}>'
        f"<Properties {props}><Members>{members}</Members></Properties>{f}</{tag}>"
    )


def member(name: str = "", sid: str = "", action: str = "ADD") -> str:
    return f'<Member name="{name}" action="{action}" sid="{sid}"/>'


def gpp(data: bytes) -> list[GpoLocalGroup]:
    return sysvol.parse_groups_xml(data, GUID_B, "rel")


def test_gpp_group_sid_name_and_members() -> None:
    out = gpp(
        groups_xml(
            group(
                f'action="U" groupSid="{RDU}" groupName="Remote Desktop Users (built-in)"',
                member(r"LAB\Domain Users", DOMAIN_USERS)
                + member(r"LAB\bob")
                + member(r"LAB\old", f"{DOM}-1300", "REMOVE"),
            ),
            group(
                'action="C" groupName="Administrators (built-in)"', member("Everyone", "S-1-1-0")
            ),
        )
    )
    assert [(x.group_sid, x.member_sid, x.member_name, x.action, x.source) for x in out] == [
        (RDU, DOMAIN_USERS, r"LAB\Domain Users", "add", "gpp"),
        (RDU, "", r"LAB\bob", "add", "gpp"),
        (RDU, f"{DOM}-1300", r"LAB\old", "remove", "gpp"),
        (ADMINS, "S-1-1-0", "Everyone", "add", "gpp"),
    ]


def test_gpp_actions_and_delete_all() -> None:
    out = gpp(
        groups_xml(
            group(f'action="R" groupSid="{ADMINS}"', member("a", f"{DOM}-1")),
            group(f'action="D" groupSid="{ADMINS}"', member("b", f"{DOM}-2")),
            group(f'action="U" groupSid="{RDU}" deleteAllUsers="1"'),
            group(f'groupSid="{RDU}" deleteAllGroups="0"', member("c", f"{DOM}-3")),
        )
    )
    assert [(x.group_sid, x.member_sid, x.action, x.replaces) for x in out] == [
        (ADMINS, f"{DOM}-1", "add", True),  # R replaces; D emits nothing
        (RDU, "", "set", True),  # deleteAllUsers with no members: a clear
        (RDU, f"{DOM}-3", "add", False),  # no action attribute means U
    ]


def test_gpp_disabled_filters_and_collections() -> None:
    target = '<FilterComputer bool="AND" not="0" type="NETBIOS" name="WS02"/>'
    out = gpp(
        groups_xml(
            group(f'groupSid="{ADMINS}"', member("a", f"{DOM}-1"), attrs='disabled="1"'),
            group(f'groupSid="{ADMINS}"', member("b", f"{DOM}-2"), filters=target),
            group(f'groupSid="{ADMINS}"', member("c", f"{DOM}-3"), filters=""),
            '<Collection clsid="{x}" name="outer" disabled="1">'
            + group(f'groupSid="{RDU}"', member("d", f"{DOM}-4"))
            + "</Collection>",
            '<Collection clsid="{x}" name="f"><Filters>'
            + target
            + '</Filters><Collection clsid="{x}" name="inner">'
            + group(f'groupSid="{RDU}"', member("e", f"{DOM}-5"))
            + "</Collection></Collection>",
        )
    )
    assert [(x.member_sid, x.disabled, x.filtered) for x in out] == [
        (f"{DOM}-1", True, False),
        (f"{DOM}-2", False, True),
        (f"{DOM}-3", False, False),  # an empty <Filters/> is not targeting
        (f"{DOM}-4", True, False),
        (f"{DOM}-5", False, True),
    ]


def test_gpp_malformed_and_user_only_files() -> None:
    with pytest.raises(sysvol.MalformedXml):
        gpp(b"<Groups><Group>")
    # the seeded cpassword file holds a User item only
    user_item = (
        '<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="localadmin">'
        '<Properties action="U" userName="localadmin"/></User>'
    )
    assert gpp(groups_xml(user_item)) == []
    utf16 = groups_xml(group(f'groupSid="{ADMINS}"', member("a", f"{DOM}-1"))).decode()
    assert len(gpp(utf16.replace("utf-8", "utf-16").encode("utf-16"))) == 1


def test_only_machine_groups_files_of_known_gpos_are_parsed() -> None:
    known = {GUID_B}
    machine = rf"Policies\{GUID_B}\Machine\Preferences\Groups\Groups.xml"
    assert sysvol.machine_groups_gpo(machine, known) == GUID_B
    assert sysvol.machine_groups_gpo(machine.lower(), known) == GUID_B
    assert sysvol.machine_groups_gpo(machine.replace("Machine", "User"), known) is None
    orphan = (
        r"Policies\{4B1D7A55-0C1E-4A3B-9D2F-7E6A5C3B2A10}\Machine\Preferences\Groups\Groups.xml"
    )
    assert sysvol.machine_groups_gpo(orphan, known) is None


# --- collection: names, links, GPO attributes --------------------------------------------


class StubCollector(Collector):
    """Answers searches from a dict keyed by (base, filter)."""

    def __init__(self, routes: dict[tuple[str, str], list[dict[str, Any]]]) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.routes = routes

    def optional(self, base: str, flt: str, attrs: list[str], **kw: Any) -> list[dict[str, Any]]:
        return self.routes.get((base, flt), [])


def raw(dn: str, **attrs: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"distinguishedname": [dn]}
    for k, v in attrs.items():
        values = v if isinstance(v, list) else [v]
        out[k.lower()] = [x if isinstance(x, bytes) else str(x).encode() for x in values]
    return out


def test_name_resolution() -> None:
    c = StubCollector(
        {
            (HEAD, "(sAMAccountName=LabAdmins)"): [
                raw("CN=LabAdmins", objectSid=sid_bytes(f"{DOM}-7"))
            ],
            (HEAD, "(sAMAccountName=WS01$)"): [raw("CN=WS01", objectSid=sid_bytes(f"{DOM}-8"))],
            (
                "CN=Partitions,CN=Configuration,DC=lab,DC=test",
                "(&(objectClass=crossRef)(nCName=DC=lab,DC=test))",
            ): [raw("CN=LAB", nETBIOSName="LAB")],
        }
    )

    def sid(name: str) -> str:
        return c._principal_sid(name, HEAD, "lab.test", "LAB")

    assert sid(r"%DomainName%\LabAdmins") == f"{DOM}-7"
    assert sid(r"LAB\LabAdmins") == sid(r"lab.test\LabAdmins") == sid("LabAdmins") == f"{DOM}-7"
    assert sid(r"BUILTIN\Administrators") == ADMINS
    assert sid(r"NT AUTHORITY\Authenticated Users") == AU
    assert sid(r"OTHER\LabAdmins") == ""  # another domain
    assert sid(r"%ComputerName%\x") == ""
    assert sid("WS01") == f"{DOM}-8"  # the computer account, name$
    entries = [
        entry(GUID_A, "", "", group_name=r"BUILTIN\Administrators", member_name=r"LAB\LabAdmins"),
        entry(GUID_A, ADMINS, "", member_name=r"OTHER\x"),
    ]
    rights = {
        GUID_A: GpoSettings(
            privileges={
                "SeRemoteInteractiveLogonRight": ["Administrators", r"LAB\LabAdmins", r"OTHER\y"],
                "SeDebugPrivilege": [r"LAB\LabAdmins"],  # only the remote logon right matters
            }
        )
    }
    out, settings = c._resolve_local_groups(
        entries, rights, HEAD, "CN=Configuration,DC=lab,DC=test", "lab.test"
    )
    assert [(x.group_sid, x.member_sid) for x in out] == [(ADMINS, f"{DOM}-7"), (ADMINS, "")]
    assert settings[GUID_A].privileges == {
        "SeRemoteInteractiveLogonRight": ["Administrators", f"{DOM}-7", r"OTHER\y"],
        "SeDebugPrivilege": [r"LAB\LabAdmins"],
    }
    assert c.notes == [
        "GPO group-membership or remote logon settings name principals that could not be "
        "resolved: OTHER\\x, OTHER\\y"
    ]


def test_gplink_parsing() -> None:
    value = (
        "[LDAP://cn={A},cn=policies,cn=system,DC=lab,DC=test;0]"
        "[LDAP://CN={B},CN=Policies,CN=System,DC=lab,DC=test;1]"
        "[LDAP://cn={C},cn=policies,cn=system,DC=lab,DC=test;2]"
        "[LDAP://cn={D},cn=policies,cn=system,DC=lab,DC=test;3]"
    )
    links = parse_gplink(LAB, "ou", value)
    assert [(dn.split(",")[0].upper(), lk.enabled, lk.enforced, lk.index) for dn, lk in links] == [
        ("CN={A}", True, False, 0),
        ("CN={B}", False, False, 1),
        ("CN={C}", True, True, 2),
        ("CN={D}", False, True, 3),
    ]
    assert machine_extensions(
        f"[{{00000000-0000-0000-0000-000000000000}}{{79F92669-4224-476C-9C5C-6EFB4D87DF4A}}]"
        f"[{CSE_GROUPS.lower()}{{79F92669-4224-476C-9C5C-6EFB4D87DF4A}}]"
    ) == ["{00000000-0000-0000-0000-000000000000}", CSE_GROUPS]


def test_collector_reads_links_flags_and_versions() -> None:
    policies = f"CN=Policies,CN=System,{HEAD}"
    a = f"CN={GUID_A},{policies}"
    routes = {
        (DC_OU, "(objectClass=*)"): [raw(DC_OU, gPLink=f"[LDAP://{a};0]")],
        (HEAD, "(|(gPLink=*)(gPOptions=*))"): [
            raw(LAB, gPLink=f"[LDAP://{a.lower()};3][LDAP://cn={{dead}},{policies};0]"),
            raw(ISOLATED, gPOptions=1, objectClass=["top", "organizationalUnit"]),
            raw(f"OU=X,{HEAD}", gPLink="[LDAP://cn={x},cn=policies,cn=system,DC=other,DC=test;0]"),
        ],
        (f"CN=Sites,CN=Configuration,{HEAD}", "(objectClass=site)"): [
            raw(f"CN=S1,CN=Sites,CN=Configuration,{HEAD}", gPLink=f"[LDAP://{a};0]")
        ],
        (policies, "(objectClass=groupPolicyContainer)"): [
            raw(
                a,
                displayName="LabX",
                name=GUID_A,
                flags=2,
                versionNumber=0x30005,
                gPCMachineExtensionNames=f"[{CSE_SECURITY}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}]",
                gPCWQLFilter="[lab.test;{11111111-2222-3333-4444-555555555555};0]",
            )
        ],
        (
            f"CN={{11111111-2222-3333-4444-555555555555}},CN=SOM,CN=WMIPolicy,CN=System,{HEAD}",
            "(objectClass=*)",
        ): [raw("CN=wmi", **{"msWMI-Name": "Only laptops"})],
    }
    c = StubCollector(routes)
    objects = [DirObject(HEAD, "lab.test", "domain"), DirObject(ISOLATED, "Isolated", "ou")]
    head = raw(HEAD, gPLink=f"[LDAP://{a};0]")
    (g,) = c._gpos(HEAD, f"CN=Configuration,{HEAD}", head, objects)
    assert g.linked_to == ["domain", "Domain Controllers OU"]
    assert [(lk.kind, lk.enabled, lk.enforced) for lk in g.links] == [
        ("domain", True, False),
        ("ou", True, False),
        ("ou", False, True),
        ("site", True, False),
    ]
    assert (g.flags, g.machine_version, g.machine_extensions) == (2, 5, [CSE_SECURITY])
    assert g.wmi_filter == "Only laptops"
    assert objects[1].gp_blocked and not objects[0].gp_blocked
    assert any(n.startswith("dangling gPLink at OU=Lab") for n in c.notes)
    assert any(n.startswith("GPO from another domain linked at OU=X") for n in c.notes)


# --- scope ---------------------------------------------------------------------------------


def test_block_inheritance_enforced_and_disabled_links() -> None:
    gpos = [
        gpo("AtDomain", GUID_A, link(HEAD, "domain")),
        gpo("AtLab", GUID_B, link(LAB)),
        gpo("Enforced", GUID_C, link(LAB, enforced=True)),
        gpo("Own", "{D}", link(ISOLATED)),
        gpo("DisabledEnforced", "{E}", link(LAB, enabled=False, enforced=True)),
    ]
    entries = [entry(g.guid, ADMINS, SERVER_ADMINS) for g in gpos]
    objects = [DirObject(ISOLATED, "Isolated", "ou", gp_blocked=True)]
    snap = gsnap(
        host("WS01"),
        host("WS03", ISOLATED, 2001),
        host("C1", f"CN=Computers,{HEAD}", 2002),
        gpos=gpos,
        entries=entries,
        objects=objects,
    )
    assert reached(snap) == {
        ("AtDomain", "WS01$"),
        ("AtLab", "WS01$"),
        ("Enforced", "WS01$"),
        # a block stops the links above it, never its own; enforced links pass it
        ("Own", "WS03$"),
        ("Enforced", "WS03$"),
        # CN=Computers cannot be linked: domain links only
        ("AtDomain", "C1$"),
    }


def test_containers_nearest_first() -> None:
    assert gpo_scope.containers(f"CN=WS03,{ISOLATED}", HEAD) == [
        ISOLATED.lower(),
        LAB.lower(),
        HEAD.lower(),
    ]


def test_site_links() -> None:
    site1 = f"CN=S1,CN=Sites,CN=Configuration,{HEAD}"
    site2 = f"CN=S2,CN=Sites,CN=Configuration,{HEAD}"
    gpos = [gpo("Site1", GUID_A, link(site1, "site")), gpo("Site2", GUID_B, link(site2, "site"))]
    entries = [entry(g.guid, ADMINS, SERVER_ADMINS) for g in gpos]
    single = gsnap(host("WS01"), gpos=gpos[:1], entries=entries[:1])
    assert [g.caveats for g in gpo_scope.grants(single)] == [()]
    multi = gsnap(host("WS01"), gpos=gpos, entries=entries, site_count=2)
    assert {g.caveats for g in gpo_scope.grants(multi)} == {("site membership assumed",)}
    # a DC's site is known: only that site's links apply, without a caveat
    dc_snap = gsnap(
        dc(), gpos=gpos, entries=entries, site_count=2, dc_sites={f"cn=dc02,{DC_OU}".lower(): site1}
    )
    assert [(g.gpo.name, g.caveats) for g in gpo_scope.grants(dc_snap)] == [("Site1", ())]


@pytest.mark.parametrize(
    ("changes", "applies"),
    [
        ({"flags": 1}, True),  # user side disabled
        ({"flags": 2}, False),
        ({"flags": 3}, False),
        ({"machine_version": 0}, False),  # "Not Applied (Empty)"
        ({"machine_extensions": [CSE_GROUPS]}, False),  # no security CSE
        ({"machine_version": None, "machine_extensions": None}, True),  # older snapshot
    ],
)
def test_gpo_status_version_and_extension(changes: dict[str, Any], applies: bool) -> None:
    g = gpo("X", GUID_A, link(LAB), **changes)
    snap = gsnap(host("WS01"), gpos=[g], entries=[entry(GUID_A, ADMINS, SERVER_ADMINS)])
    assert bool(gpo_scope.grants(snap)) is applies


def _filtered(aces: list[sd.Ace], objects: list[DirObject] | None = None, *hosts: Account) -> bool:
    g = gpo("X", GUID_A, link(LAB), aces=aces)
    snap = gsnap(
        *(hosts or (host("WS01"),)),
        gpos=[g],
        entries=[entry(GUID_A, ADMINS, SERVER_ADMINS)],
        objects=objects,
    )
    return bool(gpo_scope.grants(snap))


def test_security_filtering() -> None:
    group = f"{DOM}-1500"
    apply_group = sd.Ace(group, sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)
    empty = DirObject(f"CN=Apply,{LAB}", "Apply", "group", sid=group)
    outer = DirObject(f"CN=Outer,{LAB}", "Outer", "group", sid=f"{DOM}-1501")
    nested = replace(empty, members=[outer.dn])
    outer = replace(outer, members=[f"CN=WS01,{LAB}"])
    assert _filtered([READ, APPLY])  # the default: Authenticated Users read and apply
    assert not _filtered([READ, apply_group], [empty])  # Apply only for an empty group
    assert _filtered([READ, apply_group], [nested, outer])  # through nested groups
    assert not _filtered([sd.Ace(DOMAIN_USERS, 0x20094), APPLY])  # no read for computers
    assert _filtered([sd.Ace(AU, sd.GENERIC_ALL)])
    # the domain's computers group through the primary group
    assert _filtered([READ, sd.Ace(f"{DOM}-515", sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)])


def test_security_filtering_through_a_foreign_security_principal() -> None:
    # Pre-Windows 2000 Compatible Access holds Authenticated Users as an FSP object, so a
    # GPO that only it may apply still reaches every computer
    pre2k = DirObject(
        f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{HEAD}",
        "Pre-Windows 2000 Compatible Access",
        "group",
        sid="S-1-5-32-554",
        members=[f"CN=S-1-5-11,CN=ForeignSecurityPrincipals,{HEAD}"],
    )
    apply_pre2k = sd.Ace("S-1-5-32-554", sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)
    assert _filtered([READ, apply_pre2k], [pre2k])
    assert not _filtered([READ, apply_pre2k], [replace(pre2k, members=[])])


def test_unreadable_dacl_applies_with_a_caveat() -> None:
    g = gpo("X", GUID_A, link(LAB), aces=[], wmi_filter="Only laptops")
    snap = gsnap(host("WS01"), gpos=[g], entries=[entry(GUID_A, ADMINS, SERVER_ADMINS)])
    (grant,) = gpo_scope.grants(snap)
    assert grant.caveats == ("security filtering not readable", "WMI filter Only laptops")


def test_dc_token_holds_enterprise_dcs_and_domain_controllers() -> None:
    for sid in ("S-1-5-9", f"{DOM}-516"):
        ace = sd.Ace(sid, sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)
        g = gpo("X", GUID_A, link(DC_OU), aces=[READ, ace])
        snap = gsnap(dc(), gpos=[g], entries=[entry(GUID_A, ADMINS, SERVER_ADMINS)])
        assert reached(snap) == {("X", "DCs")}


# --- domain controllers --------------------------------------------------------------------


def test_restricted_groups_on_dcs_rewrite_domain_groups_once() -> None:
    g = gpo("DcAdmins", GUID_A, link(DC_OU))
    entries = [
        entry(GUID_A, ADMINS, SERVER_ADMINS),
        entry(GUID_A, DOMAIN_ADMINS, HELPDESK, action="set", replaces=True),
    ]
    snap = gsnap(dc("DC02", 1000), dc("DC03", 1001), gpos=[g], entries=entries)
    grants = gpo_scope.grants(snap)
    assert sorted((x.item.group_sid, x.computer, x.domain_group) for x in grants) == [
        (DOMAIN_ADMINS, None, True),
        (ADMINS, None, True),
    ]
    f = only(snap, "AD-GPO-006")
    assert f.objects == [
        "DcAdmins: LabServerAdmins -> BUILTIN\\Administrators (domain, via DCs)",
        "DcAdmins: helpdesk -> Domain Admins (domain, via DCs)",
    ]


def test_a_clear_through_the_dcs_is_reported() -> None:
    # the GPMC shape: on DCs the empty __Members line empties the domain group itself
    text = inf(f"*{SERVER_ADMINS}__Memberof = *{ADMINS}", f"*{SERVER_ADMINS}__Members =")
    entries = sysvol.parse_group_membership(text, GUID_A, GPTTMPL)
    snap = gsnap(
        dc(), host("WS01"), gpos=[gpo("Gpmc", GUID_A, link(HEAD, "domain"))], entries=entries
    )
    scope = gpo_scope.resolve(snap)
    assert [(c.item.group_sid, c.domain_group) for c in scope.clears] == [(SERVER_ADMINS, True)]
    assert scope.notes and "empties the domain group LabServerAdmins" in scope.notes[0]
    # on the member server only the local Administrators entry counts
    assert {(x.computer.sam if x.computer else "DCs", x.item.group_sid) for x in scope.grants} == {
        ("WS01$", ADMINS),
        ("DCs", ADMINS),
    }


def test_gpp_on_dcs_and_rodcs_are_skipped_with_a_note() -> None:
    gpos = [gpo("DcGpp", GUID_A, link(DC_OU)), gpo("Rodc", GUID_B, link(DC_OU))]
    entries = [
        entry(GUID_A, ADMINS, DOMAIN_USERS, "gpp"),
        entry(GUID_B, ADMINS, DOMAIN_USERS),
    ]
    rodc = dc("RODC1", 1002, UAC.WORKSTATION_TRUST_ACCOUNT | UAC.PARTIAL_SECRETS_ACCOUNT)
    snap = gsnap(rodc, gpos=gpos, entries=entries)
    assert gpo_scope.grants(snap) == []
    assert gpo_scope.resolve(snap).notes == [
        "local group settings in GPOs reaching read-only DCs are not evaluated: RODC1$"
    ]
    snap = gsnap(dc(), gpos=gpos[:1], entries=entries[:1])
    assert gpo_scope.grants(snap) == []
    assert "ignored" in gpo_scope.resolve(snap).notes[0]


def test_member_server_ignores_domain_group_targets() -> None:
    entries = [entry(GUID_A, DOMAIN_ADMINS, HELPDESK), entry(GUID_A, "S-1-5-32-546", HELPDESK)]
    snap = gsnap(host("WS01"), gpos=[gpo("X", GUID_A, link(LAB))], entries=entries)
    assert gpo_scope.grants(snap) == []


# --- checks ----------------------------------------------------------------------------------


def test_gpo_005_broad_local_admins() -> None:
    gpos = [gpo("LabX", GUID_A, link(LAB)), gpo("DcX", GUID_B, link(DC_OU))]
    entries = [
        entry(GUID_A, ADMINS, DOMAIN_USERS),
        entry(GUID_A, ADMINS, "S-1-1-0", "gpp", disabled=True),
        entry(GUID_A, ADMINS, AU, "gpp", filtered=True),
        entry(GUID_B, ADMINS, DOMAIN_USERS),
    ]
    snap = gsnap(host("WS01"), host("WS02", rid=2001), dc(), gpos=gpos, entries=entries)
    f = only(snap, "AD-GPO-005")
    assert f.severity == Severity.HIGH
    # an item with item-level targeting is listed (over-reporting), with a caveat
    assert f.objects == [
        "DcX: Domain Users -> BUILTIN\\Administrators (domain, via DCs)",
        "LabX: Authenticated Users -> Administrators on WS01$, WS02$ "
        "[item-level targeting not evaluated]",
        "LabX: Domain Users -> Administrators on WS01$, WS02$",
    ]
    assert "apply only where their targeting matches" in f.detail
    assert "AD-GPO-006" not in {x.check_id for x in run_all(snap)}  # broad is 005 only


def test_gpo_005_truncates_hosts() -> None:
    hosts = [host(f"WS{i:02}", rid=2000 + i) for i in range(7)]
    snap = gsnap(*hosts, gpos=[gpo("LabX", GUID_A, link(LAB))], entries=[entry(GUID_A, ADMINS, AU)])
    assert only(snap, "AD-GPO-005").objects == [
        "LabX: Authenticated Users -> Administrators on WS00$, WS01$, WS02$, WS03$, WS04$ (+2 more)"
    ]


def _tier0_lab(*extra: GpoLocalGroup, ca: bool = True, **kw: Any) -> Snapshot:
    """ENTRA01 (Entra Connect), EXCH01 (Exchange), CA01 (CA unless ca=False) and WS01 in
    OU=Lab, with LabLocalAdmins making LabServerAdmins local admin on all of them."""
    sync = user("MSOL_0a1b2c3d4e5f", sid=f"{DOM}-3000", sync_host="ENTRA01")
    replication = [
        sd.Ace(f"{DOM}-3000", sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
        sd.Ace(f"{DOM}-3000", sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL),
        sd.Ace(f"{DOM}-4001", sd.WRITE_DAC),
    ]
    ets = DirObject(
        f"CN=Exchange Trusted Subsystem,{HEAD}",
        "Exchange Trusted Subsystem",
        "group",
        sid=f"{DOM}-4000",
        members=[f"CN=EXCH01,{LAB}"],
    )
    ewp = DirObject(
        f"CN=Exchange Windows Permissions,{HEAD}",
        "Exchange Windows Permissions",
        "group",
        sid=f"{DOM}-4001",
        members=[ets.dn],
    )
    accounts = [
        host("ENTRA01", rid=2001),
        host("EXCH01", rid=2002),
        host("CA01", rid=2003),
        host("WS01", rid=2004),
        sync,
    ]
    snap = gsnap(
        *accounts,
        gpos=[gpo("LabLocalAdmins", GUID_A, link(LAB))],
        entries=[entry(GUID_A, ADMINS, SERVER_ADMINS), *extra],
        objects=[ets, ewp],
        ca_hosts=["CA01$"] if ca else [],
        acls={"domain": replication},
        **kw,
    )
    head = DirObject(HEAD, "lab.test", "domain", aces=replication)
    return replace(snap, objects=[head, *snap.objects[1:]])


def test_tier0_hosts() -> None:
    roles = tier0_hosts(_tier0_lab())
    assert roles[f"cn=entra01,{LAB}".lower()] == "Entra Connect server"
    assert roles[f"cn=exch01,{LAB}".lower()] == "Exchange server"
    assert roles[f"cn=ca01,{LAB}".lower()] == "CA server"
    assert f"cn=ws01,{LAB}".lower() not in roles


def test_gpo_006_non_tier0_admins_on_tier0_servers() -> None:
    snap = _tier0_lab(entry(GUID_A, ADMINS, DOMAIN_ADMINS))  # tier 0 itself: silent
    f = only(snap, "AD-GPO-006")
    assert f.objects == [
        "LabLocalAdmins: LabServerAdmins -> Administrators on CA01$ (CA server), "
        "ENTRA01$ (Entra Connect server), EXCH01$ (Exchange server)"
    ]


def test_gpo_007_remote_logon() -> None:
    gpos = [gpo("Rdp", GUID_A, link(LAB))]
    broad = gsnap(host("WS01"), gpos=gpos, entries=[entry(GUID_A, RDU, DOMAIN_USERS)])
    f = only(broad, "AD-GPO-007")
    assert (f.severity, f.objects) == (
        Severity.MEDIUM,
        ["Rdp: Domain Users -> Remote Desktop Users on WS01$"],
    )
    snap = _tier0_lab(entry(GUID_A, "S-1-5-32-580", SERVER_ADMINS))
    f = only(snap, "AD-GPO-007")
    assert f.severity == Severity.HIGH
    assert f.objects[0].startswith("LabLocalAdmins: LabServerAdmins -> Remote Management Users on ")
    assert "WS01$" not in f.objects[0]  # non-tier-0 member on a non-tier-0 host


def test_gpo_007_dc_remote_desktop_needs_the_logon_right() -> None:
    g = gpo("DcRdp", GUID_A, link(DC_OU))
    entries = [entry(GUID_A, RDU, SERVER_ADMINS)]
    snap = gsnap(dc(), gpos=[g], entries=entries)
    (grant,) = gpo_scope.grants(snap)
    assert grant.domain_group and not grant.effective
    assert "AD-GPO-007" not in {x.check_id for x in run_all(snap)}
    # a GPO reaching the DCs that gives Remote Desktop Users the right makes it count
    right = GpoSettings(privileges={"SeRemoteInteractiveLogonRight": [ADMINS, RDU]})
    snap = replace(snap, gpo_settings={GUID_A: right})
    f = only(snap, "AD-GPO-007")
    assert f.objects == [
        "DcRdp: LabServerAdmins -> BUILTIN\\Remote Desktop Users (domain, via DCs)"
    ]
    assert f.severity == Severity.HIGH


def test_gpo_007_member_server_logon_right_set_without_rdu() -> None:
    g = gpo("Rdp", GUID_A, link(LAB))
    right = GpoSettings(privileges={"SeRemoteInteractiveLogonRight": ["Administrators"]})
    snap = gsnap(
        host("WS01"),
        gpos=[g],
        entries=[entry(GUID_A, RDU, DOMAIN_USERS)],
        gpo_settings={GUID_A: right},
    )
    assert "AD-GPO-007" not in {x.check_id for x in run_all(snap)}


def test_checks_silent_when_not_collected() -> None:
    snap = replace(_tier0_lab(entry(GUID_A, ADMINS, DOMAIN_USERS)), local_groups_collected=False)
    found = {x.check_id for x in run_all(snap)}
    assert not found & {"AD-GPO-005", "AD-GPO-006", "AD-GPO-007"}


def test_gpo_003_skips_gpos_windows_does_not_apply() -> None:
    weak = GpoSettings(lm_compatibility=1)
    g = Gpo("LabDCPolicy", GUID_A, ["Domain Controllers OU"], [], machine_version=0)
    snap = snapshot(gpos=[g], gpo_settings={GUID_A: weak})
    assert "AD-GPO-003" not in {x.check_id for x in run_all(snap)}
    snap = replace(snap, gpos=[replace(g, machine_version=1, machine_extensions=[CSE_SECURITY])])
    assert only(snap, "AD-GPO-003").objects == [
        "LabDCPolicy: LmCompatibilityLevel 1 (LM/NTLMv1 allowed)"
    ]
    snap = replace(snap, gpos=[replace(g, machine_version=None)])  # older snapshot
    assert "AD-GPO-003" in {x.check_id for x in run_all(snap)}


# --- control paths and OpenGraph -------------------------------------------------------------


def test_admin_to_via_gpo_reaches_tier0_through_the_sync_server() -> None:
    snap = _tier0_lab(ca=False)  # admin on a CA host would be tier 0 in one step
    g = paths.build(snap)
    found = paths.paths_to_tier0(g)
    path = found[f"sid:{SERVER_ADMINS}"].render(g)
    assert path == (
        "LabServerAdmins -[admin to via GPO LabLocalAdmins]-> ENTRA01$ -[hosts sync account]-> "
        "MSOL_0a1b2c3d4e5f -[DCSync]-> lab.test"
    )
    exch = found[f"sid:{DOM}-2002"].render(g)
    assert exch.startswith("EXCH01$ -[member of]-> Exchange Trusted Subsystem")
    holders = paths.direct_holders(g, found)
    assert f"sid:{SERVER_ADMINS}" in holders


def test_logon_edges_are_not_traversed() -> None:
    # helpdesk may RDP to the Entra Connect server, which has a path to tier 0: logon is
    # not control, so helpdesk gains no path
    snap = _tier0_lab(entry(GUID_A, RDU, HELPDESK), ca=False)
    g = paths.build(snap)
    entra = f"sid:{DOM}-2001"
    assert (entra, "can RDP via GPO LabLocalAdmins") in g.logon_edges[f"sid:{HELPDESK}"]
    found = paths.paths_to_tier0(g)
    assert entra in found and f"sid:{HELPDESK}" not in found
    assert not set(paths.reachable(g, [f"sid:{HELPDESK}"])) & g.tier0


def test_opengraph_kinds_and_logon_edges() -> None:
    assert opengraph.edge_kinds("admin to via GPO X, Y") == [("ADD_AdminTo", False)]
    assert opengraph.edge_kinds("member of via GPO X") == [("ADD_MemberOfViaGPO", False)]
    assert opengraph.edge_kinds("hosts sync account") == [("ADD_HostsSyncAccount", False)]
    assert opengraph.edge_kinds("can PSRemote via GPO X") == [("ADD_CanPSRemote", False)]
    assert opengraph.edge_kinds("DCOM via GPO X") == [("ADD_ExecuteDCOM", False)]
    entries = [entry(GUID_A, RDU, SERVER_ADMINS)]
    snap = _tier0_lab(*entries)
    payload = opengraph.export(snap)
    edges = payload["graph"]["edges"]
    rdp = [e for e in edges if e["kind"] == "ADD_CanRDP"]
    assert rdp and all(e["properties"]["traversable"] is False for e in rdp)
    assert {e["properties"]["gpo"] for e in rdp} == {"LabLocalAdmins"}
    admin = next(e for e in edges if e["kind"] == "ADD_AdminTo")
    assert admin["properties"]["traversable"] is True
    # paths only: a logon edge stays when it ends on a kept node (the tier-0 servers do)
    kept = opengraph.export(snap, paths_only=True)["graph"]["edges"]
    ends = {e["end"]["value"] for e in kept if e["kind"] == "ADD_CanRDP"}
    assert f"{DOM}-2001" in ends and f"{DOM}-2004" not in ends


# --- persistence and redaction ---------------------------------------------------------------


def test_json_round_trip_and_old_snapshots() -> None:
    snap = _tier0_lab(dc_sites={"cn=dc02": "CN=S1"})
    snap.gpos[0].links.append(link("CN=S1", "site", enabled=False))
    back = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert back.gpos == snap.gpos
    assert back.gpo_local_groups == snap.gpo_local_groups
    assert (back.local_groups_collected, back.dc_sites, back.site_count) == (
        True,
        {"cn=dc02": "CN=S1"},
        1,
    )
    old = snap.to_json()
    for key in ("gpo_local_groups", "local_groups_collected", "dc_sites", "site_count"):
        del old[key]
    for g in old["gpos"]:
        for key in ("links", "flags", "machine_version", "machine_extensions", "wmi_filter"):
            del g[key]
    loaded = Snapshot.from_json(old)
    assert loaded.local_groups_collected is False and loaded.gpo_local_groups == []
    assert loaded.gpos[0].machine_version is None and loaded.gpos[0].links == []
    assert not {x.check_id for x in run_all(loaded)} & {"AD-GPO-005", "AD-GPO-006", "AD-GPO-007"}


def test_redaction_of_local_group_entries() -> None:
    lg = GpoLocalGroup(
        GUID_A,
        "gpp",
        rf"Policies\{GUID_A}\Machine\Preferences\Groups\Groups.xml",
        RDU,
        "Remote Desktop Users (built-in)",
        SERVER_ADMINS,
        r"ADLAB\LabServerAdmins",
        "add",
    )
    g = gpo("Secret Policy", GUID_A, link(f"OU=Finance,{HEAD}"), wmi_filter="Finance laptops")
    snap = gsnap(gpos=[g], entries=[lg], domain="adlab.test")
    data = redact(snap.to_json(), b"k")
    text = json.dumps(data)
    for secret in ("LabServerAdmins", "Finance", "Secret Policy", "ADLAB"):
        assert secret not in text
    out = data["gpo_local_groups"][0]
    assert out["group_name"] == "Remote Desktop Users (built-in)"
    assert (out["action"], out["source"]) == ("add", "gpp")
    assert data["gpos"][0]["links"][0]["kind"] == "ou"
    # the same fake SID everywhere it appears
    assert out["member_sid"] in data["principals"]
