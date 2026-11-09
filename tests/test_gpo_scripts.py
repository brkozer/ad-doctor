"""Scripts and tasks that GPOs run, who can change them, and the probe pack."""

from __future__ import annotations

import json
import socket
import ssl
import struct
import threading
from dataclasses import replace
from typing import Any

import pytest
from smbprotocol.exceptions import SMBOSError
from smbprotocol.header import NtStatus

from ad_doctor import changes, fileacl, gpo_scope, paths, probes, redact, resolve, sd, sysvol
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector, Target
from ad_doctor.gpo_scope import CSE_SCHEDULED_TASKS, CSE_SCRIPTS
from ad_doctor.model import (
    DcProbe,
    GpoScript,
    HostSmb,
    Probes,
    Severity,
    Snapshot,
    SysvolAcl,
)
from ad_doctor.sd import Ace

from .test_acl_adcs import ace_bytes, sid_bytes
from .test_checks import only, snapshot, user
from .test_gpo_local import (
    DC_OU,
    DOM,
    DOMAIN_ADMINS,
    GUID_A,
    HELPDESK,
    LAB,
    dc,
    gpo,
    gsnap,
    host,
    link,
)
from .whatif_fixtures import parity

SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"
AU = "S-1-5-11"
FOLDER = rf"Policies\{GUID_A}"
INI = rf"{FOLDER}\Machine\Scripts\scripts.ini"
SCRIPT = rf"{FOLDER}\Machine\Scripts\Startup\go.bat"
WRITE = fileacl.FILE_ADD_FILE
MODIFY = 0x1301BF
CHAIN = (SCRIPT, rf"{FOLDER}\Machine\Scripts\Startup", rf"{FOLDER}\Machine\Scripts")


def acl(path: str, *aces: Ace, directory: bool = False, **kw: Any) -> SysvolAcl:
    return SysvolAcl(path, directory, kw.pop("owner", ADMINS), list(aces), **kw)


def clean_acls(*extra: SysvolAcl) -> list[SysvolAcl]:
    """Default permissions on the script, the ini and every folder up to the GPO's."""
    chosen = {a.path.lower(): a for a in extra}
    folders = [*CHAIN[1:], rf"{FOLDER}\Machine", FOLDER]
    out = {}
    for path in (SCRIPT, INI, *folders):
        out[path.lower()] = acl(path, Ace(ADMINS, 0xD0046), directory=path in folders)
    out.update(chosen)
    return list(out.values())


def startup(**kw: Any) -> GpoScript:
    fields: dict[str, Any] = {
        "gpo": GUID_A,
        "side": "computer",
        "source": "scripts.ini",
        "phase": "startup",
        "config": INI,
        "path": "go.bat",
        "location": "sysvol",
        "target": SCRIPT,
        "run_as": "system",
    }
    fields.update(kw)
    return GpoScript(**fields)


def scripts_snap(*acls: SysvolAcl, ou: str = LAB, **kw: Any) -> Snapshot:
    script = kw.pop("script", startup())
    extensions = kw.pop("extensions", [CSE_SCRIPTS, CSE_SCHEDULED_TASKS])
    g = gpo("Runner", GUID_A, link(ou), machine_extensions=extensions, user_version=1)
    g.user_extensions = extensions
    return gsnap(
        host("APP01"),
        dc("DC02"),
        gpos=[g],
        entries=[],
        gpo_scripts=[script],
        sysvol_acls=clean_acls(*acls),
        gpo_scripts_checked=True,
        principals={HELPDESK: "helpdesk"},
        **kw,
    )


def findings(snap: Snapshot, check_id: str) -> Any:
    return next((f for f in run_all(snap) if f.check_id == check_id), None)


# --- parsing ---------------------------------------------------------------------------


def test_scripts_ini_keeps_files_never_arguments() -> None:
    text = (
        "[Startup]\r\n0CmdLine=setup.bat\r\n0Parameters=-pw hunter2\r\n"
        "1CmdLine=\\\\fs01\\deploy\\run.cmd\r\n1Parameters=\r\n"
        "[Logon]\r\n0CmdLine=ignored.bat\r\n"
    )
    out = sysvol.parse_scripts_ini(text, GUID_A, "computer", INI, "scripts.ini")
    assert [x.path for x in out] == ["setup.bat", r"\\fs01\deploy\run.cmd"]
    assert out[0].target == rf"{FOLDER}\Machine\Scripts\Startup\setup.bat"
    assert out[0].location == "sysvol" and out[0].run_as == "system"
    assert "hunter2" not in json.dumps([x.__dict__ for x in out])


def test_interpreter_is_followed_to_its_first_network_path() -> None:
    text = (
        "[Logon]\n0CmdLine=powershell.exe\n"
        '0Parameters=-File "\\\\fs01\\s\\a b.ps1" -Log \\\\fs02\\logs\\x.txt\n'
        "1CmdLine=cmd.exe\n1Parameters=/c echo hello\n"
    )
    out = sysvol.parse_scripts_ini(text, GUID_A, "user", "u.ini", "psscripts.ini")
    assert [x.path for x in out] == [r"\\fs01\s\a b.ps1"]
    assert out[0].run_as == "user"


def task_xml(body: str) -> bytes:
    return f'<?xml version="1.0" encoding="utf-8"?><ScheduledTasks>{body}</ScheduledTasks>'.encode()


V2 = (
    '<TaskV2 name="t" disabled="{off}"><Properties action="{action}" runAs="{run_as}">'
    '<Task version="1.3"><Settings><Enabled>{enabled}</Enabled></Settings><Actions>'
    "<Exec><Command>{command}</Command><Arguments>secret-arg</Arguments></Exec></Actions>"
    "</Task></Properties>{filters}</TaskV2>"
)


def v2(**kw: str) -> str:
    fields = {
        "off": "0",
        "action": "U",
        "run_as": "NT AUTHORITY\\System",
        "enabled": "true",
        "command": r"\\fs01\s\t.exe",
        "filters": "",
    }
    fields.update(kw)
    return V2.format(**fields)


def test_scheduled_task_v2_system_and_old_format() -> None:
    old = (
        '<Task name="o"><Properties action="C" appName="\\\\fs01\\s\\o.bat" args="x" '
        'runAs="S-1-5-18" enabled="1"/></Task>'
    )
    out = sysvol.parse_scheduled_tasks(task_xml(v2() + old), GUID_A, "computer", "c.xml")
    assert [(x.path, x.run_as, x.phase) for x in out] == [
        (r"\\fs01\s\t.exe", "system", "task"),
        (r"\\fs01\s\o.bat", "system", "task"),
    ]
    assert "secret-arg" not in json.dumps([x.__dict__ for x in out])


def test_scheduled_tasks_that_do_not_run_are_left_out() -> None:
    body = v2(off="1") + v2(action="D") + v2(enabled="false")
    collection = f'<Collection name="c" disabled="1">{v2()}</Collection>'
    out = sysvol.parse_scheduled_tasks(task_xml(body + collection), GUID_A, "computer", "c.xml")
    assert out == []


def test_task_run_as_and_targeting() -> None:
    other = v2(run_as="CORP\\svc")
    targeted = v2(filters='<Filters><FilterComputer name="X"/></Filters>')
    out = sysvol.parse_scheduled_tasks(task_xml(other + targeted), GUID_A, "computer", "c.xml")
    assert [(x.run_as, x.filtered) for x in out] == [("other", False), ("system", True)]
    logged_on = v2(run_as="%LogonDomain%\\%LogonUser%")
    out = sysvol.parse_scheduled_tasks(task_xml(logged_on), GUID_A, "user", "u.xml")
    assert out[0].run_as == "user"


def test_malformed_tasks_are_rejected() -> None:
    with pytest.raises(sysvol.MalformedXml):
        sysvol.parse_scheduled_tasks(b"<ScheduledTasks><", GUID_A, "computer", "c.xml")
    with pytest.raises(sysvol.MalformedXml):
        sysvol.parse_scheduled_tasks(b"<!DOCTYPE x><a/>", GUID_A, "computer", "c.xml")


@pytest.mark.parametrize(
    ("path", "location", "target", "host"),
    [
        (r"\\lab.test\NETLOGON\a\b.bat", "sysvol", r"scripts\a\b.bat", ""),
        (r"\\LAB\netlogon\b.bat", "sysvol", r"scripts\b.bat", ""),
        (r"\\dc01.lab.test\SYSVOL\lab.test\Policies\x.ps1", "sysvol", r"Policies\x.ps1", ""),
        (r"\\%USERDNSDOMAIN%\NETLOGON\b.bat", "sysvol", r"scripts\b.bat", ""),
        (r"%LOGONSERVER%\NETLOGON\b.bat", "sysvol", r"scripts\b.bat", ""),
        (r"\\FS01\share\b.bat", "host", "", "fs01"),
        (r"\\dc01\deploy\b.bat", "host", "", "dc01"),
        (r"\\%HOST%\share\b.bat", "unresolved", "", ""),
        (r"\\lab.test\NETLOGON\..\b.bat", "unresolved", "", ""),
        (r"\\lab.test\SYSVOL\other.test\b.bat", "unresolved", "", ""),
    ],
)
def test_place_sorts_paths(path: str, location: str, target: str, host: str) -> None:
    x = startup(path=path, location="", target="")
    assert sysvol.place(x, "lab.test", {"lab.test", "lab", "dc01.lab.test", "dc01"})
    assert (x.location, x.target, x.host) == (location, target, host)


@pytest.mark.parametrize("path", [r"C:\tools\b.bat", r"%SystemRoot%\b.bat", "notepad.exe"])
def test_place_ignores_what_stays_on_the_computer(path: str) -> None:
    assert not sysvol.place(startup(path=path, location="", target=""), "lab.test", set())


# --- security descriptors --------------------------------------------------------------


def file_sd(*aces: bytes, owner: str = ADMINS, control: int = 0x8004) -> bytes:
    body = b"".join(aces)
    acl_bytes = struct.pack("<BBHHH", 2, 0, 8 + len(body), len(aces), 0) + body
    owner_bytes = sid_bytes(owner)
    head = struct.pack("<BBHIIII", 1, 0, control, 20, 0, 0, 20 + len(owner_bytes))
    return head + owner_bytes + acl_bytes


def deny(sid: str, mask: int) -> bytes:
    body = struct.pack("<I", mask) + sid_bytes(sid)
    return struct.pack("<BBH", 1, 0, 4 + len(body)) + body


def test_descriptor_keeps_rights_that_matter() -> None:
    raw = file_sd(
        ace_bytes(ADMINS, 0x1F01FF),
        ace_bytes(AU, 0x1200A9),  # read and execute
        ace_bytes(HELPDESK, MODIFY, flags=sd.INHERITED_ACE),
        ace_bytes(f"{DOM}-1", 0x1F01FF, flags=sd.INHERIT_ONLY),
    )
    out = fileacl.parse(raw, "x", False)
    assert out.owner == ADMINS and out.judged
    assert [(a.sid, a.inherited) for a in out.aces] == [(ADMINS, False), (HELPDESK, True)]


def test_deny_conditional_and_owner_rights_are_not_judged() -> None:
    assert not fileacl.parse(file_sd(deny(HELPDESK, WRITE)), "x", False).judged
    assert fileacl.parse(file_sd(deny(HELPDESK, 0x1)), "x", False).judged  # no right that matters
    assert not fileacl.parse(file_sd(ace_bytes(fileacl.OWNER_RIGHTS, 0x1200A9)), "x", False).judged
    callback = struct.pack("<BBH", 9, 0, 16) + struct.pack("<I", WRITE) + bytes(8)
    assert not fileacl.parse(file_sd(callback), "x", False).judged


def test_null_dacl_is_everyone() -> None:
    out = fileacl.parse(struct.pack("<BBHIIII", 1, 0, 0x8000, 0, 0, 0, 0), "x", False)
    assert [a.sid for a in out.aces] == ["S-1-1-0"] and out.owner is None


def test_broken_descriptor_is_an_error_not_clean() -> None:
    assert fileacl.parse(b"\x01\x00", "x", False).error


def writers_of(*aces: SysvolAcl) -> fileacl.Writers:
    return fileacl.writers({a.path.lower(): a for a in clean_acls(*aces)}, SCRIPT)


def test_chain_stops_at_the_gpo_folder_and_netlogon() -> None:
    assert fileacl.chain(SCRIPT)[-1] == FOLDER
    assert fileacl.chain(r"scripts\a\b.bat") == [r"scripts\a\b.bat", r"scripts\a", "scripts"]


def test_write_on_the_file_counts() -> None:
    found = writers_of(acl(SCRIPT, Ace(HELPDESK, WRITE))).found
    assert found == {(ADMINS, SCRIPT): "owner", (HELPDESK, SCRIPT): "write"} or (
        (HELPDESK, SCRIPT) in found
    )


def test_delete_child_needs_a_way_to_create_again() -> None:
    folder = CHAIN[1]
    assert (HELPDESK, folder) not in writers_of(
        acl(folder, Ace(HELPDESK, fileacl.FILE_DELETE_CHILD), directory=True)
    ).found
    both = fileacl.FILE_DELETE_CHILD | fileacl.FILE_ADD_FILE
    assert (HELPDESK, folder) in writers_of(acl(folder, Ace(HELPDESK, both), directory=True)).found


def test_add_file_alone_changes_nothing_that_exists() -> None:
    folder = CHAIN[1]
    done = writers_of(acl(folder, Ace(HELPDESK, fileacl.FILE_ADD_FILE), directory=True))
    assert not any(sid == HELPDESK for sid, _ in done.found)


def test_delete_on_the_file_with_add_on_the_folder_replaces_it() -> None:
    folder = CHAIN[1]
    done = writers_of(
        acl(SCRIPT, Ace(HELPDESK, fileacl.DELETE)),
        acl(folder, Ace(HELPDESK, fileacl.FILE_ADD_FILE), directory=True),
    )
    assert done.found[(HELPDESK, SCRIPT)] == "delete and recreate"


def test_an_owner_can_rewrite_the_dacl() -> None:
    done = writers_of(acl(FOLDER, directory=True, owner=HELPDESK))
    assert done.found[(HELPDESK, FOLDER)] == "owner"


def test_unknown_on_the_way_is_said() -> None:
    done = writers_of(SysvolAcl(CHAIN[1], True, error="STATUS_ACCESS_DENIED"))
    assert not done.judged and done.unknown == CHAIN[1]
    assert not writers_of(acl(CHAIN[2], directory=True, judged=False)).judged


# --- AD-GPO-017 ------------------------------------------------------------------------


def test_writable_startup_script_is_reported() -> None:
    f = only(scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE))), "AD-GPO-017")
    assert f.severity == Severity.MEDIUM
    assert any("helpdesk (write)" in o and "go.bat" in o for o in f.objects)


def test_the_file_that_lists_it_counts() -> None:
    f = only(scripts_snap(acl(INI, Ace(HELPDESK, WRITE))), "AD-GPO-017")
    assert any("scripts.ini" in o for o in f.objects)


def test_a_folder_above_counts_and_says_which() -> None:
    both = fileacl.FILE_DELETE_CHILD | fileacl.FILE_ADD_FILE
    f = only(scripts_snap(acl(CHAIN[1], Ace(HELPDESK, both), directory=True)), "AD-GPO-017")
    assert any(f"through {CHAIN[1]}" in o for o in f.objects)


def test_broad_writer_is_high() -> None:
    f = only(scripts_snap(acl(SCRIPT, Ace(AU, WRITE))), "AD-GPO-017")
    assert f.severity == Severity.HIGH


def test_gpo_reaching_tier0_is_high() -> None:
    f = only(scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE)), ou=DC_OU), "AD-GPO-017")
    assert f.severity == Severity.HIGH


def test_targeted_item_tops_out_at_medium_and_says_so() -> None:
    s = scripts_snap(acl(SCRIPT, Ace(AU, WRITE)), ou=DC_OU, script=startup(filtered=True))
    f = only(s, "AD-GPO-017")
    assert f.severity == Severity.MEDIUM
    assert any("item-level targeting not evaluated" in o for o in f.objects)


@pytest.mark.parametrize("trustee", [ADMINS, SYSTEM, DOMAIN_ADMINS, "S-1-5-32-549"])
def test_tier0_writers_stay_quiet(trustee: str) -> None:
    assert findings(scripts_snap(acl(SCRIPT, Ace(trustee, WRITE))), "AD-GPO-017") is None


def test_default_permissions_stay_quiet() -> None:
    assert findings(scripts_snap(), "AD-GPO-017") is None


@pytest.mark.parametrize(
    "kw",
    [{"flags": 2}, {"machine_version": 0}, {"machine_extensions": []}],
    ids=["side off", "never written", "extension missing"],
)
def test_a_script_windows_would_not_process_stays_quiet(kw: dict[str, Any]) -> None:
    s = scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE)))
    for name, value in kw.items():
        setattr(s.gpos[0], name, value)
    assert findings(s, "AD-GPO-017") is None
    assert not any(n.startswith("gpo-script:") for n in paths.build(s).edges)


def test_unlinked_gpo_stays_quiet() -> None:
    s = scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE)))
    s.gpos[0].links = []
    assert findings(s, "AD-GPO-017") is None


def test_unread_data_is_not_a_pass_and_not_a_finding() -> None:
    s = scripts_snap(SysvolAcl(SCRIPT, False, error="STATUS_ACCESS_DENIED"))
    assert findings(s, "AD-GPO-017") is None
    assert not fileacl.writers({a.path.lower(): a for a in s.sysvol_acls}, SCRIPT).judged


def test_not_collected_stays_quiet() -> None:
    s = scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE)))
    s.gpo_scripts_checked = False
    assert findings(s, "AD-GPO-017") is None


NETLOGON = r"scripts\map.bat"


def netlogon_snap(*aces: Ace, **kw: Any) -> Snapshot:
    return snapshot(
        user("alice"),
        sysvol_acls=[
            acl(NETLOGON, *aces),
            acl("scripts", Ace(ADMINS, 0xD0046), directory=True),
        ],
        gpo_scripts_checked=True,
        principals={HELPDESK: "helpdesk"},
        **kw,
    )


def test_netlogon_script_no_gpo_names() -> None:
    assert only(netlogon_snap(Ace(HELPDESK, WRITE)), "AD-GPO-017").severity == Severity.LOW
    assert only(netlogon_snap(Ace(AU, WRITE)), "AD-GPO-017").severity == Severity.MEDIUM
    assert findings(netlogon_snap(Ace(ADMINS, WRITE)), "AD-GPO-017") is None


# --- AD-GPO-018 ------------------------------------------------------------------------


def remote(**kw: Any) -> GpoScript:
    return startup(path=r"\\app01\deploy\go.bat", location="host", target="", host="app01", **kw)


def test_host_outside_tier0_medium_and_high() -> None:
    f = only(scripts_snap(script=remote()), "AD-GPO-018")
    assert f.severity == Severity.MEDIUM and "APP01$ is outside tier 0" in f.objects[0]
    assert only(scripts_snap(script=remote(), ou=DC_OU), "AD-GPO-018").severity == Severity.HIGH


def test_tier0_host_stays_quiet() -> None:
    assert (
        findings(
            scripts_snap(
                script=startup(path=r"\\dc01\x\a.bat", location="host", host="dc01", target="")
            ),
            "AD-GPO-018",
        )
        is None
    )


def test_unknown_host_and_variable_are_info_not_a_verdict() -> None:
    unknown = startup(path=r"\\nas\x\a.bat", location="host", host="nas", target="")
    f = only(scripts_snap(script=unknown), "AD-GPO-018")
    assert f.severity == Severity.INFO and "not judged" in f.objects[0]
    variable = startup(path=r"\\%X%\x\a.bat", location="unresolved", target="")
    f = only(scripts_snap(script=variable), "AD-GPO-018")
    assert f.severity == Severity.INFO
    assert not any(
        "gpo-script" in x
        for _, o in paths.build(scripts_snap(script=unknown)).edges.items()
        for x, _h in o
        if x == "sid:nas"
    )


def test_host_names_short_full_and_ambiguous() -> None:
    a = host("APP01", dns_host="app01.lab.test")
    b = host("APP02", rid=2001, dns_host="shared.lab.test")
    c = host("APP03", rid=2002, dns_host="shared.lab.test")
    index = gpo_scope.host_index(gsnap(a, b, c, gpos=[], entries=[]))
    assert index["app01"] is a and index["app01.lab.test"] is a
    assert "shared.lab.test" not in index


# --- the graph -------------------------------------------------------------------------


def path_of(g: paths.Graph, start: str) -> list[str]:
    found = paths.paths_to_tier0(g)
    return [how for _, how in found[f"sid:{start}"].steps]


def test_startup_writer_reaches_the_computers_the_gpo_applies_to() -> None:
    g = paths.build(scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE)), ou=DC_OU))
    how = path_of(g, HELPDESK)
    assert how[0] == paths.SCRIPT_WRITE and paths.SCRIPT_RUNS in how
    assert g.kind(f"gpo-script:{GUID_A.upper()}:computer") == "scope"


def test_no_edge_for_someone_else_run_as_or_targeting() -> None:
    for script in (startup(run_as="other"), startup(filtered=True)):
        g = paths.build(scripts_snap(acl(SCRIPT, Ace(HELPDESK, WRITE)), ou=DC_OU, script=script))
        assert f"sid:{HELPDESK}" not in paths.paths_to_tier0(g)


def test_logon_script_writer_reaches_users_not_computers() -> None:
    script = startup(
        side="user",
        phase="logon",
        run_as="user",
        config=rf"{FOLDER}\User\Scripts\scripts.ini",
        target=rf"{FOLDER}\User\Scripts\Logon\go.bat",
    )
    target = script.target
    s = scripts_snap(script=script)
    s.sysvol_acls = [
        acl(target, Ace(HELPDESK, WRITE)),
        acl(script.config),
        acl(rf"{FOLDER}\User\Scripts\Logon", directory=True),
        acl(rf"{FOLDER}\User\Scripts", directory=True),
        acl(rf"{FOLDER}\User", directory=True),
        acl(FOLDER, directory=True),
    ]
    admin = replace(user("ladmin", sid=f"{DOM}-3000"), dn=f"CN=ladmin,{LAB}")
    worker = host("WS09", rid=2009)
    s.accounts += [admin, worker]
    g = paths.build(s)
    node = f"gpo-script:{GUID_A.upper()}:user"
    reached = paths.reachable(g, [f"sid:{HELPDESK}"])
    assert node in g.edges and f"sid:{admin.sid}" in reached
    assert f"sid:{worker.sid}" not in reached


def test_host_edge_comes_from_the_computer() -> None:
    s = scripts_snap(script=remote(), ou=DC_OU)
    g = paths.build(s)
    app = next(a for a in s.accounts if a.sam == "APP01$")
    assert paths.SCRIPT_HOST in path_of(g, app.sid)


def test_ambiguous_or_unknown_host_has_no_edge() -> None:
    s = scripts_snap(script=remote(), ou=DC_OU)
    s.accounts.append(host("OTHER", rid=2300))
    s.accounts[-1].sam = "APP01$"
    assert not any(
        how == paths.SCRIPT_HOST for outs in paths.build(s).edges.values() for _, how in outs
    )


def test_no_scripts_no_script_nodes() -> None:
    s = scripts_snap()
    s.gpo_scripts = []
    assert not any(k.startswith("gpo-script:") for k in paths.build(s).edges)


# --- what-if ---------------------------------------------------------------------------


def what_if_snap() -> Snapshot:
    s = scripts_snap(
        acl(SCRIPT, Ace(HELPDESK, WRITE)),
        acl(INI, owner=HELPDESK),
        ou=DC_OU,
        script=startup(),
    )
    s.gpo_scripts.append(remote())
    return s


def test_every_change_masks_like_a_rebuild() -> None:
    s = what_if_snap()
    g = paths.build(s, provenance=True)
    assert g.prov is not None
    kinds = {k[0] for k in g.prov.prims}
    assert {"script-ace", "script-host"} <= kinds
    result = parity(s, [[p] for p in range(len(g.prov.prims))], g)
    assert result["differs"] == []
    assert parity(s, [list(range(len(g.prov.prims)))], g)["differs"] == []


def test_remove_write_rights_mutator() -> None:
    s = what_if_snap()
    g = paths.build(s, provenance=True)
    assert g.prov is not None
    keys = [k for k in g.prov.prims if k[0] == "script-ace" and k[-1] == HELPDESK]
    assert len(keys) == 2
    changes.apply(s, g.prov, [g.prov.index[k] for k in keys])
    after = {a.path: a for a in s.sysvol_acls}
    assert not any(a.sid == HELPDESK for a in after[SCRIPT].aces)
    assert after[INI].owner is None


def test_script_host_mutator_leaves_the_reference() -> None:
    s = what_if_snap()
    g = paths.build(s, provenance=True)
    assert g.prov is not None
    p = next(p for p, k in enumerate(g.prov.prims) if k[0] == "script-host")
    changes.apply(s, g.prov, [p])
    assert s.gpo_scripts[1].location == "moved"
    assert findings(s, "AD-GPO-018") is None


def test_specs_resolve_and_are_named_canonically() -> None:
    s = what_if_snap()
    g = paths.build(s, provenance=True)
    r = resolve.Resolver(s, g)
    assert g.prov is not None
    got = r.resolve(f'script-ace:"{SCRIPT}":{HELPDESK}')
    assert g.prov.prims[got.prims[0]] == ("script-ace", SCRIPT.lower(), HELPDESK)
    got = r.resolve(f'script-host:"{GUID_A}":"\\\\app01\\deploy\\go.bat"')
    assert g.prov.prims[got.prims[0]][0] == "script-host"
    where = changes.Where(s, g.prov)
    for key in g.prov.prims:
        if key[0].startswith("script-"):
            assert changes.describe(s, key, where)
            text = resolve.canonical(s, key, where)
            assert r.resolve(text).prims, text


def test_fix_lines_are_comments() -> None:
    from ad_doctor import fixes

    s = what_if_snap()
    g = paths.build(s, provenance=True)
    assert g.prov is not None
    where = changes.Where(s, g.prov)
    wanted = [p for p, k in enumerate(g.prov.prims) if k[0].startswith("script-")]
    for f in changes.facts(s, g.prov, where, wanted).values():
        for line in [*fixes.change_lines(f, s), *fixes.rollback_lines(f, s)]:
            assert line.startswith("#")


# --- snapshots -------------------------------------------------------------------------


def test_snapshot_round_trip() -> None:
    s = what_if_snap()
    s.probes = Probes(
        tier0_smb=[HostSmb("CA01$", False)],
        tier0_smb_checked=True,
        dc_pack_ran=True,
        dcs=[DcProbe("DC01", smb1=True, tls10=True)],
    )
    back = Snapshot.from_json(json.loads(json.dumps(s.to_json())))
    assert back.gpo_scripts == s.gpo_scripts
    assert back.sysvol_acls == s.sysvol_acls
    assert back.probes.tier0_smb == s.probes.tier0_smb and back.probes.dc_pack_ran
    assert back.probes.dcs[0].tls10 is True


def old_data() -> dict[str, Any]:
    data = json.loads(json.dumps(scripts_snap().to_json()))
    for key in ("gpo_scripts", "sysvol_acls", "gpo_scripts_checked"):
        del data[key]
    del data["probes"]["tier0_smb"], data["probes"]["tier0_smb_checked"]
    del data["probes"]["dc_pack_ran"]
    return data


def test_older_snapshot_loads_and_says_not_evaluated() -> None:
    s = Snapshot.from_json(old_data())
    text = " ".join(s.notes)
    assert "AD-GPO-017, AD-GPO-018" in text and "AD-INF-025" in text and "AD-INF-026" in text
    assert "not evaluated" in text
    found = {f.check_id for f in run_all(s)}
    assert not found & {"AD-GPO-017", "AD-GPO-018", "AD-INF-025", "AD-INF-026"}


def test_redaction_hides_names_and_keeps_findings() -> None:
    s = scripts_snap(acl(INI, Ace(HELPDESK, WRITE)), ou=DC_OU, script=remote())
    s.accounts.append(user("bob"))
    s.gpo_scripts.append(
        startup(
            path=r"\\secret-nas.corp\share\x.bat",
            location="host",
            target="",
            host="secret-nas.corp",
        )
    )
    s.probes.tier0_smb = [HostSmb("SECRETCA$", False)]
    data = json.loads(json.dumps(s.to_json()))
    out = redact.redact(data, b"k")
    text = json.dumps(out)
    assert "secret-nas" not in text and "SECRETCA" not in text and "app01" not in text.lower()
    back = Snapshot.from_json(out)
    before = {f.check_id: f.severity for f in run_all(s)}
    after = {f.check_id: f.severity for f in run_all(back)}
    for cid in ("AD-GPO-017", "AD-GPO-018", "AD-INF-025"):
        assert before[cid] == after[cid], cid
    assert len(only(back, "AD-GPO-018").objects) == len(only(s, "AD-GPO-018").objects)


# --- collection ------------------------------------------------------------------------


GPT = rf"\\h\SYSVOL\lab.test\{INI}"


class Fake:
    """Enough of smbclient for `_read_run_files`."""

    def __init__(self, files: dict[str, bytes | Exception]) -> None:
        self.files = files
        self.calls: list[str] = []

    def __call__(self, path: str, port: int, directory: bool) -> bytes:
        self.calls.append(path)
        hit = self.files.get(path.rsplit("\\SYSVOL\\lab.test\\", 1)[-1])
        if hit is None:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)
        if isinstance(hit, Exception):
            raise hit
        return hit


def run_files(
    monkeypatch: pytest.MonkeyPatch, files: dict[str, Any], found: list[GpoScript]
) -> Any:
    fake = Fake(files)
    monkeypatch.setattr(sysvol, "_descriptor", fake)
    result = sysvol.SysvolResult()
    sysvol._read_run_files(result, r"\\h\SYSVOL\lab.test", 445, found, [], "lab.test", {"lab.test"})
    return result, fake


OK_SD = file_sd(ace_bytes(ADMINS, 0x1F01FF))


def good_tree(*paths_: str) -> dict[str, bytes]:
    out = {}
    for p in paths_:
        for step in fileacl.chain(p):
            out[step] = OK_SD
    return out


def test_relative_command_not_in_the_folder_is_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_files(monkeypatch, good_tree(INI), [startup()])
    assert result.scripts == []


def test_a_file_that_is_there_is_read_up_the_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    result, fake = run_files(monkeypatch, good_tree(INI, SCRIPT), [startup()])
    assert [s.path for s in result.scripts] == ["go.bat"]
    assert {a.path for a in result.acls} >= {SCRIPT, INI, FOLDER}
    assert not result.notes
    assert len(fake.calls) == len(set(fake.calls))


def test_unreadable_descriptor_becomes_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    files: dict[str, Any] = {**good_tree(INI, SCRIPT)}
    files[SCRIPT] = SMBOSError(NtStatus.STATUS_ACCESS_DENIED, SCRIPT)
    result, _ = run_files(monkeypatch, files, [startup()])
    assert any("could not be judged" in n and "AD-GPO-017" in n for n in result.notes)
    assert result.scripts


def test_sysvol_path_that_is_gone_is_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    x = startup(path=r"\\lab.test\NETLOGON\gone.bat", location="", target="")
    result, _ = run_files(monkeypatch, good_tree(INI), [x])
    assert result.scripts[0].location == "missing"
    assert any("not found" in n for n in result.notes)
    assert not any(a.error for a in result.acls)


def test_local_paths_are_not_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    x = startup(path=r"C:\a.bat", location="", target="")
    result, _ = run_files(monkeypatch, good_tree(INI), [x])
    assert result.scripts == []


def test_cli_switch_defaults_off(capsys: pytest.CaptureFixture[str]) -> None:
    from ad_doctor.cli import main

    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    assert "--dc-probes" in capsys.readouterr().out
    assert Target(host="x").dc_probes is False


def collector(**kw: Any) -> Collector:
    c = Collector.__new__(Collector)
    c.target = Target(host="dc01", user="LAB\\u", password="p", **kw)
    c.notes = []
    return c


def member_snap(**kw: Any) -> Snapshot:
    ca = host("CA01", dns_host="ca01.lab.test", rid=2100)
    plain = host("APP01", dns_host="app01.lab.test", rid=2101)
    return gsnap(ca, plain, dc("DC01"), gpos=[], entries=[], ca_hosts=["CA01$"], **kw)


def test_only_tier0_members_are_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def signing(host_: str, port: int) -> tuple[bool | None, str | None]:
        seen.append(host_)
        return False, None

    monkeypatch.setattr(probes, "smb_signing", signing)
    s = member_snap()
    collector()._probe_tier0_members(s)
    assert seen == ["ca01.lab.test"]
    assert s.probes.tier0_smb_checked


def test_no_probes_means_no_member_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "smb_signing", lambda *_: pytest.fail("probed"))
    s = member_snap()
    collector(probes=False)._probe_tier0_members(s)
    assert not s.probes.tier0_smb_checked


def test_unreachable_member_and_missing_name_are_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "smb_signing", lambda *_: (None, "timed out"))
    s = member_snap()
    s.accounts.append(host("CA02", rid=2102))
    s.ca_hosts.append("CA02$")
    c = collector()
    c._probe_tier0_members(s)
    assert any("CA01$" in n and "not known" in n for n in c.notes)
    assert any("CA02$" in n and "dNSHostName" in n for n in c.notes)
    assert findings(s, "AD-INF-025") is None


def test_tier0_member_without_signing() -> None:
    probe = Probes(
        tier0_smb=[HostSmb("CA01$", False), HostSmb("OK$", True)], tier0_smb_checked=True
    )
    f = only(member_snap(probes=probe), "AD-INF-025")
    assert f.severity == Severity.HIGH and f.objects == ["CA01$"]


def test_member_signing_negative_and_unknown() -> None:
    probe = Probes(tier0_smb=[HostSmb("OK$", True), HostSmb("U$", None, "x")])
    assert findings(member_snap(probes=probe), "AD-INF-025") is None


def pack(**kw: Any) -> Snapshot:
    return snapshot(user("alice"), probes=Probes(dcs=[DcProbe("DC01", **kw)], dc_pack_ran=True))


@pytest.mark.parametrize(
    ("check_id", "field", "severity"),
    [
        ("AD-INF-026", "webclient", Severity.MEDIUM),
        ("AD-INF-027", "smb1", Severity.HIGH),
        ("AD-INF-028", "tls10", Severity.MEDIUM),
        ("AD-INF-028", "tls11", Severity.MEDIUM),
    ],
)
def test_pack_checks(check_id: str, field: str, severity: Severity) -> None:
    assert only(pack(**{field: True}), check_id).severity == severity
    assert findings(pack(**{field: False}), check_id) is None
    assert findings(pack(**{field: None}), check_id) is None


def test_pack_off_judges_nothing() -> None:
    s = pack(webclient=True, smb1=True, tls10=True)
    s.probes.dc_pack_ran = False
    assert not {"AD-INF-026", "AD-INF-027", "AD-INF-028"} & {f.check_id for f in run_all(s)}


def test_modern_tls_alone_is_quiet() -> None:
    assert findings(pack(tls12=True, tls13=True, tls10=False), "AD-INF-028") is None


def test_collection_runs_the_pack_only_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(probes, "smb_posture", lambda *_: (True, False))
    monkeypatch.setattr(probes, "ldaps_channel_binding_required", lambda *_: None)
    monkeypatch.setattr(probes, "webclient", lambda *_: calls.append("web") or False)
    monkeypatch.setattr(probes, "smb1_enabled", lambda *_: calls.append("smb1") or None)
    monkeypatch.setattr(
        probes,
        "ldaps_tls_versions",
        lambda *_: (
            calls.append("tls") or dict.fromkeys(("tls10", "tls11", "tls12", "tls13"), False)
        ),
    )
    off = collector(plain_port=0, https_port=0, http_port=0, all_dcs=False, use_ssl=True)
    off._probe_dc("DC01", True)
    assert calls == []
    on = collector(
        plain_port=0, https_port=0, http_port=0, all_dcs=False, use_ssl=True, dc_probes=True
    )
    result = on._probe_dc("DC01", True)
    assert calls == ["web", "smb1", "tls"]
    assert result.webclient is False and result.smb1 is None
    assert any("could not tell: SMBv1" in n for n in on.notes)


# --- the wire ----------------------------------------------------------------------------


def serve(handler: Any) -> tuple[int, threading.Thread]:
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def run() -> None:
        with server:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                handler(conn)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return port, thread


def smb1_response(status: int, dialect: int) -> bytes:
    header = b"\xffSMB\x72" + struct.pack("<I", status) + bytes(23)
    body = bytes([17]) + struct.pack("<H", dialect) + bytes(33)
    packet = header + body
    return struct.pack(">I", len(packet)) + packet


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (smb1_response(0, 0), True),
        (smb1_response(0, 0xFFFF), False),
        (smb1_response(0xC0000022, 0), False),
        (struct.pack(">I", 8) + b"\xfeSMB" + bytes(60), False),
        (b"", False),
    ],
    ids=["picked", "no common dialect", "refused", "smb2 answer", "hung up"],
)
def test_smb1_answer(reply: bytes, expected: bool) -> None:
    received: list[bytes] = []

    def handler(conn: socket.socket) -> None:
        received.append(conn.recv(4096))
        if reply:
            conn.sendall(reply)

    port, thread = serve(handler)
    assert probes.smb1_enabled("127.0.0.1", port, timeout=5) is expected
    thread.join(5)
    assert received[0][4:9] == b"\xffSMB\x72"
    assert received[0].endswith(b"\x02NT LM 0.12\x00")
    assert struct.unpack(">I", received[0][:4])[0] == len(received[0]) - 4


def test_smb1_no_listener_is_unknown() -> None:
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    assert probes.smb1_enabled("127.0.0.1", port, timeout=2) is None


def test_tls_versions_all_refused_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "_tls_handshake", lambda *_: False)
    assert set(probes.ldaps_tls_versions("x", 636).values()) == {None}


def test_tls_versions_mixed(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(_host: str, _port: int, version: ssl.TLSVersion) -> bool:
        return version >= ssl.TLSVersion.TLSv1_2

    monkeypatch.setattr(probes, "_tls_handshake", answer)
    assert probes.ldaps_tls_versions("x", 636) == {
        "tls10": False,
        "tls11": False,
        "tls12": True,
        "tls13": True,
    }


def test_tls_handshake_no_listener_is_unknown() -> None:
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    assert probes._tls_handshake("127.0.0.1", port, ssl.TLSVersion.TLSv1_2) is None


def test_tls_server_hanging_up_counts_as_refused() -> None:
    port, thread = serve(lambda conn: conn.recv(1024))
    assert probes._tls_handshake("127.0.0.1", port, ssl.TLSVersion.TLSv1_2) is False
    thread.join(5)


def test_client_library_limit_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_version: ssl.TLSVersion) -> ssl.SSLContext:
        raise ssl.SSLError("no protocols")

    monkeypatch.setattr(probes, "_tls_context", refuse)
    assert probes._tls_handshake("127.0.0.1", 1, ssl.TLSVersion.TLSv1) is None


def test_clean_domain_reading_scripts_stays_clean() -> None:
    s = snapshot(user("alice"), gpo_scripts_checked=True)
    assert run_all(s) == []
