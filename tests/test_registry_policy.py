"""Registry.pol parsing ([MS-GPREG]), Group Policy precedence and the checks built on them."""

from __future__ import annotations

import contextlib
import json
import random
import struct
from dataclasses import replace
from typing import Any

import pytest
from smbprotocol.exceptions import SMBOSError
from smbprotocol.header import NtStatus

from ad_doctor import gpo_scope, redact, regpol, sd, sysvol
from ad_doctor.checks import run_all
from ad_doctor.gpo_scope import CSE_REGISTRY
from ad_doctor.model import Account, DirObject, GpLink, Gpo, RegistryEntry, Severity, Snapshot

from .test_checks import ids, only, snapshot
from .test_gpo_local import APPLY, DC_OU, HEAD, ISOLATED, LAB, READ, dc, host

SITE = "cn=site-a,cn=sites,cn=configuration,dc=lab,dc=test"
SITE_B = "cn=site-b,cn=sites,cn=configuration,dc=lab,dc=test"
KEY = regpol.LLMNR_KEY
NAME = regpol.LLMNR_VALUE
GUID = "{A0000000-0000-0000-0000-000000000000}"


# --- building a Registry.pol ------------------------------------------------------------------


def text16(value: str) -> bytes:
    return value.encode("utf-16-le") + b"\0\0"


def instruction(key: str, name: str, kind: int, payload: bytes) -> bytes:
    return (
        b"[\0"
        + text16(key)
        + b";\0"
        + text16(name)
        + b";\0"
        + struct.pack("<I", kind)
        + b";\0"
        + struct.pack("<I", len(payload))
        + b";\0"
        + payload
        + b"]\0"
    )


def dword(key: str, name: str, value: int) -> bytes:
    return instruction(key, name, regpol.REG_DWORD, struct.pack("<I", value))


def sz(key: str, name: str, value: str) -> bytes:
    return instruction(key, name, regpol.REG_SZ, text16(value))


def pol(*instructions: bytes) -> bytes:
    return b"PReg\x01\0\0\0" + b"".join(instructions)


# --- parser -----------------------------------------------------------------------------------


def test_parses_a_dword_and_a_string_with_their_types() -> None:
    parsed = regpol.parse(
        pol(dword(KEY, NAME, 0), sz(regpol.WSUS_KEY, "WUServer", "http://wsus.lab.test:8530"))
    )
    assert parsed.entries == [
        RegistryEntry(KEY, NAME, "set", regpol.REG_DWORD, 0),
        RegistryEntry(
            regpol.WSUS_KEY, "WUServer", "set", regpol.REG_SZ, "http://wsus.lab.test:8530"
        ),
    ]


def test_other_values_are_not_kept() -> None:
    other = dword(r"Software\Policies\Microsoft\Something", "Whatever", 1)
    assert regpol.parse(pol(other)).entries == []


def test_big_endian_qword_binary_and_multi_string_data() -> None:
    data = [
        (regpol.REG_DWORD_BIG_ENDIAN, b"\0\0\0\x05", 5),
        (regpol.REG_QWORD, struct.pack("<Q", 7), 7),
        (regpol.REG_DWORD, b"\x01", None),  # the wrong length is no number
        (regpol.REG_BINARY, b"\x01\x02", None),
        (regpol.REG_MULTI_SZ, text16("a") + text16("b") + b"\0\0", ["a", "b"]),
    ]
    for kind, payload, expected in data:
        (entry,) = regpol.parse(pol(instruction(KEY, NAME, kind, payload))).entries
        assert entry.data == expected, kind


@pytest.mark.parametrize(
    ("marker", "kind", "payload", "action", "name"),
    [
        (f"**del.{NAME}", 1, b"", "delete", NAME),
        (f"**DEL.{NAME}", 1, b"", "delete", NAME),
        ("**delvals.", 1, b"", "delete_all", ""),
        ("**DelVals", 1, b"", "delete_all", ""),
        (f"**soft.{NAME}", 4, b"\0\0\0\0", "soft", NAME),
    ],
)
def test_markers(marker: str, kind: int, payload: bytes, action: str, name: str) -> None:
    (entry,) = regpol.parse(pol(instruction(KEY, marker, kind, payload))).entries
    assert (entry.action, entry.name) == (action, name)


def test_delete_values_lists_only_the_names_read() -> None:
    entries = regpol.parse(
        pol(sz(KEY, "**DeleteValues", f"Other;{NAME};")),
    ).entries
    assert [(e.action, e.name) for e in entries] == [("delete", NAME)]


def test_delete_keys_keeps_a_key_at_or_above_a_watched_one() -> None:
    parent = r"Software\Policies\Microsoft\Windows NT"
    entries = regpol.parse(pol(sz(parent, "**DeleteKeys ", "DNSClient;Unrelated"))).entries
    assert [(e.key, e.action) for e in entries] == [(regpol.norm(KEY), "delete_key")]


def test_key_and_marker_compare_without_case() -> None:
    (entry,) = regpol.parse(pol(dword(KEY.upper(), NAME.lower(), 0))).entries
    assert entry.key == KEY.upper()
    assert regpol.norm(entry.key) == regpol.norm(KEY)


def test_secure_key_and_unknown_markers_set_nothing() -> None:
    parsed = regpol.parse(pol(dword(KEY, "**SecureKey", 1), dword(KEY, "**Strange", 1)))
    assert parsed.entries == []


def test_a_password_value_leaves_only_its_location() -> None:
    winlogon = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    parsed = regpol.parse(pol(sz(winlogon, "DefaultPassword", "hunter2-do-not-keep")))
    assert parsed.entries == []
    assert parsed.secrets == [(winlogon, "DefaultPassword")]
    assert "hunter2" not in repr(parsed)


def test_a_toggle_named_like_a_password_is_not_a_secret() -> None:
    assert regpol.parse(pol(dword(KEY, "PasswordComplexity", 1))).secrets == []
    assert regpol.parse(pol(sz(KEY, "DefaultPassword", ""))).secrets == []


@pytest.mark.parametrize(
    "bad",
    [
        b"",  # a zero-byte Registry.pol also makes Windows fail
        b"PReg",
        b"XXXX\x01\0\0\0",
        b"PReg\x02\0\0\0",
        pol(dword(KEY, NAME, 0))[:-1],
        pol(dword(KEY, NAME, 0))[:-2],
        pol(b"[\0" + KEY.encode("utf-16-le")),
        pol(b"]\0"),
        pol(instruction(KEY, NAME, 4, b"\0\0\0\0")[:20]),
        b"PReg\x01\0\0\0" + b"[\0" + text16(KEY) + b";\0" + text16(NAME) + b";\0"
        b"\x04\0\0\0;\0" + b"\xff\xff\xff\xff;\0\0\0\0\0]\0",
        pol(dword(KEY, NAME, 0)) + b"garbage",
    ],
)
def test_malformed_files_raise_and_do_not_crash(bad: bytes) -> None:
    with pytest.raises(regpol.MalformedPol):
        regpol.parse(bad)


def test_random_bytes_never_escape_as_another_exception() -> None:
    rng = random.Random(16)
    good = pol(dword(KEY, NAME, 0), sz(regpol.HARDENED_KEY, r"\\*\SYSVOL", "RequireIntegrity=1"))
    for _ in range(2000):
        data = bytearray(good)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        with contextlib.suppress(regpol.MalformedPol):
            regpol.parse(bytes(data))


def test_too_many_entries_for_the_settings_read_is_refused() -> None:
    with pytest.raises(regpol.MalformedPol):
        regpol.parse(pol(*[dword(KEY, NAME, 0)] * (regpol.MAX_KEPT + 1)))


def test_url_credentials_and_long_strings_are_cut() -> None:
    (entry,) = regpol.parse(
        pol(sz(regpol.WSUS_KEY, "WUServer", "http://user:pw@wsus.lab.test")),
    ).entries
    assert entry.data == "http://wsus.lab.test"
    (entry,) = regpol.parse(pol(sz(KEY, NAME, "x" * 5000))).entries
    assert isinstance(entry.data, str) and len(entry.data) == regpol.MAX_TEXT


def test_hardened_paths_keep_only_sysvol_and_netlogon() -> None:
    entries = regpol.parse(
        pol(
            sz(regpol.HARDENED_KEY, r"\\*\SYSVOL", "RequireMutualAuthentication=1"),
            sz(regpol.HARDENED_KEY, r"\\fs01\finance", "RequireIntegrity=1"),
        )
    ).entries
    assert [e.name for e in entries] == [r"\\*\SYSVOL"]


def test_module_names_are_kept_without_their_data() -> None:
    (entry,) = regpol.parse(pol(sz(regpol.MODULE_NAMES_KEY, "*", "*"))).entries
    assert (entry.name, entry.data) == ("*", "")


# --- collection -------------------------------------------------------------------------------


def scan(monkeypatch: pytest.MonkeyPatch, reader: Any) -> sysvol.SysvolResult:
    def no_walk(*a: Any, **k: Any) -> None:
        raise OSError("no tree")

    monkeypatch.setattr(sysvol.smbclient, "register_session", lambda *a, **k: None)
    monkeypatch.setattr(sysvol.smbclient, "walk", no_walk)
    monkeypatch.setattr(sysvol.smbclient, "reset_connection_cache", lambda: None)
    monkeypatch.setattr(sysvol, "_read", reader)
    return sysvol.scan("dc", "lab.test", "u", "p", [GUID])


def reader_for(status: int | None = None, data: bytes = b"") -> Any:
    def read(path: str, port: int) -> bytes:
        if "GptTmpl" in path:
            raise SMBOSError(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, path)
        if status is not None:
            raise SMBOSError(status, path)
        return data

    return read


def test_scan_reads_each_gpo(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, reader_for(data=pol(dword(KEY, NAME, 0))))
    assert [e.name for e in result.registry[GUID]] == [NAME]
    assert result.scanned


def test_scan_without_a_file_counts_as_read(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, reader_for(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND))
    assert result.registry == {GUID: []}


def test_scan_failed_read_stays_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, reader_for(NtStatus.STATUS_ACCESS_DENIED))
    assert result.registry == {}
    assert result.registry_unread == [rf"Policies\{GUID}\Machine\Registry.pol (SMBOSError)"]


def test_scan_malformed_file_is_a_note_and_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, reader_for(data=b"not a policy file"))
    assert result.registry == {}
    assert any("not a valid Registry.pol" in n for n in result.notes)


def test_scan_oversized_file_is_a_note_and_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    result = scan(monkeypatch, reader_for(data=b"x" * sysvol.MAX_FILE))
    assert result.registry == {}
    assert any("not evaluated" in n for n in result.notes)


def test_scan_reports_where_a_password_value_is_and_not_the_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    winlogon = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    data = pol(sz(winlogon, "DefaultPassword", "hunter2-do-not-keep"))
    result = scan(monkeypatch, reader_for(data=data))
    assert any("DefaultPassword" in n for n in result.notes)
    assert "hunter2" not in json.dumps([result.notes, str(result.registry)])


# --- precedence: a table written from Microsoft's documentation --------------------------------

# GPO links: (name, value, container, gPLink index, enforced, enabled), lowest precedence first.
# Sources: "Group Policy scope in Windows" and "Group Policy processing for Windows" (Microsoft
# Learn), New-GPLink -Order, [MS-GPOL] GPO Search and the glossary's "enforced GPO".
DOM = f"{HEAD}".lower()
Link = tuple[str, int, str, int, bool, bool]


def links(*rows: Link) -> list[Link]:
    return list(rows)


TABLE: list[tuple[str, list[Link], str, set[str], int]] = [
    (
        "site, then domain, then OU: the last writer wins",
        links(("site", 1, SITE, 0, False, True), ("dom", 2, HEAD, 0, False, True),
              ("ou", 3, LAB, 0, False, True)),
        LAB, set(), 3,
    ),
    (
        "a child OU overrides its parent",
        links(("parent", 1, LAB, 0, False, True), ("child", 2, ISOLATED, 0, False, True)),
        ISOLATED, set(), 2,
    ),
    (
        "same OU: the rightmost gPLink entry is link order 1 and wins",
        links(("newest", 1, LAB, 0, False, True), ("oldest", 2, LAB, 1, False, True)),
        LAB, set(), 2,
    ),
    (
        "enforced at the domain beats an unenforced OU link",
        links(("dom", 1, HEAD, 0, True, True), ("ou", 2, LAB, 0, False, True)),
        LAB, set(), 1,
    ),
    (
        "enforced at the domain beats enforced at the OU: the highest enforced wins",
        links(("dom", 1, HEAD, 0, True, True), ("ou", 2, LAB, 0, True, True)),
        LAB, set(), 1,
    ),
    (
        "enforced at the site beats enforced at the domain",
        links(("site", 1, SITE, 0, True, True), ("dom", 2, HEAD, 0, True, True)),
        LAB, set(), 1,
    ),
    (
        "two enforced links in one OU: the rightmost wins",
        links(("left", 1, LAB, 0, True, True), ("right", 2, LAB, 1, True, True)),
        LAB, set(), 2,
    ),
    (
        "Block Inheritance stops an unenforced domain link",
        links(("dom", 1, HEAD, 0, False, True), ("ou", 2, ISOLATED, 0, False, True)),
        ISOLATED, {ISOLATED}, 2,
    ),
    (
        "Block Inheritance does not stop an enforced link",
        links(("dom", 1, HEAD, 0, True, True), ("ou", 2, ISOLATED, 0, False, True)),
        ISOLATED, {ISOLATED}, 1,
    ),
    (
        "a block on the parent leaves the parent's own links in",
        links(("parent", 1, LAB, 0, False, True), ("dom", 2, HEAD, 0, False, True)),
        ISOLATED, {LAB}, 1,
    ),
    (
        "a block also stops site links",
        links(("site", 1, SITE, 0, False, True), ("ou", 2, LAB, 0, False, True)),
        LAB, {LAB}, 2,
    ),
    (
        "a disabled link never applies, enforced or not",
        links(("off", 1, LAB, 1, True, False), ("on", 2, LAB, 0, False, True)),
        LAB, set(), 2,
    ),
    (
        "a GPO linked twice counts where it comes last",
        links(("twice", 1, LAB, 0, False, True), ("dom", 2, HEAD, 0, False, True),
              ("twice", 1, HEAD, 1, False, True)),
        LAB, set(), 1,
    ),
]  # fmt: skip


def gpo(
    name: str,
    entries: list[RegistryEntry] | None = None,
    placed: list[tuple[str, int, bool, bool]] | None = None,
    **kw: Any,
) -> tuple[Gpo, list[RegistryEntry] | None]:
    guid = "{" + f"{abs(hash(name)) % 10**12:012d}".rjust(36, "0") + "}"
    made = Gpo(
        name=name,
        guid=guid,
        linked_to=[],
        aces=[READ, APPLY],
        links=[
            GpLink(c, "site" if c in (SITE, SITE_B) else "ou", enabled, enforced, index)
            for c, index, enforced, enabled in (placed or [])
        ],
        machine_version=1,
        machine_extensions=[CSE_REGISTRY],
        **kw,
    )
    return made, entries


def set_value(value: int, key: str = KEY, name: str = NAME) -> RegistryEntry:
    return RegistryEntry(key, name, "set", regpol.REG_DWORD, value)


def build(rows: list[Link], blocked: set[str] | None = None, **kw: Any) -> Snapshot:
    grouped: dict[str, tuple[int, list[tuple[str, int, bool, bool]]]] = {}
    for name, value, container, index, enforced, enabled in rows:
        grouped.setdefault(name, (value, []))[1].append((container, index, enforced, enabled))
    made = [gpo(n, [set_value(v)], placed) for n, (v, placed) in grouped.items()]
    return snap_of(made, blocked, **kw)


def snap_of(
    made: list[tuple[Gpo, list[RegistryEntry] | None]],
    blocked: set[str] | None = None,
    **kw: Any,
) -> Snapshot:
    objects = [DirObject(dn=c, name=c, kind="ou", gp_blocked=True) for c in (blocked or set())]
    return snapshot(
        gpos=[g for g, _ in made],
        gpo_registry={g.guid: e for g, e in made if e is not None},
        registry_policy_collected=True,
        objects=objects,
        site_count=1,
        **kw,
    )


def member(ou: str = LAB, name: str = "HOST1", rid: int = 3000) -> Account:
    return host(name, ou, rid, os="Windows Server 2022 Standard")


def resolved(snap: Snapshot, a: Account) -> gpo_scope.Effective:
    return gpo_scope.RegistryView(snap).value(a, KEY, NAME)


@pytest.mark.parametrize(
    ("title", "rows", "where", "blocked", "winner"),
    TABLE,
    ids=[row[0] for row in TABLE],
)
def test_precedence_table(
    title: str, rows: list[Link], where: str, blocked: set[str], winner: int
) -> None:
    computer = member(where)
    snap = build(rows, blocked, accounts=[computer])
    e = resolved(snap, computer)
    assert e.decided, title
    assert e.value == winner, title


def test_processing_order_reaches_the_same_gpos_as_the_scope_logic() -> None:
    for _, rows, where, blocked, _ in TABLE:
        computer = member(where)
        r = gpo_scope._Resolver(build(rows, blocked, accounts=[computer]))
        assert {g.guid for g, _ in r.processing_order(computer)} == {
            g.guid for g, _ in r.linked(computer)
        }


def test_a_filtered_out_gpo_drops_out_of_precedence() -> None:
    computer = member()
    other = sd.Ace("S-1-5-21-1-2-3-9999", 0x20094)
    apply_other = sd.Ace("S-1-5-21-1-2-3-9999", sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)
    denied, _ = gpo("hidden", placed=[(LAB, 1, False, True)])
    denied = replace(denied, aces=[other, apply_other])
    made = [
        gpo("kept", [set_value(1)], [(LAB, 0, False, True)]),
        (denied, [set_value(9)]),
    ]
    snap = snap_of(made, accounts=[computer])
    known = DirObject(dn="CN=x", name="x", kind="group", sid="S-1-5-21-1-2-3-9999")
    snap = replace(snap, objects=[known])
    assert resolved(snap, computer).value == 1


def test_a_wmi_filter_on_the_winner_leaves_it_undecided() -> None:
    computer = member()
    made = [
        gpo("low", [set_value(1)], [(LAB, 0, False, True)]),
        gpo("filtered", [set_value(0)], [(LAB, 1, False, True)], wmi_filter="Only laptops"),
    ]
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert not e.decided
    assert {o.data for o in e.outcomes} == {0, 1}
    assert e.why == ["WMI filter Only laptops"]


def test_a_wmi_filter_on_a_lower_gpo_does_not_matter() -> None:
    computer = member()
    made = [
        gpo("filtered", [set_value(0)], [(LAB, 0, False, True)], wmi_filter="Only laptops"),
        gpo("high", [set_value(1)], [(LAB, 1, False, True)]),
    ]
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and e.value == 1


def test_an_unknown_filter_group_is_a_caveat_and_undecided() -> None:
    computer = member()
    foreign = "S-1-5-21-9-9-9-1234"
    g, entries = gpo("filtered", [set_value(0)], [(LAB, 1, False, True)])
    g = replace(
        g,
        aces=[sd.Ace(foreign, 0x20094), sd.Ace(foreign, sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY)],
    )
    e = resolved(snap_of([(g, entries)], accounts=[computer]), computer)
    assert not e.decided
    assert e.why == [gpo_scope.FILTER_CAVEAT]


def test_several_sites_leave_a_member_undecided() -> None:
    computer = member()
    made = [gpo("site", [set_value(0)], [(SITE, 0, False, True)])]
    snap = replace(snap_of(made, accounts=[computer]), site_count=2)
    e = resolved(snap, computer)
    assert not e.decided and e.why == [gpo_scope.SITE_CAVEAT]


def test_a_dc_gets_only_its_own_sites_links() -> None:
    server = replace(dc(), os="Windows Server 2025 Standard")
    made = [
        gpo("mine", [set_value(1)], [(SITE, 0, False, True)]),
        gpo("other", [set_value(0)], [(SITE_B, 0, False, True)]),
    ]
    snap = replace(
        snap_of(made, accounts=[server]),
        site_count=2,
        dc_sites={server.dn.lower(): SITE},
    )
    e = resolved(snap, server)
    assert e.decided and e.value == 1


def test_a_gpo_windows_would_skip_does_not_count() -> None:
    computer = member()
    off, entries = gpo("off", [set_value(0)], [(LAB, 1, False, True)], flags=2)
    empty, _ = gpo("empty", [set_value(0)], [(LAB, 2, False, True)])
    empty = replace(empty, machine_version=0)
    no_cse, _ = gpo("nocse", [set_value(0)], [(LAB, 3, False, True)])
    no_cse = replace(no_cse, machine_extensions=[])
    base = gpo("base", [set_value(1)], [(LAB, 0, False, True)])
    made = [base, (off, entries), (empty, [set_value(0)]), (no_cse, [set_value(0)])]
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and e.value == 1


def test_unreadable_winner_is_undecided_but_a_winner_above_it_decides() -> None:
    computer = member()
    made = [gpo("low", [set_value(1)], [(LAB, 0, False, True)]),
            gpo("unread", None, [(LAB, 1, False, True)])]  # fmt: skip
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert not e.decided
    assert "not readable" in e.why[0]
    made = [gpo("unread", None, [(LAB, 0, False, True)]),
            gpo("high", [set_value(1)], [(LAB, 1, False, True)])]  # fmt: skip
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and e.value == 1


def test_delete_marker_on_top_removes_a_lower_value() -> None:
    computer = member()
    deleting = [RegistryEntry(KEY, NAME, "delete")]
    made = [gpo("low", [set_value(0)], [(LAB, 0, False, True)]),
            gpo("high", deleting, [(LAB, 1, False, True)])]  # fmt: skip
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and not e.present and e.gpo == "high"


def test_delvals_clears_the_key_and_later_entries_of_the_same_file_stay() -> None:
    computer = member()
    wipe = RegistryEntry(KEY, "", "delete_all")
    made = [gpo("low", [set_value(1)], [(LAB, 0, False, True)]),
            gpo("high", [wipe, set_value(0)], [(LAB, 1, False, True)])]  # fmt: skip
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and e.value == 0


def test_delete_key_removes_values_below_it() -> None:
    computer = member()
    wipe = RegistryEntry(r"Software\Policies\Microsoft\Windows NT", "", "delete_key")
    made = [gpo("low", [set_value(0)], [(LAB, 0, False, True)]),
            gpo("high", [wipe], [(LAB, 1, False, True)])]  # fmt: skip
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and not e.present


def test_soft_leaves_a_value_alone_and_says_so_when_it_sets_one() -> None:
    computer = member()
    soft = RegistryEntry(KEY, NAME, "soft", regpol.REG_DWORD, 0)
    made = [gpo("low", [set_value(1)], [(LAB, 0, False, True)]),
            gpo("high", [soft], [(LAB, 1, False, True)])]  # fmt: skip
    assert resolved(snap_of(made, accounts=[computer]), computer).value == 1
    alone = [gpo("high", [soft], [(LAB, 0, False, True)])]
    e = resolved(snap_of(alone, accounts=[computer]), computer)
    assert e.value == 0 and e.why == [gpo_scope.SOFT_CAVEAT]


def test_key_and_value_names_compare_without_case() -> None:
    computer = member()
    entry = RegistryEntry(KEY.upper(), NAME.lower(), "set", regpol.REG_DWORD, 0)
    e = resolved(
        snap_of([gpo("g", [entry], [(LAB, 0, False, True)])], accounts=[computer]), computer
    )
    assert e.value == 0


def test_two_gpos_agreeing_are_decided_even_if_one_may_not_apply() -> None:
    computer = member()
    made = [gpo("a", [set_value(0)], [(LAB, 0, False, True)]),
            gpo("b", [set_value(0)], [(LAB, 1, False, True)], wmi_filter="w")]  # fmt: skip
    e = resolved(snap_of(made, accounts=[computer]), computer)
    assert e.decided and e.value == 0


# --- checks -----------------------------------------------------------------------------------

LLMNR, WSUS, POWERSHELL, UNC = "AD-GPO-009", "AD-GPO-010", "AD-GPO-011", "AD-GPO-012"
NEW = {LLMNR, WSUS, POWERSHELL, UNC}


def with_entries(entries: list[RegistryEntry], **kw: Any) -> tuple[Snapshot, Account]:
    computer = kw.pop("computer", member())
    made = [gpo("Baseline", entries, [(LAB, 0, False, True)], **kw)]
    return snap_of(made, accounts=[computer]), computer


GOOD_HARDENING = "RequireMutualAuthentication=1,RequireIntegrity=1"
ALL_GOOD = [
    set_value(0),
    RegistryEntry(regpol.SCRIPT_BLOCK_KEY, regpol.SCRIPT_BLOCK_VALUE, "set", 4, 1),
    RegistryEntry(regpol.MODULE_KEY, regpol.MODULE_VALUE, "set", 4, 1),
    RegistryEntry(regpol.MODULE_NAMES_KEY, "*", "set", 1, ""),
    RegistryEntry(regpol.HARDENED_KEY, r"\\*\SYSVOL", "set", 1, GOOD_HARDENING),
    RegistryEntry(regpol.HARDENED_KEY, r"\\*\NETLOGON", "set", 1, GOOD_HARDENING),
]


def test_old_snapshots_and_runs_without_sysvol_are_not_judged() -> None:
    computer = member()
    snap = snapshot(computer)
    assert not NEW & ids(run_all(snap))
    data = json.loads(json.dumps(snap.to_json()))
    del data["registry_policy_collected"], data["gpo_registry"]
    loaded = Snapshot.from_json(data)
    assert not loaded.registry_policy_collected
    assert all(c in " ".join(loaded.notes) for c in NEW)
    assert not NEW & ids(run_all(loaded))


def test_all_settings_good_gives_no_finding() -> None:
    snap, _ = with_entries(list(ALL_GOOD))
    assert not NEW & ids(run_all(snap))


def test_llmnr_no_gpo_is_low_and_says_the_host_is_unknown() -> None:
    snap, computer = with_entries([])
    f = only(snap, LLMNR)
    assert f.severity is Severity.LOW
    assert "own registry" in f.detail
    assert f.objects == ["Lab: HOST1: no GPO disables LLMNR"]
    assert "HOST1" in f.objects[0] and computer.sam == "HOST1$"


def test_llmnr_set_to_one_is_medium() -> None:
    snap, _ = with_entries([set_value(1)])
    f = only(snap, LLMNR)
    assert f.severity is Severity.MEDIUM and "Baseline" in f.objects[0]


def test_llmnr_set_to_zero_is_quiet() -> None:
    snap, _ = with_entries([set_value(0)])
    assert LLMNR not in ids(run_all(snap))


def test_llmnr_undecided_is_info() -> None:
    snap, _ = with_entries([set_value(0)], wmi_filter="Some filter")
    f = only(snap, LLMNR)
    assert f.severity is Severity.INFO and "Some filter" in f.objects[0]


def test_llmnr_unreadable_gpo_is_info_not_a_weakness() -> None:
    computer = member()
    snap = snap_of([gpo("Unread", None, [(LAB, 0, False, True)])], accounts=[computer])
    f = only(snap, LLMNR)
    assert f.severity is Severity.INFO and "not readable" in f.objects[0]


def test_llmnr_non_dword_is_info() -> None:
    entry = RegistryEntry(KEY, NAME, "set", 1, "0")
    snap, _ = with_entries([entry])
    assert only(snap, LLMNR).severity is Severity.INFO


def test_only_windows_hosts_count() -> None:
    linux = host("NAS1", LAB, 3001, os="Data ONTAP")
    bare = host("CNO1", LAB, 3002)
    sso = host("AZUREADSSOACC", LAB, 3003, os="Windows Server 2022")
    computer = member()
    snap = snap_of(
        [gpo("Baseline", [], [(LAB, 0, False, True)])], accounts=[computer, linux, bare, sso]
    )
    assert only(snap, LLMNR).objects == ["Lab: HOST1: no GPO disables LLMNR"]


def test_many_computers_collapse_into_one_row_with_a_stable_key() -> None:
    computers = [member(LAB, f"H{i:02}", 3000 + i) for i in range(8)]
    snap = snap_of([gpo("Baseline", [], [(LAB, 0, False, True)])], accounts=computers)
    f = only(snap, LLMNR)
    assert len(f.objects) == 1 and "+3 more" in f.objects[0]
    assert f.key(f.objects[0]) == "Lab: no GPO disables LLMNR"


def wsus(url: str, use: int | None = 1) -> list[RegistryEntry]:
    out = [RegistryEntry(regpol.WSUS_KEY, regpol.WSUS_SERVER, "set", 1, url)]
    if use is not None:
        out.append(RegistryEntry(regpol.WSUS_AU_KEY, regpol.WSUS_USE, "set", 4, use))
    return out


def test_wsus_http_is_medium_on_a_member_with_the_url_shown() -> None:
    snap, _ = with_entries(wsus("http://wsus.lab.test:8530"))
    f = only(snap, WSUS)
    assert f.severity is Severity.MEDIUM and "http://wsus.lab.test:8530" in f.objects[0]


def test_wsus_http_is_high_on_a_dc() -> None:
    server = replace(dc(), os="Windows Server 2025 Standard")
    made = [gpo("Updates", wsus("HTTP://wsus.lab.test"), [(DC_OU, 0, False, True)])]
    f = only(snap_of(made, accounts=[server]), WSUS)
    assert f.severity is Severity.HIGH


@pytest.mark.parametrize(
    "entries",
    [wsus("https://wsus.lab.test"), wsus("http://wsus.lab.test", use=0),
     wsus("http://wsus.lab.test", use=None), []],
)  # fmt: skip
def test_wsus_quiet(entries: list[RegistryEntry]) -> None:
    snap, _ = with_entries(entries)
    assert WSUS not in ids(run_all(snap))


def test_wsus_undecided_is_info() -> None:
    snap, _ = with_entries(wsus("http://wsus.lab.test"), wmi_filter="Some filter")
    assert only(snap, WSUS).severity is Severity.INFO


def test_wsus_unreadable_alone_is_no_evidence() -> None:
    computer = member()
    snap = snap_of([gpo("Unread", None, [(LAB, 0, False, True)])], accounts=[computer])
    assert WSUS not in ids(run_all(snap))


def test_powershell_not_set_is_low() -> None:
    snap, _ = with_entries([])
    f = only(snap, POWERSHELL)
    assert f.severity is Severity.LOW
    assert "script block logging not set; module logging not set" in f.objects[0]
    assert "own registry" in f.detail


def test_powershell_explicitly_off_is_medium() -> None:
    entries = [RegistryEntry(regpol.SCRIPT_BLOCK_KEY, regpol.SCRIPT_BLOCK_VALUE, "set", 4, 0)]
    snap, _ = with_entries(entries)
    f = only(snap, POWERSHELL)
    assert f.severity is Severity.MEDIUM and "off by Baseline" in f.objects[0]


def test_powershell_module_logging_without_names_is_low() -> None:
    entries = [
        RegistryEntry(regpol.SCRIPT_BLOCK_KEY, regpol.SCRIPT_BLOCK_VALUE, "set", 4, 1),
        RegistryEntry(regpol.MODULE_KEY, regpol.MODULE_VALUE, "set", 4, 1),
    ]
    snap, _ = with_entries(entries)
    f = only(snap, POWERSHELL)
    assert f.severity is Severity.LOW and "no module listed" in f.objects[0]


def test_powershell_both_on_is_quiet() -> None:
    snap, _ = with_entries(list(ALL_GOOD))
    assert POWERSHELL not in ids(run_all(snap))


def test_powershell_undecided_is_info() -> None:
    snap, _ = with_entries(list(ALL_GOOD), wmi_filter="Some filter")
    f = only(snap, POWERSHELL)
    assert f.severity is Severity.INFO and "not decided" in f.objects[0]


def old_host() -> Account:
    return replace(member(), os="Windows Server 2012 R2 Standard")


def test_unc_absent_on_an_old_os_is_medium() -> None:
    snap, _ = with_entries([], computer=old_host())
    f = only(snap, UNC)
    assert f.severity is Severity.MEDIUM and "no default" in f.objects[0]


def test_unc_absent_on_a_new_os_is_info_and_says_so() -> None:
    snap, _ = with_entries([])
    f = only(snap, UNC)
    assert f.severity is Severity.INFO and "by default" in f.objects[0]


def test_unc_good_is_quiet() -> None:
    snap, _ = with_entries(list(ALL_GOOD), computer=old_host())
    assert UNC not in ids(run_all(snap))


def test_unc_weak_flags_are_medium_on_a_new_os_too() -> None:
    entries = [
        RegistryEntry(
            regpol.HARDENED_KEY, r"\\*\SYSVOL", "set", 1, "RequireMutualAuthentication=0"
        ),
        RegistryEntry(regpol.HARDENED_KEY, r"\\*\NETLOGON", "set", 1, GOOD_HARDENING),
    ]
    snap, _ = with_entries(entries)
    f = only(snap, UNC)
    assert f.severity is Severity.MEDIUM
    assert "SYSVOL: set without" in f.objects[0] and "NETLOGON" not in f.objects[0]


def test_unc_named_server_is_info() -> None:
    entries = [
        RegistryEntry(regpol.HARDENED_KEY, r"\\dc01\SYSVOL", "set", 1, GOOD_HARDENING),
        RegistryEntry(regpol.HARDENED_KEY, r"\\*\NETLOGON", "set", 1, GOOD_HARDENING),
    ]
    snap, _ = with_entries(entries, computer=old_host())
    f = only(snap, UNC)
    assert f.severity is Severity.INFO and "named servers (dc01)" in f.objects[0]


def test_unc_undecided_is_info() -> None:
    snap, _ = with_entries(list(ALL_GOOD), wmi_filter="Some filter")
    assert only(snap, UNC).severity is Severity.INFO


def test_unc_privacy_counts_as_integrity() -> None:
    flags = "RequireMutualAuthentication=1,RequirePrivacy=1"
    entries = [
        RegistryEntry(regpol.HARDENED_KEY, r"\\*\SYSVOL", "set", 1, flags),
        RegistryEntry(regpol.HARDENED_KEY, r"\\*\NETLOGON", "set", 1, flags),
    ]
    snap, _ = with_entries(entries, computer=old_host())
    assert UNC not in ids(run_all(snap))


@pytest.mark.parametrize(
    ("os_name", "legacy"),
    [
        ("Windows Server 2008 R2 Standard", True),
        ("Windows 7 Enterprise", True),
        ("Windows 8.1 Pro", True),
        ("Windows Server\u00ae 2012 Standard", True),
        ("Windows 10 Enterprise", False),
        ("Windows 11 Pro", False),
        ("Windows Server 2016 Standard", False),
        ("Windows Server 2025 Standard Evaluation", False),
    ],
)
def test_unc_default_depends_on_the_windows_version(os_name: str, legacy: bool) -> None:
    computer = replace(member(), os=os_name)
    snap, _ = with_entries([], computer=computer)
    expected = Severity.MEDIUM if legacy else Severity.INFO
    assert only(snap, UNC).severity is expected


# --- snapshots --------------------------------------------------------------------------------


def test_registry_policy_survives_json() -> None:
    snap, _ = with_entries(list(ALL_GOOD))
    assert Snapshot.from_json(json.loads(json.dumps(snap.to_json()))) == snap


def test_redaction_hides_hosts_and_keeps_the_findings() -> None:
    entries = [
        *wsus("http://wsus01.secretcorp.test:8530"),
        RegistryEntry(
            regpol.HARDENED_KEY, r"\\dc77.secretcorp.test\SYSVOL", "set", 1, GOOD_HARDENING
        ),
        RegistryEntry(regpol.MODULE_NAMES_KEY, "SecretCorp.Tools", "set", 1, ""),
    ]
    computer = member()
    # a domain object that happens to share words with the registry path
    software = DirObject(dn=f"OU=Software,{HEAD}", name="Software", kind="ou")
    windows = DirObject(dn=f"OU=Windows,{HEAD}", name="Windows", kind="ou")
    made = [gpo("Baseline", entries, [(LAB, 0, False, True)])]
    snap = replace(snap_of(made, accounts=[computer]), objects=[software, windows])
    before = {f.check_id: f.severity for f in run_all(snap) if f.check_id in NEW}
    redacted = redact.redact(json.loads(json.dumps(snap.to_json())), b"key")
    dumped = json.dumps(redacted["gpo_registry"])
    assert "wsus01" not in dumped and "secretcorp" not in dumped.lower()
    assert regpol.WSUS_KEY.replace("\\", "\\\\") in dumped
    back = Snapshot.from_json(redacted)
    assert {f.check_id: f.severity for f in run_all(back) if f.check_id in NEW} == before


def test_notes_when_gpos_are_unread_name_the_checks() -> None:
    from ad_doctor.collect import _registry_notes

    computer = member()
    snap = snap_of([gpo("Unread", None, [(LAB, 0, False, True)])], accounts=[computer])
    notes = " ".join(_registry_notes(snap, []))
    assert "Unread" in notes and LLMNR in notes
    snap = replace(snap, registry_policy_collected=False)
    assert "not judged" in " ".join(_registry_notes(snap, []))
