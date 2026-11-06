"""Key credentials and strong mappings on tier 0: parsing, reading, AD-ACC-013, redaction."""

from __future__ import annotations

import json
import struct
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from ad_doctor import keycred, redact, report, viewer
from ad_doctor.checks import run_all
from ad_doctor.collect import REPL_METADATA, VALUE_METADATA, Collector
from ad_doctor.model import UAC, KeyCredential, Severity, Snapshot

from .test_checks import NOW, computer, ids, only, snapshot, user

DEVICE = UUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
MATERIAL = bytes(range(200))
OWNER = "CN=adm,CN=Users,DC=lab,DC=test"
WHEN = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
STRONG = "X509:<I>DC=test,DC=lab,CN=lab-CA<SR>1200000000ac11000000002b"
WEAK = "X509:<I>DC=test,DC=lab,CN=lab-CA<S>CN=adm"


def entry(identifier: int, value: bytes) -> bytes:
    return struct.pack("<HB", len(value), identifier) + value


def filetime(when: datetime) -> bytes:
    return struct.pack("<q", (when - FILETIME_EPOCH) // timedelta(microseconds=1) * 10)


def blob(*entries: bytes, version: int = 0x200) -> bytes:
    return struct.pack("<I", version) + b"".join(entries)


def user_blob() -> bytes:
    return blob(
        entry(1, bytes(32)),
        entry(2, bytes(32)),
        entry(3, MATERIAL),
        entry(4, b"\x01"),
        entry(5, b"\x00"),
        entry(6, DEVICE.bytes_le),
        entry(7, b"\x01\x00"),
        entry(8, filetime(WHEN)),
        entry(9, filetime(WHEN)),
    )


def computer_blob() -> bytes:
    return blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, b"\x00"), entry(9, filetime(WHEN)))


def value(raw: bytes) -> str:
    text = raw.hex().upper()
    return f"B:{len(text)}:{text}:{OWNER}"


def row(
    attribute: str = keycred.ATTRIBUTE, data: str = "", deleted: str = "1601-01-01T00:00:00Z"
) -> str:
    return (
        "<DS_REPL_VALUE_META_DATA>"
        f"<pszAttributeName>{attribute}</pszAttributeName><pszObjectDn>{OWNER}</pszObjectDn>"
        f"<cbData>401</cbData><pbData>{data}</pbData><ftimeDeleted>{deleted}</ftimeDeleted>"
        "<ftimeCreated>2026-10-02T08:00:00Z</ftimeCreated>"
        "</DS_REPL_VALUE_META_DATA>"
    )


# --- parsing ------------------------------------------------------------------------------


def test_user_key_gives_device_time_usage_and_source() -> None:
    key = keycred.parse_blob(user_blob())
    assert key.parsed and key.readable
    assert key.device_id == str(DEVICE)
    assert key.created == WHEN
    assert (key.usage, key.source) == (1, 0)
    assert not key.self_written


def test_only_the_shape_of_the_validated_write_counts_as_self_written() -> None:
    assert keycred.parse_blob(computer_blob()).self_written
    custom = blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, b"\x00"), entry(7, b"\x01\x00"))
    logon = blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, b"\x00"), entry(8, bytes(8)))
    fido = blob(entry(3, MATERIAL), entry(4, b"\x07"), entry(5, b"\x00"))
    entra = blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, b"\x01"))
    for shape in (custom, logon, fido, entra):
        assert not keycred.parse_blob(shape).self_written


def test_all_zero_device_id_is_no_device() -> None:
    raw = blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(6, bytes(16)))
    assert keycred.parse_blob(raw).device_id == ""


def test_time_of_an_entra_key_is_a_dotnet_datetime() -> None:
    ticks = (WHEN - datetime(1, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1) * 10
    stamp = struct.pack("<Q", ticks | (1 << 62))  # kind: UTC
    raw = blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, b"\x01"), entry(9, stamp))
    assert keycred.parse_blob(raw).created == WHEN


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\x02",
        blob(version=0x100),
        blob(),
        blob(entry(4, b"\x01")),  # no key material
        blob(entry(3, MATERIAL)),  # no usage
        blob(entry(3, MATERIAL), entry(4, b"\x01\x01")),
        blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, b"")),
        blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(6, b"short")),
        blob(entry(3, MATERIAL), entry(4, b"\x01")) + b"\x01",
        blob(entry(3, MATERIAL), entry(4, b"\x01")) + b"\xff\xff\x03abc",
    ],
)
def test_malformed_blobs_are_not_parsed(raw: bytes) -> None:
    assert not keycred.parse_blob(raw).parsed


def test_every_truncation_is_survived() -> None:
    raw = user_blob()
    for size in range(len(raw)):
        keycred.parse_blob(raw[:size])


@pytest.mark.parametrize("stamp", [b"\xff" * 7 + b"\x7f", b"\xff" * 8, bytes(3)])
def test_impossible_times_are_dropped(stamp: bytes) -> None:
    for source in (b"\x00", b"\x01"):
        raw = blob(entry(3, MATERIAL), entry(4, b"\x01"), entry(5, source), entry(9, stamp))
        key = keycred.parse_blob(raw)
        assert key.parsed
        if source == b"\x00":
            assert key.created is None


@pytest.mark.parametrize(
    "text", ["", "junk", "B:4:zz:dn", "B:5:abcde:dn", "B:6:ab:dn", "B:3:abc:dn"]
)
def test_a_broken_dn_binary_is_one_unparsed_key(text: str) -> None:
    assert keycred.read([text], "") == [KeyCredential()]


def test_the_key_itself_is_not_kept() -> None:
    (key,) = keycred.read([value(user_blob())], "")
    snap = snapshot(user("adm", key_credentials=[key]))
    text = json.dumps(snap.to_json()).lower()
    assert MATERIAL.hex() not in text and MATERIAL[:16].hex() not in text


# --- value metadata -----------------------------------------------------------------------


def test_metadata_gives_the_time_the_value_was_added() -> None:
    start = user_blob().hex()[:290].upper()
    (key,) = keycred.read([value(user_blob())], row(data=start))
    assert key.parsed and key.added == datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


def test_a_value_only_the_metadata_shows_is_present_and_unreadable() -> None:
    (key,) = keycred.read([], row(data="0002"))
    assert not key.readable and not key.parsed
    assert key.added == datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


def test_one_readable_value_does_not_hide_a_second() -> None:
    other = "ffff"
    keys = keycred.read([value(user_blob())], row(data=user_blob().hex()[:40]) + row(data=other))
    assert [k.readable for k in keys] == [True, False]


def test_removed_values_and_other_attributes_are_not_keys() -> None:
    metadata = row(deleted="2026-10-03T00:00:00Z") + row(attribute="msDS-RevealedUsers")
    assert keycred.read([], metadata) == []


def test_a_row_without_a_usable_time_still_counts() -> None:
    text = row().replace("2026-10-02T08:00:00Z", "soon")
    (key,) = keycred.read([], text)
    assert not key.readable and key.added is None


# --- collection ---------------------------------------------------------------------------


def collector() -> Collector:
    return Collector(None)  # type: ignore[arg-type]


def test_nothing_returned_with_readable_metadata_means_no_key() -> None:
    c, a = collector(), user("adm")
    c._read_keys(a, [{REPL_METADATA.lower(): [b"<x/>"]}])
    assert a.key_credentials == [] and c._keys_note() == []


@pytest.mark.parametrize("entries", [[], [{}], [{VALUE_METADATA.lower(): [b""]}]])
def test_unreadable_metadata_is_unknown_not_clean(entries: list[dict[str, Any]]) -> None:
    c, a = collector(), user("adm")
    c._read_keys(a, entries)
    (note,) = c._keys_note()
    assert "adm" in note and "unknown" in note and "AD-ACC-013" in note


def test_value_metadata_in_ranges_is_unknown_not_clean() -> None:
    c, a = collector(), user("rodc")
    c.ranged.add((a.dn.lower(), VALUE_METADATA.lower()))
    c._read_keys(a, [{REPL_METADATA.lower(): [b"<x/>"]}])
    assert "rodc" in c._keys_note()[0]


def test_long_note_is_cut() -> None:
    c = collector()
    c.keys_unread = [f"a{i}" for i in range(7)]
    assert "(+2 more)" in c._keys_note()[0]


def test_ranged_attribute_is_remembered() -> None:
    class Extend:
        class standard:
            @staticmethod
            def paged_search(*args: Any, **kw: Any) -> list[dict[str, Any]]:
                raw = {f"{VALUE_METADATA};range=0-999": [b"x"]}
                return [{"type": "searchResEntry", "dn": "CN=R", "raw_attributes": raw}]

    class Conn:
        extend = Extend

    c = Collector(Conn())  # type: ignore[arg-type]
    c.search("CN=R", "(objectClass=*)", [VALUE_METADATA])
    assert ("cn=r", VALUE_METADATA.lower()) in c.ranged


# --- AD-ACC-013 ---------------------------------------------------------------------------


def admin(**kw: Any) -> Any:
    return user("adm", **kw)


def admin_snapshot(*accounts: Any) -> Snapshot:
    return snapshot(*accounts, privileged={"Domain Admins": [a.dn for a in accounts]})


def hello() -> KeyCredential:
    return keycred.parse_blob(user_blob())


def test_hello_shaped_key_on_an_admin_is_medium_and_names_the_device() -> None:
    a = admin(key_credentials=[hello()])
    f = only(admin_snapshot(a), "AD-ACC-013")
    assert f.severity is Severity.MEDIUM
    (text,) = f.objects
    assert str(DEVICE) in text and "2026-10-01" in text and "NGC" in text
    assert "Windows Hello" in f.detail


def test_identity_ignores_the_times() -> None:
    first = KeyCredential(parsed=True, device_id=str(DEVICE), usage=1, created=WHEN)
    later = KeyCredential(parsed=True, device_id=str(DEVICE), usage=1, added=NOW)
    keys = []
    for key in (first, later):
        f = only(admin_snapshot(admin(key_credentials=[key])), "AD-ACC-013")
        keys.append(f.key(f.objects[0]))
    assert keys[0] == keys[1]
    assert report.fingerprint("AD-ACC-013", keys[0]) == report.fingerprint("AD-ACC-013", keys[1])


def test_key_without_device_on_an_admin_is_high() -> None:
    key = KeyCredential(parsed=True, usage=1, source=0)
    f = only(admin_snapshot(admin(key_credentials=[key])), "AD-ACC-013")
    assert f.severity is Severity.HIGH and "no device ID" in f.objects[0]


def test_unusual_usage_on_an_admin_is_high() -> None:
    key = KeyCredential(parsed=True, usage=8, device_id=str(DEVICE))
    f = only(admin_snapshot(admin(key_credentials=[key])), "AD-ACC-013")
    assert f.severity is Severity.HIGH and "FEK" in f.objects[0]


def test_unparsed_value_is_high() -> None:
    f = only(admin_snapshot(admin(key_credentials=[KeyCredential(added=NOW)])), "AD-ACC-013")
    assert f.severity is Severity.HIGH and "does not parse" in f.objects[0]


def test_unreadable_key_is_reported_not_passed() -> None:
    key = KeyCredential(readable=False, added=NOW)
    f = only(admin_snapshot(admin(key_credentials=[key])), "AD-ACC-013")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["adm: key credential, contents not readable, added 2026-11-01"]


def test_computer_own_key_on_a_dc_is_low() -> None:
    key = keycred.parse_blob(computer_blob())
    dc = computer("DC02", 0x2000, laps=False, key_credentials=[key])
    f = only(snapshot(dc), "AD-ACC-013")
    assert f.severity is Severity.LOW and f.objects[0].startswith("DC02$: computer key")


def test_other_key_shape_on_a_dc_is_high() -> None:
    dc = computer("DC02", 0x2000, laps=False, key_credentials=[hello()])
    assert only(snapshot(dc), "AD-ACC-013").severity is Severity.HIGH


def test_key_on_disabled_krbtgt_is_high() -> None:
    snap = snapshot()
    next(a for a in snap.accounts if a.sam == "krbtgt").key_credentials = [hello()]
    assert only(snap, "AD-ACC-013").severity is Severity.HIGH


def test_builtin_administrator_counts_without_a_group() -> None:
    a = user("Administrator", sid="S-1-5-21-1-2-3-500", key_credentials=[hello()])
    assert "AD-ACC-013" in ids(run_all(snapshot(a)))


def test_managed_account_key_is_high() -> None:
    a = user("gmsa$", managed=True, key_credentials=[hello()])
    assert only(admin_snapshot(a), "AD-ACC-013").severity is Severity.HIGH


def test_outside_tier_0_and_disabled_accounts_are_silent() -> None:
    assert "AD-ACC-013" not in ids(run_all(snapshot(user("bob", key_credentials=[hello()]))))
    off = admin(uac=0x200 | UAC.ACCOUNTDISABLE, key_credentials=[hello()])
    assert "AD-ACC-013" not in ids(run_all(admin_snapshot(off)))


def test_strong_mapping_on_tier_0_is_medium_and_shows_only_its_type() -> None:
    f = only(admin_snapshot(admin(alt_security_identities=[STRONG])), "AD-ACC-013")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["adm: certificate mapping X509:<I><SR>"]


def test_kerberos_mapping_is_listed_by_type() -> None:
    a = admin(alt_security_identities=["Kerberos:adm@LAB.TEST"])
    assert only(admin_snapshot(a), "AD-ACC-013").objects == ["adm: certificate mapping Kerberos:"]


def test_a_value_that_is_no_mapping_is_not_shown() -> None:
    a = admin(alt_security_identities=["person@corp.example"])
    assert only(admin_snapshot(a), "AD-ACC-013").objects == ["adm: certificate mapping other:"]


def test_weak_mapping_stays_with_esc14_and_ordinary_users_are_silent() -> None:
    found = ids(run_all(admin_snapshot(admin(alt_security_identities=[WEAK]))))
    assert "AD-ADCS-009" in found and "AD-ACC-013" not in found
    plain = snapshot(user("bob", alt_security_identities=[STRONG]))
    assert "AD-ACC-013" not in ids(run_all(plain))


def test_worst_grade_decides() -> None:
    a = admin(key_credentials=[hello(), KeyCredential()], alt_security_identities=[STRONG])
    f = only(admin_snapshot(a), "AD-ACC-013")
    assert f.severity is Severity.HIGH and len(f.objects) == 3


# --- snapshots, redaction, viewer ---------------------------------------------------------


def stored() -> Snapshot:
    key = keycred.parse_blob(user_blob())
    key.added = NOW
    a = admin(
        key_credentials=[key, KeyCredential(readable=False, added=NOW)],
        alt_security_identities=[STRONG, "X509:<RFC822>person@corp.example"],
    )
    return admin_snapshot(a)


def test_key_credentials_survive_the_snapshot_file() -> None:
    snap = stored()
    back = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    a = next(x for x in back.accounts if x.sam == "adm")
    assert a.key_credentials[0].created == WHEN and a.key_credentials[0].added == NOW
    assert not a.key_credentials[1].readable
    assert only(back, "AD-ACC-013").objects == only(snap, "AD-ACC-013").objects


def test_older_snapshot_loads_and_says_keys_were_not_judged() -> None:
    data = json.loads(json.dumps(snapshot(user("adm")).to_json()))
    del data["key_credentials_checked"]
    for a in data["accounts"]:
        del a["key_credentials"]
    back = Snapshot.from_json(data)
    assert any("AD-ACC-013" in n for n in back.notes)
    assert "AD-ACC-013" not in ids(run_all(back))


def test_new_snapshot_has_no_such_note() -> None:
    data = json.loads(json.dumps(snapshot(key_credentials_checked=True).to_json()))
    assert not any("AD-ACC-013" in n for n in Snapshot.from_json(data).notes)


def test_redaction_covers_device_ids_and_mapping_values() -> None:
    data = json.loads(json.dumps(stored().to_json()))
    out = redact.redact(data, b"k")
    text = json.dumps(out)
    for secret in (str(DEVICE), "1200000000ac11000000002b", "person@corp.example", "lab-CA"):
        assert secret not in text, secret
    a = next(x for x in out["accounts"] if x["key_credentials"])
    assert UUID(a["key_credentials"][0]["device_id"])
    assert a["alt_security_identities"][0].startswith("X509:<I>x")
    assert "<SR>x" in a["alt_security_identities"][0]


def test_redaction_is_stable_and_keeps_the_findings() -> None:
    data = json.loads(json.dumps(stored().to_json()))
    first, second = redact.redact(data, b"k"), redact.redact(data, b"k")
    assert first == second
    f = only(Snapshot.from_json(first), "AD-ACC-013")
    assert f.severity is only(stored(), "AD-ACC-013").severity
    assert len(f.objects) == 3
    assert str(DEVICE) not in " ".join(f.objects)


def test_redaction_keeps_weak_and_strong_apart() -> None:
    a = admin(alt_security_identities=[WEAK])
    data = json.loads(json.dumps(admin_snapshot(a).to_json()))
    back = Snapshot.from_json(redact.redact(data, b"k"))
    assert "AD-ADCS-009" in ids(run_all(back))
    assert "AD-ACC-013" not in ids(run_all(back))


def test_redaction_of_a_mapping_without_a_type() -> None:
    r = redact.Redactor(b"k")
    assert "person" not in r.mapping("person@corp.example")
    assert "LAB" not in r.mapping("Kerberos:adm@LAB.TEST")


def test_viewer_shows_each_key_and_mapping() -> None:
    snap = stored()
    vm = viewer.viewmodel(report.Report(snap, run_all(snap)), snap, viewer.Options())
    (item,) = [f for f in vm["findings"] if f["id"] == "AD-ACC-013"]
    text = " ".join(item["objects"])
    assert str(DEVICE) in text and "not readable" in text and "X509:<I><SR>" in text
    assert item["keys"]
