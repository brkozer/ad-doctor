"""msDS-KeyCredentialLink values, without keeping the keys.

A value is DN-Binary: B:<hex length>:<KEYCREDENTIALLINK_BLOB in hex>:<owner DN>. The blob
([MS-ADTS] 2.2.20) is a version and a list of length, identifier, value entries. Only what
identifies a key to a person is kept; KeyMaterial is read for its presence and dropped.

A read that returns nothing proves nothing: LDAP leaves out an attribute the account may
not read exactly as it leaves out an empty one. msDS-ReplValueMetaData lists the values
of linked attributes even when the attribute itself is denied, so it tells the two apart.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

from .model import KeyCredential, filetime_to_datetime

BLOB_VERSION = 0x200
KEY_MATERIAL = 0x03
KEY_USAGE = 0x04
KEY_SOURCE = 0x05
DEVICE_ID = 0x06
CUSTOM_KEY_INFORMATION = 0x07
LAST_LOGON = 0x08
CREATION_TIME = 0x09
USAGE_NGC = 0x01
SOURCE_AD = 0x00

ATTRIBUTE = "msDS-KeyCredentialLink"
DN_BINARY = re.compile(r"^B:(\d{1,9}):([0-9A-Fa-f]*):")
VALUE_BLOCK = re.compile(r"<DS_REPL_VALUE_META_DATA>(.*?)</DS_REPL_VALUE_META_DATA>", re.S)
VALUE_ATTRIBUTE = re.compile(r"<pszAttributeName>([^<]*)</pszAttributeName>")
VALUE_DELETED = re.compile(r"<ftimeDeleted>([^<]*)</ftimeDeleted>")
VALUE_CREATED = re.compile(r"<ftimeCreated>([^<]*)</ftimeCreated>")
# the DC cuts this short of the whole blob, so it can only match the start of a value
VALUE_DATA = re.compile(r"<pbData>([0-9A-Fa-f]*)</pbData>")
DOTNET_TICKS = 0x3FFFFFFFFFFFFFFF  # DateTime.ToBinary: the top two bits hold the kind


def _blob(value: str) -> bytes | None:
    m = DN_BINARY.match(value)
    if not m or int(m.group(1)) != len(m.group(2)) or len(m.group(2)) % 2:
        return None
    return bytes.fromhex(m.group(2))


def _time(raw: bytes | None, source: int | None) -> datetime | None:
    """FILETIME from AD. Entra-written keys hold a .NET DateTime instead (DSInternals)."""
    if raw is None or len(raw) != 8:
        return None
    number = int.from_bytes(raw, "little", signed=True)
    try:
        if source == SOURCE_AD or source is None:
            return filetime_to_datetime(number)
        ticks = number & DOTNET_TICKS
        return datetime(1, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


def parse_blob(blob: bytes) -> KeyCredential:
    """The readable parts of a blob; parsed stays False on anything malformed."""
    if len(blob) < 4 or int.from_bytes(blob[:4], "little") != BLOB_VERSION:
        return KeyCredential()
    entries: dict[int, bytes] = {}
    pos = 4
    while pos < len(blob):
        if pos + 3 > len(blob):
            return KeyCredential()
        length = int.from_bytes(blob[pos : pos + 2], "little")
        identifier = blob[pos + 2]
        pos += 3
        if pos + length > len(blob):
            return KeyCredential()
        entries[identifier] = blob[pos : pos + length]
        pos += length
    usage = entries.get(KEY_USAGE, b"")
    source = entries.get(KEY_SOURCE, b"\x00")
    device = entries.get(DEVICE_ID, bytes(16))
    if not entries.get(KEY_MATERIAL) or len(usage) != 1 or len(source) != 1 or len(device) != 16:
        return KeyCredential()
    return KeyCredential(
        parsed=True,
        device_id=str(UUID(bytes_le=device)) if any(device) else "",
        created=_time(entries.get(CREATION_TIME), source[0]),
        usage=usage[0],
        source=source[0],
        # the only shape a computer may write to itself ([MS-ADTS] validated write)
        self_written=usage[0] == USAGE_NGC
        and source[0] == SOURCE_AD
        and CUSTOM_KEY_INFORMATION not in entries
        and LAST_LOGON not in entries,
    )


def _live_rows(metadata: str) -> list[tuple[str, datetime | None]]:
    """(start of the value in hex, when it was added) of each value still present."""
    rows = []
    for block in VALUE_BLOCK.findall(metadata):
        name = VALUE_ATTRIBUTE.search(block)
        deleted = VALUE_DELETED.search(block)
        if not name or name.group(1) != ATTRIBUTE or not deleted:
            continue
        if not deleted.group(1).startswith("1601"):
            continue  # removed: the row stays until the tombstone goes
        created = VALUE_CREATED.search(block)
        data = VALUE_DATA.search(block)
        try:
            added = (
                datetime.fromisoformat(created.group(1).replace("Z", "+00:00")) if created else None
            )
        except ValueError:
            added = None
        rows.append((data.group(1).lower() if data else "", added))
    return rows


def read(values: list[str], metadata: str) -> list[KeyCredential]:
    """Every key on an account: the values read, then those only the metadata shows."""
    rows = _live_rows(metadata)
    keys = []
    for value in values:
        blob = _blob(value)
        key = parse_blob(blob) if blob is not None else KeyCredential()
        text = blob.hex() if blob is not None else None
        row = next((r for r in rows if text is None or text.startswith(r[0])), None)
        if row is not None:
            rows.remove(row)
            key.added = row[1]
        keys.append(key)
    return keys + [KeyCredential(readable=False, added=added) for _, added in rows]
