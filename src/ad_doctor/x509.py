"""What the CA checks need from an X.509 certificate, from its DER encoding.

The certificate is read as data only: signatures are not verified and extensions are not
looked at. Malformed input raises ValueError, IndexError or UnicodeDecodeError.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

SEQUENCE = 0x30
SET = 0x31
OID = 0x06
INTEGER = 0x02
BIT_STRING = 0x03
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
CONTEXT_0 = 0xA0

COMMON_NAME = "2.5.4.3"
RSA = "1.2.840.113549.1.1.1"
RSA_PSS = "1.2.840.113549.1.1.10"
DSA = "1.2.840.10040.4.1"
EC = "1.2.840.10045.2.1"
SIGNATURE_HASHES = {
    "1.2.840.113549.1.1.2": "md2",
    "1.2.840.113549.1.1.3": "md4",
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.14": "sha224",
    "1.3.14.3.2.3": "md5",
    "1.3.14.3.2.2": "md4",
    "1.3.14.3.2.4": "md4",
    "1.3.14.3.2.27": "sha1",
    "1.3.14.3.2.29": "sha1",
    "1.2.840.10040.4.3": "sha1",
    "2.16.840.1.101.3.4.3.1": "sha224",
    "2.16.840.1.101.3.4.3.2": "sha256",
    "2.16.840.1.101.3.4.3.3": "sha384",
    "2.16.840.1.101.3.4.3.4": "sha512",
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
HASHES = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
CURVE_BITS = {"1.2.840.10045.3.1.7": 256, "1.3.132.0.34": 384, "1.3.132.0.35": 521}
STRING_TAGS = {0x0C: "utf-8", 0x13: "ascii", 0x14: "latin-1", 0x16: "ascii", 0x1E: "utf-16-be"}


@dataclass(frozen=True)
class Certificate:
    common_name: str
    key_type: str  # rsa, dsa, ec or unknown
    key_bits: int | None
    signature_hash: str  # md2, md5, sha1, sha256 and so on, or unknown
    self_signed: bool
    not_after: datetime | None


def _read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """(tag, content, position after the element); the sizes are checked against the input."""
    tag = data[pos]
    size = data[pos + 1]
    pos += 2
    if size & 0x80:
        count = size & 0x7F
        if not 0 < count <= 4 or pos + count > len(data):
            raise ValueError("bad DER length")
        size = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + size > len(data):
        raise ValueError("DER element runs past its parent")
    return tag, data[pos : pos + size], pos + size


def _children(data: bytes) -> list[tuple[int, bytes]]:
    out = []
    pos = 0
    while pos < len(data):
        tag, content, pos = _read(data, pos)
        out.append((tag, content))
    return out


def _oid(content: bytes) -> str:
    if not content:
        raise ValueError("empty OID")
    arcs = [min(content[0] // 40, 2), content[0] - 40 * min(content[0] // 40, 2)]
    value = 0
    for byte in content[1:]:
        value = value << 7 | byte & 0x7F
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(str(a) for a in arcs)


def _bits(integer: bytes) -> int:
    return int.from_bytes(integer, "big").bit_length()


def _time(tag: int, content: bytes) -> datetime | None:
    text = content.decode("ascii")
    try:
        if tag == UTC_TIME:
            parsed = datetime.strptime(text, "%y%m%d%H%M%SZ")
        elif tag == GENERALIZED_TIME:
            parsed = datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            return None
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _common_name(name: bytes) -> str:
    for _set_tag, rdn in _children(name):
        for _seq_tag, pair in _children(rdn):
            parts = _children(pair)
            if len(parts) == 2 and parts[0][0] == OID and _oid(parts[0][1]) == COMMON_NAME:
                encoding = STRING_TAGS.get(parts[1][0])
                return parts[1][1].decode(encoding) if encoding else ""
    return ""


def _signature_hash(algorithm: bytes) -> str:
    parts = _children(algorithm)
    oid = _oid(parts[0][1])
    if oid != RSA_PSS:
        return SIGNATURE_HASHES.get(oid, "unknown")
    # RSASSA-PSS names its hash in the parameters; without [0] the hash is SHA-1
    params = _children(parts[1][1]) if len(parts) > 1 and parts[1][0] == SEQUENCE else []
    for tag, content in params:
        if tag == CONTEXT_0:
            inner = _children(_children(content)[0][1])
            return HASHES.get(_oid(inner[0][1]), "unknown")
    return "sha1"


def _key(info: bytes) -> tuple[str, int | None]:
    parts = _children(info)
    algorithm = _children(parts[0][1])
    oid = _oid(algorithm[0][1])
    if oid in (RSA, RSA_PSS):
        # the BIT STRING starts with a count of unused bits
        modulus = _children(_children(parts[1][1][1:])[0][1])[0][1]
        return "rsa", _bits(modulus)
    if oid == DSA and len(algorithm) > 1:
        return "dsa", _bits(_children(algorithm[1][1])[0][1])
    if oid == DSA:
        return "dsa", None  # the parameters are inherited from the issuer
    if oid == EC:
        curve = _oid(algorithm[1][1]) if len(algorithm) > 1 and algorithm[1][0] == OID else ""
        return "ec", CURVE_BITS.get(curve)
    return "unknown", None


def parse(der: bytes) -> Certificate:
    """The fields of one certificate; ValueError or IndexError when it is malformed."""
    tag, body, _end = _read(der, 0)
    if tag != SEQUENCE:
        raise ValueError("not a certificate")
    tbs = _children(_children(body)[0][1])
    fields = tbs[1:] if tbs[0][0] == CONTEXT_0 else tbs
    if len(fields) < 6 or fields[0][0] != INTEGER:
        raise ValueError("not a certificate")
    _serial, algorithm, issuer, validity, subject, key_info = fields[:6]
    times = _children(validity[1])
    key_type, key_bits = _key(key_info[1])
    return Certificate(
        common_name=_common_name(subject[1]),
        key_type=key_type,
        key_bits=key_bits,
        signature_hash=_signature_hash(algorithm[1]),
        self_signed=issuer[1] == subject[1],
        not_after=_time(*times[1]),
    )
