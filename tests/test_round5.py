"""Round 5: the MS-RRP client and the CA-side checks (ESC6, ESC7, ESC11, ESC16)."""

from __future__ import annotations

import json
import struct

import pytest

from ad_doctor import probes, sd, winreg
from ad_doctor.checks import ca_control, officer_templates, run_all
from ad_doctor.model import CaConfig, Probes, Severity, Snapshot
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_ADMINS, DOMAIN_SID, DOMAIN_USERS, HELPDESK, template
from .test_checks import computer, only, snapshot

CA_HOST = "ca01.lab.test"
BASE = probes.CA_CONFIGURATION
POLICY = "CertificateAuthority_MicrosoftDefault.Policy"


# --- DCE/RPC framing --------------------------------------------------------------------


def _pdu(ptype: int, flags: int, call_id: int, stub: bytes) -> bytes:
    if ptype == winreg.PTYPE_RESPONSE:
        body = struct.pack("<IHBx", len(stub), 0, 0) + stub
    elif ptype == winreg.PTYPE_FAULT:
        body = struct.pack("<IHBxI", 0, 0, 0, struct.unpack("<I", stub)[0]) + b"\0" * 4
    else:
        body = stub
    header = struct.pack(
        "<BBBB4sHHI", 5, 0, ptype, flags, b"\x10\0\0\0", winreg.HEADER_LEN + len(body), 0, call_id
    )
    return header + body


def _bind_ack() -> bytes:
    body = struct.pack("<HHI", winreg.MAX_FRAG, winreg.MAX_FRAG, 0)
    body += struct.pack("<H", 0) + b"\0\0"  # zero-length secondary address, padded
    body += struct.pack("<BxxxHHx", 1, 0, 0) + b"\0" * 19
    return _pdu(winreg.PTYPE_BIND_ACK, 3, 1, body)


class FakeTransport:
    """A message-mode pipe that answers each request from a scripted queue."""

    def __init__(self, replies: list[bytes]) -> None:
        self.replies = replies
        self.sent: list[bytes] = []
        self._pending = b""

    def write(self, data: bytes) -> None:
        self.sent.append(data)
        if data[2] == winreg.PTYPE_BIND:
            self._pending = _bind_ack()
        else:
            self._pending = self.replies.pop(0)

    def read(self) -> bytes:
        out, self._pending = self._pending, b""
        return out


def test_bind_sets_the_transmit_size() -> None:
    client = winreg.RpcClient(FakeTransport([]))
    client.bind()
    assert client.max_xmit == winreg.MAX_FRAG
    assert client.transport.sent[0][2] == winreg.PTYPE_BIND


def test_call_reassembles_a_fragmented_response() -> None:
    first = _pdu(winreg.PTYPE_RESPONSE, winreg.PFC_FIRST_FRAG, 2, b"AAAA")
    last = _pdu(winreg.PTYPE_RESPONSE, winreg.PFC_LAST_FRAG, 2, b"BBBB")
    client = winreg.RpcClient(FakeTransport([first + last]))
    client.bind()
    assert client.call(17, b"") == b"AAAABBBB"


def test_call_arrives_in_small_reads() -> None:
    whole = _pdu(winreg.PTYPE_RESPONSE, 3, 2, b"HELLO")

    class Dribble(FakeTransport):
        def read(self) -> bytes:
            out, self._pending = self._pending[:4], self._pending[4:]
            return out

    client = winreg.RpcClient(Dribble([whole]))
    client.bind()
    assert client.call(17, b"") == b"HELLO"


def test_a_fault_is_raised_with_its_status() -> None:
    fault = _pdu(winreg.PTYPE_FAULT, 3, 2, struct.pack("<I", 0x00000005))
    client = winreg.RpcClient(FakeTransport([fault]))
    client.bind()
    with pytest.raises(winreg.RpcFault) as exc:
        client.call(17, b"")
    assert exc.value.status == 5


def test_a_bind_nak_is_an_error() -> None:
    class Nak(FakeTransport):
        def write(self, data: bytes) -> None:
            self.sent.append(data)
            self._pending = _pdu(winreg.PTYPE_BIND_NAK, 3, 1, b"\0\0")

    with pytest.raises(winreg.RpcError):
        winreg.RpcClient(Nak([])).bind()


# --- BaseRegQueryValue encoding/decoding ------------------------------------------------


def _value_response(
    value_type: int, data: bytes, status: int = 0, needed: int | None = None
) -> bytes:
    needed = len(data) if needed is None else needed
    stub = struct.pack("<II", 0x20000, value_type)  # lpType
    stub += struct.pack("<IIII", 0x20004, len(data), 0, len(data)) + data
    stub += b"\0" * (-len(data) % 4)
    stub += struct.pack("<II", 0x20008, needed)  # lpcbData
    stub += struct.pack("<II", 0x2000C, len(data))  # lpcbLen
    stub += struct.pack("<I", status)
    return stub


def test_parse_dword_value() -> None:
    status, value_type, data, _ = winreg.parse_query_value(
        _value_response(winreg.REG_DWORD, struct.pack("<I", 0x11014E))
    )
    assert status == 0
    assert winreg.decode_value(value_type, data) == 0x11014E


def test_parse_multi_sz_value() -> None:
    raw = (sd.SZOID_NTDS_CA_SECURITY_EXT + "\0\0").encode("utf-16-le")
    _, value_type, data, _ = winreg.parse_query_value(_value_response(winreg.REG_MULTI_SZ, raw))
    assert winreg.decode_value(value_type, data) == [sd.SZOID_NTDS_CA_SECURITY_EXT]


def test_registry_retries_on_more_data() -> None:
    """Registry.query_value asks again with the size the server reported."""
    big = ("x" * 3000 + "\0").encode("utf-16-le")
    small = _value_response(winreg.REG_SZ, b"", winreg.ERROR_MORE_DATA, len(big))
    full = _value_response(winreg.REG_SZ, big)
    reg = winreg.Registry.__new__(winreg.Registry)
    # the two queries are call ids 2 and 3 (the bind was call id 1)
    reg.rpc = winreg.RpcClient(
        FakeTransport(
            [_pdu(winreg.PTYPE_RESPONSE, 3, 2, small), _pdu(winreg.PTYPE_RESPONSE, 3, 3, full)]
        )
    )
    reg.rpc.bind()
    reg.hklm = b"h" * 20
    assert reg.query_value(b"k" * 20, "Big") == "x" * 3000


# --- read_ca_config against a fake registry ---------------------------------------------


class FakeRegistry:
    """A nested dict key -> {value_name: value}; serves the four RRP reads."""

    def __init__(self, tree: dict[str, dict[str, winreg.RegValue]]) -> None:
        self.tree = tree
        self.hklm = b"HKLM"
        self.closed = 0

    def open_key(self, parent: bytes, path: str) -> bytes:
        full = path if parent == self.hklm else parent.decode() + "\\" + path
        if full not in self.tree:
            raise winreg.RegistryError(winreg.ERROR_FILE_NOT_FOUND, f"open {path}")
        return full.encode()

    def query_value(self, key: bytes, name: str) -> winreg.RegValue:
        values = self.tree[key.decode()]
        if name not in values:
            raise winreg.RegistryError(winreg.ERROR_FILE_NOT_FOUND, f"read {name}")
        return values[name]

    def close_key(self, key: bytes) -> None:
        self.closed += 1


def _tree(**policy: winreg.RegValue) -> dict[str, dict[str, winreg.RegValue]]:
    ca = f"{BASE}\\adlab-CA"
    return {
        BASE: {"Active": "adlab-CA"},
        ca: {"InterfaceFlags": 0x641, "Security": b""},
        f"{ca}\\PolicyModules": {"Active": POLICY},
        f"{ca}\\PolicyModules\\{POLICY}": {
            "EditFlags": 0x11014E,
            "RequestDisposition": 1,
            **policy,
        },
    }


def test_read_ca_config_default_lab_values() -> None:
    cfg = probes.read_ca_config(FakeRegistry(_tree()), CA_HOST, "adlab-CA")
    assert cfg.error is None
    assert cfg.name == "adlab-CA"
    assert cfg.edit_flags == 0x11014E
    assert cfg.interface_flags == 0x641
    assert cfg.disabled_extensions == []
    assert cfg.policy_module == POLICY


def test_read_ca_config_reports_esc6_and_esc16() -> None:
    cfg = probes.read_ca_config(
        FakeRegistry(
            _tree(EditFlags=0x15014E, DisableExtensionList=[sd.SZOID_NTDS_CA_SECURITY_EXT])
        ),
        CA_HOST,
        "adlab-CA",
    )
    assert cfg.edit_flags & sd.EDITF_ATTRIBUTESUBJECTALTNAME2
    assert cfg.disabled_extensions == [sd.SZOID_NTDS_CA_SECURITY_EXT]


def test_read_ca_config_third_party_policy_leaves_fields_unknown() -> None:
    tree = _tree()
    tree[f"{BASE}\\adlab-CA\\PolicyModules"]["Active"] = "Acme.Policy"
    cfg = probes.read_ca_config(FakeRegistry(tree), CA_HOST, "adlab-CA")
    assert cfg.third_party_policy
    assert cfg.edit_flags is None and cfg.disabled_extensions is None
    assert cfg.error is None


def test_read_ca_config_access_denied() -> None:
    class Denied(FakeRegistry):
        def open_key(self, parent: bytes, path: str) -> bytes:
            raise winreg.RegistryError(winreg.ERROR_ACCESS_DENIED, "open")

    cfg = probes.read_ca_config(Denied({}), CA_HOST, "adlab-CA")
    assert cfg.error is not None and "access denied" in cfg.error
    assert cfg.edit_flags is None


# --- the checks over hand-built CaConfig objects ----------------------------------------

CA01 = computer("CA01", sid=f"{DOMAIN_SID}-1500", dns_host=CA_HOST)


def _snap(*configs: CaConfig, **kw: object) -> Snapshot:
    return snapshot(CA01, probes=Probes(ca_configs=list(configs)), ca_hosts=["CA01$"], **kw)


def ca(**kw: object) -> CaConfig:
    values: dict[str, object] = {"name": "adlab-CA", "host": CA_HOST}
    values.update(kw)
    return CaConfig(**values)  # type: ignore[arg-type]


def found(snap: Snapshot) -> dict[str, object]:
    return {f.check_id: f for f in run_all(snap)}


def test_esc6_alone_is_medium() -> None:
    f = only(_snap(ca(edit_flags=0x15014E)), "AD-ADCS-012")
    assert f.objects == ["adlab-CA"]
    assert f.severity == Severity.MEDIUM


def test_esc6_pending_drops_a_level() -> None:
    f = only(_snap(ca(edit_flags=0x15014E, request_disposition=0x101)), "AD-ADCS-012")
    assert f.severity == Severity.LOW
    assert "hold every request" in f.detail


def test_esc6_absent_edit_flags_does_not_fire() -> None:
    assert "AD-ADCS-012" not in found(_snap(ca(edit_flags=None)))


def test_esc11_fires_high() -> None:
    f = only(_snap(ca(interface_flags=0x441)), "AD-ADCS-014")
    assert f.severity == Severity.HIGH


def test_esc11_absent_interface_flags_is_unknown() -> None:
    assert "AD-ADCS-014" not in found(_snap(ca(interface_flags=None)))


def test_esc16_alone_is_medium() -> None:
    f = only(_snap(ca(disabled_extensions=[sd.SZOID_NTDS_CA_SECURITY_EXT])), "AD-ADCS-015")
    assert f.severity == Severity.MEDIUM


def test_esc6_and_esc16_chain_is_high() -> None:
    snap = _snap(ca(edit_flags=0x15014E, disabled_extensions=[sd.SZOID_NTDS_CA_SECURITY_EXT]))
    f = only(snap, "AD-CHAIN-004")
    assert f.severity == Severity.HIGH
    assert f.objects == ["adlab-CA"]
    both = found(snap)
    assert both["AD-ADCS-012"].severity == Severity.MEDIUM
    assert both["AD-ADCS-015"].severity == Severity.MEDIUM


def test_esc7_manage_ca_is_high() -> None:
    snap = _snap(ca(aces=[Ace(HELPDESK, sd.CA_MANAGE)]), principals={HELPDESK: "helpdesk"})
    f = only(snap, "AD-ADCS-013")
    assert f.objects == ["adlab-CA: helpdesk (ManageCA)"]
    assert f.severity == Severity.HIGH


def test_esc7_officer_only_without_vulnerable_template_is_medium() -> None:
    snap = _snap(ca(aces=[Ace(HELPDESK, sd.CA_OFFICER)]), principals={HELPDESK: "helpdesk"})
    f = only(snap, "AD-ADCS-013")
    assert f.objects == ["adlab-CA: helpdesk (ManageCertificates)"]
    assert f.severity == Severity.MEDIUM
    assert "does not yet give a certificate" in f.detail


def test_esc7_officer_with_vulnerable_template_is_high() -> None:
    snap = _snap(
        ca(aces=[Ace(HELPDESK, sd.CA_OFFICER)]),
        templates=[template("LabESC1", enrollee_supplies_subject=True)],
        principals={HELPDESK: "helpdesk"},
    )
    f = only(snap, "AD-ADCS-013")
    assert f.severity == Severity.HIGH
    assert "LabESC1" in f.detail


def test_esc7_skips_default_tier0_holders() -> None:
    snap = _snap(
        ca(
            owner="S-1-5-32-544",
            aces=[
                Ace(DOMAIN_ADMINS, sd.CA_MANAGE | sd.CA_OFFICER),
                Ace("S-1-5-32-544", sd.CA_MANAGE),
            ],
        )
    )
    assert "AD-ADCS-013" not in found(snap)


def test_esc7_owner_counts_as_manage_ca() -> None:
    snap = _snap(ca(owner=HELPDESK), principals={HELPDESK: "helpdesk"})
    f = only(snap, "AD-ADCS-013")
    assert f.objects == ["adlab-CA: helpdesk (ManageCA)"]


def test_esc7_feeds_a_control_path() -> None:
    snap = _snap(ca(aces=[Ace(DOMAIN_USERS, sd.CA_MANAGE)]))
    paths = found(snap)["AD-PATH-001"].objects  # type: ignore[attr-defined]
    assert any("ManageCA (ESC7)]-> CA01$" in p for p in paths)


def test_adcs016_on_unreadable_ca() -> None:
    f = only(_snap(ca(error="RemoteRegistry not running or disabled")), "AD-ADCS-016")
    assert f.objects == [f"{CA_HOST}: RemoteRegistry not running or disabled"]
    assert f.severity == Severity.LOW


def test_third_party_policy_never_reads_as_clean() -> None:
    snap = _snap(ca(policy_module="Acme.Policy"))
    f = found(snap)
    assert "AD-ADCS-012" not in f and "AD-ADCS-015" not in f
    assert any("policy module Acme.Policy" in o for o in f["AD-ADCS-016"].objects)


def test_ca_control_and_officer_templates_helpers() -> None:
    snap = _snap(
        ca(aces=[Ace(HELPDESK, sd.CA_MANAGE)]),
        templates=[template("T", enrollee_supplies_subject=True)],
    )
    assert [(c.name, sid, right) for c, sid, right in ca_control(snap)] == [
        ("adlab-CA", HELPDESK, "ManageCA")
    ]
    assert officer_templates(snap) == ["T"]


def test_ca_configs_survive_the_snapshot_roundtrip() -> None:
    snap = _snap(ca(edit_flags=0x15014E, aces=[Ace(HELPDESK, sd.CA_OFFICER)], owner="S-1-5-32-544"))
    back = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert back.probes.ca_configs == snap.probes.ca_configs
