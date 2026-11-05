"""A small read-only MS-RRP (remote registry) client over the SMB named pipe \\pipe\\winreg.

It speaks just enough DCE/RPC (connection-oriented, no RPC-level authentication: the SMB
session authenticates the caller) to open keys and read values: OpenLocalMachine,
BaseRegOpenKey, BaseRegQueryValue and BaseRegCloseKey. Every key is opened with KEY_READ;
nothing is ever written.

Opening the pipe starts the RemoteRegistry service on the target if it is set to start on
demand (a trigger on the pipe), which is a visible change of service state on that host.
"""

from __future__ import annotations

import struct
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from typing import Protocol

from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBException
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    ShareAccess,
)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

TIMEOUT = 10

# DCE/RPC (C706 chapter 12, MS-RPCE)
RRP_SYNTAX = uuid.UUID("338cd001-2244-31f1-aaaa-900038001003").bytes_le + struct.pack("<HH", 1, 0)
NDR_SYNTAX = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)
PTYPE_REQUEST = 0
PTYPE_RESPONSE = 2
PTYPE_FAULT = 3
PTYPE_BIND = 11
PTYPE_BIND_ACK = 12
PTYPE_BIND_NAK = 13
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
HEADER_LEN = 16
REQUEST_HEADER_LEN = 24
MAX_FRAG = 4280
READ_SIZE = 65536

# MS-RRP opnums
OPNUM_OPEN_LOCAL_MACHINE = 2
OPNUM_CLOSE_KEY = 5
OPNUM_OPEN_KEY = 15
OPNUM_QUERY_VALUE = 17
KEY_READ = 0x20019

# Win32 error codes the callers act on
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_MORE_DATA = 234

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7

# NTSTATUS values that mean "nothing listens on the pipe (yet)"
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_PIPE_NOT_AVAILABLE = 0xC00000AC
PIPE_RETRIES = 3
PIPE_RETRY_DELAY = 2.0
FIRST_QUERY_SIZE = 4096
MAX_VALUE_SIZE = 1 << 20

RegValue = str | int | list[str] | bytes


class RpcError(Exception):
    """The RPC exchange failed: malformed PDU, bind refused or a fault."""


class RpcFault(RpcError):
    def __init__(self, status: int) -> None:
        super().__init__(f"RPC fault 0x{status:08x}")
        self.status = status


class RegistryError(Exception):
    """A registry call returned a Win32 error code."""

    def __init__(self, code: int, what: str) -> None:
        super().__init__(f"{what}: Win32 error {code}")
        self.code = code


class PipeUnavailable(Exception):
    """The winreg pipe did not open (RemoteRegistry stopped, disabled or still starting)."""


class Transport(Protocol):
    """A message-mode byte pipe: each write is one message, each read returns one."""

    def write(self, data: bytes) -> None: ...

    def read(self) -> bytes: ...


class RpcClient:
    """Connection-oriented DCE/RPC over a transport, one interface, one call at a time."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.call_id = 0
        self.max_xmit = MAX_FRAG

    def _header(self, ptype: int, flags: int, length: int) -> bytes:
        # version 5.0, little-endian/ASCII/IEEE data representation, no auth trailer
        return struct.pack("<BBBB4sHHI", 5, 0, ptype, flags, b"\x10\0\0\0", length, 0, self.call_id)

    def bind(self, syntax: bytes = RRP_SYNTAX) -> None:
        self.call_id += 1
        body = struct.pack("<HHI", MAX_FRAG, MAX_FRAG, 0)
        body += struct.pack("<B3x", 1)  # one presentation context
        body += struct.pack("<HBx", 0, 1) + syntax + NDR_SYNTAX
        self.transport.write(self._header(PTYPE_BIND, 3, HEADER_LEN + len(body)) + body)
        ptype, frag = self._fragment(b"")[:2]
        if ptype == PTYPE_BIND_NAK:
            raise RpcError("bind refused (bind_nak)")
        if ptype != PTYPE_BIND_ACK or len(frag) < 26:
            raise RpcError(f"unexpected PDU type {ptype} in reply to bind")
        # the server's max_recv_frag bounds what this client may send (C706 12.6.4.4)
        _server_xmit, server_recv = struct.unpack_from("<HH", frag, HEADER_LEN)
        addr_len = struct.unpack_from("<H", frag, HEADER_LEN + 8)[0]
        pos = HEADER_LEN + 10 + addr_len
        pos += -pos % 4
        if len(frag) < pos + 8:
            raise RpcError("bind_ack too short")
        count = frag[pos]
        result = struct.unpack_from("<H", frag, pos + 4)[0]
        if count < 1 or result != 0:
            raise RpcError(f"presentation context rejected (result {result})")
        self.max_xmit = max(REQUEST_HEADER_LEN + 8, min(server_recv, MAX_FRAG))

    def call(self, opnum: int, stub: bytes) -> bytes:
        """Send one request (fragmented as the server allows) and return the response stub."""
        self.call_id += 1
        chunk = self.max_xmit - REQUEST_HEADER_LEN
        pos = 0
        while True:
            part = stub[pos : pos + chunk]
            flags = (PFC_FIRST_FRAG if pos == 0 else 0) | (
                PFC_LAST_FRAG if pos + chunk >= len(stub) else 0
            )
            head = self._header(PTYPE_REQUEST, flags, REQUEST_HEADER_LEN + len(part))
            self.transport.write(head + struct.pack("<IHH", len(stub) - pos, 0, opnum) + part)
            pos += chunk
            if flags & PFC_LAST_FRAG:
                break
        return self._response()

    def _fragment(self, buf: bytes) -> tuple[int, bytes, bytes]:
        """(PDU type, one whole fragment, bytes left over) reading more as needed."""
        while len(buf) < HEADER_LEN:
            buf += self._read()
        if buf[0] != 5:
            raise RpcError(f"not a DCE/RPC v5 PDU (version {buf[0]})")
        frag_len = struct.unpack_from("<H", buf, 8)[0]
        if frag_len < HEADER_LEN:
            raise RpcError(f"bad fragment length {frag_len}")
        while len(buf) < frag_len:
            buf += self._read()
        return buf[2], buf[:frag_len], buf[frag_len:]

    def _read(self) -> bytes:
        data = self.transport.read()
        if not data:
            raise RpcError("pipe closed in the middle of a PDU")
        return data

    def _response(self) -> bytes:
        stub, buf = b"", b""
        while True:
            ptype, frag, buf = self._fragment(buf)
            call_id = struct.unpack_from("<I", frag, 12)[0]
            if call_id != self.call_id:
                raise RpcError(f"reply for call {call_id}, expected {self.call_id}")
            if ptype == PTYPE_FAULT:
                status = struct.unpack_from("<I", frag, 24)[0] if len(frag) >= 28 else 0
                raise RpcFault(status)
            if ptype != PTYPE_RESPONSE or len(frag) < REQUEST_HEADER_LEN:
                raise RpcError(f"unexpected PDU type {ptype} in reply to a request")
            auth_len = struct.unpack_from("<H", frag, 10)[0]
            stub += frag[REQUEST_HEADER_LEN : len(frag) - (auth_len + 8 if auth_len else 0)]
            if frag[3] & PFC_LAST_FRAG:
                return stub


# --- NDR encoding of the few MS-RRP types used here -------------------------------------


def _unicode_string(text: str) -> bytes:
    """RRP_UNICODE_STRING (lengths include the terminating NUL) with its deferred buffer."""
    raw = (text + "\0").encode("utf-16-le")
    chars = len(raw) // 2
    head = struct.pack("<HHI", len(raw), len(raw), 0x20000)
    body = struct.pack("<III", chars, 0, chars) + raw
    return head + body + b"\0" * (-len(body) % 4)


def _status(stub: bytes, what: str) -> None:
    if len(stub) < 4:
        raise RpcError(f"{what}: response too short")
    code = struct.unpack_from("<I", stub, len(stub) - 4)[0]
    if code:
        raise RegistryError(code, what)


def _handle(stub: bytes, what: str) -> bytes:
    _status(stub, what)
    if len(stub) < 24:
        raise RpcError(f"{what}: response too short")
    return stub[:20]


def query_value_request(key: bytes, name: str, size: int) -> bytes:
    stub = key + _unicode_string(name)
    stub += struct.pack("<II", 0x20004, 0)  # lpType
    # lpData: room for `size` bytes, nothing sent (a padded buffer is refused as bad stub data)
    stub += struct.pack("<IIII", 0x20008, size, 0, 0)
    stub += struct.pack("<II", 0x2000C, size)  # lpcbData
    stub += struct.pack("<II", 0x20010, 0)  # lpcbLen
    return stub


def parse_query_value(stub: bytes) -> tuple[int, int, bytes, int]:
    """(Win32 status, value type, data, size the server reported) from a response stub."""
    try:
        pos = 0
        value_type = data_size = 0
        data = b""
        (ptr,) = struct.unpack_from("<I", stub, pos)
        pos += 4
        if ptr:
            (value_type,) = struct.unpack_from("<I", stub, pos)
            pos += 4
        (ptr,) = struct.unpack_from("<I", stub, pos)
        pos += 4
        if ptr:
            _max, offset, actual = struct.unpack_from("<III", stub, pos)
            pos += 12
            data = stub[pos + offset : pos + offset + actual]
            pos += offset + actual
            pos += -pos % 4
        (ptr,) = struct.unpack_from("<I", stub, pos)
        pos += 4
        if ptr:
            (data_size,) = struct.unpack_from("<I", stub, pos)
            pos += 4
        (ptr,) = struct.unpack_from("<I", stub, pos)
        pos += 4 + (4 if ptr else 0)
        (status,) = struct.unpack_from("<I", stub, pos)
    except struct.error as exc:
        raise RpcError(f"malformed BaseRegQueryValue response: {exc}") from exc
    return status, value_type, data, data_size


def decode_value(value_type: int, data: bytes) -> RegValue:
    if value_type == REG_DWORD and len(data) >= 4:
        return int(struct.unpack_from("<I", data)[0])
    if value_type in (REG_SZ, REG_EXPAND_SZ):
        return data.decode("utf-16-le", errors="replace").split("\0", 1)[0]
    if value_type == REG_MULTI_SZ:
        return [s for s in data.decode("utf-16-le", errors="replace").split("\0") if s]
    return data


class Registry:
    """Read-only access to HKEY_LOCAL_MACHINE of one host."""

    def __init__(self, rpc: RpcClient) -> None:
        self.rpc = rpc
        rpc.bind()
        stub = rpc.call(OPNUM_OPEN_LOCAL_MACHINE, struct.pack("<II", 0, KEY_READ))
        self.hklm = _handle(stub, "OpenLocalMachine")

    def open_key(self, parent: bytes, path: str) -> bytes:
        stub = parent + _unicode_string(path) + struct.pack("<II", 0, KEY_READ)
        return _handle(self.rpc.call(OPNUM_OPEN_KEY, stub), f"open {path}")

    def query_value(self, key: bytes, name: str) -> RegValue:
        size = FIRST_QUERY_SIZE
        for _ in range(4):
            stub = self.rpc.call(OPNUM_QUERY_VALUE, query_value_request(key, name, size))
            status, value_type, data, needed = parse_query_value(stub)
            if status == ERROR_MORE_DATA and size < needed <= MAX_VALUE_SIZE:
                size = needed
                continue
            if status:
                raise RegistryError(status, f"read {name}")
            return decode_value(value_type, data)
        raise RegistryError(ERROR_MORE_DATA, f"read {name}")

    def close_key(self, key: bytes) -> None:
        with suppress(RpcError, RegistryError):
            self.rpc.call(OPNUM_CLOSE_KEY, key)


# --- SMB transport ----------------------------------------------------------------------


class SmbPipe:
    """\\pipe\\winreg on IPC$ over an authenticated SMB session."""

    def __init__(
        self,
        host: str,
        port: int,
        user: str | None,
        password: str | None,
        kerberos: bool = False,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.conn = Connection(uuid.uuid4(), host, port, require_signing=False)
        self.conn.connect(timeout=TIMEOUT)
        try:
            session = Session(
                self.conn,
                user,
                password,
                require_encryption=False,
                auth_protocol="kerberos" if kerberos else "negotiate",
            )
            session.connect()
            tree = TreeConnect(session, rf"\\{host}\IPC$")
            tree.connect()
            self.pipe = _open_pipe(tree, sleep)
        except BaseException:
            self.close()
            raise

    def write(self, data: bytes) -> None:
        self.pipe.write(data, 0)

    def read(self) -> bytes:
        return bytes(self.pipe.read(0, READ_SIZE))

    def close(self) -> None:
        with suppress(Exception):
            self.conn.disconnect(close=True)


def _open_pipe(tree: TreeConnect, sleep: Callable[[float], None]) -> Open:
    """Open the pipe, waiting for RemoteRegistry while its trigger start completes."""
    for attempt in range(PIPE_RETRIES):
        pipe = Open(tree, "winreg")
        try:
            pipe.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_DATA
                | FilePipePrinterAccessMask.FILE_WRITE_DATA,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            return pipe
        except SMBException as exc:
            status = getattr(exc, "status", None)
            if status not in (STATUS_PIPE_NOT_AVAILABLE, STATUS_OBJECT_NAME_NOT_FOUND):
                raise
            if attempt + 1 < PIPE_RETRIES:
                sleep(PIPE_RETRY_DELAY)
    raise PipeUnavailable("winreg pipe not available")
