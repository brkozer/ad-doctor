"""Active checks against a domain controller or CA, each one cheap and non-intrusive.

- SMB: negotiate (is signing required?) and open the spoolss pipe (is the Print Spooler,
  a coercion vector, running on the DC?).
- HTTP: ask the CA's web enrollment page for its authentication methods (ESC8).
- LDAPS: an NTLM bind without channel binding (is channel binding enforced?).
- MS-RRP over \\pipe\\winreg: read the CA's configuration (ESC6, ESC7, ESC11, ESC16, audit
  filter).
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import struct
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from typing import Any, Protocol

import ldap3
import spnego
from ldap3.core.exceptions import LDAPException
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
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import SpnegoError

from . import sd, winreg
from .model import DEFAULT_POLICY_MODULE, CaConfig

TIMEOUT = 10
SEC_E_BAD_BINDINGS = "80090346"
CA_CONFIGURATION = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
CONFIG_KEY = r"CertSvc\Configuration"


def smb_posture(
    host: str, port: int, user: str | None, password: str | None, kerberos: bool = False
) -> tuple[bool | None, bool | None]:
    """(signing required, spooler pipe present); None where the probe could not tell."""
    conn = Connection(uuid.uuid4(), host, port, require_signing=False)
    try:
        conn.connect(timeout=TIMEOUT)
    except (SMBException, OSError, ValueError):
        return None, None
    signing = bool(conn.require_signing)
    spooler: bool | None = None
    try:
        session = Session(
            conn,
            user,
            password,
            require_encryption=False,
            auth_protocol="kerberos" if kerberos else "negotiate",
        )
        session.connect()
        tree = TreeConnect(session, rf"\\{host}\IPC$")
        tree.connect()
        pipe = Open(tree, "spoolss")
        try:
            pipe.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_DATA,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            spooler = True
            pipe.close()
        except SMBException as exc:
            # STATUS_OBJECT_NAME_NOT_FOUND: nothing listens on the pipe
            text = str(exc).lower()
            spooler = False if "0xc0000034" in text or "not found" in text else None
    except (SMBException, OSError, ValueError):
        spooler = None
    finally:
        with suppress(Exception):
            conn.disconnect(close=True)
    return signing, spooler


def web_enrollment_ntlm(
    connect_host: str, host_header: str, port: int
) -> tuple[str | None, str | None]:
    """(URL if /certsrv/ answers over plain HTTP with NTLM or Negotiate (ESC8), error)."""
    conn = http.client.HTTPConnection(connect_host, port, timeout=TIMEOUT)
    try:
        conn.request("GET", "/certsrv/", headers={"Host": host_header})
        resp = conn.getresponse()
        schemes = " ".join(v for k, v in resp.getheaders() if k.lower() == "www-authenticate")
    except (OSError, http.client.HTTPException) as exc:
        # unreachable is not the same as not vulnerable: the caller reports it
        if isinstance(exc, ConnectionRefusedError):
            return None, None  # nothing listens on the port: no web enrollment
        return None, str(exc) or type(exc).__name__
    finally:
        conn.close()
    if resp.status == 401 and any(s in schemes for s in ("NTLM", "Negotiate")):
        return f"http://{host_header}/certsrv/", None
    return None, None


def tls_end_point(cert_der: bytes) -> GssChannelBindings:
    """tls-server-end-point channel binding (RFC 5929) for the server certificate."""
    digest = hashlib.sha256(cert_der).digest()
    return GssChannelBindings(application_data=b"tls-server-end-point:" + digest)


class SpnegoNtlmClient:
    """Drop-in for ldap3's NtlmClient that uses pyspnego and can send channel bindings.

    ldap3 2.9 has no channel binding support, so binds fail on DCs that enforce it
    (LdapEnforceChannelBinding=2). The bindings for the next bind are set on the class
    right before binding, because ldap3 constructs the client itself.
    """

    channel_bindings: GssChannelBindings | None = None

    def __init__(self, user_name: str, domain: str, password: str) -> None:
        self._ctx = spnego.client(
            f"{domain}\\{user_name}",
            password,
            protocol="ntlm",
            channel_bindings=type(self).channel_bindings,
            # AD refuses NTLM signing/sealing on top of TLS
            context_req=spnego.ContextReq.no_integrity,
        )
        self._challenge = b""

    def create_negotiate_message(self) -> bytes:
        token = self._ctx.step()
        assert token is not None
        return token

    def parse_challenge_message(self, message: bytes) -> None:
        self._challenge = message

    def create_authenticate_message(self) -> bytes:
        token = self._ctx.step(self._challenge)
        assert token is not None
        return token


def ntlm_bind(conn: ldap3.Connection, channel_binding: bool) -> bool:
    """NTLM bind on an open connection, with or without the TLS channel binding."""
    import ldap3.utils.ntlm as ldap3_ntlm

    bindings = None
    if channel_binding:
        sock: Any = conn.socket
        cert = sock.getpeercert(binary_form=True) if isinstance(sock, ssl.SSLSocket) else None
        bindings = tls_end_point(cert) if cert else None
    SpnegoNtlmClient.channel_bindings = bindings
    original = ldap3_ntlm.NtlmClient
    ldap3_ntlm.NtlmClient = SpnegoNtlmClient
    try:
        return bool(conn.bind())
    finally:
        ldap3_ntlm.NtlmClient = original
        SpnegoNtlmClient.channel_bindings = None


def ldaps_channel_binding_required(host: str, port: int, user: str, password: str) -> bool | None:
    """Bind over LDAPS without channel binding: refused with SEC_E_BAD_BINDINGS = enforced."""
    server = ldap3.Server(host, port=port, use_ssl=True, connect_timeout=TIMEOUT)
    conn = ldap3.Connection(server, user=user, password=password, authentication=ldap3.NTLM)
    try:
        conn.open()
        if ntlm_bind(conn, channel_binding=False):
            return False
        message = str(conn.result.get("message", ""))
        return True if SEC_E_BAD_BINDINGS in message.lower() else None
    except LDAPException:
        return None
    finally:
        with suppress(Exception):
            conn.unbind()


class RegistryReader(Protocol):
    hklm: bytes

    def open_key(self, parent: bytes, path: str) -> bytes: ...

    def query_value(self, key: bytes, name: str) -> winreg.RegValue: ...

    def close_key(self, key: bytes) -> None: ...


def _win32_code(exc: Exception) -> int | None:
    if isinstance(exc, winreg.RegistryError):
        return exc.code
    if isinstance(exc, winreg.RpcFault):
        return exc.status  # rpc_s_access_denied is 5 as well
    return None


def _config_error(exc: Exception) -> str:
    code = _win32_code(exc)
    if code == winreg.ERROR_ACCESS_DENIED:
        return f"access denied to {CONFIG_KEY} (winreg AllowedPaths or key ACL hardened)"
    if code == winreg.ERROR_FILE_NOT_FOUND:
        return f"no {CONFIG_KEY} key (no CA installed on this host?)"
    return f"{CONFIG_KEY} not readable: {exc}"


def read_ca_config(reg: RegistryReader, host: str, fallback_name: str) -> CaConfig:
    """The settings ESC6, ESC7, ESC11 and ESC16 depend on, from an open registry.

    A value that is absent stays None (unknown); DisableExtensionList is the exception,
    since its absence means no extension is disabled.
    """
    opened: list[bytes] = []

    def open_key(parent: bytes, path: str) -> bytes:
        key = reg.open_key(parent, path)
        opened.append(key)
        return key

    def value(key: bytes, name: str) -> winreg.RegValue | None:
        try:
            return reg.query_value(key, name)
        except winreg.RegistryError as exc:
            if exc.code == winreg.ERROR_FILE_NOT_FOUND:
                return None
            raise

    try:
        try:
            conf = open_key(reg.hklm, CA_CONFIGURATION)
            active = value(conf, "Active")
        except (winreg.RegistryError, winreg.RpcFault) as exc:
            return CaConfig(fallback_name, host, error=_config_error(exc))
        if not isinstance(active, str) or not active:
            return CaConfig(fallback_name, host, error=f"no active CA in {CONFIG_KEY}")
        cfg = CaConfig(active, host)
        try:
            ca_key = open_key(conf, active)
            flags = value(ca_key, "InterfaceFlags")
            cfg.interface_flags = flags if isinstance(flags, int) else None
            cfg.audit_checked = True
            try:
                audit = value(ca_key, "AuditFilter")
                cfg.audit_absent = audit is None
            except (winreg.RegistryError, winreg.RpcFault):
                audit = None  # AD-ADCS-016 reports it; the other values may still be readable
            cfg.audit_filter = audit if isinstance(audit, int) else None
            security = value(ca_key, "Security")
            if isinstance(security, bytes) and security:
                try:
                    cfg.owner, cfg.aces = sd.parse_ca(security)
                except (IndexError, struct.error, ValueError):
                    # the bytes come from the remote host: a broken value must not end the scan
                    cfg.error = f"CA security descriptor of {active} not parseable"
                    return cfg
            modules = open_key(ca_key, "PolicyModules")
            module = value(modules, "Active")
        except (winreg.RegistryError, winreg.RpcFault) as exc:
            cfg.error = f"CA settings of {active} not readable: {exc}"
            return cfg
        cfg.policy_module = module if isinstance(module, str) and module else DEFAULT_POLICY_MODULE
        if cfg.third_party_policy:
            # EditFlags and DisableExtensionList belong to Microsoft's module; another
            # module may not have them or may give them another meaning
            return cfg
        try:
            policy = open_key(modules, cfg.policy_module)
            edit = value(policy, "EditFlags")
            disposition = value(policy, "RequestDisposition")
            disabled = value(policy, "DisableExtensionList")
        except (winreg.RegistryError, winreg.RpcFault) as exc:
            cfg.error = f"policy module settings of {active} not readable: {exc}"
            return cfg
        cfg.edit_flags = edit if isinstance(edit, int) else None
        cfg.request_disposition = disposition if isinstance(disposition, int) else None
        if isinstance(disabled, list):
            cfg.disabled_extensions = disabled
        elif isinstance(disabled, str):
            cfg.disabled_extensions = [disabled] if disabled else []
        elif disabled is None:
            cfg.disabled_extensions = []
        return cfg
    finally:
        for key in reversed(opened):
            reg.close_key(key)


def _smb_reason(exc: Exception) -> str:
    status = getattr(exc, "status", None)
    if isinstance(status, int):
        return f"NTSTATUS 0x{status:08x}"
    return str(exc) or type(exc).__name__


def ca_registry(
    connect_host: str,
    port: int,
    ca_host: str,
    fallback_name: str,
    user: str | None,
    password: str | None,
    kerberos: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> CaConfig:
    """Read one CA's configuration over the winreg pipe; failures end up in `error`.

    Opening the pipe trigger-starts RemoteRegistry on the CA if it is stopped.
    """
    try:
        pipe = winreg.SmbPipe(connect_host, port, user, password, kerberos, sleep)
    except winreg.PipeUnavailable:
        return CaConfig(fallback_name, ca_host, error="RemoteRegistry not running or disabled")
    except (SMBException, SpnegoError, OSError, ValueError) as exc:
        return CaConfig(
            fallback_name, ca_host, error=f"SMB to {ca_host}:{port} failed: {_smb_reason(exc)}"
        )
    try:
        return read_ca_config(winreg.Registry(winreg.RpcClient(pipe)), ca_host, fallback_name)
    except (
        winreg.RpcError,
        winreg.RegistryError,
        SMBException,
        OSError,
        ValueError,
        IndexError,
        struct.error,
    ) as exc:
        return CaConfig(fallback_name, ca_host, error=f"remote registry read failed: {exc}")
    finally:
        pipe.close()
