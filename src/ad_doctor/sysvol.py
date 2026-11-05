"""SYSVOL over SMB: Group Policy Preferences passwords (MS14-025), GPO security templates
(GptTmpl.inf) and credentials written into logon scripts.

Only file names, line numbers, account names and setting values are kept; secrets never
leave this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import smbclient
from smbprotocol.exceptions import SMBException

from .model import GpoSettings, GppPassword, ScriptSecret

MAX_FILE = 1_000_000
CPASSWORD = re.compile(rb'\bcpassword="([^"]+)"')
ACCOUNT = re.compile(rb'\b(?:userName|accountName|runAs|newName)="([^"]*)"')
# Preference files that can hold credentials
GPP_FILES = {
    "groups.xml",
    "services.xml",
    "scheduledtasks.xml",
    "datasources.xml",
    "drives.xml",
    "printers.xml",
}
SCRIPT_EXTENSIONS = (".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".kix", ".ini", ".txt")

# A literal secret: not empty, not a variable reference (%VAR%, $var, !var!)
_LIT = r"""['"]?(?![%$!])[^\s'"%$!]{3,}"""
SECRET_PATTERNS = [
    ("net use with a password", re.compile(rf"\bnet\s+use\b.*\s/user:\S+\s+{_LIT}", re.I)),
    (
        "plain-text SecureString",
        re.compile(r"""ConvertTo-SecureString\s+['"][^'"]+['"]\s+-AsPlainText""", re.I),
    ),
    ("password argument", re.compile(rf"\s-Password\s+{_LIT}", re.I)),
    # letters may not precede the keyword: db_password= matches, cwd= does not
    (
        "password assignment",
        re.compile(rf"(?<![a-z])(?:password|passwd|pwd)\s*[=:]\s*{_LIT}", re.I),
    ),
]

LSA = r"MACHINE\System\CurrentControlSet\Control\Lsa"


class SysvolError(Exception):
    pass


@dataclass
class SysvolResult:
    gpp_passwords: list[GppPassword] = field(default_factory=list)
    gpo_settings: dict[str, GpoSettings] = field(default_factory=dict)
    script_secrets: list[ScriptSecret] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)


def scan_xml(data: bytes) -> list[str]:
    """Account names of the items in one preference file that carry a cpassword."""
    users = []
    for item in re.split(rb"<(?=[A-Za-z])", data):
        if CPASSWORD.search(item):
            names = [n for n in ACCOUNT.findall(item) if n]
            users.append(names[0].decode(errors="replace") if names else "?")
    return users


def scan_script(text: str) -> list[tuple[int, str]]:
    """(line number, kind) of every line that looks like it carries a literal password."""
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        comment = stripped.startswith(("#", "::", "'", ";")) or stripped.lower().startswith("rem ")
        if not stripped or comment:
            continue
        for kind, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                hits.append((number, kind))
                break
    return hits


def parse_gpttmpl(text: str) -> GpoSettings:
    settings = GpoSettings()
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if section == "system access" and key.lower() == "cleartextpassword":
            settings.clear_text_password = _int(value)
        elif section == "registry values":
            # value is "<type>,<data>"
            data = value.split(",", 1)[-1]
            if key.lower() == rf"{LSA}\LmCompatibilityLevel".lower():
                settings.lm_compatibility = _int(data)
            elif key.lower() == rf"{LSA}\NoLMHash".lower():
                settings.no_lm_hash = _int(data)
        elif section == "privilege rights":
            holders = [v.strip().lstrip("*") for v in value.split(",")]
            settings.privileges[key] = [h for h in holders if h]
    return settings


def _int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def scan(
    host: str,
    domain: str,
    user: str | None,
    password: str | None,
    gpo_guids: list[str],
    port: int = 445,
    kerberos: bool = False,
) -> SysvolResult:
    base = rf"\\{host}\SYSVOL\{domain}"
    result = SysvolResult()
    try:
        smbclient.register_session(
            host,
            username=user,
            password=password,
            port=port,
            auth_protocol="kerberos" if kerberos else "negotiate",
        )
        for top in ("Policies", "scripts"):
            root = rf"{base}\{top}"
            try:
                walker = list(smbclient.walk(root, port=port))
            except (SMBException, OSError):
                continue
            for dirpath, _dirs, files in walker:
                for name in files:
                    lower = name.lower()
                    rel = rf"{dirpath}\{name}"[len(base) + 1 :]
                    wanted = top == "Policies" and lower in GPP_FILES
                    script = lower.endswith(SCRIPT_EXTENSIONS) and lower != "gpt.ini"
                    if not wanted and not script:
                        continue
                    try:
                        data = _read(rf"{dirpath}\{name}", port)
                    except (SMBException, OSError) as exc:
                        # admin-only scripts and files being replicated are normal
                        result.unreadable.append(f"{rel} ({type(exc).__name__})")
                        continue
                    if wanted:
                        result.gpp_passwords += [GppPassword(rel, u) for u in scan_xml(data)]
                    else:
                        text = _decode(data)
                        result.script_secrets += [
                            ScriptSecret(rel, line, kind) for line, kind in scan_script(text)
                        ]
        for guid in gpo_guids:
            path = rf"{base}\Policies\{guid}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            try:
                result.gpo_settings[guid] = parse_gpttmpl(_decode(_read(path, port)))
            except (SMBException, OSError):
                continue  # no security settings in this GPO
        return result
    except (SMBException, OSError, ValueError) as exc:
        raise SysvolError(str(exc) or type(exc).__name__) from exc
    finally:
        smbclient.reset_connection_cache()


def _read(path: str, port: int) -> bytes:
    with smbclient.open_file(path, mode="rb", port=port) as fh:
        data: bytes = fh.read(MAX_FILE)
    return data
