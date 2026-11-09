"""SYSVOL over SMB: Group Policy Preferences passwords (MS14-025), GPO security templates
(GptTmpl.inf), registry policy (Machine\\Registry.pol), local group membership set by Group
Policy (Restricted Groups and GPP Local Groups) and credentials written into logon scripts.

Only file names, line numbers, account names and setting values are kept; secrets never
leave this module.
"""

from __future__ import annotations

import errno
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

import smbclient
from smbprotocol.exceptions import SMBException

from . import auditpol, regpol
from .model import (
    GpoAutologon,
    GpoLocalGroup,
    GpoSettings,
    GppPassword,
    RegistryEntry,
    ScriptSecret,
    well_known_sid,
)

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
    "registry.xml",
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
NETLOGON = r"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters"
GPTTMPL = r"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
REGISTRY_POL = r"Machine\Registry.pol"
AUDIT_CSV = r"Machine\Microsoft\Windows NT\Audit\audit.csv"
REGISTRY_XML = r"Machine\Preferences\Registry\Registry.xml"
MAX_XML_DEPTH = 64  # Collection elements inside one another
HKLM = {"HKEY_LOCAL_MACHINE", "HKLM"}
REG_TYPES = {
    "REG_SZ": regpol.REG_SZ,
    "REG_EXPAND_SZ": regpol.REG_EXPAND_SZ,
    "REG_BINARY": regpol.REG_BINARY,
    "REG_DWORD": regpol.REG_DWORD,
    "REG_MULTI_SZ": regpol.REG_MULTI_SZ,
    "REG_QWORD": regpol.REG_QWORD,
}
_GUID = r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
MACHINE_GROUPS = re.compile(
    rf"^Policies\\({_GUID})\\Machine\\Preferences\\Groups\\Groups\.xml$", re.I
)
MACHINE_REGISTRY_XML = re.compile(
    rf"^Policies\\({_GUID})\\Machine\\Preferences\\Registry\\Registry\.xml$", re.I
)
USER_GROUPS = re.compile(rf"^Policies\\({_GUID})\\User\\Preferences\\Groups\\Groups\.xml$", re.I)
XML_DECLARATION = re.compile(r"^\s*<\?xml[^>]*\?>")


class SysvolError(Exception):
    pass


class MalformedXml(ValueError):
    pass


@dataclass
class SysvolResult:
    gpp_passwords: list[GppPassword] = field(default_factory=list)
    gpo_settings: dict[str, GpoSettings] = field(default_factory=dict)
    script_secrets: list[ScriptSecret] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    local_groups: list[GpoLocalGroup] = field(default_factory=list)
    registry: dict[str, list[RegistryEntry]] = field(default_factory=dict)
    # SYSVOL-relative Registry.pol files that could not be read
    registry_unread: list[str] = field(default_factory=list)
    audit: dict[str, list[RegistryEntry]] = field(default_factory=dict)
    preferences: dict[str, list[RegistryEntry]] = field(default_factory=dict)
    autologon: list[GpoAutologon] = field(default_factory=list)
    # SYSVOL-relative audit.csv and Registry.xml files that could not be read
    policy_unread: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # False when SYSVOL was not read, so "no local group settings" means "not collected"
    scanned: bool = False


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
            elif key.lower() == rf"{LSA}\MSV1_0\RestrictSendingNTLMTraffic".lower():
                settings.restrict_sending_ntlm = _int(data)
            elif key.lower() == rf"{LSA}\MSV1_0\ClientAllowedNTLMServers".lower():
                # REG_MULTI_SZ: "7,<server>,<server>"
                servers = value.partition(",")[2].split(",")
                settings.ntlm_exceptions = [s for s in map(_unquote, servers) if s]
            elif key.lower() == rf"{NETLOGON}\VulnerableChannelAllowList".lower():
                settings.vulnerable_channel_allow = _unquote(data)
        elif section == "privilege rights":
            holders = [v.strip().lstrip("*") for v in value.split(",")]
            settings.privileges[key] = [h for h in holders if h]
        elif section == "event audit" and key.lower() in auditpol.LEGACY_CATEGORIES:
            settings.audit_categories.append(auditpol.LEGACY_CATEGORIES[key.lower()])
    return settings


def _int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def _principal(token: str) -> tuple[str, str]:
    """(SID, name as written) of a Restricted Groups token: '*S-1-...' or a name."""
    bare = token.lstrip("*")
    if bare.upper().startswith("S-1-"):
        return bare.upper(), token
    return well_known_sid(token), token


def _unquote(value: str) -> str:
    return value.strip().strip('"').strip()


def parse_group_membership(text: str, guid: str, path: str) -> list[GpoLocalGroup]:
    """Restricted Groups: the [Group Membership] section of a GptTmpl.inf.

    'X__Members = A,B' makes A and B the only members of X (an empty value empties X;
    GPMC writes that line whenever only "This group is a member of" is filled in), and
    'X__Memberof = G1,G2' adds X to G1 and G2.
    """
    out = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "group membership" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        left, sep, suffix = key.strip().rpartition("__")  # names may contain '_'
        left = _unquote(left)
        if not sep or not left:
            continue
        items = [v for v in (_unquote(v) for v in value.split(",")) if v]
        if suffix.lower() == "members":
            members = items or [""]  # empty: the group is emptied
            out += [_restricted(guid, path, left, m, "set", True) for m in members]
        elif suffix.lower() == "memberof":
            out += [_restricted(guid, path, g, left, "add", False) for g in items]
    return out


def _restricted(
    guid: str, path: str, group: str, member: str, action: str, replaces: bool
) -> GpoLocalGroup:
    group_sid, group_name = _principal(group)
    member_sid, member_name = _principal(member) if member else ("", "")
    return GpoLocalGroup(
        guid, "restricted", path, group_sid, group_name, member_sid, member_name, action, replaces
    )


def _has_filters(element: ET.Element) -> bool:
    filters = element.find("Filters")
    return filters is not None and len(filters) > 0


def parse_groups_xml(data: bytes, guid: str, path: str) -> list[GpoLocalGroup]:
    """GPP Local Users and Groups: the Group items of a Machine Groups.xml.

    Disabled items and item-level targeting are kept (flagged) so the scope engine can
    count them; a disabled or filtered Collection passes that on to everything inside it.
    """
    text = XML_DECLARATION.sub("", _decode(data), count=1)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise MalformedXml(str(exc)) from exc
    out: list[GpoLocalGroup] = []

    def visit(node: ET.Element, disabled: bool, filtered: bool) -> None:
        for child in node:
            off = disabled or child.get("disabled") == "1"
            targeted = filtered or _has_filters(child)
            if child.tag == "Collection":
                visit(child, off, targeted)
            elif child.tag == "Group":
                out.extend(_group_item(child, guid, path, off, targeted))

    visit(root, False, False)
    return out


def _group_item(
    item: ET.Element, guid: str, path: str, disabled: bool, filtered: bool
) -> list[GpoLocalGroup]:
    props = item.find("Properties")
    if props is None:
        return []
    action = (props.get("action") or "U").upper()
    if action == "D":
        return []  # built-in groups cannot be deleted
    replaces = action == "R" or "1" in (props.get("deleteAllUsers"), props.get("deleteAllGroups"))
    group_name = props.get("groupName") or item.get("name") or ""
    group_sid = (props.get("groupSid") or "").upper() or well_known_sid(group_name)

    def entry(sid: str, name: str, how: str) -> GpoLocalGroup:
        return GpoLocalGroup(
            guid, "gpp", path, group_sid, group_name, sid, name, how, replaces, disabled, filtered
        )

    members = [
        entry(
            (m.get("sid") or "").upper(),
            m.get("name") or "",
            "remove" if (m.get("action") or "").upper() == "REMOVE" else "add",
        )
        for m in props.findall("Members/Member")
    ]
    if not members and replaces:
        return [entry("", "", "set")]
    return members


def _gpp_number(value: str) -> int | None:
    """A REG_DWORD or REG_QWORD of Registry.xml: hexadecimal digits, as GPMC writes it."""
    text = value.strip()
    if not (text and len(text) <= 16 and text.isascii()):
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _gpp_data(kind: int, value: str) -> int | str | None:
    if kind in (regpol.REG_DWORD, regpol.REG_QWORD):
        return _gpp_number(value)
    if kind in (regpol.REG_SZ, regpol.REG_EXPAND_SZ):
        return value[: regpol.MAX_TEXT]
    return None


def _registry_item(out: regpol.Parsed, item: ET.Element, disabled: bool, filtered: bool) -> None:
    props = item.find("Properties")
    if props is None:
        return
    key, name = props.get("key") or "", props.get("name") or ""
    kind = REG_TYPES.get((props.get("type") or "").upper(), 0)
    value = props.get("value") or ""
    action = (props.get("action") or "U").upper()
    text_type = kind in (regpol.REG_SZ, regpol.REG_EXPAND_SZ, regpol.REG_MULTI_SZ)
    if action != "D" and text_type and regpol.SECRET_NAME.search(name) and value.strip():
        out.secrets.append((key[:256], name[:128]))
    if (props.get("hive") or "").upper() not in HKLM:
        return
    data = _gpp_data(kind, value)
    if action != "D":
        regpol.note_winlogon(out.autologon, key, name, data, not disabled)
    if disabled:
        return
    if action == "D":
        if props.get("default") == "1":
            return
        if not name:
            if regpol.deletes_watched(key):
                regpol.keep(out, RegistryEntry(key, "", "delete_key", filtered=filtered))
        elif regpol.watched(key, name):
            regpol.keep(out, RegistryEntry(key, name, "delete", filtered=filtered))
    elif regpol.watched(key, name):
        how = "soft" if action == "C" else "set"  # C writes only where no value exists
        regpol.keep(out, RegistryEntry(key, name, how, kind, data, filtered))


def parse_registry_xml(data: bytes) -> regpol.Parsed:
    """Registry preference items of a Machine Registry.xml: what the checks read, in file order,
    and the facts about values named like a password. Disabled items are not applied, but a
    password in one is still in the file. Collections pass on disabled and filters."""
    text = XML_DECLARATION.sub("", _decode(data), count=1)
    if "<!doctype" in text.casefold():
        raise MalformedXml("a document type declaration")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise MalformedXml(str(exc)) from exc
    out = regpol.Parsed()
    # explicit stack: a hostile file can nest Collections far past Python's recursion limit
    stack = [(iter(root), False, False)]
    while stack:
        child = next(stack[-1][0], None)
        if child is None:
            stack.pop()
            continue
        _, disabled, filtered = stack[-1]
        off = disabled or child.get("disabled") == "1"
        targeted = filtered or _has_filters(child)
        if child.tag == "Collection":
            if len(stack) >= MAX_XML_DEPTH:
                raise MalformedXml("Collections nested too deeply")
            stack.append((iter(child), off, targeted))
        elif child.tag == "Registry":
            _registry_item(out, child, off, targeted)
    return out


def machine_groups_gpo(rel: str, gpo_guids: set[str]) -> str | None:
    """GUID of the GPO whose Machine Groups.xml this SYSVOL path is, if it is a known GPO."""
    m = MACHINE_GROUPS.match(rel)
    return m.group(1).upper() if m and m.group(1).upper() in gpo_guids else None


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    # UTF-16LE without a BOM: ASCII text with a zero in every odd byte
    odd = data[1:64:2]
    if len(odd) >= 4 and odd.count(0) * 4 >= len(odd) * 3:
        return data.decode("utf-16-le", errors="replace")
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
    known = {g.upper() for g in gpo_guids}
    user_side: list[str] = []
    gpp_registry: list[str] = []
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
                    if (m := MACHINE_REGISTRY_XML.match(rel)) and m.group(1).upper() in known:
                        gpp_registry.append(rel)
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
                        guid = machine_groups_gpo(rel, known)
                        if guid:
                            try:
                                result.local_groups += parse_groups_xml(data, guid, rel)
                            except MalformedXml:
                                result.notes.append(f"{rel}: malformed XML, not evaluated")
                        elif (m := USER_GROUPS.match(rel)) and m.group(1).upper() in known:
                            user_side.append(rel)
                    else:
                        text = _decode(data)
                        result.script_secrets += [
                            ScriptSecret(rel, line, kind) for line, kind in scan_script(text)
                        ]
        for guid in gpo_guids:
            rel = rf"Policies\{guid}\{GPTTMPL}"
            try:
                text = _decode(_read(rf"{base}\{rel}", port))
            except (SMBException, OSError) as exc:
                if getattr(exc, "errno", None) == errno.ENOENT:
                    # no security settings in this GPO: read, and nothing set. A failed read
                    # stays out of gpo_settings, which the checks take as unknown.
                    result.gpo_settings[guid] = GpoSettings()
                else:
                    result.unreadable.append(f"{rel} ({type(exc).__name__})")
                continue
            result.gpo_settings[guid] = parse_gpttmpl(text)
            result.local_groups += parse_group_membership(text, guid.upper(), rel)
        for guid in gpo_guids:
            _read_registry(result, base, guid, port)
            _read_audit(result, base, guid, port)
            _read_preferences(result, base, guid, port)
        if gpp_registry:
            result.notes.append(
                f"{len(gpp_registry)} GPOs set registry values through Preferences "
                "(Machine\\Preferences\\Registry): AD-GPO-009 to -012 do not evaluate them, and "
                f"they can change what Registry.pol sets: {', '.join(gpp_registry[:5])}"
            )
        if user_side:
            result.notes.append(
                f"{len(user_side)} GPOs set local groups in the user context "
                f"(User\\Preferences\\Groups), not evaluated: {', '.join(user_side[:5])}"
            )
        result.scanned = True
        return result
    except (SMBException, OSError, ValueError) as exc:
        raise SysvolError(str(exc) or type(exc).__name__) from exc
    finally:
        smbclient.reset_connection_cache()


def _read_registry(result: SysvolResult, base: str, guid: str, port: int) -> None:
    """One GPO's computer-side Registry.pol. A failed read or a bad file stays out of
    `result.registry`, which the checks take as unknown."""
    rel = rf"Policies\{guid}\{REGISTRY_POL}"
    try:
        data = _read(rf"{base}\{rel}", port)
    except (SMBException, OSError) as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            result.registry[guid] = []  # read, and this GPO sets no registry policy
        else:
            result.registry_unread.append(f"{rel} ({type(exc).__name__})")
        return
    if len(data) >= MAX_FILE:
        result.notes.append(f"{rel}: over {MAX_FILE} bytes, not evaluated")
        return
    try:
        parsed = regpol.parse(data)
    except regpol.MalformedPol as exc:
        result.notes.append(f"{rel}: not a valid Registry.pol ({exc}), not evaluated")
        return
    result.registry[guid] = parsed.entries
    _keep_facts(result, guid, rel, "pol", parsed)


def _keep_facts(
    result: SysvolResult, guid: str, rel: str, source: str, parsed: regpol.Parsed
) -> None:
    """The fact and the location only: the data never leaves the parser."""
    for key, name in parsed.secrets[:20]:
        result.notes.append(f"{rel}: holds a value named like a password: {key}\\{name}")
    found = parsed.autologon
    if found.auto_on or found.password:
        result.autologon.append(
            GpoAutologon(guid.upper(), rel, source, found.password, found.auto_on)
        )


def _policy_file(result: SysvolResult, base: str, rel: str, port: int) -> bytes | None:
    """A GPO file that may not exist: b"" when it does not, None when it could not be judged."""
    try:
        data = _read(rf"{base}\{rel}", port)
    except (SMBException, OSError) as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return b""
        result.policy_unread.append(f"{rel} ({type(exc).__name__})")
        return None
    if len(data) >= MAX_FILE:
        result.notes.append(f"{rel}: over {MAX_FILE} bytes, not evaluated")
        return None
    return data


def _read_audit(result: SysvolResult, base: str, guid: str, port: int) -> None:
    rel = rf"Policies\{guid}\{AUDIT_CSV}"
    data = _policy_file(result, base, rel, port)
    if data is None:
        return
    try:
        result.audit[guid] = auditpol.parse(_decode(data))
    except auditpol.MalformedAudit as exc:
        result.notes.append(f"{rel}: not a valid audit.csv ({exc}), not evaluated")


def _read_preferences(result: SysvolResult, base: str, guid: str, port: int) -> None:
    rel = rf"Policies\{guid}\{REGISTRY_XML}"
    data = _policy_file(result, base, rel, port)
    if data is None:
        return
    if not data:
        result.preferences[guid] = []
        return
    try:
        parsed = parse_registry_xml(data)
    except (MalformedXml, regpol.MalformedPol) as exc:
        result.notes.append(f"{rel}: not valid Registry.xml ({exc}), not evaluated")
        return
    result.preferences[guid] = parsed.entries
    _keep_facts(result, guid, rel, "xml", parsed)


def _read(path: str, port: int) -> bytes:
    with smbclient.open_file(path, mode="rb", port=port) as fh:
        data: bytes = fh.read(MAX_FILE)
    return data
