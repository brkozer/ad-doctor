"""SYSVOL over SMB: Group Policy Preferences passwords (MS14-025), GPO security templates
(GptTmpl.inf), registry policy (Machine\\Registry.pol), local group membership set by Group
Policy (Restricted Groups and GPP Local Groups), credentials written into logon scripts,
and which files GPOs run with who can change those files.

Only file names, line numbers, account names and setting values are kept; secrets never
leave this module, and neither do the arguments of a script or a task.
"""

from __future__ import annotations

import errno
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

import smbclient
from smbprotocol.exceptions import SMBException
from smbprotocol.open import FilePipePrinterAccessMask, SMB2QueryInfoRequest, SMB2QueryInfoResponse

from . import auditpol, fileacl, regpol
from .model import (
    GpoAutologon,
    GpoLocalGroup,
    GpoScript,
    GpoSettings,
    GppPassword,
    RegistryEntry,
    ScriptSecret,
    SysvolAcl,
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
RUN_CONFIG = re.compile(
    rf"^Policies\\({_GUID})\\(Machine|User)\\"
    r"(?:Scripts\\(scripts|psscripts)\.ini|Preferences\\ScheduledTasks\\ScheduledTasks\.xml)$",
    re.I,
)
XML_DECLARATION = re.compile(r"^\s*<\?xml[^>]*\?>")
# files that run on their own, looked at in NETLOGON even when no GPO names them
RUNNABLE = (".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".kix", ".js", ".wsf", ".exe", ".msi")
# programs whose argument is what really runs
INTERPRETERS = {
    "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "msiexec", "regsvr32", "rundll32",
}  # fmt: skip
POWERSHELL = {"powershell", "pwsh"}
# powershell.exe switches that take a value, by their full names and their own short ones
PS_VALUE_SWITCHES = (
    "executionpolicy", "windowstyle", "version", "inputformat", "outputformat", "psconsolefile",
    "configurationname", "configurationfile", "custompipename", "settingsfile", "workingdirectory",
)  # fmt: skip
PS_VALUE_SHORT = {"ep", "ex", "wd"}
# where a file name that has spaces and no quotes ends
RUN_SUFFIXES = (*RUNNABLE, ".com", ".vbe", ".jse", ".hta", ".dll", ".ocx", ".cpl", ".scr", ".msp")
UNCLEAR = "unclear"  # GpoScript.location: a network path that may not be what runs
SECTIONS = {
    "computer": {"startup": "Startup", "shutdown": "Shutdown"},
    "user": {"logon": "Logon", "logoff": "Logoff"},
}
TASK_TAGS = {"Task", "TaskV2", "ImmediateTask", "ImmediateTaskV2"}
MISSING = "not found"
MAX_DESCRIPTOR = 65536
SECURITY_INFO = 3  # SMB2_0_INFO_SECURITY
OWNER_AND_DACL_INFO = 0x1 | 0x4  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
LOGON_SERVER = "%logonserver%"
USER_DOMAIN = "%userdnsdomain%"
SYSTEM_NAMES = {"nt authority\\system", "system", "s-1-5-18"}
LOGGED_ON = {"%logondomain%\\%logonuser%", "%logonuser%"}
WORD = re.compile(r"""(?:"[^"]*"|'[^']*'|\S)+""")
SWITCH = re.compile(r"[-/][A-Za-z?]")
MSI_FILE = re.compile(
    r"""[-/](?:package|uninstall|update|i|a|x|p|f[a-z]*|j[um]?)(?=$|["'\\{%]|[a-z]:)""", re.I
)
CMD_STATEMENT = re.compile(r"""(?:"[^"]*"|'[^']*'|[^&|])+""")
PS_STATEMENT = re.compile(r"""(?:"[^"]*"|'[^']*'|[^&|;])+""")
STATEMENT_LEAD = re.compile(r"^\s*(?:@|call\s+|\.\s+)*", re.I)
REDIRECT = re.compile(r"""\d?>>?\s*(?:"[^"]*"|\S+)""")
LOCAL_FILE = re.compile(r"[a-z]:|\.{0,2}\\", re.I)
MAX_PATH = 512
MAX_NESTED = 4  # cmd /c powershell -Command cmd /c ...: a hostile file can go on for ever
MAX_STATEMENTS = 16


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
    scripts: list[GpoScript] = field(default_factory=list)
    acls: list[SysvolAcl] = field(default_factory=list)
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
            audited = _int(value)
            if audited is not None:
                category = auditpol.LEGACY_CATEGORIES[key.lower()]
                (settings.audit_categories if audited else settings.audit_off).append(category)
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
    key, name = regpol.bound(props.get("key") or ""), regpol.bound(props.get("name") or "")
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
        kept = regpol.kept_data(key, name, data)
        regpol.keep(out, RegistryEntry(key, name, how, kind, kept, filtered))


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


def _stem(program: str) -> str:
    return PureWindowsPath(program).stem.lower()


def _network(path: str) -> bool:
    return path.startswith("\\\\") or path.lower().startswith(LOGON_SERVER)


def _file_end(text: str, spaces: bool = True) -> tuple[str, str]:
    """(file, what follows it) of an unquoted command line. Where a file name can hold spaces,
    it runs to the first word with a known extension; a switch or no such word ends it at the
    first space. What follows can hold a password, so it must never count as the file."""
    words = list(re.finditer(r"\S+", text))
    if not words:
        return "", ""
    first = words[0]
    if spaces and _stem(first.group()) not in INTERPRETERS:
        for index, word in enumerate(words):
            if index and SWITCH.match(word.group()):
                break
            if word.group().lower().endswith(RUN_SUFFIXES):
                return text[: word.end()], text[word.end() :]
    return first.group(), text[first.end() :]


def _program(line: str, spaces: bool = True) -> tuple[str, str]:
    """(the file at the start of a command line, what follows it). `spaces`: the line is a
    GPO's command field, not text a shell splits at spaces, so a file name can hold them."""
    text = line.strip()
    quote = text[:1]
    if quote not in ('"', "'"):
        return _file_end(text, spaces)
    inner, closed, rest = text[1:].partition(quote)
    if not closed:
        return _file_end(text[1:])
    file, beyond = _file_end(inner)
    return file, f"{beyond} {rest}".strip()


def _unclear(text: str) -> list[tuple[str, str]]:
    """The first network path of a command line that does not say what it runs."""
    for word in WORD.finditer(REDIRECT.sub("", text)):
        path = _program(word.group().lstrip("&("))[0]
        if _network(path):
            return [(path[:MAX_PATH], UNCLEAR)]
    return []


def _unwrap(line: str) -> str:
    """A command line without the quotes around all of it: "a b c", and ""a b" c" as cmd
    takes it. In "a b" "c" the quotes belong to the words, and they stay."""
    text = line.strip()
    if len(text) > 1 and text[0] in "\"'" and text[-1] == text[0]:
        close = text.find(text[0], 1)
        if close == len(text) - 1 or not text[close + 1].isspace():
            return text[1:-1]
    return text


def _cmd_line(text: str) -> str | None:
    """What follows cmd's /c, /k or /r, which can touch it, as in /c"x y"."""
    for word in WORD.finditer(text):
        raw = word.group()
        if not raw.startswith("/"):
            return None
        if raw[1:2].lower() in ("c", "k", "r"):
            return text[word.start() + 2 :]
    return None


def _powershell_run(text: str) -> tuple[str | None, str | None]:
    """(the value of -File, or the command text) of a powershell or pwsh command line. Both
    programs take any unique start of a switch's name, and a value after a colon."""
    words = list(WORD.finditer(text))
    index = 0
    while index < len(words):
        word = words[index]
        raw = word.group()
        if raw[0] not in "-/":
            return None, text[word.start() :]
        name, colon, value = raw[1:].partition(":")
        name = name.lower()
        if name and "file".startswith(name):
            if colon:
                return value, None
            return (words[index + 1].group() if index + 1 < len(words) else ""), None
        if name and "command".startswith(name):
            return None, text[word.start() + len(name) + 2 if colon else word.end() :]
        if name in ("e", "ec") or (len(name) > 1 and "encodedcommand".startswith(name)):
            return "", None  # encoded: no path to follow, as before
        takes_value = name in PS_VALUE_SHORT or (
            name and any(s.startswith(name) for s in PS_VALUE_SWITCHES)
        )
        index += 2 if takes_value and not colon else 1
    return None, None


def _file_operand(name: str, text: str) -> str | None:
    """The file msiexec, regsvr32, rundll32, wscript, cscript or mshta is told to run."""
    words = [word.group() for word in WORD.finditer(text)]
    if name == "regsvr32":
        for word in words:
            if word.lower().startswith("/i:") and _network(_program(word[3:])[0]):
                return word[3:]
    for index, word in enumerate(words):
        if name == "msiexec":
            match = MSI_FILE.match(word)
            if match:
                following = words[index + 1] if index + 1 < len(words) else ""
                return word[match.end() :] or following
        elif word[0] not in "-/":
            return word.split(",", 1)[0] if name == "rundll32" else word
    return None


def _run_targets(command: str, arguments: str, depth: int = 0) -> list[tuple[str, str]]:
    """(path, location) of what a command line runs: the command, or for an interpreter only
    the argument it executes, when that is on the network. A log file or a data file named in
    the arguments is not run. Where the line does not say what runs, its first network path
    comes back as `UNCLEAR`. Arguments never come back: they can hold a password."""
    program, rest = _program(command, depth == 0)
    if not program:
        return []
    name = _stem(program)
    if name not in INTERPRETERS:
        return [(program[:MAX_PATH], "")]
    text = f"{rest} {arguments}".strip()
    if depth >= MAX_NESTED:
        return _unclear(text)
    file, line = None, None
    if name == "cmd":
        line = _cmd_line(text)
    elif name in POWERSHELL:
        file, line = _powershell_run(text)
    else:
        file = _file_operand(name, text)
    if file is not None:
        path = _program(file)[0]
        return [(path[:MAX_PATH], "")] if _network(path) else []
    if line is None:
        return _unclear(text)
    out: list[tuple[str, str]] = []
    if name in POWERSHELL:
        statements = PS_STATEMENT.findall(_unwrap(line.replace('\\"', '"')))
    else:
        statements = CMD_STATEMENT.findall(_unwrap(line))
    for found in statements[:MAX_STATEMENTS]:
        statement = STATEMENT_LEAD.sub("", found, count=1)
        head = _program(statement, False)[0]
        if _network(head) or _stem(head) in INTERPRETERS:
            out += _run_targets(statement, "", depth + 1)
        elif head and not (LOCAL_FILE.match(head) or head.lower().endswith(RUN_SUFFIXES)):
            out += _unclear(statement)
    return out


def parse_scripts_ini(text: str, guid: str, side: str, config: str, source: str) -> list[GpoScript]:
    """The scripts of one scripts.ini or psscripts.ini ([MS-GPSCR]): `<n>CmdLine` and
    `<n>Parameters` under [Startup], [Shutdown], [Logon] or [Logoff]. A relative path is in
    the GPO's own Scripts\\<phase> folder."""
    entries: dict[tuple[str, str], dict[str, str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        match = re.match(r"(\d+)(CmdLine|Parameters)\s*=(.*)", line, re.I)
        if match and section in SECTIONS[side]:
            field_name = match.group(2).lower()
            entries.setdefault((section, match.group(1)), {})[field_name] = match.group(3).strip()
    out = []
    folder = config.rsplit("\\", 1)[0]
    for (phase, _), item in entries.items():
        for path, location in _run_targets(item.get("cmdline", ""), item.get("parameters", "")):
            script = GpoScript(
                guid, side, source, phase, config, path, location,
                run_as="system" if side == "computer" else "user",
            )  # fmt: skip
            if not re.match(r"\\\\|[a-z]:|%", path, re.I) and ".." not in path.split("\\"):
                script.location = "sysvol"
                script.target = rf"{folder}\{SECTIONS[side][phase]}\{path}"
            out.append(script)
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(node: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in node if _local(c.tag) == name), None)


def _text(node: ET.Element | None, path: tuple[str, ...]) -> str:
    for name in path:
        node = None if node is None else _child(node, name)
    return (node.text or "").strip() if node is not None else ""


def _task_run_as(side: str, name: str) -> str:
    who = name.strip().lower()
    if side == "user":
        return "user" if not who or who in LOGGED_ON else "other"
    return "system" if who in SYSTEM_NAMES else "other"


def _task_item(
    item: ET.Element, guid: str, side: str, config: str, filtered: bool
) -> list[GpoScript]:
    props = _child(item, "Properties")
    if props is None or (props.get("action") or "U").upper() == "D":
        return []
    runs: list[tuple[str, str]] = []
    task = _child(props, "Task")
    if task is not None:
        if _text(task, ("Settings", "Enabled")).lower() == "false":
            return []
        actions = _child(task, "Actions")
        for action in () if actions is None else actions:
            if _local(action.tag) == "Exec":
                runs.append((_text(action, ("Command",)), _text(action, ("Arguments",))))
        name = props.get("runAs") or _text(task, ("Principals", "Principal", "UserId"))
    else:
        if props.get("enabled") == "0":
            return []
        runs.append((props.get("appName") or "", props.get("args") or ""))
        name = props.get("runAs") or ""
    run_as = _task_run_as(side, name)
    return [
        GpoScript(
            guid,
            side,
            "scheduledtasks.xml",
            "task",
            config,
            path,
            location,
            run_as=run_as,
            filtered=filtered,
        )
        for command, arguments in runs
        for path, location in _run_targets(command, arguments)
    ]


def parse_scheduled_tasks(data: bytes, guid: str, side: str, config: str) -> list[GpoScript]:
    """The programs of a Preferences ScheduledTasks.xml. Disabled items and items that
    delete a task do not run; item-level targeting is kept as a flag."""
    text = XML_DECLARATION.sub("", _decode(data), count=1)
    if "<!doctype" in text.casefold():
        raise MalformedXml("a document type declaration")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise MalformedXml(str(exc)) from exc
    out: list[GpoScript] = []
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
        elif child.tag in TASK_TAGS and not off:
            out += _task_item(child, guid, side, config, targeted)
    return out


def place(script: GpoScript, domain: str, hosts: set[str]) -> bool:
    """Fill in where the file is. False when it is on the computer that runs it (a local
    path, a program on the PATH), which says nothing about who can reach it. `hosts` holds
    the lower-cased names SYSVOL and NETLOGON are served under."""
    if script.location:
        return True
    path = script.path.replace("/", "\\")
    if path.lower().startswith(LOGON_SERVER):
        path = rf"\\{domain}{path[len(LOGON_SERVER) :]}"
    if not path.startswith("\\\\"):
        return False
    path = re.sub(re.escape(USER_DOMAIN), lambda _: domain, path, flags=re.I)
    if "%" in path or ".." in path.split("\\"):
        script.location = "unresolved"
        return True
    host, _, rest = path[2:].partition("\\")
    share, _, inner = rest.partition("\\")
    if not inner:
        return False
    if host.lower() in hosts and share.lower() in ("netlogon", "sysvol"):
        if share.lower() == "netlogon":
            script.location, script.target = "sysvol", rf"scripts\{inner}"
            return True
        top, _, below = inner.partition("\\")
        if top.lower() == domain.lower() and below:
            script.location, script.target = "sysvol", below
            return True
        script.location = "unresolved"
        return True
    script.location, script.host = "host", host.lower()
    return True


def _descriptor(path: str, port: int, directory: bool) -> bytes:
    """Owner and DACL of a file or folder: READ_CONTROL and one QUERY_INFO, nothing else."""
    with smbclient.open_file(
        path,
        mode="rb",
        buffering=0,
        file_type="dir" if directory else "file",
        desired_access=FilePipePrinterAccessMask.READ_CONTROL,
        share_access="rwd",
        port=port,
    ) as handle:
        opened = handle.fd
        request = SMB2QueryInfoRequest()
        request["info_type"] = SECURITY_INFO
        request["output_buffer_length"] = MAX_DESCRIPTOR
        request["additional_information"] = OWNER_AND_DACL_INFO
        request["file_id"] = opened.file_id
        session = opened.tree_connect.session.session_id
        sent = opened.connection.send(request, session, opened.tree_connect.tree_connect_id)
        response = SMB2QueryInfoResponse()
        response.unpack(opened.connection.receive(sent)["data"].get_value())
        raw: bytes = response["buffer"].get_value()
    return raw


def _read_acl(base: str, rel: str, port: int, directory: bool) -> SysvolAcl:
    try:
        raw = _descriptor(rf"{base}\{rel}", port, directory)
    except (SMBException, OSError, ValueError) as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return SysvolAcl(rel, directory, error=MISSING)
        return SysvolAcl(rel, directory, error=type(exc).__name__)
    return fileacl.parse(raw, rel, directory)


def _read_run_files(
    result: SysvolResult,
    base: str,
    port: int,
    found: list[GpoScript],
    netlogon: list[str],
    domain: str,
    hosts: set[str],
) -> None:
    """Where each file a GPO runs is, and the permissions on it and the folders above."""
    acls: dict[str, SysvolAcl] = {}

    def read(rel: str, directory: bool) -> SysvolAcl:
        key = rel.lower()
        if key not in acls:
            acls[key] = _read_acl(base, rel, port, directory)
        return acls[key]

    def read_chain(rel: str) -> bool:
        first, *folders = fileacl.chain(rel)
        if read(first, False).error == MISSING:
            return False
        for folder in folders:
            read(folder, True)
        return True

    for script in found:
        relative = bool(script.location)
        if not place(script, domain, hosts):
            continue
        if script.location == "sysvol" and not read_chain(script.target):
            if relative:
                continue  # not in the GPO's folder: a program on the PATH
            script.location = "missing"
        read_chain(script.config)
        result.scripts.append(script)
    for rel in netlogon:
        read_chain(rel)
    result.acls = [acl for acl in acls.values() if acl.error != MISSING]
    unknown = [
        f"{acl.path} ({acl.error or 'deny or conditional ACE'})"
        for acl in result.acls
        if acl.error or not acl.judged
    ]
    if unknown:
        result.notes.append(
            f"permissions of {len(unknown)} paths that scripts run from could not be judged, so "
            f"AD-GPO-017 did not evaluate them: {', '.join(unknown[:5])}"
        )
    missing = [s.path for s in result.scripts if s.location == "missing"]
    if missing:
        result.notes.append(
            f"{len(missing)} files that GPOs run were not found in SYSVOL or NETLOGON: "
            + ", ".join(missing[:5])
        )


def _run_entries(result: SysvolResult, rel: str, data: bytes, known: set[str]) -> list[GpoScript]:
    match = RUN_CONFIG.match(rel)
    if not match or match.group(1).upper() not in known:
        return []
    guid = match.group(1).upper()
    side = "computer" if match.group(2).lower() == "machine" else "user"
    if match.group(3):
        return parse_scripts_ini(_decode(data), guid, side, rel, f"{match.group(3).lower()}.ini")
    try:
        return parse_scheduled_tasks(data, guid, side, rel)
    except MalformedXml:
        result.notes.append(f"{rel}: malformed XML, AD-GPO-017 and AD-GPO-018 did not evaluate it")
        return []


def _lists_runs(rel: str, known: set[str]) -> bool:
    """Whether this SYSVOL path is a scripts.ini, psscripts.ini or ScheduledTasks.xml of a GPO."""
    match = RUN_CONFIG.match(rel)
    return match is not None and match.group(1).upper() in known


def scan(
    host: str,
    domain: str,
    user: str | None,
    password: str | None,
    gpo_guids: list[str],
    port: int = 445,
    kerberos: bool = False,
    dc_hosts: Iterable[str] = (),
    netbios: str = "",
) -> SysvolResult:
    base = rf"\\{host}\SYSVOL\{domain}"
    result = SysvolResult()
    known = {g.upper() for g in gpo_guids}
    user_side: list[str] = []
    gpp_registry: list[str] = []
    run_entries: list[GpoScript] = []
    netlogon: list[str] = []
    run_unread: list[str] = []
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
            except (SMBException, OSError) as exc:
                result.notes.append(
                    rf"SYSVOL\{top} could not be listed ({type(exc).__name__}): what is in it, "
                    "AD-GPO-017 and AD-GPO-018 included, was not evaluated"
                )
                continue
            for dirpath, _dirs, files in walker:
                for name in files:
                    lower = name.lower()
                    rel = rf"{dirpath}\{name}"[len(base) + 1 :]
                    wanted = top == "Policies" and lower in GPP_FILES
                    script = lower.endswith(SCRIPT_EXTENSIONS) and lower != "gpt.ini"
                    if (m := MACHINE_REGISTRY_XML.match(rel)) and m.group(1).upper() in known:
                        gpp_registry.append(rel)
                    if top == "scripts" and lower.endswith(RUNNABLE):
                        netlogon.append(rel)
                    if not wanted and not script:
                        continue
                    try:
                        data = _read(rf"{dirpath}\{name}", port)
                    except (SMBException, OSError) as exc:
                        # admin-only scripts and files being replicated are normal
                        result.unreadable.append(f"{rel} ({type(exc).__name__})")
                        if _lists_runs(rel, known):
                            run_unread.append(rel)
                        continue
                    run_entries += _run_entries(result, rel, data, known)
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
        short = netbios or domain.split(".")[0]  # the first label only when the name is unknown
        names = {domain.lower(), short.lower(), *(h.lower() for h in dc_hosts)}
        _read_run_files(result, base, port, run_entries, netlogon, domain, names)
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
        if run_unread:
            result.notes.append(
                f"{len(run_unread)} files that list what GPOs run could not be read, so "
                f"AD-GPO-017 and AD-GPO-018 did not evaluate them: {', '.join(run_unread[:5])}"
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
        result.notes.append(f"{rel}{regpol.SECRET_NOTE}{key}\\{name}")
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
