"""Generate a PowerShell remediation script for review.

Every command that changes something runs with -WhatIf (or is commented out when the tool
has no dry-run mode), so the script is safe to execute as-is and does nothing until an
administrator has read it and removed the guards.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from . import catalog
from .changes import Facts, trustee_of
from .checks import OLD_KEYS
from .model import DEFAULT_POLICY_MODULE, Finding, Snapshot
from .sd import SZOID_NTDS_CA_SECURITY_EXT, Ace

Fix = Callable[[Finding, Snapshot], list[str]]
# Control characters, line breaks among them: object text comes from the directory (GPO
# and CA names), and a newline in it must not end a comment and start a command. The
# bidi controls are here too: they can reorder what a reviewer reads on screen.
_CONTROL = re.compile("[\x00-\x1f\x7f\x85\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def one_line(text: str) -> str:
    """The text with every control character written as a visible escape."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def _name(obj: str) -> str:
    """The principal in a finding object, without the context ad-doctor appends."""
    return obj.split(" -> ", 1)[0].split(" (", 1)[0]


def _is_computer(obj: str) -> bool:
    return _name(obj).endswith("$")


# PowerShell closes a single-quoted string on any of these, not only on the ASCII one.
_PS_QUOTES = re.compile("(['\u2018\u2019\u201a\u201b])")


def _q(value: str) -> str:
    """A PowerShell verbatim string: every single-quote character doubled, so a directory
    name (attacker controlled) can never end the literal; $ and ` are inert inside it."""
    return "'" + _PS_QUOTES.sub(r"\1\1", value) + "'"


def _ldap(value: str) -> str:
    """An RFC 4515 assertion value."""
    return "".join(f"\\{ord(c):02x}" if c in "\\*()\x00" else c for c in value)


def _per_object(template: str) -> Fix:
    def fix(f: Finding, snap: Snapshot) -> list[str]:
        return [template.format(o=_q(_name(o)), c=_q(_name(o).rstrip("$"))) for o in f.objects]

    return fix


def _rc4_fix(f: Finding, snap: Snapshot) -> list[str]:
    """Only an explicit RC4-only value on a user has a safe one-line change; the rest needs
    a password reset or a test first. AES only on an account without AES keys makes the KDC
    deny its tickets, so a suspect password comes first."""
    out = []
    for o in f.objects:
        name = f.key(o)
        if OLD_KEYS in o:
            out.append(f"# {o}: reset the password first, see the AD-KRB-005 page")
        elif "no AES in" in o and not name.endswith("$"):
            out.append(f"Set-ADUser {_q(name)} -KerberosEncryptionType AES128,AES256 -WhatIf")
        else:
            out.append(f"# {o}: see the AD-KRB-005 page before changing it")
    return out


def _netbios(snap: Snapshot) -> str:
    return snap.domain.split(".")[0].upper()


def _dsacls(target: str) -> Fix:
    def fix(f: Finding, snap: Snapshot) -> list[str]:
        dn = target.format(domain=snap.domain_dn)
        return [f'# dsacls "{dn}" /R "{_netbios(snap)}\\{_name(o)}"' for o in f.objects]

    return fix


def _remove_member(obj: str) -> str:
    group, _, member = obj.partition(": ")
    return f"Remove-ADGroupMember {_q(group)} -Members {_q(member)} -WhatIf"


def _certutil(setting: str) -> Fix:
    """CA registry changes: certutil has no dry run, so the lines stay commented out."""

    def fix(f: Finding, snap: Snapshot) -> list[str]:
        hosts = {c.name: c.host for c in snap.probes.ca_configs}
        return [
            f'# certutil -config "{hosts.get(o, "<host>")}\\{o}" -setreg {setting}; '
            "Restart-Service certsvc  # on the CA"
            for o in f.objects
        ]

    return fix


def _gpo_entries(f: Finding, snap: Snapshot) -> list[str]:
    """Local group entries in GPOs: SYSVOL edits have no dry run, so only pointers."""
    return [
        "# In GPMC, edit each GPO below: Computer Configuration > Policies > Windows Settings >",
        "# Security Settings > Restricted Groups, and Preferences > Control Panel Settings >",
        "# Local Users and Groups. Remove the entry (or Remove-GPLink the GPO from the OU).",
        *(f"#   {o}" for o in f.objects),
    ]


def _manual(f: Finding, snap: Snapshot) -> list[str]:
    return [f"# manual: {f.remediation}"]


FIXES: dict[str, Fix] = {
    "AD-KRB-002": _per_object("Set-ADAccountControl {o} -DoesNotRequirePreAuth $false -WhatIf"),
    "AD-KRB-004": _per_object("Set-ADAccountControl {o} -UseDESKeyOnly $false -WhatIf"),
    "AD-DEL-001": _per_object("Set-ADAccountControl {o} -TrustedForDelegation $false -WhatIf"),
    "AD-DEL-002": _per_object(
        "Set-ADAccountControl {o} -TrustedToAuthForDelegation $false -WhatIf"
    ),
    "AD-DEL-003": lambda f, snap: [
        (
            f"Set-ADComputer {_q(_name(o).rstrip('$'))}"
            if _is_computer(o)
            else f"Set-ADUser {_q(_name(o))}"
        )
        + " -PrincipalsAllowedToDelegateToAccount $null -WhatIf"
        for o in f.objects
    ],
    "AD-ACC-001": _per_object("Set-ADAccountControl {o} -PasswordNotRequired $false -WhatIf"),
    "AD-ACC-002": _per_object(
        "Set-ADAccountControl {o} -AllowReversiblePasswordEncryption $false -WhatIf"
    ),
    "AD-ACC-003": _per_object("Set-ADUser {o} -PasswordNeverExpires $false -WhatIf"),
    "AD-ACC-004": _per_object("Disable-ADAccount {o} -WhatIf"),
    "AD-ACC-005": _per_object("Disable-ADAccount {o} -WhatIf"),
    "AD-ACC-014": _per_object("Disable-ADAccount {o} -WhatIf"),
    "AD-ACC-006": _per_object("Set-ADUser {o} -Clear adminCount -WhatIf"),
    "AD-ACC-007": _per_object("Set-ADUser {o} -Clear sIDHistory -WhatIf"),
    "AD-PRIV-002": _per_object("Set-ADAccountControl {o} -AccountNotDelegated $true -WhatIf"),
    "AD-PRIV-004": _per_object("Remove-ADGroupMember DnsAdmins -Members {o} -WhatIf"),
    "AD-DNS-001": _per_object("Set-DnsServerPrimaryZone -Name {o} -DynamicUpdate Secure -WhatIf"),
    "AD-POL-001": lambda f, snap: [
        f"Set-ADDefaultDomainPasswordPolicy -Identity {_q(snap.domain)} -MinPasswordLength 14 "
        "-ComplexityEnabled $true -LockoutThreshold 10 -WhatIf"
    ],
    "AD-POL-002": lambda f, snap: [
        f"Set-ADDomain -Identity {_q(snap.domain)} "
        "-Replace @{'ms-DS-MachineAccountQuota'=0} -WhatIf"
    ],
    "AD-INF-002": lambda f, snap: [
        "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet "
        f"-Target {_q(snap.domain)} -WhatIf"
    ],
    "AD-KRB-005": _rc4_fix,
    "AD-ACC-009": _per_object(
        "Set-ADUser {o} -Clear userPassword,unixUserPassword,msSFU30Password -WhatIf"
    ),
    "AD-ACC-010": _per_object("Set-ADAccountControl {o} -PasswordNotRequired $false -WhatIf"),
    "AD-PRIV-007": lambda f, snap: [
        # -LDAPFilter in a verbatim string: the name never lands in a "..." (expandable)
        # string, where $(...) and backticks would run while the argument is built
        f"Set-ADObject (Get-ADObject -LDAPFilter {_q(f'(sAMAccountName={_ldap(_name(o))})')}) "
        f"-Replace @{{primaryGroupID={515 if _is_computer(o) else 513}}} -WhatIf"
        for o in f.objects
    ],
    "AD-PRIV-008": lambda f, snap: [_remove_member(o) for o in f.objects],
    "AD-PRIV-009": _per_object("Remove-ADGroupMember 'Cert Publishers' -Members {o} -WhatIf"),
    "AD-INF-009": lambda f, snap: [
        "# on each DC: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled"
    ],
    "AD-ACL-005": lambda f, snap: [
        f"# $p = 'AD:CN=AdminSDHolder,CN=System,{snap.domain_dn}'; $a = Get-Acl $p; "
        "$a.SetAccessRuleProtection($true, $false); Set-Acl $p $a"
    ],
    "AD-ACL-001": _dsacls("{domain}"),
    "AD-ACL-002": _dsacls("CN=AdminSDHolder,CN=System,{domain}"),
    "AD-ACL-003": _dsacls("{domain}"),
    "AD-ADCS-012": _certutil("policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2"),
    "AD-ADCS-014": _certutil("CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST"),
    "AD-ADCS-015": _certutil("policy\\DisableExtensionList -1.3.6.1.4.1.311.25.2"),
    "AD-GPO-005": _gpo_entries,
    "AD-GPO-006": _gpo_entries,
    "AD-GPO-007": _gpo_entries,
}


# -- what-if changes ---------------------------------------------------------------------

_CONFIG = "(Get-ADRootDSE).configurationNamingContext"
_PKS = "CN=Public Key Services,CN=Services,"
_SID = "[Security.Principal.SecurityIdentifier]"
_FLAG_EDITS = {
    # flag -> (attribute, PowerShell expression for the new value, for the old value)
    "enrollee-supplies-subject": ("msPKI-Certificate-Name-Flag", "-band -bnot 1", "-bor 1"),
    "require-approval": ("msPKI-Enrollment-Flag", "-bor 2", "-band -bnot 2"),
}
_EKUS = {"any-purpose-eku": "2.5.29.37.0", "request-agent-eku": "1.3.6.1.4.1.311.20.2.1"}


def _rdn(value: str) -> str:
    """A value as one RDN of a DN (RFC 4514 escapes)."""
    out = "".join("\\" + c if c in ',+"\\<>;=' else c for c in value)
    if out.startswith(("#", " ")):
        out = "\\" + out
    if out.endswith(" "):
        out = out[:-1] + "\\ "
    return out


def _path(change: Facts, drive: bool = True) -> str:
    """A PowerShell expression for the change's object: its AD: drive path, or its DN."""
    kind = change.prim[0]
    prefix = "AD:" if drive else ""
    if kind in ("template-ace", "template-flag"):
        dn = f"CN={_rdn(change.prim[1])},CN=Certificate Templates,{_PKS}"
        return f"{_q(prefix + dn)} + {_CONFIG}"
    if kind == "pki-ace":
        key = change.prim[1].removeprefix("PKI:")
        if key.startswith("CA "):
            dn = f"CN={_rdn(key[3:])},CN=Enrollment Services,{_PKS}"
        else:
            dn = f"CN={_rdn(key)},{_PKS}"
        return f"{_q(prefix + dn)} + {_CONFIG}"
    return _q(prefix + change.dn)


def _ace_filter(sid: str, ace: Ace) -> str:
    kind = f"[guid]{_q(ace.object_type)}" if ace.object_type else "[guid]::Empty"
    return (
        f"$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq {_q(sid)} "
        f"-and [int]$_.ActiveDirectoryRights -eq {ace.mask} -and $_.ObjectType -eq {kind}"
    )


def _ace_removal(change: Facts, sid: str) -> list[str]:
    """One read-change-write per ACE: Get-Acl, RemoveAccessRuleSpecific on the explicit
    rules with that SID, mask and object type, Set-Acl -WhatIf. Never dsacls /R, which
    removes every ACE of the trustee on the object."""
    path = _path(change)
    return [
        f"$p = {path}; $a = Get-Acl -LiteralPath $p; "
        f"$a.GetAccessRules($true, $false, {_SID}) | Where-Object {{ {_ace_filter(sid, ace)} }} "
        "| ForEach-Object { [void]$a.RemoveAccessRuleSpecific($_) }; "
        "Set-Acl -LiteralPath $p -AclObject $a -WhatIf"
        for ace in change.aces
    ]


def _ace_rollback(change: Facts, sid: str) -> list[str]:
    path = _path(change)
    out = []
    for ace in change.aces:
        kind = f"[guid]{_q(ace.object_type)}" if ace.object_type else "[guid]::Empty"
        out.append(
            f"$p = {path}; $a = Get-Acl -LiteralPath $p; $a.AddAccessRule((New-Object "
            f"DirectoryServices.ActiveDirectoryAccessRule(({_SID}{_q(sid)}), "
            f"[DirectoryServices.ActiveDirectoryRights]{ace.mask}, 'Allow', {kind}))); "
            "Set-Acl -LiteralPath $p -AclObject $a -WhatIf"
        )
    return out


def _ca_key(snap: Snapshot, ca: str) -> tuple[str, str]:
    """The CA's policy registry key as a literal for the lines, and the CA's host."""
    c = next((x for x in snap.probes.ca_configs if x.name == ca), None)
    module = (c.policy_module if c else None) or DEFAULT_POLICY_MODULE
    key = f"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca}"
    return _q(f"{key}\\PolicyModules\\{module}"), c.host if c else "<host>"


def _oid_object(oid: str) -> str:
    """A PowerShell expression for the DN of the msPKI-Enterprise-Oid object with this OID."""
    search_base = f"{_q(f'CN=OID,{_PKS}')} + {_CONFIG}"
    return (
        f"(Get-ADObject -SearchBase ({search_base}) "
        f"-LDAPFilter {_q(f'(msPKI-Cert-Template-OID={_ldap(oid)})')}).DistinguishedName"
    )


def change_lines(change: Facts, snap: Snapshot) -> list[str]:
    """Fix lines for one what-if change: every command that writes runs with -WhatIf,
    or is commented out when it has no dry run."""
    kind, *_ = change.prim
    sid = trustee_of(change.prim)
    out: list[str] = []
    if kind in ("ace", "inherited-ace", "adminsdholder-ace", "template-ace", "pki-ace"):
        out += _ace_removal(change, sid)
        if not change.aces:
            out.append("# no explicit ACE of this trustee is left on the object in the snapshot")
        if kind == "inherited-ace":
            out.append(f"# inherited by {change.copies} objects below: they lose it too")
        if kind == "adminsdholder-ace":
            out.append(
                f"# SDProp removes the copies on {change.copies} protected objects at its next "
                "run (every 60 minutes)"
            )
        if kind == "ace" and not change.inheritance_known:
            out.append(
                "# older snapshot: if Get-Acl shows IsInherited, the ACE comes from a container "
                "above; this line then removes nothing"
            )
    elif kind == "owner":
        da = _q(f"{snap.domain_sid}-512")
        out.append(
            f"# $p = {_path(change)}; $a = Get-Acl -LiteralPath $p; $a.SetOwner(({_SID}{da})); "
            "Set-Acl -LiteralPath $p -AclObject $a -WhatIf  # or another tier-0 owner"
        )
    elif kind == "member":
        out.append(
            f"Remove-ADGroupMember -Identity {_q(change.dn)} -Members {_q(change.member_dn)} "
            "-Confirm:$false -WhatIf"
        )
    elif kind == "gplink":
        guid = change.prim[1].strip("{}")
        out.append(f"Remove-GPLink -Guid {_q(guid)} -Target {_q(change.dn)} -WhatIf")
    elif kind == "gpo-entry":
        e = change.entry
        member = e.member_name if e and e.member_name else change.prim[3]
        group = e.group_name if e and e.group_name else change.prim[2]
        where = e.path if e else "the GPO"
        out += [
            f"# GPO {change.gpo_name} {change.prim[1]}: remove {member} from {group} in "
            f"{where} (GPMC: Restricted Groups or Local Users and Groups; no dry run)",
        ]
    elif kind == "template-flag":
        flag = change.prim[2]
        path = _path(change, drive=False)
        if flag in _FLAG_EDITS:
            attr, op, _ = _FLAG_EDITS[flag]
            out.append(
                f"$dn = {path}; $t = Get-ADObject -Identity $dn -Properties {_q(attr)}; "
                f"Set-ADObject -Identity $dn -Replace @{{{_q(attr)} = ($t.{_q(attr)} {op})}} "
                "-WhatIf"
            )
        else:
            eku = _q(_EKUS[flag])
            out.append(
                f"$dn = {path}; Set-ADObject -Identity $dn -Remove @{{"
                f"'msPKI-Certificate-Application-Policy' = {eku}; 'pKIExtendedKeyUsage' = {eku}}} "
                "-WhatIf"
            )
        out.append("# check what the template is for before changing it")
    elif kind == "ca-right":
        out.append(
            f"# on the CA {change.prim[1]}: certsrv.msc > Properties > Security: take "
            f"{change.prim[3]} away from {snap.name_of(sid)} ({sid}); no dry run"
        )
    elif kind == "oid-link":
        out.append(
            f"$dn = {_oid_object(change.prim[1])}; "
            "Set-ADObject -Identity $dn -Clear 'msDS-OIDToGroupLink' -WhatIf"
        )
    elif kind == "ca-flag":
        key, host = _ca_key(snap, change.prim[1])
        if change.prim[2] == "san-from-request":
            out.append(
                f"$k = {key}; Set-ItemProperty -LiteralPath $k -Name EditFlags "
                "-Value ((Get-ItemProperty -LiteralPath $k).EditFlags -band -bnot 0x40000) -WhatIf"
            )
        else:
            ext = _q(SZOID_NTDS_CA_SECURITY_EXT)
            out.append(
                f"$k = {key}; Set-ItemProperty -LiteralPath $k -Name DisableExtensionList "
                "-Value @((Get-ItemProperty -LiteralPath $k).DisableExtensionList | "
                f"Where-Object {{ $_.Trim() -ne {ext} }}) -Type MultiString -WhatIf"
            )
        out.append(f"# run on the CA {host}, then Restart-Service certsvc")
    elif kind == "gmsa-reader":
        rest = ", ".join(_q(s) for s in change.readers) if change.readers else "$null"
        out.append(
            f"Set-ADServiceAccount -Identity {_q(change.dn)} "
            f"-PrincipalsAllowedToRetrieveManagedPassword {rest} -WhatIf"
        )
    elif kind == "delegation":
        what = change.prim[2]
        if what == "unconstrained":
            out.append(
                f"Set-ADAccountControl -Identity {_q(change.dn)} "
                "-TrustedForDelegation $false -WhatIf"
            )
        elif what == "protocol-transition":
            out.append(
                f"Set-ADAccountControl -Identity {_q(change.dn)} "
                "-TrustedToAuthForDelegation $false -WhatIf"
            )
        elif what == "rbcd":
            out.append(
                f"Set-ADObject -Identity {_q(change.dn)} "
                "-Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity' -WhatIf"
            )
        else:
            spn = what.removeprefix("constrained:")
            out.append(
                f"Set-ADObject -Identity {_q(change.dn)} "
                f"-Remove @{{'msDS-AllowedToDelegateTo' = {_q(spn)}}} -WhatIf"
            )
    elif kind == "rbcd-principal":
        rest = ", ".join(_q(s) for s in change.readers) if change.readers else "$null"
        out.append(
            f"Set-ADComputer -Identity {_q(change.dn)} "
            f"-PrincipalsAllowedToDelegateToAccount {rest} -WhatIf"
        )
    elif kind == "sid-history":
        out.append(
            f"Set-ADObject -Identity {_q(change.dn)} "
            f"-Remove @{{'sIDHistory' = {_q(change.prim[2])}}} -WhatIf"
        )
    elif kind in ("script-ace", "script-host"):
        out.append(f"# {change.label} (the file's Security tab or the GPO; no dry run)")
    return [one_line(line) for line in out]


def rollback_lines(change: Facts, snap: Snapshot) -> list[str]:
    """How to put the fact back, with the values from the snapshot (guarded too)."""
    kind, *_ = change.prim
    sid = trustee_of(change.prim)
    out: list[str] = []
    if kind in ("ace", "inherited-ace", "adminsdholder-ace", "template-ace", "pki-ace"):
        out += _ace_rollback(change, sid)
        if kind == "inherited-ace" and change.aces:
            out.append("# set the same inheritance flags as before (see Get-Acl output)")
    elif kind == "owner":
        owner = _q(change.owner or "<owner SID>")
        out.append(
            f"# $p = {_path(change)}; $a = Get-Acl -LiteralPath $p; $a.SetOwner(({_SID}{owner})); "
            "Set-Acl -LiteralPath $p -AclObject $a -WhatIf"
        )
    elif kind == "member":
        out.append(
            f"Add-ADGroupMember -Identity {_q(change.dn)} -Members {_q(change.member_dn)} -WhatIf"
        )
    elif kind == "gplink":
        guid = change.prim[1].strip("{}")
        enabled = "Yes" if change.link is None or change.link.enabled else "No"
        enforced = "Yes" if change.link is not None and change.link.enforced else "No"
        out.append(
            f"New-GPLink -Guid {_q(guid)} -Target {_q(change.dn)} -LinkEnabled {enabled} "
            f"-Enforced {enforced} -WhatIf"
        )
    elif kind == "template-flag":
        flag = change.prim[2]
        path = _path(change, drive=False)
        if flag in _FLAG_EDITS:
            attr, _, op = _FLAG_EDITS[flag]
            out.append(
                f"$dn = {path}; $t = Get-ADObject -Identity $dn -Properties {_q(attr)}; "
                f"Set-ADObject -Identity $dn -Replace @{{{_q(attr)} = ($t.{_q(attr)} {op})}} "
                "-WhatIf"
            )
        else:
            eku = _q(_EKUS[flag])
            out.append(
                f"$dn = {path}; Set-ADObject -Identity $dn -Add @{{"
                f"'msPKI-Certificate-Application-Policy' = {eku}; 'pKIExtendedKeyUsage' = {eku}}} "
                "-WhatIf"
            )
    elif kind == "oid-link":
        out.append(
            f"$dn = {_oid_object(change.prim[1])}; Set-ADObject -Identity $dn "
            f"-Replace @{{'msDS-OIDToGroupLink' = {_q(change.dn)}}} -WhatIf"
        )
    elif kind == "ca-flag":
        key, host = _ca_key(snap, change.prim[1])
        if change.prim[2] == "san-from-request":
            out.append(
                f"$k = {key}; Set-ItemProperty -LiteralPath $k -Name EditFlags "
                "-Value ((Get-ItemProperty -LiteralPath $k).EditFlags -bor 0x40000) -WhatIf"
            )
        else:
            ext = _q(SZOID_NTDS_CA_SECURITY_EXT)
            out.append(
                f"$k = {key}; Set-ItemProperty -LiteralPath $k -Name DisableExtensionList "
                f"-Value (@((Get-ItemProperty -LiteralPath $k).DisableExtensionList) + {ext}) "
                "-Type MultiString -WhatIf"
            )
        out.append(f"# run on the CA {host}, then Restart-Service certsvc")
    elif kind == "gmsa-reader":
        everyone = ", ".join(_q(s) for s in dict.fromkeys([*change.listed, sid]))
        out.append(
            f"Set-ADServiceAccount -Identity {_q(change.dn)} "
            f"-PrincipalsAllowedToRetrieveManagedPassword {everyone} -WhatIf"
        )
    elif kind == "delegation":
        what = change.prim[2]
        if what == "unconstrained":
            out.append(
                f"Set-ADAccountControl -Identity {_q(change.dn)} "
                "-TrustedForDelegation $true -WhatIf"
            )
        elif what == "protocol-transition":
            out.append(
                f"Set-ADAccountControl -Identity {_q(change.dn)} -TrustedToAuthForDelegation $true "
                "-WhatIf"
            )
        elif what.startswith("constrained:"):
            spn = what.removeprefix("constrained:")
            out.append(
                f"Set-ADObject -Identity {_q(change.dn)} "
                f"-Add @{{'msDS-AllowedToDelegateTo' = {_q(spn)}}} -WhatIf"
            )
        elif change.readers:
            everyone = ", ".join(_q(s) for s in change.readers)
            out.append(
                f"Set-ADComputer -Identity {_q(change.dn)} "
                f"-PrincipalsAllowedToDelegateToAccount {everyone} -WhatIf"
            )
        else:
            out.append(
                "# rbcd: put back the msDS-AllowedToActOnBehalfOfOtherIdentity value saved before"
            )
    elif kind == "rbcd-principal":
        everyone = ", ".join(_q(s) for s in dict.fromkeys([*change.listed, sid]))
        out.append(
            f"Set-ADComputer -Identity {_q(change.dn)} "
            f"-PrincipalsAllowedToDelegateToAccount {everyone} -WhatIf"
        )
    elif kind == "sid-history":
        out.append(
            f"# {change.prim[2]}: sIDHistory cannot be written back with Set-ADObject; "
            "it takes a migration (ADMT, DsAddSidHistory) or a restore"
        )
    else:  # gpo-entry, ca-right: no dry run
        out.append("# put the entry back the way it was removed (no dry run)")
    return [one_line(line) for line in out]


def render_change_script(
    domain: str, collected: str, sections: list[tuple[str, list[str], list[str]]], title: str
) -> str:
    """The fix script of a what-if or plan run: the render_fixes framing, one section per
    change (header, lines, what it is expected to clear)."""
    needs_gp = any(
        line.startswith(("Remove-GPLink", "New-GPLink")) for _, ls, _ in sections for line in ls
    )
    out = [
        f"# ad-doctor {title} for {domain}",
        f"# from the snapshot of {collected}, {len(sections)} changes "
        "(simulated on the snapshot; AD unchanged)",
        "# Review every line. Commands run with -WhatIf; commented lines have no dry-run mode.",
        "# Remove the guards only for the changes you have approved.",
        "#Requires -Modules ActiveDirectory",
        *(["#Requires -Modules GroupPolicy"] if needs_gp else []),
        "",
    ]
    for header, lines, expect in sections:
        out.append(f"# --- {header}")
        out += lines
        if expect:
            together = ", with the other changes" if len(sections) > 1 else ""
            out.append(f"# expected to clear{together}: " + "; ".join(expect))
        out.append("")
    return "\n".join(one_line(line) for line in out)


def snippet(f: Finding, snap: Snapshot) -> list[str]:
    """The script lines for one finding (guarded like the whole script)."""
    return [one_line(line) for line in FIXES.get(f.check_id, _manual)(f, snap)]


# check ID -> userAccountControl bit, and whether it must be set for the fix to still apply
# (0 means the check looks at msDS-AllowedToActOnBehalfOfOtherIdentity instead)
PREFLIGHT: dict[str, tuple[int, bool]] = {
    "AD-KRB-002": (0x400000, True),
    "AD-KRB-004": (0x200000, True),
    "AD-DEL-001": (0x80000, True),
    "AD-DEL-002": (0x1000000, True),
    "AD-DEL-003": (0, True),
    "AD-ACC-001": (0x20, True),
    "AD-ACC-002": (0x80, True),
    "AD-ACC-003": (0x10000, True),
    "AD-ACC-004": (0x2, False),
    "AD-ACC-005": (0x2, False),
}

_PREFLIGHT_FUNCTION = """\
function Test-AdDoctorPreflight {
    param([string]$Check, [string]$Name, [string]$Filter, [int]$Flag, [bool]$MustBeSet)
    $props = 'userAccountControl', 'primaryGroupID', 'pwdLastSet', 'lastLogonTimestamp', 'servicePrincipalName', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $found = @(Get-ADObject -LDAPFilter $Filter -Properties $props -ErrorAction Stop)
    if ($found.Count -ne 1) {
        Write-Output "STOP  $Check $Name : $($found.Count) objects match"
        $script:AdDoctorStops++
        return
    }
    $o = $found[0]
    $logon = $null
    if ($o.lastLogonTimestamp) { $logon = [DateTime]::FromFileTimeUtc([long]$o.lastLogonTimestamp) }
    if ($Flag -eq 0) {
        $applies = $null -ne $o.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    } else {
        $applies = (($o.userAccountControl -band $Flag) -ne 0) -eq $MustBeSet
    }
    $stop = $null
    if (-not $applies) { $stop = 'the setting is no longer as the snapshot had it' }
    elseif ($Check -eq 'AD-DEL-001' -and $o.primaryGroupID -in 516, 521) { $stop = 'this is a domain controller' }
    elseif ($Check -eq 'AD-ACC-005' -and $logon -and $logon -gt $AdDoctorSnapshot) { $stop = "logged on since the snapshot ($logon UTC)" }
    if ($stop) {
        Write-Output "STOP  $Check $Name : $stop"
        $script:AdDoctorStops++
        return
    }
    $warn = @()
    if ($Check -eq 'AD-DEL-002' -and @($o.'msDS-AllowedToDelegateTo').Count -gt 0) { $warn += 'these services lose protocol transition: ' + ($o.'msDS-AllowedToDelegateTo' -join ', ') }
    if ($Check -eq 'AD-ACC-001' -and [long]$o.pwdLastSet -eq 0) { $warn += 'no password has been set: set one first' }
    if ($Check -eq 'AD-ACC-003' -and @($o.servicePrincipalName).Count -gt 0) { $warn += 'it has an SPN: an expiring password may stop a service' }
    if ($logon -and $logon -gt [DateTime]::UtcNow.AddDays(-30)) { $warn += "in use: last logon $logon UTC" }
    foreach ($w in $warn) { Write-Output "WARN  $Check $Name : $w" }
    if ($warn.Count -eq 0) { Write-Output "OK    $Check $Name" }
}"""  # noqa: E501


def render_preflight(findings: list[Finding], snap: Snapshot) -> str:
    """A read-only script to run before the fix script: it looks each object up again and
    says whether the fix still applies. It changes nothing, so it has no -WhatIf to remove."""
    taken = snap.collected_at.isoformat()
    out = [
        f"# ad-doctor preflight for {snap.domain}",
        f"# generated {snap.collected_at:%Y-%m-%d %H:%M} UTC; covers {len(PREFLIGHT)} fixes",
        "# Read-only: its only directory command is Get-ADObject. Nothing here changes AD.",
        "# Run it before the --fixes script. STOP: the object no longer matches the snapshot.",
        "# WARN: the fix is still valid, but read the reason before removing -WhatIf.",
        "#Requires -Modules ActiveDirectory",
        "$script:AdDoctorStops = 0",
        f"$AdDoctorSnapshot = [DateTime]::Parse({_q(taken)}).ToUniversalTime()",
        _PREFLIGHT_FUNCTION,
        "",
    ]
    covered = [f for f in findings if f.check_id in PREFLIGHT]
    for f in covered:
        flag, must = PREFLIGHT[f.check_id]
        out.append(f"# --- {f.check_id}")
        for obj in f.objects:
            name = _name(obj)
            query = _q(f"(sAMAccountName={_ldap(name)})")
            out.append(
                f"Test-AdDoctorPreflight {_q(f.check_id)} {_q(name)} {query} "
                f"0x{flag:x} ${str(must).lower()}"
            )
        out.append("")
    others = sorted({f.check_id for f in findings if f.check_id not in PREFLIGHT})
    if others:
        out.append("# No preflight for these checks: " + ", ".join(others))
    out += [
        "if ($script:AdDoctorStops) {",
        '    Write-Output "$script:AdDoctorStops object(s) stopped"',
        "    exit 1",
        "}",
        "",
    ]
    return "\n".join(one_line(line) if not line.startswith("function ") else line for line in out)


def render_fixes(findings: list[Finding], snap: Snapshot) -> str:
    out = [
        f"# ad-doctor remediation script for {snap.domain}",
        f"# generated {snap.collected_at:%Y-%m-%d %H:%M} UTC from {len(findings)} findings",
        "# Review every line. Commands run with -WhatIf; commented lines have no dry-run mode.",
        "# Remove the guards only for the changes you have approved.",
        "#Requires -Modules ActiveDirectory",
        "",
    ]
    for f in findings:
        out.append(f"# --- {f.check_id} [{f.severity}] {f.title}")
        if (e := catalog.get(f.check_id)) is not None:
            out.append(f"# docs: {e.url}")
        out += FIXES.get(f.check_id, _manual)(f, snap)
        out.append("")
    return "\n".join(one_line(line) for line in out)
