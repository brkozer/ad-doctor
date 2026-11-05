"""Generate a PowerShell remediation script for review.

Every command that changes something runs with -WhatIf (or is commented out when the tool
has no dry-run mode), so the script is safe to execute as-is and does nothing until an
administrator has read it and removed the guards.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from . import catalog
from .model import Finding, Snapshot

Fix = Callable[[Finding, Snapshot], list[str]]
# Control characters, line breaks among them: object text comes from the directory (GPO
# and CA names), and a newline in it must not end a comment and start a command.
_CONTROL = re.compile("[\x00-\x1f\x7f\x85\u2028\u2029]")


def one_line(text: str) -> str:
    """The text with every control character written as a visible escape."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def _name(obj: str) -> str:
    """The principal in a finding object, without the context ad-doctor appends."""
    return obj.split(" -> ", 1)[0].split(" (", 1)[0]


def _is_computer(obj: str) -> bool:
    return _name(obj).endswith("$")


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _per_object(template: str) -> Fix:
    def fix(f: Finding, snap: Snapshot) -> list[str]:
        return [template.format(o=_q(_name(o)), c=_q(_name(o).rstrip("$"))) for o in f.objects]

    return fix


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
    "AD-ACC-006": _per_object("Set-ADUser {o} -Clear adminCount -WhatIf"),
    "AD-ACC-007": _per_object("Set-ADUser {o} -Clear sIDHistory -WhatIf"),
    "AD-PRIV-002": _per_object("Set-ADAccountControl {o} -AccountNotDelegated $true -WhatIf"),
    "AD-PRIV-004": _per_object("Remove-ADGroupMember DnsAdmins -Members {o} -WhatIf"),
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
    "AD-KRB-005": _per_object("Set-ADUser {o} -KerberosEncryptionType AES128,AES256 -WhatIf"),
    "AD-ACC-009": _per_object(
        "Set-ADUser {o} -Clear userPassword,unixUserPassword,msSFU30Password -WhatIf"
    ),
    "AD-ACC-010": _per_object("Set-ADAccountControl {o} -PasswordNotRequired $false -WhatIf"),
    "AD-PRIV-007": lambda f, snap: [
        f'Set-ADObject (Get-ADObject -Filter "sAMAccountName -eq {_q(_name(o))}") '
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
