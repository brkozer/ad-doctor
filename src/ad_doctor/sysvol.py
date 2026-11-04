"""SYSVOL scan for Group Policy Preferences passwords (MS14-025) over SMB.

Only file names, account names and the fact that a cpassword exists are kept; the
encrypted value itself never leaves this module.
"""

from __future__ import annotations

import re

import smbclient
from smbprotocol.exceptions import SMBException

from .model import GppPassword

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


class SysvolError(Exception):
    pass


def scan_xml(data: bytes) -> list[str]:
    """Account names of the items in one preference file that carry a cpassword."""
    users = []
    for item in re.split(rb"<(?=[A-Za-z])", data):
        if CPASSWORD.search(item):
            names = [n for n in ACCOUNT.findall(item) if n]
            users.append(names[0].decode(errors="replace") if names else "?")
    return users


def find_gpp_passwords(
    host: str, domain: str, user: str, password: str, port: int = 445
) -> list[GppPassword]:
    root = rf"\\{host}\SYSVOL\{domain}\Policies"
    try:
        smbclient.register_session(host, username=user, password=password, port=port)
        found = []
        for dirpath, _dirs, files in smbclient.walk(root, port=port):
            for name in files:
                if name.lower() not in GPP_FILES:
                    continue
                path = rf"{dirpath}\{name}"
                with smbclient.open_file(path, mode="rb", port=port) as fh:
                    data = fh.read(MAX_FILE)
                rel = path[len(root) - len("Policies") :]
                found += [GppPassword(rel, u) for u in scan_xml(data)]
        return found
    except (SMBException, OSError, ValueError) as exc:
        raise SysvolError(str(exc) or type(exc).__name__) from exc
    finally:
        smbclient.reset_connection_cache()
