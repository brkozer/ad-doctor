"""Live test against the seeded lab domain (lab/seed.ps1).

Run with: AD_DOCTOR_LAB_HOST=... AD_DOCTOR_LAB_USER=... AD_DOCTOR_PASSWORD=... pytest -m lab
"""

from __future__ import annotations

import os

import pytest

from ad_doctor import opengraph
from ad_doctor.checks import run_all
from ad_doctor.collect import Target, collect
from ad_doctor.model import Snapshot

pytestmark = pytest.mark.lab

# Every misconfiguration seed.ps1 plants. Covered by the unit tests only: AD-KRB-001,
# AD-ACC-005, AD-ACC-011 and AD-KRB-006 (need time to pass), AD-ACC-007 and AD-INF-006
# (need a second domain), AD-INF-012 (needs an RODC), AD-ACC-009 (confidential on 2025),
# AD-INF-008 (DCs require SMB signing), AD-INF-009, AD-CHAIN-002/003 (no spooler on
# Server Core 2025) and AD-INF-011 (needs a week without backup).
EXPECTED = {
    "AD-KRB-002": {"legacy_app"},
    "AD-KRB-003": {"svc_sql", "svc_web"},
    "AD-KRB-004": {"des_user"},
    "AD-DEL-001": {"APP01$"},
    "AD-DEL-002": {"svc_iis -> cifs/fs01.adlab.test"},
    "AD-DEL-003": {"FS01$"},
    "AD-ACC-001": {"blank_ok"},
    "AD-ACC-002": {"old_vpn"},
    "AD-ACC-003": {"adm_bob"},
    "AD-ACC-004": {"Guest"},
    "AD-PRIV-002": {"adm_bob", "svc_sql"},
    "AD-POL-001": {"adlab.test"},
    "AD-POL-002": {"adlab.test"},
    "AD-SEC-001": {"APP01$", "FS01$", "OLD2008$", "PRE2K$"},
    "AD-ADCS-001": {"LabESC1 (enroll: Domain Users)"},
    "AD-ADCS-002": {"LabESC2 (enroll: Domain Users)"},
    "AD-ADCS-003": {"LabESC3 (enroll: Domain Users)"},
    "AD-ADCS-004": {"LabESC4 (Authenticated Users)"},
    "AD-ACL-001": {"svc_sync", "MSOL_0a1b2c3d4e5f"},
    "AD-ACL-002": {"helpdesk"},
    "AD-ACL-003": {"helpdesk", "Exchange Windows Permissions"},
    "AD-ADCS-005": {"NTAuthCertificates (helpdesk)"},
    "AD-ADCS-006": {"LabESC9 (enroll: Domain Users)"},
    "AD-ADCS-007": {"LabESC13 (enroll: Domain Users)"},
    "AD-ADCS-008": {"LabESC15 (enroll: Domain Users)"},
    "AD-GPO-001": {"LabDCPolicy -> Domain Controllers OU (helpdesk)"},
    "AD-ACC-006": {"ex_admin"},
    "AD-PRIV-003": {"Schema Admins: Administrator", "Enterprise Admins: Administrator"},
    "AD-PRIV-004": {"helpdesk"},
    "AD-PRIV-005": {"Anonymous Logon"},
    "AD-INF-001": {"OLD2008$ (Windows Server 2008 R2 Standard)"},
    "AD-INF-002": {"adlab.test"},
    "AD-INF-004": {"0000002"},
    "AD-INF-005": {"DC01.adlab.test"},
    "AD-ACC-008": {"notes_user"},
    "AD-ACC-010": {"PRE2K$"},
    "AD-KRB-005": {"svc_web"},
    "AD-DEL-004": {"svc_dc -> ldap/DC01.adlab.test"},
    "AD-ACL-004": {
        "DC01$: kc_writer (write msDS-KeyCredentialLink)",
        "adm_bob: helpdesk (write/WriteDacl/WriteOwner)",
    },
    "AD-ACL-005": {"CN=AdminSDHolder,CN=System,DC=adlab,DC=test"},
    "AD-ACL-006": {"gmsa_web$ (readable by Domain Users)"},
    "AD-ADCS-009": {"map_user"},
    "AD-ADCS-010": {"http://DC01.adlab.test/certsrv/"},
    "AD-ADCS-011": {"LabWeakKey (1024 bits)"},
    "AD-GPO-002": {"Domain Controllers OU: gpo_linker", "domain: helpdesk"},
    "AD-GPO-003": {
        "LabDCPolicy: LmCompatibilityLevel 1 (LM/NTLMv1 allowed)",
        "LabDCPolicy: SeDebugPrivilege granted to Authenticated Users",
    },
    "AD-GPO-004": {"LabUserPolicy (helpdesk)"},
    "AD-GPP-002": {r"scripts\map.bat:1 (net use with a password)"},
    "AD-INF-007": {"Lab: ou_admin"},
    "AD-INF-010": {"DC01.adlab.test"},
    "AD-PRIV-006": {"Domain Admins: old_admin (disabled)"},
    "AD-PRIV-007": {"hidden_admin (primary group Domain Admins)"},
    "AD-PRIV-008": {"Backup Operators: op_user"},
    "AD-PRIV-009": {"helpdesk"},
    "AD-PRIV-010": {"adm_bob"},
    "AD-SEC-002": {"WS01$"},
    "AD-CHAIN-001": {"adlab.test"},
    "AD-PATH-001": {
        "gpo_linker -[link GPOs]-> Domain Controllers",
        "kc_writer -[write msDS-KeyCredentialLink]-> DC01$",
    },
    "AD-ACL-007": {"Exchange Windows Permissions: WriteDacl on the domain object"},
    "AD-PRIV-011": {"MSOL_0a1b2c3d4e5f on ENTRA01: not in a tier-0 group, no LAPS"},
    "AD-ACL-008": {"MSOL_0a1b2c3d4e5f (sync account): helpdesk (reset password)"},
    "AD-GPP-001": {
        r"Policies\{4B1D7A55-0C1E-4A3B-9D2F-7E6A5C3B2A10}\Machine\Preferences\Groups\Groups.xml"
        " (localadmin)"
    },
}


@pytest.fixture(scope="module")
def snap() -> Snapshot:
    host = os.environ.get("AD_DOCTOR_LAB_HOST")
    if not host:
        pytest.skip("AD_DOCTOR_LAB_HOST not set")
    target = Target(
        host=host,
        port=int(os.environ.get("AD_DOCTOR_LAB_PORT", "636")),
        user=os.environ["AD_DOCTOR_LAB_USER"],
        password=os.environ["AD_DOCTOR_PASSWORD"],
        use_ssl=os.environ.get("AD_DOCTOR_LAB_SSL", "1") == "1",
        smb_port=int(os.environ.get("AD_DOCTOR_LAB_SMB_PORT", "445")),
        plain_port=int(os.environ.get("AD_DOCTOR_LAB_PLAIN_PORT", "389")),
        http_port=int(os.environ.get("AD_DOCTOR_LAB_HTTP_PORT", "80")),
    )
    snap = collect(target)
    assert snap.domain == "adlab.test"
    # an ordinary user cannot see fine-grained password policies; nothing else may fail
    assert [n for n in snap.notes if "fine-grained" not in n] == []
    return snap


@pytest.fixture(scope="module")
def findings(snap: Snapshot) -> dict[str, set[str]]:
    return {f.check_id: set(f.objects) for f in run_all(snap)}


def test_every_dc_probed(snap: Snapshot) -> None:
    assert [d.name.lower() for d in snap.probes.dcs] == ["dc01.adlab.test"]
    assert snap.probes.dcs[0].error is None


def test_opengraph_export_of_the_lab(snap: Snapshot) -> None:
    payload = opengraph.export(snap)
    msol = next(a.sid for a in snap.accounts if a.sam == "MSOL_0a1b2c3d4e5f")
    kinds = {(e["start"]["value"], e["kind"]) for e in payload["graph"]["edges"]}
    assert (msol, "ADD_DCSync") in kinds
    assert all(":" not in n["id"] for n in payload["graph"]["nodes"])


@pytest.mark.parametrize("check_id", sorted(EXPECTED))
def test_seeded_misconfiguration_found(findings: dict[str, set[str]], check_id: str) -> None:
    assert check_id in findings
    assert EXPECTED[check_id] <= findings[check_id]


def test_clean_and_default_objects_not_flagged(findings: dict[str, set[str]]) -> None:
    for check_id, objects in findings.items():
        assert "alice" not in objects
        if check_id.startswith("AD-ADCS"):
            # only the seeded objects: the built-in templates, the CA object and its host
            # account are not exploitable by default
            assert objects == EXPECTED[check_id]
    # Domain Users reach tier 0 through the vulnerable templates
    assert any(
        p.startswith("Domain Users -[enroll (ESC1-3)]-> template Lab")
        for p in findings["AD-PATH-001"]
    )
    # nothing beyond the seeded objects in these areas: defaults stay quiet
    exact = (
        "AD-GPO-001",
        "AD-GPO-003",
        "AD-GPO-004",
        "AD-ACL-001",
        "AD-ACL-002",
        "AD-ACL-003",
        "AD-ACL-006",
        "AD-ACL-007",
        "AD-ACL-008",
        "AD-DEL-001",
        "AD-DEL-004",
        "AD-GPP-002",
        "AD-PRIV-007",
    )
    for check_id in exact:
        assert findings[check_id] == EXPECTED[check_id]
