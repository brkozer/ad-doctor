"""Live test against the seeded lab domain (lab/seed.ps1).

Run with: AD_DOCTOR_LAB_HOST=... AD_DOCTOR_LAB_USER=... AD_DOCTOR_PASSWORD=... pytest -m lab
"""

from __future__ import annotations

import os

import pytest

from ad_doctor.checks import run_all
from ad_doctor.collect import Target, collect

pytestmark = pytest.mark.lab

# Every misconfiguration seed.ps1 plants. AD-KRB-001 and AD-ACC-005 need time to pass;
# AD-ACC-007 (SID history) and AD-INF-006 (trusts) need a second domain, so they are
# covered by the unit tests only.
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
    "AD-SEC-001": {"APP01$", "FS01$", "WS01$"},
    "AD-ADCS-001": {"LabESC1 (enroll: Domain Users)"},
    "AD-ADCS-002": {"LabESC2 (enroll: Domain Users)"},
    "AD-ADCS-003": {"LabESC3 (enroll: Domain Users)"},
    "AD-ADCS-004": {"LabESC4 (Authenticated Users)"},
    "AD-ACL-001": {"svc_sync"},
    "AD-ACL-002": {"helpdesk"},
    "AD-ACL-003": {"helpdesk"},
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
    "AD-INF-005": {"adlab.test"},
    "AD-GPP-001": {
        r"Policies\{4B1D7A55-0C1E-4A3B-9D2F-7E6A5C3B2A10}\Machine\Preferences\Groups\Groups.xml"
        " (localadmin)"
    },
}


@pytest.fixture(scope="module")
def findings() -> dict[str, set[str]]:
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
    )
    snap = collect(target)
    assert snap.domain == "adlab.test"
    assert snap.notes == []
    return {f.check_id: set(f.objects) for f in run_all(snap)}


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
    # nothing seeded in the GPO, delegation or ACL areas beyond what EXPECTED lists
    for check_id in ("AD-GPO-001", "AD-ACL-001", "AD-ACL-002", "AD-ACL-003", "AD-DEL-001"):
        assert findings[check_id] == EXPECTED[check_id]
