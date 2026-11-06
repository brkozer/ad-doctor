"""Live test against the seeded lab domain (lab/seed.ps1).

Run with: AD_DOCTOR_LAB_HOST=... AD_DOCTOR_LAB_USER=... AD_DOCTOR_PASSWORD=... pytest -m lab
"""

from __future__ import annotations

import os

import pytest

from ad_doctor import gpo_scope, opengraph, paths
from ad_doctor.checks import run_all, tier0_hosts
from ad_doctor.collect import Target, collect
from ad_doctor.model import Severity, Snapshot

pytestmark = pytest.mark.lab

# Every misconfiguration seed.ps1 plants. Covered by the unit tests only: AD-KRB-001,
# AD-ACC-005, AD-ACC-011 and AD-KRB-006 (need time to pass), AD-ACC-007 and AD-INF-006
# (need a second domain), AD-INF-012 (needs an RODC), AD-ACC-009 (confidential on 2025),
# AD-INF-008 (DCs require SMB signing), AD-INF-009 and the high grade of AD-CHAIN-002/003
# (no spooler on Server Core 2025) and AD-INF-011 (needs a week without backup).
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
    "AD-SEC-001": {"APP01$", "FS01$", "OLD2008$", "PRE2K$", "ROGUE01$"},
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
    "AD-ADCS-012": {"adlab-CA"},
    "AD-ADCS-013": {"adlab-CA: helpdesk (ManageCertificates)"},
    "AD-ADCS-014": {"adlab-CA"},
    "AD-ADCS-015": {"adlab-CA"},
    # LabESC15 is a schema v1 server template, so it is both ESC15 and ESC17
    "AD-ADCS-017": {"LabESC15 (enroll: Domain Users)"},
    "AD-CHAIN-002": {"APP01$"},
    "AD-CHAIN-003": {"http://DC01.adlab.test/certsrv/"},
    "AD-CHAIN-004": {"adlab-CA"},
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
    "AD-KRB-005": {
        "svc_sql: no value set, the domain default applies",
        "svc_web: no AES in msDS-SupportedEncryptionTypes (0x4)",
    },
    "AD-ADCS-018": {
        "adlab-CA: AuditFilter 3, off: certificate requests, revocation and CRLs, "
        "CA security settings, archived keys, CA configuration"
    },
    "AD-DEL-004": {"svc_dc -> ldap/DC01.adlab.test"},
    "AD-ACL-004": {
        "DC01$: kc_writer (write msDS-KeyCredentialLink)",
        "DC01$: rbcd_writer (write RBCD)",
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
    "AD-GPO-004": {
        "LabUserPolicy (helpdesk)",
        "LabOuReach (gpo_editor)",
        "LabSiteReach (gpo_site_editor)",
        "LabDisabledLink (gpo_ctl)",
        "LabComputerOff (gpo_ctl)",
        "LabFilteredOut (gpo_ctl)",
    },
    "AD-GPP-002": {r"scripts\map.bat:1 (net use with a password)"},
    "AD-INF-007": {"Lab: ou_admin"},
    "AD-INF-010": {"DC01.adlab.test"},
    "AD-PRIV-006": {"Domain Admins: old_admin (disabled)"},
    "AD-PRIV-007": {
        "hidden_admin (primary group Domain Admins)",
        "ROGUE01$ (primary group Domain Controllers, but not a DC)",
    },
    "AD-INF-014": {"ROGUE01$"},
    "AD-PRIV-008": {"Backup Operators: op_user"},
    "AD-PRIV-009": {"helpdesk"},
    "AD-PRIV-010": {"adm_bob"},
    "AD-SEC-002": {"WS01$"},
    "AD-CHAIN-001": {"adlab.test"},
    "AD-PATH-001": {
        "gpo_linker -[link GPOs]-> Domain Controllers",
        "kc_writer -[write msDS-KeyCredentialLink]-> DC01$",
        "rbcd_writer -[write RBCD]-> DC01$",
        "LabServerAdmins -[admin to via GPO LabLocalAdmins]-> ENTRA01$ -[hosts sync account]-> "
        "MSOL_0a1b2c3d4e5f -[DCSync]-> adlab.test",
    },
    "AD-ACL-007": {"Exchange Windows Permissions: WriteDacl on the domain object"},
    "AD-PRIV-011": {"MSOL_0a1b2c3d4e5f on ENTRA01: not in a tier-0 group, no LAPS"},
    "AD-ACL-008": {"MSOL_0a1b2c3d4e5f (sync account): helpdesk (reset password)"},
    "AD-GPP-001": {
        r"Policies\{4B1D7A55-0C1E-4A3B-9D2F-7E6A5C3B2A10}\Machine\Preferences\Groups\Groups.xml"
        " (localadmin)"
    },
    # Round 5 GPO cases A-G: only A, B and D surface; C (disabled link), E (security
    # filtering), F (computer side off), G (DC remote desktop without the logon right) and
    # the disabled GPP item stay silent. The item-level targeted item is listed with a
    # caveat (its targeting is not evaluated; here it names WS02, the OU's only computer).
    "AD-GPO-005": {
        "LabRdp: Domain Users -> Administrators on WS02$ [item-level targeting not evaluated]"
    },
    "AD-GPO-006": {
        "LabLocalAdmins: LabServerAdmins -> Administrators on ENTRA01$ (Entra Connect server), "
        "EXCH01$ (Exchange server)"
    },
    "AD-GPO-007": {
        "LabEnforced: LabServerAdmins -> Remote Desktop Users on ENTRA01$ (Entra Connect "
        "server), EXCH01$ (Exchange server)",
        "LabRdp: Domain Users -> Remote Desktop Users on WS02$",
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
    # an ordinary user cannot see fine-grained password policies or dMSAs; nothing else may fail
    assert [n for n in snap.notes if "fine-grained" not in n and "dMSA" not in n] == []
    return snap


@pytest.fixture(scope="module")
def findings(snap: Snapshot) -> dict[str, set[str]]:
    return {f.check_id: set(f.objects) for f in run_all(snap)}


def test_gpo_reach_through_ou_and_site_links(snap: Snapshot) -> None:
    g = paths.build(snap)

    def own_reach(sam: str) -> tuple[set[str], int]:
        found = paths.reachable(g, paths.identity_nodes(snap, sam)[:1])
        names = {g.name(n) for n in found if g.kind(n) == "computer"}
        return names, sum(n in g.tier0 for n in found)

    computers, tier0 = own_reach("gpo_editor")
    assert {"ENTRA01$", "EXCH01$", "WS02$"} <= computers and tier0
    computers, tier0 = own_reach("gpo_site_editor")
    assert {"DC01$", "ROGUE01$", "WS02$"} <= computers and tier0
    # a disabled link, the computer side off, a filter that matches nobody
    assert own_reach("gpo_ctl") == (set(), 0)
    # the block on OU=Isolated stops LabOuReach: only the enforced GPO gets through
    lab = next(n for n, name in g.names.items() if name == "computers under Lab")
    assert "WS03$" not in {g.name(d) for d, _ in g.edges[lab]}


def test_every_dc_probed(snap: Snapshot) -> None:
    assert [d.name.lower() for d in snap.probes.dcs] == ["dc01.adlab.test"]
    assert snap.probes.dcs[0].error is None


def test_registered_dcs_and_rogue_candidate(snap: Snapshot) -> None:
    assert snap.dc_registration_checked
    assert sorted(a.sam for a in snap.accounts if a.is_dc) == ["DC01$", "ROGUE01$"]
    assert [a.sam for a in snap.accounts if a.rogue_dc] == ["ROGUE01$"]
    rogue = next(a for a in snap.accounts if a.rogue_dc)
    assert rogue.dn.lower() in snap.tier0_dns()


def test_plain_user_is_blind_to_dmsas(snap: Snapshot) -> None:
    # dmsa_lab exists (seed.ps1), and adreader must not see it
    assert not snap.dmsa_visible
    assert not any(a.sam.lower().startswith("dmsa_lab") for a in snap.accounts)
    assert any("no dMSA visible" in n for n in snap.notes)
    found = next(f for f in run_all(snap) if f.check_id == "AD-INF-007")
    assert "existing dMSA links were not checked" in found.detail


def test_coercion_is_assumed_without_a_spooler(snap: Snapshot) -> None:
    assert snap.probes.dcs[0].spooler is False  # Server Core 2025 has none
    grades = {f.check_id: f for f in run_all(snap)}
    for check_id in ("AD-CHAIN-002", "AD-CHAIN-003"):
        assert grades[check_id].severity is Severity.MEDIUM
        assert "assumed possible" in grades[check_id].detail


def test_outgoing_ntlm_read_from_the_dc_gpo(snap: Snapshot) -> None:
    gpo = next(g for g in snap.gpos if g.name == "LabDCPolicy")
    assert snap.gpo_settings[gpo.guid].restrict_sending_ntlm == 1  # audit, not deny
    state = gpo_scope.dc_outgoing_ntlm(snap)
    assert state.denied is False and "DC01" in state.detail


def test_plain_user_reads_password_metadata_of_tier0(snap: Snapshot) -> None:
    assert snap.pwd_metadata_checked
    by_sam = {a.sam: a for a in snap.accounts}
    for sam in ("krbtgt", "Administrator", "adm_bob", "DC01$"):
        assert by_sam[sam].pwd_changed is not None, sam
    assert by_sam["alice"].pwd_changed is None  # not tier 0: never asked for
    assert not any("unicodePwd not readable" in n for n in snap.notes)


def test_moved_pwd_last_set_is_found(snap: Snapshot) -> None:
    (f,) = [f for f in run_all(snap) if f.check_id == "AD-ACC-012"]
    assert f.severity is Severity.MEDIUM
    assert [f.key(o) for o in f.objects] == ["adm_bob"]


def test_cutover_read_from_the_rodc_group(snap: Snapshot) -> None:
    assert snap.aes_cutover is not None


def test_ca_audit_filter_read_over_winreg(snap: Snapshot) -> None:
    (ca,) = snap.probes.ca_configs
    assert ca.audit_checked and ca.audit_filter == 3
    (f,) = [f for f in run_all(snap) if f.check_id == "AD-ADCS-018"]
    assert f.severity is Severity.MEDIUM


def test_netlogon_allow_list_from_the_dc_gpo(snap: Snapshot) -> None:
    (hit,) = gpo_scope.dc_channel_allow(snap)[0]
    assert hit.gpo.name == "LabDCPolicy" and hit.dcs == ("DC01$",)
    (f,) = [f for f in run_all(snap) if f.check_id == "AD-GPO-008"]
    assert f.severity is Severity.HIGH
    assert f.objects == ["LabDCPolicy: Domain Controllers, helpdesk on DC01$"]


def test_hidden_domain_admin_shows_up_as_a_member_value(snap: Snapshot) -> None:
    assert snap.tier0_members_checked
    (member,) = snap.unreadable_members
    assert member.dn == "CN=veiled_admin,OU=Veiled,OU=Lab,DC=adlab,DC=test"
    assert member.group == "Domain Admins"
    assert "veiled_admin" not in {a.sam for a in snap.accounts}
    (f,) = [f for f in run_all(snap) if f.check_id == "AD-PRIV-012"]
    assert f.severity is Severity.HIGH


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
        "AD-GPO-005",
        "AD-GPO-006",
        "AD-GPO-007",
        "AD-KRB-005",
        "AD-ADCS-018",
    )
    for check_id in exact:
        assert findings[check_id] == EXPECTED[check_id]
    # every CA setting was read: nothing is left unknown
    assert "AD-ADCS-016" not in findings


def test_gpo_local_group_scope(snap: Snapshot) -> None:
    scope = gpo_scope.resolve(snap)
    assert scope.clears == [] and scope.notes == []
    targeted = [g for g in scope.grants if gpo_scope.ILT_CAVEAT in g.caveats]
    assert [(g.gpo.name, g.computer.sam if g.computer else "") for g in targeted] == [
        ("LabRdp", "WS02$")
    ]
    by_gpo: dict[str, set[str]] = {}
    for g in scope.grants:
        by_gpo.setdefault(g.gpo.name, set()).add(g.computer.sam if g.computer else "DCs")
    # Block Inheritance on OU=Isolated stops LabLocalAdmins but not the enforced LabEnforced
    assert "WS03$" not in by_gpo["LabLocalAdmins"]
    assert "WS03$" in by_gpo["LabEnforced"]
    for silent in ("LabDisabledLink", "LabFilteredOut", "LabComputerOff"):
        assert silent not in by_gpo
    gpos = {g.name: g for g in snap.gpos}
    assert [link.enabled for link in gpos["LabDisabledLink"].links] == [False]
    assert gpos["LabComputerOff"].flags == 2
    assert [link.enforced for link in gpos["LabEnforced"].links] == [True]
    # on the DC the setting rewrites the domain's Remote Desktop Users, which grants no logon
    dc_rdp = [g for g in scope.grants if g.gpo.name == "LabDcRdp"]
    assert [(g.domain_group, g.computer, g.effective) for g in dc_rdp] == [(True, None, False)]
    roles = tier0_hosts(snap)
    assert sorted(roles.values()) == [
        "Entra Connect server",
        "Exchange server",
        "domain controller",
        "unregistered DC",
    ]
    g = paths.build(snap)
    ws03 = next(a.sid for a in snap.accounts if a.sam == "WS03$")
    server_admins = next(o.sid for o in snap.objects if o.name == "LabServerAdmins")
    assert (f"sid:{ws03}", "can RDP via GPO LabEnforced") in g.logon_edges[f"sid:{server_admins}"]
