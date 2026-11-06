"""Checks, control paths and tooling added after the competitor review."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from xml.etree import ElementTree

import pytest

from ad_doctor import accept, invariants, paths, redact, sd
from ad_doctor.checks import run_all
from ad_doctor.cli import main
from ad_doctor.collect import _last_backup
from ad_doctor.model import (
    UAC,
    DirObject,
    Gmsa,
    Gpo,
    GpoSettings,
    Probes,
    Rodc,
    ScriptSecret,
    Snapshot,
)
from ad_doctor.report import Report, mermaid_paths, render_junit
from ad_doctor.sd import Ace
from ad_doctor.sysvol import parse_gpttmpl, scan_script

from .test_acl_adcs import DOMAIN_SID, ace_bytes, descriptor, template
from .test_checks import NORMAL, NOW, computer, only, snapshot, user

DA = f"{DOMAIN_SID}-512"
HELPDESK = f"{DOMAIN_SID}-1105"
DOMAIN_USERS = f"{DOMAIN_SID}-513"


def ids(snap: Snapshot) -> set[str]:
    return {f.check_id for f in run_all(snap)}


def admin_snapshot(**kw: object) -> tuple[Snapshot, DirObject]:
    """A domain with one admin whose DACL the test controls."""
    admin = user("adm_bob", sid=f"{DOMAIN_SID}-1500")
    obj = DirObject(admin.dn, "adm_bob", "user", sid=admin.sid, owner=DA, aces=[])
    snap = snapshot(admin, privileged={"Domain Admins": [admin.dn]}, objects=[obj], **kw)
    return snap, obj


# --- security descriptor parsing -------------------------------------------------------


def test_parse_owner_and_protection() -> None:
    raw = bytearray(descriptor(ace_bytes(HELPDESK, sd.WRITE_DAC)))
    # control: DACL present + protected; owner placed after the ACL
    owner_sid = bytes.fromhex("01050000000000051500000001000000020000000300000000020000")
    raw[2:4] = (0x8004 | sd.SE_DACL_PROTECTED).to_bytes(2, "little")
    raw[4:8] = len(raw).to_bytes(4, "little")
    raw += owner_sid
    desc = sd.parse(bytes(raw))
    assert desc.owner == "S-1-5-21-1-2-3-512"
    assert desc.dacl_protected
    assert desc.aces == [Ace(HELPDESK, sd.WRITE_DAC)]


def test_attribute_and_class_rights() -> None:
    ace = Ace(HELPDESK, sd.WRITE_PROPERTY, sd.KEY_CREDENTIAL_LINK)
    assert ace.writes(sd.KEY_CREDENTIAL_LINK) and not ace.writes(sd.MEMBER)
    assert Ace(HELPDESK, sd.GENERIC_WRITE).writes(sd.MEMBER)
    assert Ace(HELPDESK, sd.CREATE_CHILD).creates(sd.DMSA_CLASS)
    user_class = "bf967aba-0de6-11d0-a285-00aa003049e2"
    assert not Ace(HELPDESK, sd.CREATE_CHILD, user_class).creates(sd.DMSA_CLASS)


# --- tier-0 objects ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ace", "expected"),
    [
        (Ace(HELPDESK, sd.WRITE_PROPERTY, sd.KEY_CREDENTIAL_LINK), "write msDS-KeyCredentialLink"),
        (Ace(HELPDESK, sd.CONTROL_ACCESS, sd.RESET_PASSWORD), "reset password"),
        (Ace(HELPDESK, sd.WRITE_PROPERTY, sd.SERVICE_PRINCIPAL_NAME), "write SPN"),
        (Ace(HELPDESK, sd.GENERIC_ALL), "full control"),
    ],
)
def test_tier0_object_control(ace: Ace, expected: str) -> None:
    snap, obj = admin_snapshot(principals={HELPDESK: "helpdesk"})
    obj.aces = [ace]
    assert only(snap, "AD-ACL-004").objects == [f"adm_bob: helpdesk ({expected})"]


def test_tier0_defaults_are_quiet() -> None:
    snap, obj = admin_snapshot()
    obj.aces = [
        Ace("S-1-5-10", sd.WRITE_PROPERTY),  # SELF
        Ace(f"{DOMAIN_SID}-526", sd.WRITE_PROPERTY, sd.KEY_CREDENTIAL_LINK),  # Key Admins
        Ace(f"{DOMAIN_SID}-517", sd.WRITE_PROPERTY, "bf967a7f-0de6-11d0-a285-00aa003049e2"),
        Ace(DA, sd.GENERIC_ALL),
    ]
    assert "AD-ACL-004" not in ids(snap)


def test_tier0_owner() -> None:
    snap, obj = admin_snapshot(principals={HELPDESK: "helpdesk"})
    obj.owner = HELPDESK
    assert only(snap, "AD-ACL-004").objects == ["adm_bob: owned by helpdesk"]


def test_adminsdholder_inheritance() -> None:
    holder = DirObject(
        "CN=AdminSDHolder,CN=System,DC=lab,DC=test", "AdminSDHolder", "container",
        aces=[Ace(DA, sd.GENERIC_ALL)], dacl_protected=False,
    )  # fmt: skip
    assert only(snapshot(objects=[holder]), "AD-ACL-005")
    holder.dacl_protected = True
    assert "AD-ACL-005" not in ids(snapshot(objects=[holder]))


def test_gmsa_readers() -> None:
    gm = Gmsa("gmsa_web$", "CN=gmsa_web,CN=Managed Service Accounts,DC=lab,DC=test", [DOMAIN_USERS])
    f = only(snapshot(gmsas=[gm]), "AD-ACL-006")
    assert f.severity.name == "HIGH" and f.objects == ["gmsa_web$ (readable by Domain Users)"]


# --- accounts and groups -----------------------------------------------------------------


def test_account_hygiene_checks() -> None:
    old = NOW - timedelta(days=500)
    snap = snapshot(
        user("notes", secret_in_description=True),
        user("unix", password_attributes=["unixUserPassword"]),
        user("adm_old", pwd_last_set=old, sid=f"{DOMAIN_SID}-1600"),
        user("hidden", primary_group=512),
        computer("PRE2K", 0x1000 | UAC.PASSWD_NOTREQD, logon_count=0),
        computer("FAKEDC", primary_group=516),
        privileged={"Domain Admins": ["CN=adm_old,CN=Users,DC=lab,DC=test"]},
    )
    found = {f.check_id: f.objects for f in run_all(snap)}
    assert found["AD-ACC-008"] == ["notes"]
    assert found["AD-ACC-009"] == ["unix (unixUserPassword)"]
    assert found["AD-ACC-010"] == ["PRE2K$"]
    assert found["AD-ACC-011"] == ["adm_old"]
    assert found["AD-PRIV-007"] == [
        "FAKEDC$ (primary group Domain Controllers, but not a DC)",
        "hidden (primary group Domain Admins)",
    ]


def test_odd_privileged_members_and_operators() -> None:
    off = user("old_admin", NORMAL | UAC.ACCOUNTDISABLE)
    pc = computer("APP9")
    da_group = DirObject(
        "CN=Domain Admins,CN=Users,DC=lab,DC=test", "Domain Admins", "group", sid=DA,
        members=["CN=S-1-5-21-9-9-9-500,CN=ForeignSecurityPrincipals,DC=lab,DC=test"],
    )  # fmt: skip
    snap = snapshot(
        off,
        pc,
        privileged={"Domain Admins": [off.dn, pc.dn], "Backup Operators": [off.dn]},
        objects=[da_group],
    )
    found = {f.check_id: f.objects for f in run_all(snap)}
    assert found["AD-PRIV-006"] == [
        "Backup Operators: old_admin (disabled)",
        "Domain Admins: APP9$ (computer)",
        "Domain Admins: S-1-5-21-9-9-9-500 (foreign)",
        "Domain Admins: old_admin (disabled)",
    ]
    assert found["AD-PRIV-008"] == ["Backup Operators: old_admin"]


def test_cert_publishers_and_protected_users() -> None:
    admin = user("adm_bob")
    pub = DirObject(
        "CN=Cert Publishers,CN=Users,DC=lab,DC=test", "Cert Publishers", "group",
        sid=f"{DOMAIN_SID}-517", members=[computer("CA01").dn, admin.dn],
    )  # fmt: skip
    snap = snapshot(
        admin, computer("CA01"), objects=[pub], ca_hosts=["CA01$"],
        privileged={"Domain Admins": [admin.dn]},
    )  # fmt: skip
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-PRIV-009"].objects == ["adm_bob"]
    assert found["AD-PRIV-010"].severity.name == "INFO"


# --- Kerberos, delegation, certificates ---------------------------------------------------


def test_rc4_only_and_seamless_sso() -> None:
    snap = snapshot(
        user("svc_old", spns=["HTTP/old"], enc_types=0x4),
        user("svc_new", spns=["HTTP/new"], enc_types=0x1C),
        computer("AZUREADSSOACC", pwd_last_set=NOW - timedelta(days=90)),
    )
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-KRB-005"].objects == ["svc_old: no AES in msDS-SupportedEncryptionTypes (0x4)"]
    assert "90 days" in found["AD-KRB-006"].detail


def test_delegation_to_dcs() -> None:
    snap = snapshot(
        user("svc_a", allowed_to_delegate_to=["ldap/DC01.lab.test", "cifs/fs01.lab.test"]),
        user("svc_b", allowed_to_delegate_to=["HOST/dc01"]),
    )
    snap.accounts[2].dns_host = "dc01.lab.test"
    assert only(snap, "AD-DEL-004").objects == [
        "svc_a -> ldap/DC01.lab.test",
        "svc_b -> HOST/dc01",
    ]


@pytest.mark.parametrize(
    ("mapping", "weak"),
    [
        ("X509:<I>DC=test,CN=CA<S>CN=bob", True),
        ("X509:<RFC822>bob@lab.test", True),
        ("X509:<I>DC=test,CN=CA<SR>1234abcd", False),
        ("X509:<SKI>0011", False),
        ("X509:<SHA1-PUKEY>aabb", False),
    ],
)
def test_esc14(mapping: str, weak: bool) -> None:
    snap = snapshot(user("bob", alt_security_identities=[mapping]))
    assert ("AD-ADCS-009" in ids(snap)) is weak


def test_esc8_weak_keys_and_chains() -> None:
    snap = snapshot(
        computer("APP01", 0x1000 | UAC.TRUSTED_FOR_DELEGATION),
        templates=[template("Old", min_key_size=1024), template("Ecc", min_key_size=256)],
        probes=Probes(
            spooler_on_dc=True,
            smb_signing_required=False,
            ldaps_channel_binding_required=False,
            web_enrollment_ntlm=["http://ca01.lab.test/certsrv/"],
        ),
        ldap_signing_required=False,
    )
    snap.policy.machine_account_quota = 10
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-ADCS-011"].objects == ["Old (1024 bits)"]
    assert {"AD-ADCS-010", "AD-INF-008", "AD-INF-010"} <= found.keys()
    assert found["AD-INF-009"].severity.name == "HIGH"  # spooler + unconstrained delegation
    assert {"AD-CHAIN-001", "AD-CHAIN-002", "AD-CHAIN-003"} <= found.keys()
    assert found["AD-CHAIN-002"].objects == ["APP01$"]


# --- infrastructure, GPOs, SYSVOL ---------------------------------------------------------


def test_bad_successor_only_on_2025() -> None:
    ou = DirObject("OU=Lab,DC=lab,DC=test", "Lab", "ou", aces=[Ace(HELPDESK, sd.CREATE_CHILD)])
    snap = snapshot(objects=[ou], principals={HELPDESK: "helpdesk"})
    snap.policy.functional_level = 7
    assert "AD-INF-007" not in ids(snap)
    snap.policy.functional_level = 10
    assert only(snap, "AD-INF-007").objects == ["Lab: helpdesk"]


def test_gplink_write_and_gpo_settings() -> None:
    dc_ou = DirObject(
        "OU=Domain Controllers,DC=lab,DC=test", "Domain Controllers", "ou",
        aces=[Ace(HELPDESK, sd.WRITE_PROPERTY, sd.GP_LINK)],
    )  # fmt: skip
    settings = GpoSettings(
        lm_compatibility=1, no_lm_hash=0, clear_text_password=1,
        privileges={
            "SeDebugPrivilege": ["S-1-5-32-544", "S-1-5-11"],
            "SeChangeNotifyPrivilege": ["S-1-1-0"],
        },
    )  # fmt: skip
    snap = snapshot(
        objects=[dc_ou],
        principals={HELPDESK: "helpdesk"},
        gpos=[
            Gpo("DC Policy", "{G1}", ["Domain Controllers OU"], []),
            Gpo("Unlinked", "{G2}", [], [Ace(HELPDESK, sd.GENERIC_WRITE)]),
        ],
        gpo_settings={"{G1}": settings, "{G2}": GpoSettings(lm_compatibility=0)},
    )  # fmt: skip
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-GPO-002"].objects == ["Domain Controllers OU: helpdesk"]
    assert found["AD-GPO-003"].objects == [
        "DC Policy: LM hashes stored (NoLMHash 0)",
        "DC Policy: LmCompatibilityLevel 1 (LM/NTLMv1 allowed)",
        "DC Policy: SeDebugPrivilege granted to Authenticated Users",
        "DC Policy: reversible password encryption enabled",
    ]
    assert found["AD-GPO-004"].objects == ["Unlinked (helpdesk)"]


def test_script_secrets_backup_rodc_laps() -> None:
    denied = DirObject(
        "CN=Denied RODC Password Replication Group,CN=Users,DC=lab,DC=test", "Denied RODC",
        "group", sid=f"{DOMAIN_SID}-572",
    )  # fmt: skip
    da = DirObject("CN=Domain Admins,CN=Users,DC=lab,DC=test", "Domain Admins", "group", sid=DA)
    snap = snapshot(
        computer("WS7", laps_password_readable=True),
        script_secrets=[ScriptSecret(r"scripts\map.bat", 3, "net use with a password")],
        backup_checked=True,
        last_backup=NOW - timedelta(days=40),
        rodcs=[Rodc("RODC1$", [da.dn], [])],
        objects=[denied, da],
    )
    found = {f.check_id: f for f in run_all(snap)}
    assert found["AD-GPP-002"].objects == [r"scripts\map.bat:3 (net use with a password)"]
    assert "40 days" in found["AD-INF-011"].detail
    assert found["AD-INF-012"].objects == [
        "RODC1$: Denied RODC Password Replication Group not in never-reveal",
        "RODC1$: allowed Domain Admins",
    ]
    assert found["AD-SEC-002"].objects == ["WS7$"]


def test_scan_script_ignores_variables_and_comments() -> None:
    text = "\n".join(
        [
            "rem net use z: \\\\fs\\s /user:LAB\\svc Secret1",
            "net use z: \\\\fs\\s /user:LAB\\svc Passw0rd!",
            "net use y: \\\\fs\\s /user:LAB\\svc %PASSWORD%",
            "$p = ConvertTo-SecureString 'Hunter2!' -AsPlainText -Force",
            "Connect-Thing -Password $cred",
            "password = $env:SECRET",
            "db_password=SuperSecret9",
        ]
    )
    assert scan_script(text) == [
        (2, "net use with a password"),
        (4, "plain-text SecureString"),
        (7, "password assignment"),
    ]


def test_parse_gpttmpl() -> None:
    text = (
        "[Unicode]\nUnicode=yes\n[System Access]\nClearTextPassword = 0\n[Registry Values]\n"
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5\n"
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1\n[Privilege Rights]\n"
        "SeDebugPrivilege = *S-1-5-32-544\nSeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551\n"
    )
    s = parse_gpttmpl(text)
    assert (s.clear_text_password, s.lm_compatibility, s.no_lm_hash) == (0, 5, 1)
    assert s.privileges["SeBackupPrivilege"] == ["S-1-5-32-544", "S-1-5-32-551"]


def test_last_backup_parsing() -> None:
    xml = (
        "<DS_REPL_ATTR_META_DATA><pszAttributeName>dSASignature</pszAttributeName>"
        "<ftimeLastOriginatingChange>2026-10-30T02:00:00Z</ftimeLastOriginatingChange>"
        "</DS_REPL_ATTR_META_DATA>"
    )
    assert _last_backup(xml) is not None and _last_backup(xml).day == 30  # type: ignore[union-attr]
    never = xml.replace("2026-10-30T02:00:00Z", "1601-01-01T00:00:00Z")
    assert _last_backup(never) is None


# --- control paths -------------------------------------------------------------------------


def path_snapshot() -> Snapshot:
    """helpdesk -> GenericAll on group 'IT' -> IT is member of Domain Admins."""
    admin = user("adm_bob", sid=f"{DOMAIN_SID}-1500")
    it = DirObject(
        "CN=IT,OU=Groups,DC=lab,DC=test", "IT", "group", sid=f"{DOMAIN_SID}-1700",
        aces=[Ace(HELPDESK, sd.GENERIC_ALL)],
    )  # fmt: skip
    da = DirObject(
        "CN=Domain Admins,CN=Users,DC=lab,DC=test", "Domain Admins", "group", sid=DA,
        members=[admin.dn, it.dn],
    )  # fmt: skip
    hd = user("helpdesk", sid=HELPDESK)
    worker = user("worker", sid=f"{DOMAIN_SID}-1800")
    outsider = user("outsider", sid=f"{DOMAIN_SID}-1801")
    hd_group = DirObject(
        "CN=Helpdesk,OU=Groups,DC=lab,DC=test", "Helpdesk", "group", sid=f"{DOMAIN_SID}-1900",
        members=[worker.dn],
    )  # fmt: skip
    it.aces.append(Ace(hd_group.sid, sd.WRITE_PROPERTY, sd.MEMBER))
    return snapshot(
        admin, hd, worker, outsider,
        privileged={"Domain Admins": [admin.dn]},
        objects=[it, da, hd_group],
        principals={HELPDESK: "helpdesk"},
    )  # fmt: skip


def test_control_paths() -> None:
    snap = path_snapshot()
    f = only(snap, "AD-PATH-001")
    assert set(f.objects) == {
        "Helpdesk -[write members]-> IT -[member of]-> Domain Admins",
        "helpdesk -[full control]-> IT -[member of]-> Domain Admins",
    }
    # helpdesk directly, worker through the Helpdesk group; outsider has no path and
    # adm_bob is tier 0 already
    assert "2 of 3 enabled users (66%)" in f.detail


def test_paths_reach_tier0_through_broad_groups() -> None:
    snap = snapshot(templates=[template("Bad", enrollee_supplies_subject=True)])
    f = only(snap, "AD-PATH-001")
    assert f.objects == ["Domain Users -[enroll (ESC1-3)]-> template Bad"]
    assert "every user" in f.detail


def test_blast_radius_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap_path = tmp_path / "snap.json"
    snap_path.write_text(json.dumps(path_snapshot().to_json()))
    assert main(["blast-radius", str(snap_path), "worker"]) == 2
    out = capsys.readouterr().out
    assert "REACHES TIER 0" in out
    chain = "worker -[member of]-> Helpdesk -[write members]-> IT -[member of]-> Domain Admins"
    assert chain in out
    assert main(["blast-radius", str(snap_path), "outsider", "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["reaches_tier0"] is False
    assert main(["blast-radius", str(snap_path), "nobody"]) == 1


def test_mermaid_rendering() -> None:
    lines = mermaid_paths(["a -[owns]-> b -[member of]-> Domain Admins", "c -[owns]-> b"])
    assert lines[0] == "```mermaid" and lines[-1] == "```"
    assert sum("-->" in line for line in lines) == 3


def test_graph_skips_self_and_creator_owner() -> None:
    snap, obj = admin_snapshot()
    obj.aces = [Ace("S-1-5-10", sd.GENERIC_ALL), Ace("S-1-3-0", sd.GENERIC_ALL)]
    obj.owner = "S-1-3-0"
    assert paths.paths_to_tier0(paths.build(snap)) == {}


# --- policy as code, accepted risks, redaction, JUnit -------------------------------------


def test_invariants(tmp_path: Path) -> None:
    spec = tmp_path / "inv.toml"
    spec.write_text(
        '[groups]\n"Domain Admins" = ["adm_bob", "adm_alice"]\n'
        "[limits]\ntier0_users = 0\n"
        "[settings]\nmachine_account_quota = 0\nmin_pwd_length = 16\nrecycle_bin = true\n"
        '[dcsync]\nallowed = ["svc_sync"]\n'
        '[templates]\npublished = ["User"]\n'
    )
    snap, _ = admin_snapshot(
        acls={"domain": [Ace(HELPDESK, sd.CONTROL_ACCESS)]},
        principals={HELPDESK: "helpdesk"},
        templates=[template("VulnUser")],
        recycle_bin=True,
    )
    found = {f.check_id: f.objects for f in invariants.evaluate(snap, invariants.load(spec))}
    assert found["AD-INV-001"] == ["Domain Admins: missing adm_alice"]
    assert found["AD-INV-002"] == ["adm_bob"]
    assert found["AD-INV-003"] == ["min_pwd_length: 14 (declared >= 16)"]
    assert found["AD-INV-004"] == ["helpdesk"]
    assert found["AD-INV-005"] == ["VulnUser"]


def test_invariants_reject_unknown_settings(tmp_path: Path) -> None:
    spec = tmp_path / "inv.toml"
    spec.write_text("[settings]\nfavourite_colour = 1\n")
    with pytest.raises(invariants.InvariantError, match="favourite_colour"):
        invariants.load(spec)


def test_accept_governance(tmp_path: Path) -> None:
    path = tmp_path / "a.toml"
    path.write_text(
        '[[accept]]\ncheck = "AD-SEC-001"\nreason = "r"\nexpires = 2026-11-20\n'
        'owner = "infra"\nticket = "OPS-1"\n\n'
        '[[accept]]\ncheck = "AD-KRB-002"\nreason = "gone"\nexpires = 2027-06-01\n'
    )
    snap = snapshot(computer("WS9", laps=False))
    kept, accepted, notes = accept.apply(run_all(snap), accept.load(path), NOW.date())
    assert kept == [] and accepted[0].objects == ["WS9$"]
    assert notes == [
        "acceptance of AD-SEC-001 expires on 2026-11-20 (infra, OPS-1)",
        "acceptance of AD-KRB-002 matches no finding any more (stale)",
    ]


def test_redact_is_stable_and_keeps_findings() -> None:
    snap = path_snapshot()
    data = snap.to_json()
    a = redact.redact(json.loads(json.dumps(data)), b"k1")
    b = redact.redact(json.loads(json.dumps(data)), b"k1")
    c = redact.redact(json.loads(json.dumps(data)), b"k2")
    assert a == b and a != c
    text = json.dumps(a)
    for secret in ("helpdesk", "adm_bob", "lab.test", "DC=lab", DOMAIN_SID + "-"):
        assert secret.lower() not in text.lower()
    assert "Domain Admins" in text  # built-in names stay readable
    redacted = Snapshot.from_json(a)
    before = {f.check_id: len(f.objects) for f in run_all(snap)}
    after = {f.check_id: len(f.objects) for f in run_all(redacted)}
    assert before == after


def test_redact_cli_needs_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, dst = tmp_path / "s.json", tmp_path / "r.json"
    src.write_text(json.dumps(path_snapshot().to_json()))
    monkeypatch.delenv("AD_DOCTOR_REDACT_KEY", raising=False)
    assert main(["redact", str(src), "-o", str(dst)]) == 1
    monkeypatch.setenv("AD_DOCTOR_REDACT_KEY", "secret")
    assert main(["redact", str(src), "-o", str(dst)]) == 0
    assert json.loads(dst.read_text())["redacted"] is True


def test_junit() -> None:
    snap = snapshot(user("legacy", NORMAL | UAC.DONT_REQ_PREAUTH))
    r = Report(snap, run_all(snap))
    root = ElementTree.fromstring(render_junit(r, ["AD-KRB-002", "AD-KRB-001"]))
    assert root.attrib["tests"] == "2" and root.attrib["failures"] == "1"
    failed = [c for c in root if c.find("failure") is not None]
    assert failed[0].attrib["name"].startswith("AD-KRB-002")


def test_fingerprints_in_json(tmp_path: Path) -> None:
    snap_path, out = tmp_path / "s.json", tmp_path / "r.json"
    snap = snapshot(user("legacy", NORMAL | UAC.DONT_REQ_PREAUTH))
    snap_path.write_text(json.dumps(snap.to_json()))
    assert main(["analyze", str(snap_path), "-f", "json", "-o", str(out)]) == 0
    f = json.loads(out.read_text())["findings"][0]
    assert len(f["fingerprints"]["legacy"]) == 16


def test_snapshot_roundtrip_with_new_fields() -> None:
    snap = snapshot(
        objects=[DirObject("CN=X,DC=lab", "X", "group", sid=DA, owner=DA, aces=[Ace(DA, 1)])],
        gpo_settings={
            "{G}": GpoSettings(lm_compatibility=2, privileges={"SeDebugPrivilege": ["S-1-5-11"]})
        },
        gmsas=[Gmsa("g$", "CN=g,DC=lab,DC=test", [DA])],
        rodcs=[Rodc("R$", ["a"], ["b"])],
        probes=Probes(spooler_on_dc=True, web_enrollment_ntlm=["http://x/certsrv/"]),
        backup_checked=True,
        last_backup=NOW,
    )  # fmt: skip
    assert Snapshot.from_json(json.loads(json.dumps(snap.to_json()))) == snap
