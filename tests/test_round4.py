"""Every-DC probes, Exchange and Entra Connect checks, BloodHound OpenGraph export."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from ad_doctor import invariants, opengraph, paths, redact, sd
from ad_doctor.checks import run_all
from ad_doctor.cli import main
from ad_doctor.collect import Collector, Target, _sync_host
from ad_doctor.model import UAC, DcProbe, DirObject, Probes, Snapshot
from ad_doctor.sd import Ace

from .test_acl_adcs import DOMAIN_SID
from .test_checks import computer, only, snapshot, user
from .test_round3 import HELPDESK, path_snapshot

EWP = f"{DOMAIN_SID}-1110"
ETS = f"{DOMAIN_SID}-1111"
DOMAIN_DN = "DC=lab,DC=test"


def found(snap: Snapshot) -> dict[str, Any]:
    return {f.check_id: f for f in run_all(snap)}


# --- every DC ----------------------------------------------------------------------------


def test_per_dc_probes_name_the_weak_dc() -> None:
    probes = Probes(
        smb_signing_required=True,
        dcs=[
            DcProbe("dc01.lab.test", ldap_signing_required=True, smb_signing_required=True),
            DcProbe("dc02.lab.test", ldap_signing_required=False, smb_signing_required=False,
                    spooler=True),
            DcProbe("dc03.lab.test", error="no SMB connection"),
        ],
    )  # fmt: skip
    f = found(snapshot(probes=probes, ldap_signing_required=True))
    assert f["AD-INF-008"].objects == ["dc02.lab.test"]
    assert "1 of 2 probed DCs" in f["AD-INF-008"].detail
    assert f["AD-INF-005"].objects == ["dc02.lab.test"]  # the scanned DC was fine
    assert f["AD-INF-009"].objects == ["dc02.lab.test"]
    assert f["AD-INF-013"].objects == ["dc03.lab.test: no SMB connection"]
    assert probes.overall("ldap_signing_required", True) is False


def test_old_snapshots_fall_back_to_the_scanned_dc() -> None:
    f = found(snapshot(probes=Probes(smb_signing_required=False)))
    assert f["AD-INF-008"].objects == ["lab.test"]
    assert "AD-INF-013" not in f


def test_overall_needs_every_dc() -> None:
    probes = Probes(dcs=[DcProbe("a", ldap_signing_required=True), DcProbe("b")])
    assert probes.overall("ldap_signing_required", None) is None
    probes.dcs[1].ldap_signing_required = True
    assert probes.overall("ldap_signing_required", None) is True


def test_invariant_uses_every_dc(tmp_path: Path) -> None:
    spec = tmp_path / "inv.toml"
    spec.write_text("[settings]\nldap_signing_required = true\n")
    probes = Probes(dcs=[DcProbe("a", ldap_signing_required=True),
                         DcProbe("b", ldap_signing_required=False)])  # fmt: skip
    snap = snapshot(probes=probes, ldap_signing_required=True)
    assert [f.check_id for f in invariants.evaluate(snap, invariants.load(spec))] == ["AD-INV-003"]


def test_collector_probes_each_dc(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, int]] = []

    def smb(host: str, port: int, *a: object) -> tuple[bool, bool]:
        calls.append(("smb", host, port))
        return host != "dc02.lab.test", False

    def signing(self: Collector, host: str, port: int) -> tuple[bool, None]:
        calls.append(("ldap", host, port))
        return True, None

    monkeypatch.setattr("ad_doctor.probes.smb_posture", smb)
    monkeypatch.setattr(Collector, "_probe_signing", signing)
    target = Target("127.0.0.1", user="LAB\\scan", password="x", smb_port=10445,
                    plain_port=10389, http_port=0)  # fmt: skip
    collector = Collector(None, target)  # type: ignore[arg-type]
    dc1 = computer("DC01", 0x2000, dns_host="dc01.lab.test")
    dc2 = computer("DC02", 0x2000, dns_host="dc02.lab.test")
    off = computer("DC03", 0x2000 | UAC.ACCOUNTDISABLE, dns_host="dc03.lab.test")
    result = collector._probes("dc01.lab.test", [dc1, dc2, off])
    assert [d.name for d in result.dcs] == ["dc01.lab.test", "dc02.lab.test"]
    # the scanned DC through the given address and ports, the others by name on defaults
    assert ("smb", "127.0.0.1", 10445) in calls and ("ldap", "127.0.0.1", 10389) in calls
    assert ("smb", "dc02.lab.test", 445) in calls and ("ldap", "dc02.lab.test", 389) in calls
    assert result.smb_signing_required is True
    assert result.dcs[1].smb_signing_required is False
    assert collector.scanned_ldap_signing is True

    calls.clear()
    target.all_dcs = False
    assert len(collector._probes("dc01.lab.test", [dc1, dc2]).dcs) == 1


def test_snapshot_roundtrip_with_dc_probes() -> None:
    snap = snapshot(probes=Probes(dcs=[DcProbe("dc02.lab.test", spooler=True, error="x")]))
    assert Snapshot.from_json(json.loads(json.dumps(snap.to_json()))) == snap


# --- Exchange --------------------------------------------------------------------------


def exchange_snapshot(inherit_only: bool = False) -> Snapshot:
    exch = computer("EXCH01", sid=f"{DOMAIN_SID}-1300")
    ets = DirObject(f"CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,"
                    f"{DOMAIN_DN}", "Exchange Trusted Subsystem", "group", sid=ETS,
                    members=[exch.dn])  # fmt: skip
    ewp = DirObject(f"CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,"
                    f"{DOMAIN_DN}", "Exchange Windows Permissions", "group", sid=EWP,
                    members=[ets.dn])  # fmt: skip
    head = DirObject(DOMAIN_DN, "lab.test", "domain")
    acls: dict[str, list[Ace]] = {"domain": []}
    if inherit_only:
        head.inheritable = [Ace(EWP, sd.WRITE_DAC)]
    else:
        acls["domain"] = [Ace(EWP, sd.WRITE_DAC)]
        head.aces = [Ace(EWP, sd.WRITE_DAC)]
    return snapshot(exch, objects=[ets, ewp, head], acls=acls)


def test_privexchange_direct() -> None:
    snap = exchange_snapshot()
    f = only(snap, "AD-ACL-007")
    assert f.severity.name == "HIGH"
    assert f.objects == ["Exchange Windows Permissions: WriteDacl on the domain object"]
    assert "EXCH01$" in f.detail
    # the control-path engine follows the server into the domain
    g = paths.build(snap)
    reach = paths.paths_to_tier0(g)
    chain = reach[f"sid:{DOMAIN_SID}-1300"].render(g)
    assert chain == (
        "EXCH01$ -[member of]-> Exchange Trusted Subsystem -[member of]-> "
        "Exchange Windows Permissions -[full control]-> lab.test"
    )


def test_privexchange_fixed_by_inherit_only() -> None:
    f = only(exchange_snapshot(inherit_only=True), "AD-ACL-007")
    assert f.severity.name == "MEDIUM"
    assert "inherited by users and groups" in f.objects[0]


def test_no_exchange_no_finding() -> None:
    assert "AD-ACL-007" not in found(snapshot())


# --- Entra Connect ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sam", "description", "expected"),
    [
        ("MSOL_0123456789ab", "Account created by Microsoft Azure Active Directory Connect "
         "with installation identifier abc running on computer ENTRA01 configured to "
         "synchronize to tenant example.onmicrosoft.com.", "ENTRA01"),
        ("MSOL_0123456789ab", "", "unknown server"),
        ("Sync_AADC02_0123456789ab", "", "AADC02"),
        ("msol_admin", "running on computer X", None),
        ("alice", "", None),
    ],
)  # fmt: skip
def test_sync_host(sam: str, description: str, expected: str | None) -> None:
    assert _sync_host(sam, description) == expected


def entra_snapshot(dcsync: bool = True, helpdesk_reset: bool = False) -> Snapshot:
    msol = user("MSOL_0123456789ab", sid=f"{DOMAIN_SID}-1400", sync_host="ENTRA01")
    server = computer("ENTRA01", sid=f"{DOMAIN_SID}-1401", laps=False)
    obj = DirObject(msol.dn, msol.sam, "user", sid=msol.sid, owner=f"{DOMAIN_SID}-512")
    if helpdesk_reset:
        obj.aces = [Ace(HELPDESK, sd.CONTROL_ACCESS, sd.RESET_PASSWORD)]
    aces = []
    if dcsync:
        aces = [Ace(msol.sid, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES),
                Ace(msol.sid, sd.CONTROL_ACCESS, sd.DS_REPL_GET_CHANGES_ALL)]  # fmt: skip
    head = DirObject(DOMAIN_DN, "lab.test", "domain", aces=list(aces))
    return snapshot(
        msol, server, user("helpdesk", sid=HELPDESK),
        acls={"domain": aces}, objects=[obj, head], principals={HELPDESK: "helpdesk"},
    )  # fmt: skip


def test_entra_connect_server_not_tier0() -> None:
    f = only(entra_snapshot(), "AD-PRIV-011")
    assert f.objects == ["MSOL_0123456789ab on ENTRA01: not in a tier-0 group, no LAPS"]
    assert "AD-ACL-008" not in found(entra_snapshot())


def test_entra_connect_control() -> None:
    snap = entra_snapshot(helpdesk_reset=True)
    f = only(snap, "AD-ACL-008")
    assert f.objects == ["MSOL_0123456789ab (sync account): helpdesk (reset password)"]
    path = only(snap, "AD-PATH-001").objects
    assert "helpdesk -[reset password]-> MSOL_0123456789ab -[DCSync]-> lab.test" in path


def test_entra_connect_without_replication_rights_is_quiet() -> None:
    f = found(entra_snapshot(dcsync=False, helpdesk_reset=True))
    assert not {"AD-PRIV-011", "AD-ACL-008"} & f.keys()


def test_redact_covers_sync_hosts_and_dc_names() -> None:
    snap = entra_snapshot()
    snap.probes = Probes(dcs=[DcProbe("dc02.lab.test", smb_signing_required=False)])
    text = json.dumps(redact.redact(snap.to_json(), b"k"))
    assert "entra01" not in text.lower() and "dc02" not in text.lower()


# --- OpenGraph ---------------------------------------------------------------------------


KIND = re.compile(r"^[A-Za-z0-9_]+$")


def _primitive(v: object) -> bool:
    if isinstance(v, list):
        return all(isinstance(x, str | int | float | bool) for x in v)
    return isinstance(v, str | int | float | bool)


def test_opengraph_payload_is_valid() -> None:
    snap = path_snapshot()
    payload = opengraph.export(snap)
    assert payload["metadata"] == {"source_kind": "ADDoctor"}
    nodes, edges = payload["graph"]["nodes"], payload["graph"]["edges"]
    ids = {n["id"] for n in nodes}
    assert len(ids) == len(nodes)
    for n in nodes:
        assert ":" not in n["id"] and 1 <= len(n["kinds"]) <= 3
        assert all(k.startswith("ADD_") for k in n["kinds"])
        assert "objectid" not in n["properties"]
        assert all(_primitive(v) for v in n["properties"].values())
    for e in edges:
        assert KIND.match(e["kind"]) and e["kind"].startswith("ADD_")
        assert e["start"]["value"] in ids and e["end"]["value"] in ids
    # principals keep their SID so they merge with SharpHound's nodes
    assert HELPDESK in ids
    by_id = {n["id"]: n for n in nodes}
    assert by_id[HELPDESK]["properties"]["pathtotier0"] is True
    assert by_id[f"{DOMAIN_SID}-512"]["properties"]["tier0"] is True
    kinds = {(e["start"]["value"], e["kind"]) for e in edges}
    assert (HELPDESK, "ADD_FullControl") in kinds


def test_opengraph_well_known_and_split_labels() -> None:
    assert opengraph.node_id(path_snapshot(), "sid:S-1-5-11") == "LAB.TEST-S-1-5-11"
    assert opengraph.edge_kinds("write members, add self (inherited)") == [
        ("ADD_WriteMembers", True),
        ("ADD_AddSelf", True),
    ]
    assert opengraph.edge_kinds("write/WriteDacl/WriteOwner") == [("ADD_WriteDaclOwner", False)]
    assert opengraph.edge_kinds("linked to Domain Controllers OU") == [("ADD_GPLink", False)]


def test_opengraph_paths_only_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap = path_snapshot()
    full = opengraph.export(snap)
    trimmed = opengraph.export(snap, paths_only=True)
    assert len(trimmed["graph"]["edges"]) <= len(full["graph"]["edges"])
    outsider = next(a.sid for a in snap.accounts if a.sam == "outsider")
    g = paths.build(snap)
    assert all(e["start"]["value"] != outsider for e in trimmed["graph"]["edges"])
    assert g.tier0
    src, out = tmp_path / "s.json", tmp_path / "g.json"
    src.write_text(json.dumps(snap.to_json()))
    assert main(["export-graph", str(src), "-o", str(out), "--paths-only"]) == 0
    assert json.loads(out.read_text())["graph"]["edges"]
    assert "edges" in capsys.readouterr().out


def test_entra_connect_ignores_key_admins_default() -> None:
    snap = entra_snapshot()
    key_admins = f"{DOMAIN_SID}-526"
    for o in snap.objects:
        o.aces.append(Ace(key_admins, sd.WRITE_PROPERTY, sd.KEY_CREDENTIAL_LINK))
    assert "AD-ACL-008" not in found(snap)


def test_containment_handles_escaped_commas() -> None:
    ou = DirObject("OU=Smith\\, J,DC=lab,DC=test", "Smith, J", "ou",
                   inheritable=[Ace(HELPDESK, sd.GENERIC_ALL)])  # fmt: skip
    victim = user("victim", sid=f"{DOMAIN_SID}-1600")
    victim.dn = f"CN=victim,{ou.dn}"
    g = paths.build(snapshot(victim, objects=[ou]))
    assert (f"sid:{victim.sid}", "contains") in g.edges[f"dn:{ou.dn.lower()}"]
    assert (f"sid:{victim.sid}", "full control (inherited)") in g.edges[f"sid:{HELPDESK}"]
