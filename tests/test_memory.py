"""Memory shape of the snapshot types: a large domain holds hundreds of thousands of them."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ad_doctor import cli, opengraph, sd
from ad_doctor.model import Account, DirObject, KeyCredential, Snapshot, _encode
from ad_doctor.sd import Ace
from tests.test_checks import snapshot, user
from tests.test_round3 import path_snapshot


def test_bulk_types_have_no_instance_dict() -> None:
    # from 30 attributes on, CPython stops sharing dict keys: over 1 KB more per account
    for item in (Account("CN=a", "a", 0), DirObject("CN=g", "g", "group"), Ace("S-1-5-11", 1)):
        assert not hasattr(item, "__dict__")


def _rich_snapshot() -> Snapshot:
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    a = user("a", sid="S-1-5-21-1-2-3-1000")
    a.pwd_changed = when
    a.key_credentials = [KeyCredential(parsed=True, device_id="d", created=when, added=when)]
    group = DirObject(
        "CN=g,DC=lab,DC=test", "g", "group", sid="S-1-5-21-1-2-3-1100",
        aces=[Ace("S-1-5-11", sd.GENERIC_ALL, sd.MEMBER)], members=[a.dn],
    )  # fmt: skip
    return snapshot(a, objects=[group], privileged={"Domain Admins": [a.dn]})


def _without_default_inherited(value: Any) -> Any:
    """asdict's output as the snapshot writes it: an ACE holds `inherited` only when
    it is set, an account `rbcd_principals` only when the attribute is."""
    if isinstance(value, dict):
        out = {k: _without_default_inherited(v) for k, v in value.items()}
        if "mask" in out and out.get("inherited") is False:
            del out["inherited"]
        if out.get("rbcd_principals", "") is None and not out.get("rbcd"):
            del out["rbcd_principals"]
        return out
    if isinstance(value, list):
        return [_without_default_inherited(v) for v in value]
    return value


def test_to_json_is_what_asdict_gave() -> None:
    snap = _rich_snapshot()
    snap.objects[0].aces.append(Ace("S-1-5-11", sd.WRITE_DAC, inherited=True))
    expected = _without_default_inherited(_encode(asdict(snap)))
    assert snap.to_json() == expected
    assert list(snap.to_json()) == list(expected)
    aces = snap.to_json()["objects"][0]["aces"]
    assert "inherited" not in aces[0] and aces[1]["inherited"] is True
    assert Snapshot.from_json(json.loads(json.dumps(snap.to_json()))) == snap


def test_load_shares_equal_aces_and_member_dns() -> None:
    data = json.loads(json.dumps(_rich_snapshot().to_json()))
    obj = data["objects"][0]
    obj["aces"].append(dict(obj["aces"][0]))
    obj["inheritable"].append(dict(obj["aces"][0]))
    obj["members"].append("CN=gone,DC=lab,DC=test")
    # json.loads never shares strings; a separate copy is what a real file gives
    obj["members"][0] = "".join(list(obj["members"][0]))
    snap = Snapshot.from_json(data)
    o = snap.objects[0]
    assert o.aces[0] is o.aces[1] is o.inheritable[0]
    assert o.members[0] is next(a.dn for a in snap.accounts if a.sam == "a")
    assert o.members[1] == "CN=gone,DC=lab,DC=test"


def test_load_keeps_a_group_with_no_member_key() -> None:
    data = json.loads(json.dumps(_rich_snapshot().to_json()))
    del data["objects"][0]["members"]
    assert Snapshot.from_json(data).objects[0].members == []


def test_opengraph_shared_dicts_give_the_right_edges() -> None:
    payload: dict[str, Any] = json.loads(json.dumps(opengraph.export(path_snapshot())))
    edges = payload["graph"]["edges"]
    assert edges
    for e in edges:
        assert set(e) == {"kind", "start", "end", "properties"}
        assert e["start"]["match_by"] == e["end"]["match_by"] == "id"
        assert e["start"]["value"] != e["end"]["value"]
        assert e["properties"]["traversable"] in (True, False)


def test_export_graph_writes_what_dumps_gave(tmp_path: Path) -> None:
    snapshot_file, out = tmp_path / "snap.json", tmp_path / "graph.json"
    snap = path_snapshot()
    snapshot_file.write_text(json.dumps(snap.to_json()), encoding="utf-8")
    assert cli.main(["export-graph", str(snapshot_file), "-o", str(out)]) == 0
    expected = json.dumps(opengraph.export(Snapshot.from_json(snap.to_json())), indent=1)
    assert out.read_text(encoding="utf-8") == expected
