"""The check catalog: complete, consistent with the code, valid, and in the wheel."""

from __future__ import annotations

import re

import pytest

from ad_doctor import catalog, checks
from ad_doctor.checks import MITRE, REGISTRY
from ad_doctor.cli import main
from ad_doctor.explain import titles
from ad_doctor.model import Severity

ALL_IDS = set(titles())  # REGISTRY (incl. AD-PATH-001) + AD-INV-*
CAT = catalog.load()


def test_every_check_has_an_entry() -> None:
    missing = sorted(ALL_IDS - CAT.keys())
    assert not missing, f"checks without a catalog entry: {', '.join(missing)}"


def test_no_entry_without_a_check() -> None:
    orphans = sorted(CAT.keys() - ALL_IDS)
    assert not orphans, f"catalog entry for an unknown or removed check: {', '.join(orphans)}"


@pytest.mark.parametrize("check_id", sorted(CAT))
def test_entry_is_consistent(check_id: str) -> None:
    e = CAT[check_id]
    # the loader validates the schema; re-assert the cross-entry rules here
    assert set(e.related) <= ALL_IDS, "related points at a check that does not exist"
    assert check_id not in e.related, "a check cannot be related to itself"
    assert len(e.summary) <= catalog.SUMMARY_MAX
    assert len({r.url for r in e.references}) == len(e.references), "duplicate reference URL"
    assert all(r.url.startswith("https://") for r in e.references), "reference URLs must be https"
    assert not any("attack.mitre.org" in r.url for r in e.references), "MITRE links are generated"
    for section in (e.risk, e.detection, e.remediation, e.false_positives, e.severity_logic):
        assert "TODO" not in section, "unfinished section"
    # a TOML basic string needs "\\" for one backslash; "\\\\" shows two in the docs
    for value in e.attributes:
        assert "\\\\" not in value, f"doubled backslash in attribute {value!r}"
    for t in e.mitre:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", t), f"not an ATT&CK technique ID: {t}"


def test_findings_carry_the_catalog_techniques() -> None:
    """The catalog is the only source of MITRE mappings: checks.MITRE and every finding
    take theirs from it."""
    assert dict(MITRE) == {cid: e.mitre for cid, e in CAT.items() if e.mitre}
    registered = {c.id for c in REGISTRY}
    for cid, e in CAT.items():
        if cid in registered:
            # a severity the entry lists, so the conftest severity gate stays quiet
            severity = next(s for s in Severity if str(s) == e.severities[0])
            f = checks._finding(cid, severity, "", "", [])
            assert tuple(f.mitre) == e.mitre, cid


def test_aliases_are_unique() -> None:
    seen: dict[str, str] = {}
    for e in CAT.values():
        for a in e.aliases:
            assert a not in seen, f"alias {a!r} used by {seen[a]} and {e.id}"
            assert a.upper() not in CAT, f"alias {a!r} shadows a check ID"
            seen[a] = e.id


def test_registered_ids_have_a_known_category() -> None:
    from ad_doctor.model import CATEGORIES

    for cid in ALL_IDS:
        assert cid.split("-")[1] in CATEGORIES


def test_explain_by_id_and_alias(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["explain", "esc1"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("AD-ADCS-001")
    assert "https://attack.mitre.org/techniques/T1649/" in out
    assert main(["explain", "AD-ADCS-001"]) == 0
    assert main(["explain", "AD-NOPE-999"]) == 1
    err = capsys.readouterr().err
    assert "not a check ID or alias" in err


def test_explain_formats() -> None:
    e = catalog.find("esc1")
    assert e is not None
    from ad_doctor import explain

    assert "# AD-ADCS-001" in explain.render_markdown(e)
    import json

    data = json.loads(explain.render_json(e))
    assert data["id"] == "AD-ADCS-001" and data["url"] == e.url


def test_sarif_rules_link_to_the_docs() -> None:
    import json

    from ad_doctor.report import Report, render_sarif
    from tests.test_checks import snapshot

    rules = json.loads(render_sarif(Report(snapshot(), [])))["runs"][0]["tool"]["driver"]["rules"]
    documented = {r["id"]: r for r in rules if r["id"] in CAT}
    assert documented, "no documented rule in the SARIF output"
    for cid, rule in documented.items():
        assert rule["helpUri"] == CAT[cid].url
        assert rule["fullDescription"]["text"]
        assert rule["help"]["markdown"] and rule["help"]["text"]


def test_catalog_ships_in_the_wheel() -> None:
    """importlib.resources must find the TOML files (they are packaged, not just on disk)."""
    from importlib import resources

    names = {f.name for f in resources.files("ad_doctor.catalog").iterdir()}
    assert "AD-ADCS-001.toml" in names
    assert sum(n.endswith(".toml") for n in names) == len(CAT)
