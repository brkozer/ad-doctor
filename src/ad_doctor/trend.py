"""History for the viewer's Trend screen (`ad-doctor view --history DIR`).

A history directory holds earlier JSON reports of the same domain, as `scan -f json` or
`analyze -f json` writes them (a CI job that keeps one per run builds it up). Each report
becomes one point: severity counts, score, category scores, tier-0 exposure, and the
ad-doctor version and check set, so the screen can mark the scans where the tool changed
rather than the domain. Other JSON files in the directory (snapshots) are skipped.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITIES = ("high", "medium", "low", "info")
# AD-PATH-001's detail before reports carried its data
_EXPOSURE = re.compile(r"(\d+) of (\d+) enabled users")


def point(data: dict[str, Any], name: str) -> dict[str, Any]:
    """One report as a trend point."""
    findings = data.get("findings", [])
    counts = Counter(str(f.get("severity")) for f in findings)
    out: dict[str, Any] = {
        "name": name,
        "at": data["collected_at"],
        "version": str(data.get("version", "")),
        "score": data.get("score", 0),
        "grade": data.get("grade", ""),
        "counts": {s: counts.get(s, 0) for s in SEVERITIES},
        "objects": sum(len(f.get("objects", [])) for f in findings),
        "categories": dict(data.get("category_scores", {})),
    }
    out.update(_exposure(data))
    checks = data.get("checks")
    out["checks"] = sorted(checks) if isinstance(checks, list) else None
    return out


def _exposure(data: dict[str, Any]) -> dict[str, Any]:
    """exposed and users from AD-PATH-001. A report without that finding has no control
    path to tier 0 (exposure 0, users unknown), unless the check did not run or the
    finding was accepted, in which case nothing is known."""
    f = next((f for f in data.get("findings", []) if f.get("id") == "AD-PATH-001"), None)
    if f is not None:
        d = f.get("data") or {}
        if isinstance(d.get("users"), int) and isinstance(d.get("exposed"), int):
            return {"exposed": d["exposed"], "users": d["users"]}
        m = _EXPOSURE.search(str(f.get("detail", "")))
        return {"exposed": int(m[1]), "users": int(m[2])} if m else {"exposed": None, "users": None}
    checks = data.get("checks")
    ran = not isinstance(checks, list) or "AD-PATH-001" in checks
    accepted = any(a.get("check_id") == "AD-PATH-001" for a in data.get("accepted", []))
    return {"exposed": 0 if ran and not accepted else None, "users": None}


def load(directory: Path, domain: str) -> list[dict[str, Any]]:
    """Every report in `directory` (not recursive), oldest first."""
    if not directory.is_dir():
        raise ValueError(f"--history {directory}: not a directory")
    points = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"--history: {path.name}: {exc}") from exc
        if not isinstance(data, dict) or data.get("tool") != "ad-doctor":
            continue  # a snapshot or something else kept alongside the reports
        if str(data.get("domain", "")).lower() != domain.lower():
            raise ValueError(
                f"--history: {path.name} is a report of {data.get('domain')!r}, not {domain!r}"
            )
        points.append(point(data, path.name))
    if not points:
        raise ValueError(
            f"--history {directory}: no ad-doctor JSON report in it (write them with -f json)"
        )
    points.sort(key=lambda p: p["at"])
    return points


def build(history: list[dict[str, Any]], current: dict[str, Any]) -> dict[str, Any]:
    """The Trend screen's data: the history plus this run, with markers where the
    ad-doctor version or the set of checks changed between two scans."""
    points = [p for p in history if p["at"] != current["at"]] + [current]
    points.sort(key=lambda p: p["at"])
    markers = []
    for i in range(1, len(points)):
        before, now = points[i - 1], points[i]
        notes = []
        if before["version"] != now["version"]:
            notes.append(f"ad-doctor {before['version']} → {now['version']}")
        if before["checks"] is not None and now["checks"] is not None:
            added = sorted(set(now["checks"]) - set(before["checks"]))
            removed = sorted(set(before["checks"]) - set(now["checks"]))
            if added or removed:
                parts = [f"+{len(added)}"] if added else []
                parts += [f"-{len(removed)}"] if removed else []
                notes.append(f"checks {' '.join(parts)}")
                if added:
                    notes.append("new: " + ", ".join(added[:6]) + (" …" if len(added) > 6 else ""))
        if notes:
            markers.append({"index": i, "notes": notes})
    categories = list(dict.fromkeys(c for p in points for c in p["categories"]))
    rows = []
    for p in points:
        row = {k: v for k, v in p.items() if k != "checks"}
        row["checks"] = len(p["checks"]) if p["checks"] is not None else None
        rows.append(row)
    return {"points": rows, "markers": markers, "categories": categories}
