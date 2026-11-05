"""Severity gate: no check may emit a severity its catalog entry does not list.

A session-scoped autouse fixture wraps the three `_finding` helpers (checks, paths'
imported copy, and invariants' own) so that every finding produced anywhere in the suite
is recorded. At the end of the session, any (check, severity) pair that is not in the
entry's `severities` fails the run. This catches a check whose code can emit, say, HIGH
while the catalog only documents MEDIUM.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from ad_doctor import catalog, checks, invariants, paths
from ad_doctor.model import Finding

_emitted: set[tuple[str, str]] = set()


def _wrap(module: Any, name: str) -> Any:
    original = getattr(module, name)

    def wrapper(*args: Any, **kwargs: Any) -> Finding:
        f = original(*args, **kwargs)
        _emitted.add((f.check_id, str(f.severity)))
        return f

    return original, wrapper


@pytest.fixture(scope="session", autouse=True)
def _record_severities() -> Iterator[None]:
    # paths.py imports _finding by name, and invariants.py defines its own, so patch all three
    targets = [(checks, "_finding"), (paths, "_finding"), (invariants, "_finding")]
    saved = []
    for module, name in targets:
        original, wrapper = _wrap(module, name)
        saved.append((module, name, original))
        setattr(module, name, wrapper)
    try:
        yield
    finally:
        for module, name, original in saved:
            setattr(module, name, original)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    cat = catalog.load()
    undocumented = sorted(
        f"{cid} emitted {sev} (catalog lists {list(cat[cid].severities)})"
        for cid, sev in _emitted
        if cid in cat and sev not in cat[cid].severities
    )
    if undocumented:
        raise pytest.UsageError(
            "a check emitted a severity its catalog entry does not list:\n  "
            + "\n  ".join(undocumented)
        )
