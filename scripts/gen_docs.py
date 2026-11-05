"""Generate the check pages of the documentation site from the catalog.

    uv run python scripts/gen_docs.py                  # docs/checks/*.md and docs/changelog.md
    uv run python scripts/gen_docs.py --allow-missing  # stub pages for undocumented checks
    uv run zensical build --strict                     # then build the site into site/

The output is not committed (see .gitignore); CI runs this before every docs build and
fails when a registered check has no catalog entry.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from ad_doctor import catalog, docgen, explain

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "checks"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--allow-missing", action="store_true", help="stub undocumented checks")
    args = p.parse_args()
    cat = catalog.load()
    checks = explain.titles()

    missing = [cid for cid in checks if cid not in cat]
    if missing and not args.allow_missing:
        print(f"no catalog entry for: {', '.join(missing)}", file=sys.stderr)
        return 1
    if orphans := sorted(cat.keys() - checks.keys()):
        print(f"catalog entries without a check: {', '.join(orphans)}", file=sys.stderr)
        return 1

    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    rows = []
    for cid, title in checks.items():
        e = cat.get(cid)
        page = docgen.check_page(e, title) if e else docgen.stub_page(cid, title)
        (OUT / f"{cid}.md").write_text(page, encoding="utf-8")
        rows.append((cid, title, e.severities if e else (), e.summary if e else ""))
    (OUT / "index.md").write_text(docgen.index_page(rows), encoding="utf-8")
    shutil.copy(ROOT / "CHANGELOG.md", DOCS / "changelog.md")
    stubbed = f" ({len(missing)} stubs)" if missing else ""
    print(f"wrote {len(rows)} check pages to {OUT.relative_to(ROOT)}{stubbed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
