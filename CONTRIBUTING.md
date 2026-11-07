# Contributing

Thanks for helping. Bug reports, false positives and check ideas are as welcome as code.

## Reporting a false positive or a missed finding

Use the issue templates. The most useful thing you can attach is a redacted snapshot:

```bash
ad-doctor collect dc01.corp.example -u 'CORP\auditor' -o snap.json
AD_DOCTOR_REDACT_KEY='any secret' ad-doctor redact snap.json -o snap.redacted.json
```

Redaction replaces names, SIDs, host names and addresses with stable pseudonyms, so the
findings stay the same and nothing identifies your domain. Look through the file before
you attach it anyway.

## Development setup

```bash
git clone https://github.com/brkozer/ad-doctor && cd ad-doctor
uv sync
uv run pytest
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy src
```

CI runs the same four commands on Python 3.12 and 3.13.

The HTML viewer (`src/ad_doctor/viewer.py`, with its script and style in
`src/ad_doctor/viewer_assets/`) also has browser tests and Node tests. They need Node 20
or later and run in their own CI job:

```bash
cd tests/browser
npm ci && npx playwright install chromium
npm run fixtures       # builds xss.html, full.html, sealed.html with ad-doctor view
npx playwright test
node screenshots.mjs ../../report.html shots    # every screen, desktop and phone, light and dark

cd ../..
uv run python -m tests.viewer_fixtures parity tests/js/build   # Python's blast radius
node --test tests/js/*.test.mjs   # the page's graph search, TOML drafts and diff against it
```

`core.js` holds the parts of the page that compute (the blast-radius search, acceptance
drafts, the ad-hoc diff); it has no DOM access, and the Node tests load the same file.
`uv run pytest` also runs `node` for the acceptance-draft round trip when Node is installed.

The viewer's script must only ever write text: no `innerHTML` or other HTML sink, no
storage, no network (`tests/test_viewer.py` greps for them), and every attribute goes
through the allowlist in `h()`.

The unit tests build snapshots in memory and need no domain. `tests/test_lab.py` runs
against the seeded lab DC in [`lab/`](lab/README.md) and is skipped unless the
`AD_DOCTOR_LAB_*` variables are set.

The what-if tests compare the masked graph with one built from the changed snapshot for
every change of the fixtures. `AD_DOCTOR_WHATIF_SNAPSHOTS` (snapshot files, separated
like `PATH`) adds every single change and 200 random sets on each of those snapshots, and
`uv run pytest -m slow` runs the 10,000-user sample, which takes minutes.

## Adding a check

1. **Pick an ID** in the right area (`AD-ACL-009`, `AD-KRB-007`, ...). IDs are never
   reused or renumbered; users accept risks and set baselines by ID.
2. **Write the check** in `src/ad_doctor/checks.py` as a pure function of the snapshot,
   decorated with `@check(id, title)`. Return one finding that lists every affected object,
   or `None`. Its MITRE ATT&CK techniques go in the catalog entry (step 6), which is the
   only source of `checks.MITRE`.
3. **Collect what it needs** in `collect.py`, through `optional()` when the data may be
   missing or unreadable, so the scan goes on with a note instead of failing. New snapshot
   fields need defaults so that older snapshots still load.
4. **Feed the graph** if the misconfiguration gives control over something: add the edge
   in `paths.py` so attack paths and `blast-radius` see it.
5. **Test it**: at least one test where it fires, one where it stays quiet, and the
   default configuration must stay clean (`test_clean_domain_has_no_findings`). If the lab
   can reproduce it, seed it in `lab/seed.ps1` and assert it in `tests/test_lab.py`.
6. **Document it.** Add `src/ad_doctor/catalog/<ID>.toml` (copy an existing entry for the
   schema; the loader in `catalog/__init__.py` validates it). Add a row to the check table
   in the README, and a `-WhatIf` fix in `fixes.py` if the fix is a safe command.
   `tests/test_catalog.py` fails when a check has no entry, and the severity gate in
   `tests/conftest.py` fails the run when a test makes a check emit a severity its entry's
   `severities` does not list, so write a test for every grade. `uv run python
   scripts/gen_docs.py` regenerates the site pages and
   `uv run --group docs zensical build --strict` builds them.

Keep the finding text short and concrete: what an attacker can do, then how to fix it.

## Pull requests

- one change per pull request, with tests
- commit messages in the imperative (`feat: ...`, `fix: ...`, `docs: ...`)
- add a line to `CHANGELOG.md` under *Unreleased*

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
