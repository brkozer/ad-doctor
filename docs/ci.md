# CI integration

```yaml
- run: uvx --from git+https://github.com/brkozer/ad-doctor ad-doctor scan "$DC" --ldaps -u "$AD_USER" -f sarif -o ad.sarif --baseline last.json --fail-on high
  env: { AD_DOCTOR_PASSWORD: "${{ secrets.AD_PASSWORD }}" }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: ad.sarif }
```

Each SARIF rule carries the check's summary as `fullDescription`, its remediation and
references as `help.markdown`, and a `helpUri` to its [catalog page](checks/index.md), so
GitHub code-scanning alerts show the full explanation even for rules that did not fire. The
JUnit format writes one test case per check (failed when it found something, skipped when
accepted) and the Markdown and HTML reports link each finding to its docs page.

## Exit codes and `--fail-on`

`ad-doctor` exits `0` when it ran, `2` when `--fail-on high|medium|low` is set and a finding
at or above that severity exists, and `1` on an error. Pair it with a baseline so a job
fails only on regressions.

## Baselines

`--baseline FILE` marks findings missing from an earlier report or snapshot as new, by a
stable `(check, object)` fingerprint; `--fail-on` then considers only those new findings. A
scheduled scan can therefore stay green until something changes.

```bash
ad-doctor scan "$DC" --ldaps -u "$AD_USER" --baseline last.json --fail-on high
ad-doctor diff 2026-10.json 2026-11.json       # or compare two saved runs directly
```

## Accepted risks

Risks you have reviewed and chosen to keep go in a file passed with `--accept`. Each entry
needs a check ID, a reason and an expiry; leave out `objects` to accept the whole check.

```toml
[[accept]]
check = "AD-KRB-003"
objects = ["svc_backup"]
reason = "Backup appliance cannot use a gMSA; 32-character password, rotation ticket OPS-1182"
expires = 2027-03-31
```

Expired acceptances turn back into findings, acceptances that no longer match anything are
reported as stale, and the ones expiring within 30 days are listed. Every check page links
here, because accepting a risk is the documented alternative to fixing it.
