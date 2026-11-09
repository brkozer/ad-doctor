# CI integration

```yaml
- run: uvx ad-doctor scan "$DC" --ldaps -u "$AD_USER" -f sarif -o ad.sarif --baseline last.json --fail-on high
  env: { AD_DOCTOR_PASSWORD: "${{ secrets.AD_PASSWORD }}" }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: ad.sarif }
```

Each SARIF rule carries the check's summary as `fullDescription`, its remediation and
references as `help.markdown`, and a `helpUri` to its [catalog page](checks/index.md), so
GitHub code-scanning alerts show the full explanation even for rules that did not fire. The
JUnit format writes one test case per check (failed when it found something, skipped when
accepted, not applicable or not evaluated) and the
Markdown report links each finding to its docs page; the HTML viewer links nowhere and shows
the URL as text to copy.

Collection notes are also in the machine formats: JUnit `system-out`, and SARIF
`invocations[0].toolConfigurationNotifications`, where a note about a check has the level
`warning` and lists the check IDs under `properties.notJudged`. A range such as
`AD-DNS-001 to AD-DNS-003` names every check in it. A note that names no check
(for example "SYSVOL not checked") still feeds the status of the checks it holds back.

## Check status

Every report says what it could judge. The JSON report carries it under `check_status`, one
entry per check, with `status` one of:

| Status | Meaning |
|---|---|
| `judged` | the check gave an answer; `outcome` is `finding`, `accepted` or `no_finding` |
| `not_applicable` | the snapshot proves there is nothing to judge: no AD CS, no trusts, no Windows Server 2025 DC for the dMSA checks |
| `not_evaluated` | no answer; `reason` is `unreadable`, `older_snapshot` or `switched_off`, and `notes` says why |

A check that found something stays `judged` even when a note says part of it could not be
read; it then has `partial: true`. `coverage` has the counts and `score_is_minimum`.

The status comes from the collection notes, so a snapshot from any version gets one, and from
a few values a probe leaves empty. A check with no answer never passes: the JUnit case is
skipped, SARIF has the status in the rule's `properties` and a
`toolExecutionNotifications` entry tied to the rule (never a result), the text and Markdown
reports and the viewer say the score is a minimum, and `diff`, `--baseline` and the
viewer's Changes screen keep its earlier findings out of "resolved". An acceptance of such a
check is not reported as stale, and the score is the sum of findings as always: nothing is
added for what was not judged, which is why it can only be a minimum.

The other direction works the same way: a finding of a check the *older* run did not evaluate
(a check newer than that version, or data it could not read) is listed as "not evaluated in the
older run", is not new and does not fail `--fail-on`, in `diff`, `--baseline` and the viewer.

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

## Several domains

`ad-doctor rollup` takes the JSON reports of several domains (`scan -f json` or
`analyze -f json`) and prints one row per domain and one per check that fired anywhere, with the
domains it fired in:

```bash
ad-doctor rollup reports/corp.json reports/child.json -f markdown -o rollup.md
```

Scores stay per domain and are never averaged. A check that did not run in a domain, or that a
note says could not judge everything, is listed as not judged there, not as clean. Older reports
of the same domain are ignored, with a note, and so a directory of monthly reports can be passed
as it is. A note says when reports come from different versions or ran different checks.

## Before you apply a fix

`--preflight FILE` on `scan` and `analyze` writes a PowerShell script for the first ten fixes
(AD-KRB-002, AD-KRB-004, AD-DEL-001 to 003, AD-ACC-001 to 005) that only reads: `Get-ADObject` for
each object, then `OK`, `WARN` or `STOP`. `STOP` means the object has changed since the snapshot,
or that the fix would touch a domain controller. Run it, read the warnings, then decide what to do
with the `--fixes` script, which still runs everything with `-WhatIf`.
