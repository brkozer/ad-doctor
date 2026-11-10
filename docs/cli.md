---
title: Command line
---

# Command line

Every command and option. The [quick start](quickstart.md) walks through a first scan,
and `ad-doctor COMMAND --help` lists the options of one command.

```bash
uv tool install ad-doctor        # or: pipx install ad-doctor; ad-doctor[kerberos] adds Kerberos

# scan (password from AD_DOCTOR_PASSWORD or a prompt)
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor'

# HTML report and a reviewable remediation script
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor' -f html -o report.html --fixes fix.ps1

# Kerberos from the current ticket cache (kinit first; use the DC's host name)
ad-doctor scan dc01.corp.example --ldaps -k

# collect once, analyze and compare offline
ad-doctor collect dc01.corp.example --ldaps -u 'CORP\auditor' -o 2026-11.json
ad-doctor analyze 2026-11.json -f markdown -o report.md --invariants invariants.toml
ad-doctor diff 2026-10.json 2026-11.json
ad-doctor blast-radius 2026-11.json helpdesk_jane
ad-doctor paths 2026-11.json --chokepoints        # where one change breaks the most paths
ad-doctor view 2026-11.json --baseline 2026-10.json --accept accept.toml --fixes --open
AD_DOCTOR_REDACT_KEY=... ad-doctor redact 2026-11.json -o shareable.json

# the control graph for BloodHound CE (File Ingest accepts OpenGraph JSON)
ad-doctor export-graph 2026-11.json -o graph.json --paths-only

# every domain of the forest, one snapshot and report each, then the forest-level view
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor' --forest -o forest-2026-11/
ad-doctor rollup --forest forest-2026-11/
```

| Option | |
|---|---|
| `-f text\|json\|markdown\|html\|sarif\|junit`, `-o FILE` | report format and destination |
| `--fail-on high\|medium\|low` | exit 2 when a finding at that severity exists |
| `--baseline FILE` | mark findings missing from an earlier report or snapshot as new; `--fail-on` then considers only those |
| `--accept FILE` | accepted risks (see [`examples/accept.toml`](https://github.com/brkozer/ad-doctor/blob/main/examples/accept.toml)) |
| `--invariants FILE` | declared state to enforce (see [`examples/invariants.toml`](https://github.com/brkozer/ad-doctor/blob/main/examples/invariants.toml)) |
| `--fixes FILE` | write the PowerShell remediation script |
| `--preflight FILE` | write a read-only PowerShell script to run before the fixes (first 10 fixes only) |
| `--only ID ...` | run a subset of checks (`ad-doctor checks` lists them) |
| `view FILE`, `--open` | write the offline HTML viewer from a snapshot or a JSON report (`--baseline`, `--accept`, `--invariants`, `--fixes` as above; `--history DIR` for the trend, `--graph auto\|full\|paths\|none` for blast radius, `--encrypt`/`--no-encrypt`) |
| `paths FILE --chokepoints` | list the control paths to tier 0, or rank the steps they share (`-f text\|json\|mermaid`) |
| `explain ID\|alias` | print a check's full explanation and fix offline (`-f text\|markdown\|json`, `--web`) |
| `-k`, `--kerberos` | bind with Kerberos instead of a password |
| `--no-sysvol`, `--smb-port` | skip or redirect the SMB part |
| `--no-probes`, `--http-port`, `--https-port` | skip every probe (LDAP signing, SMB, channel binding, enrollment, CA registry; SYSVOL has its own `--no-sysvol`), or move the web enrollment ports (0 skips one) |
| `--no-ca-registry` | skip reading CA settings (ESC6/7/11/16, audit filter) over `\pipe\winreg` |
| `--single-dc` | probe only the DC being scanned instead of every DC in the domain |
| `--dc-probes` | also probe each DC for WebClient, SMBv1 and the TLS versions of LDAPS; off by default |
| `--no-patch-level` | do not read each DC's and CA's build and UBR over `\pipe\winreg` |
| `rollup REPORT ...` | one view over the JSON reports of several domains (`-f text\|json\|markdown`) |
| `collect --forest`, `scan --forest`, `-o DIR` | every domain of the forest, one at a time: one snapshot and report per domain; exit 3 when part of the forest was not read, even if `--fail-on` matched ([forest scan](forest.md)). The credentials go to every DC named in the Configuration partition, and whoever can write those objects can receive them ([where the credentials go](forest.md#where-the-credentials-go)) |
| `--forest-allow-dns SUFFIX` | with `--forest`, send credentials only to DCs inside this DNS suffix, in place of the default rule that a DC lies inside its own domain's name (repeatable) |
| `--forest-ca-file PEM` | with `--forest --ldaps`, validate the certificate and name of every DC the directory named; without it `--ldaps` does not authenticate the server |
| `rollup --forest DIR` | the rollup of that run, plus who holds Enterprise Admins and Schema Admins and which domains were not read |
| `service-accounts FILE` | the service accounts of a snapshot (`-f text\|json`) |
| `tier-scorecard FILE` | counts about tier 0 from a snapshot, with no score (`-f text\|json`) |
| `--signing-probe-port PORT` | plain LDAP port for the signing probe; `0` skips it |

Parts that cannot run (no AD CS, SYSVOL unreachable, Kerberos without an NTLM account for
the signing probes) become notes in the report instead of failing the scan, and every
format shows each check as **judged**, **not applicable** (the snapshot proves the feature
is absent) or **not evaluated**, with the reason (data unreadable, older snapshot, switched
off). A check that was not evaluated never counts as passed: JUnit marks it skipped, a
finding it had before stays out of "resolved" and the risk score is then a minimum. Domain
controllers that require LDAP signing (the default on Windows Server 2025) reject plain
LDAP binds, so use `--ldaps`.

## In CI

```yaml
- run: uvx ad-doctor scan "$DC" --ldaps -u "$AD_USER" -f sarif -o ad.sarif --baseline last.json --fail-on high
  env: { AD_DOCTOR_PASSWORD: "${{ secrets.AD_PASSWORD }}" }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: ad.sarif }
```

The [CI page](ci.md) covers exit codes, baselines, accepted risks and check status in
CI.
