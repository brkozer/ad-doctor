# Quick start

```bash
uv tool install ad-doctor   # or: pipx install ad-doctor; ad-doctor[kerberos] adds Kerberos
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor'
```

The password comes from `AD_DOCTOR_PASSWORD` or a prompt. Domain controllers that require
LDAP signing (the default on Windows Server 2025) reject plain LDAP binds, so use `--ldaps`.
An enabled domain user is enough; see [permissions](permissions.md).

## A report you can hand over

```bash
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor' -f html -o report.html --fixes fix.ps1
```

`-f` chooses the format (`text`, `json`, `markdown`, `html`, `sarif`, `junit`) and `-o`
the file. The HTML report is the [offline viewer](viewer.md): one file with no network
access that names each finding's page in the [check catalog](checks/index.md);
`ad-doctor view` builds it with a baseline, a trend, acceptances, fix lines and the
control graph for blast radius (encrypted with a passphrase by default). The fix script runs
every change with `-WhatIf`. The same
explanation is available offline for any check:

```bash
ad-doctor explain AD-ADCS-001      # or by alias: ad-doctor explain esc1
ad-doctor explain AD-KRB-003 -f markdown
ad-doctor checks                   # list every check
```

## Collect once, analyze and compare offline

```bash
ad-doctor collect dc01.corp.example --ldaps -u 'CORP\auditor' -o 2026-11.json
ad-doctor analyze 2026-11.json -f markdown -o report.md --invariants invariants.toml
ad-doctor diff 2026-10.json 2026-11.json
ad-doctor blast-radius 2026-11.json helpdesk_jane
```

## Kerberos instead of a password

```bash
kinit auditor@CORP.EXAMPLE
ad-doctor scan dc01.corp.example --ldaps -k
```

## Common options

| Option | |
|---|---|
| `-f`, `-o FILE` | report format and destination |
| `--fail-on high\|medium\|low` | exit 2 when a finding at that severity exists |
| `--baseline FILE` | mark findings missing from an earlier run as new; `--fail-on` then considers only those |
| `--accept FILE` | [accepted risks](ci.md#accepted-risks) |
| `--invariants FILE` | [declared state](invariants.md) to enforce |
| `--fixes FILE` | write the PowerShell remediation script |
| `--only ID ...` | run a subset of checks |
| `-k`, `--kerberos` | bind with Kerberos instead of a password |
| `--no-sysvol`, `--no-probes` | skip the SYSVOL read, or every other [probe](probes.md) |
| `--no-ca-registry` | skip reading CA settings (ESC6/7/11/16, audit filter) over `\pipe\winreg` |
| `--single-dc` | probe only the DC being scanned |

Parts that cannot run (no AD CS, SYSVOL unreachable) become notes in the report rather than
failing the scan.
