# Snapshots and redaction

A snapshot is the whole directory read in one pass, saved as JSON. Collecting once and
analyzing offline keeps the heavy LDAP work separate from the fast, network-free checks, and
lets you compare runs over time.

```bash
ad-doctor collect dc01.corp.example --ldaps -u 'CORP\auditor' -o 2026-11.json
ad-doctor analyze 2026-11.json -f html -o report.html
ad-doctor diff 2026-10.json 2026-11.json
```

`analyze` takes the same reporting options as `scan` (`-f`, `-o`, `--accept`,
`--invariants`, `--fixes`, `--baseline`, `--fail-on`). Snapshots carry a schema version, so
an older snapshot still loads after an upgrade (new fields fall back to defaults).

## Handling snapshots and reports

A snapshot or report describes how to attack the domain it came from, so treat it like the
scanning account's credentials:

- store it where only the people fixing the findings can read it
- on POSIX, the files ad-doctor writes (`collect -o`, `analyze`/`scan -o`, `redact -o`,
  `--fixes`) are created mode `0600`
- ad-doctor never stores password values: it records only that a password-bearing attribute
  or a credential-looking line exists, and where

## Redaction

Before a snapshot leaves your hands &mdash; attached to a bug report, sent to a consultant
&mdash; redact it:

```bash
AD_DOCTOR_REDACT_KEY='any secret' ad-doctor redact 2026-11.json -o shareable.json
```

Redaction replaces names, DNs, host names, addresses and the domain SID with stable
pseudonyms derived from a keyed HMAC. The same input maps to the same pseudonym, so the
findings and attack paths are identical on the redacted snapshot, but nothing identifies the
domain. Look through the file before you send it anyway.
