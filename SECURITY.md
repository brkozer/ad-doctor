# Security policy

## Reporting a vulnerability

Please report security problems in ad-doctor privately through
[GitHub's private vulnerability reporting](https://github.com/brkozer/ad-doctor/security/advisories/new),
not in a public issue. Include the version, the command you ran and what happened. You
should get an answer within a week.

Things that count as a vulnerability here:

- ad-doctor writing to the directory, or doing anything beyond the reads and probes
  listed below
- credentials or password material ending up in a snapshot, report, log or fix script
- `redact` leaving a name, SID, host name or address readable
- a crafted directory object or SYSVOL file that makes the scanner run code, hang or
  crash

A check that misses a misconfiguration, or reports one that is not there, is a bug, not a
vulnerability: please open a regular issue (there is a template for false positives).

## What ad-doctor does on the network

ad-doctor is read-only. It binds to LDAP with the account you give it and reads; it never
modifies an object. On top of that it makes these active, non-intrusive probes, all of
which `--no-probes` turns off:

| Probe | Against | What it does |
|---|---|---|
| LDAP signing | each DC, port 389 | an NTLM bind without signing (`--signing-probe-port 0` skips it) |
| LDAPS channel binding | each DC, port 636 | an NTLM bind without a channel binding token |
| SMB signing | each DC, port 445 | SMB negotiate, then a session as the scanning account |
| Print Spooler | each DC | opens the `spoolss` named pipe and closes it |
| Web enrollment (ESC8) | each enterprise CA, port 80 | one `GET /certsrv/` to read the authentication headers |
| SYSVOL | the scanned DC | reads GPO and script files (`--no-sysvol` skips it) |

`--single-dc` limits the DC probes to the DC being scanned.

## Handling the output

Snapshots and reports describe how to attack the domain they came from. Treat them like
the credentials of the scanning account:

- store them where only the people fixing the findings can read them
- use `ad-doctor redact` before attaching a snapshot to an issue or sending it anywhere
- the fix script runs every command with `-WhatIf`; read it before removing the guards

ad-doctor never stores password values: it records only that a password-bearing attribute
or a credential-looking line exists, and where.
