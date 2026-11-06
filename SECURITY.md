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
- a viewer file that runs a directory name as markup or code, makes a network request,
  stores data in the browser, or reveals encrypted content without the passphrase

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
| HTTPS enrollment | each enterprise CA, port 443, and each URL in `msPKI-Enrollment-Servers` | one `GET` over TLS to read the authentication headers; no credentials are sent, the server certificate is not checked, and EPA is not determined (`--https-port 0` skips it). A URL that uses plain HTTP gets the same `GET` over HTTP |
| CA registry (ESC6/7/11/16, audit filter) | each enterprise CA, port 445 | reads the CA's configuration over `\pipe\winreg` (MS-RRP), `KEY_READ` only; `--no-ca-registry` skips it |
| SYSVOL | the scanned DC | reads GPO files (security templates, Group Policy Preferences, Restricted Groups and Local Groups) and scripts (`--no-sysvol` skips it) |

`--single-dc` limits the DC probes to the DC being scanned.

The CA registry probe opens `\pipe\winreg` on the CA host. On a host where the RemoteRegistry
service is set to start on demand, opening that pipe trigger-starts it: a visible change of
service state (System event 7036), plus an SMB logon (4624 type 3), and reads under
`CertSvc` may be audited if object-access auditing is on for that key. Remote registry
access to a CA is also the kind of activity EDR and Microsoft Defender for Identity may
alert on. It is still a read: nothing in the directory, the CA database or the registry is
modified. Use `--no-ca-registry` (or `--no-probes`) to skip it.

## Handling the output

Snapshots and reports describe how to attack the domain they came from. Treat them like
the credentials of the scanning account:

- store them where only the people fixing the findings can read them
- use `ad-doctor redact` before attaching a snapshot to an issue or sending it anywhere
- the fix script runs every command with `-WhatIf`; read it before removing the guards

ad-doctor never stores password values: it records only that a password-bearing attribute
or a credential-looking line exists, and where.

## The HTML viewer file

`ad-doctor view` (and `-f html`) writes one HTML file that is meant to be opened on
another machine and sometimes sent to someone. What it holds and how it is protected:

**What is in it.** The report (findings, objects, fingerprints, remediation), the control
paths to tier 0 and their chokepoints, and whatever the command line added: the baseline
diff, the acceptance and invariant state, earlier reports for the trend (`--history`), the
fix-script lines (`--fixes`) and the control graph (`--graph`). With `--graph full` that is
every principal and object with an edge, every control edge and every account's name and
SID: a map of who can take over what. `--graph paths` holds only the blast radius of the
principals on control paths and of the accounts named with `--blast-radius-for`. The raw
snapshot is never embedded, there is no option for it, and a redacted snapshot yields a
file with its pseudonyms only.

**Encryption.** A file that embeds graph data is encrypted by default; `--no-encrypt`
writes it in the clear and must be given explicitly. `scan -f html` and `analyze -f html`
embed no graph and are not encrypted. The payload is gzip-compressed, then encrypted with
AES-256-GCM (pycryptodome) under a key derived with PBKDF2-HMAC-SHA256, 600,000
iterations, a random 16-byte salt and a random 12-byte nonce; the page decrypts it with
WebCrypto. The passphrase comes from `AD_DOCTOR_VIEW_PASSPHRASE` or a prompt (entered
twice), must be at least 14 characters with at least 6 different ones, and is never
written to the file, the command line shown in it, or any log. The prompt offers a random
seven-word passphrase (63 bits, from a 512-word list and Python's `secrets`). `view`
removes `AD_DOCTOR_VIEW_PASSPHRASE` from its own environment once read, so a browser it
starts with `--open` does not inherit it. Readable before unlock: the ad-doctor version,
the build time, the KDF and cipher parameters, and the SHA-256 of the ciphertext. The
version, build time and parameters are the GCM additional data, so editing them makes
decryption fail. The SHA-256 is not (it is the hash of the ciphertext itself): the page
computes it from the data in the file, shows that, and refuses to unlock when it differs
from the recorded one; the size it shows is measured too. The GCM tag authenticates the
whole ciphertext. The domain name and every directory name are inside it.

**In the browser.** A meta Content-Security-Policy allows only the file's own inlined
script and style (by SHA-256), `connect-src 'none'`, no forms, frames or plugins, and
Trusted Types. The script never parses markup: directory names, which any user can choose
for a computer account, are written as text, and a Playwright test renders a domain whose
names are XSS payloads. Nothing is stored (no localStorage, IndexedDB, cookies or service
worker). In an encrypted file no directory name goes into the address bar: the blast
radius screen puts an index in the URL (`#blast?a=@3`), not the account, and the findings
search is not written to the URL, so the browser's history holds no names. **Lock** drops
the page's references to the decrypted data and reloads it. A dropped report for the
ad-hoc diff is read in the tab and kept in memory only; an acceptance draft is only
downloaded.

**Residual risks.** Once unlocked, the data is in the browser's memory like any page:

- browser extensions with access to file URLs can read the page, so open it in a clean
  browser profile without extensions, on a trusted workstation;
- the operating system can write that memory to swap or a hibernation file, and a crash
  dump can contain it; Lock and closing the tab end its use but JavaScript cannot wipe
  memory, so the decrypted data lingers until the browser reuses it;
- the passphrase protects the file against someone who copies it, not against a
  compromised machine that opens it; anyone with the passphrase and the file has the
  whole map;
- the file is a view, not evidence: anyone can edit HTML; the SHA-256 shows that the
  payload is the one written at build time, not who wrote it;
- in a file written with `--no-encrypt`, account names picked by hand in a link
  (`#blast?a=NAME`) or typed into the findings search do reach the URL and the history.

The CLI writes the file with mode 0600 on POSIX.
