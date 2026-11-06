# Network probes

On top of the LDAP reads, ad-doctor makes a few active, read-only probes. Each is one
connection per target and nothing is written. `--no-probes` turns off all of them except
SYSVOL, which has `--no-sysvol`.

| Probe | Against | What it does |
|---|---|---|
| LDAP signing | each DC, port 389 | an NTLM bind without signing (`--signing-probe-port 0` skips it) |
| LDAPS channel binding | each DC, port 636 | an NTLM bind without a channel-binding token |
| SMB signing | each DC, port 445 | SMB negotiate, then a session as the scanning account |
| Print Spooler | each DC | opens the `spoolss` named pipe and closes it |
| Web enrollment (ESC8) | each enterprise CA, port 80 | one `GET /certsrv/` to read the authentication headers |
| HTTPS enrollment | each enterprise CA, port 443, and each URL in `msPKI-Enrollment-Servers` | one `GET` over TLS to read the authentication headers; no credentials are sent, the server certificate is not checked, and EPA is not determined (`--https-port 0` skips it). A URL that uses plain HTTP gets the same `GET` over HTTP |
| CA registry (ESC6/7/11/16, audit filter) | each enterprise CA, port 445 | reads the CA's configuration over `\pipe\winreg` (MS-RRP), `KEY_READ` only; `--no-ca-registry` skips it |
| SYSVOL | the scanned DC | reads GPO files and scripts (`--no-sysvol` skips it) |

The DC being scanned is reached through the address and ports on the command line; the
other DCs by their DNS names on the standard ports. `--single-dc` limits the DC probes to
the DC being scanned. A URL from `msPKI-Enrollment-Servers` is reached on the port it names;
only a URL with no port follows `--http-port` or `--https-port`. When one of these probes
does not run, or such a URL gives no answer to judge, a note says so.

## Intrusiveness of the CA registry probe

Opening `\pipe\winreg` on a CA host is a read, but it is not invisible. On a host where the
`RemoteRegistry` service is set to start on demand, opening the pipe **trigger-starts the
service**: a visible change of service state (System event 7036), plus an SMB logon
(4624 type 3), and reads under `CertSvc` may be audited if object-access auditing is on for
that key. Remote registry access to a CA is also the kind of activity EDR and Microsoft
Defender for Identity may alert on.

It is still only a read: nothing in the directory, the CA database or the registry is
modified. Use `--no-ca-registry` to skip just this probe, or `--no-probes` to skip it with
the others.
When it is skipped, the CA-side checks (ESC6, ESC7, ESC11, ESC16, audit filter) simply produce no result
for that CA.

See [SECURITY.md](https://github.com/brkozer/ad-doctor/blob/main/SECURITY.md) for the
reporting policy and how ad-doctor handles output.
