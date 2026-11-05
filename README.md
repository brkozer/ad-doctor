# ad-doctor

[![ci](https://github.com/brkozer/ad-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/brkozer/ad-doctor/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Read-only Active Directory security audit that fits in a pipeline.

ad-doctor binds as an ordinary domain user, takes one snapshot of the domain over LDAP
(plus SYSVOL and a few cheap probes of every DC over SMB, LDAP and HTTP) and runs 87
checks for what attackers look for first: roastable accounts, risky delegation,
exploitable certificate templates and CA settings (ESC1–9, 11, 13–16), DCSync and other takeover rights,
shadow credentials, BadSuccessor, PrivExchange, exposed Entra Connect sync accounts,
editable GPOs on domain controllers, local admin and remote logon rights handed out by
Group Policy, passwords in Group Policy and scripts, relay-friendly DCs, weak trusts and
legacy configuration. It then finds every control path from a
non-admin to tier 0. It writes nothing to the directory.

<p align="center"><img src="docs/demo.svg" alt="ad-doctor scanning the lab domain: ESC8 web enrollment, a relay-to-RBCD chain, a password in a logon script, BadSuccessor rights and the control paths to tier 0" width="100%"></p>

The screenshots are real scans of the lab domain in [`lab/`](lab): a Windows Server 2025
DC seeded with one instance of every misconfiguration that a single domain can hold.

## What sets it apart

- **Attack paths without a graph database.** `AD-PATH-001` builds the control graph
  (group membership, takeover ACEs, ownership, DCSync, GPO links, exploitable templates,
  gMSA readers, local admin rights that Group Policy hands out, an Entra Connect server
  holding its sync account) from the snapshot and reports the shortest path from every non-tier-0
  principal to tier 0, plus the share of users that have one. `ad-doctor blast-radius`
  answers "what does this account control if it is phished?".
- **Plays well with BloodHound.** `ad-doctor export-graph` writes the same graph as a
  BloodHound OpenGraph payload. Principals keep their SIDs, so the edges attach to an
  existing SharpHound graph of the domain instead of building a second one. Remote logon
  rights that GPOs grant (RDP, WinRM, DCOM) are exported with `traversable: false`: logon
  is not control, so the path search does not follow them.
- **Every DC, not just one.** LDAP signing, SMB signing, the spooler and channel binding
  are probed on each domain controller, and findings name the ones that drift from the
  rest; DCs that cannot be reached are reported rather than assumed fine.
- **Fast on large domains.** 100,000 users, 33,000 computers and 127,000 ACEs load in
  about 3 s and go through every check, attack paths included, in about 6 s on one 2017
  Xeon core
  ([benchmark](#performance)).
- **Compound findings.** `AD-CHAIN-*` raise the alarm when individually medium findings
  add up to a known one-step compromise (relay to RBCD, coercion plus unconstrained
  delegation, coercion plus ESC8).
- **Built for CI and change management.** SARIF 2.1.0 (validated against the schema),
  JUnit, JSON with stable per-finding fingerprints, exit codes with `--fail-on`, and
  `--baseline` / `diff` so a scheduled job fails only on *new* findings.
- **Policy as code.** An `invariants.toml` declares the expected state (exact tier-0
  membership, allowed DCSync principals, published templates, required settings); any
  drift becomes a finding.
- **Accepted risks with owners and expiry.** Expired acceptances turn back into findings,
  acceptances that no longer match anything are reported as stale, and the ones expiring
  within 30 days are listed.
- **A fix script you can review.** `--fixes fix.ps1` writes the PowerShell for each
  finding with `-WhatIf` on every change (commented out where there is no dry-run), so it
  is safe to run as-is.
- **Shareable snapshots.** `ad-doctor redact` pseudonymizes names, DNs, hosts and the
  domain SID with a keyed HMAC, so a snapshot can go to a consultant or a bug report and
  still produce the same findings.
- **Runs from any Linux box** with an ordinary account: no domain-joined host, no RSAT,
  no admin rights. NTLM with channel binding (works where the DC enforces it) or Kerberos
  from a ticket cache.

Tools like PingCastle and Purple Knight cover more ground overall and Locksmith goes
deeper into AD CS; ad-doctor is the scriptable option, and the one that tests itself
against a live DC.

<p align="center"><img src="docs/report.png" alt="HTML report: risk score, findings by severity and category, expandable findings with remediation and MITRE ATT&CK links" width="85%"></p>

## Checks

| Area | ID | Finding | Severity |
|---|---|---|---|
| Kerberos | AD-KRB-001 | krbtgt password older than 180 days | high |
| | AD-KRB-002 | Accounts without Kerberos pre-authentication (AS-REP roasting) | high |
| | AD-KRB-003 | User accounts with SPNs (Kerberoasting); high when privileged | medium/high |
| | AD-KRB-004 | Accounts limited to DES | medium |
| | AD-KRB-005 | Service accounts without AES keys (RC4 only) | medium |
| | AD-KRB-006 | Seamless SSO (`AZUREADSSOACC$`) key not rolled over in 30 days | medium |
| Delegation | AD-DEL-001 | Unconstrained delegation outside domain controllers | high |
| | AD-DEL-002 | Constrained delegation with protocol transition | medium |
| | AD-DEL-003 | Resource-based constrained delegation configured | low |
| | AD-DEL-004 | Delegation to DC services or krbtgt, RBCD on DCs | high |
| Accounts | AD-ACC-001 | Enabled accounts allowed an empty password (`PASSWD_NOTREQD`) | medium |
| | AD-ACC-002 | Reversible password encryption | high |
| | AD-ACC-003 | Privileged accounts whose password never expires | medium |
| | AD-ACC-004 | Guest account enabled | high |
| | AD-ACC-005 | Enabled users inactive for 90+ days | low |
| | AD-ACC-006 | `adminCount` left on accounts that are no longer privileged | low |
| | AD-ACC-007 | SID history; high for privileged or same-domain SIDs | medium/high |
| | AD-ACC-008 | Passwords in `description` or `info` (text never reproduced) | medium |
| | AD-ACC-009 | Readable `userPassword` / `unixUserPassword` / `msSFU30Password` | high |
| | AD-ACC-010 | Pre-created computers whose password is their name | high |
| | AD-ACC-011 | Privileged passwords older than a year | medium |
| Privileged access | AD-PRIV-001 | Tier-0 groups with more than 5 members | low |
| | AD-PRIV-002 | Privileged accounts that can be delegated | medium |
| | AD-PRIV-003 | Schema Admins or Enterprise Admins not empty | low |
| | AD-PRIV-004 | Members of DnsAdmins | medium |
| | AD-PRIV-005 | Anonymous or Everyone in Pre-Windows 2000 Compatible Access | medium |
| | AD-PRIV-006 | Disabled, computer or foreign accounts in tier-0 groups | medium |
| | AD-PRIV-007 | Membership hidden through `primaryGroupID` | high |
| | AD-PRIV-008 | Operator groups not empty | medium |
| | AD-PRIV-009 | Cert Publishers members that are not CA servers | medium |
| | AD-PRIV-010 | Protected Users not used for administrators | info |
| | AD-PRIV-011 | Entra Connect sync account can DCSync and its server is not protected as tier 0 | medium |
| Policy | AD-POL-001 | Weak default password policy | medium |
| | AD-POL-002 | `ms-DS-MachineAccountQuota` above 0 | medium |
| Hardening | AD-SEC-001 | Windows computers without LAPS | medium |
| | AD-SEC-002 | LAPS passwords readable by the scanning account | high |
| Infrastructure | AD-INF-001 | Computers on unsupported Windows versions; high for DCs | medium/high |
| | AD-INF-002 | AD Recycle Bin disabled | low |
| | AD-INF-003 | Domain functional level below Windows Server 2016 | low |
| | AD-INF-004 | Unsafe `dsHeuristics` (anonymous LDAP, AdminSDHolder exclusions) | medium/high |
| | AD-INF-005 | LDAP signing not required (probe, every DC) | medium |
| | AD-INF-006 | Trusts without SID filtering or with TGT delegation | high |
| | AD-INF-007 | BadSuccessor: dMSA creation rights outside tier 0 (2025 domains) | high |
| | AD-INF-008 | SMB signing not required (probe, every DC) | high |
| | AD-INF-009 | Print Spooler running (probe, every DC); high with unconstrained delegation | medium/high |
| | AD-INF-010 | LDAPS channel binding not enforced (probe, every DC) | medium |
| | AD-INF-011 | No backup of the domain partition in 7 days | medium |
| | AD-INF-012 | RODCs that may cache privileged credentials | medium |
| | AD-INF-013 | Domain controllers the probes could not reach | low |
| Certificate services | AD-ADCS-001 | ESC1: enrollee-supplied subject on an authentication template | high |
| | AD-ADCS-002 | ESC2: any-purpose or no-EKU template | high |
| | AD-ADCS-003 | ESC3: enrollment agent template open to broad groups | high |
| | AD-ADCS-004 | ESC4: broad groups can modify a certificate template | high |
| | AD-ADCS-005 | ESC5: non-tier-0 control over CA objects, templates or NTAuth | high |
| | AD-ADCS-006 | ESC9: authentication template without the security extension | medium |
| | AD-ADCS-007 | ESC13: issuance policy linked to a group | high |
| | AD-ADCS-008 | ESC15: schema v1 template with enrollee-supplied subject | high |
| | AD-ADCS-009 | ESC14: weak explicit certificate mappings | medium/high |
| | AD-ADCS-010 | ESC8: web enrollment accepts NTLM over HTTP (probe) | high |
| | AD-ADCS-011 | Published templates allowing RSA keys under 2048 bits | medium |
| | AD-ADCS-012 | ESC6: CA accepts a SAN from request attributes (registry probe) | medium/low |
| | AD-ADCS-013 | ESC7: non-tier-0 principals manage the CA (ManageCA high; ManageCertificates graded by what it reaches) | medium/high |
| | AD-ADCS-014 | ESC11: CA does not require encryption for ICPR requests (registry probe) | high/medium |
| | AD-ADCS-015 | ESC16: CA leaves out the SID security extension (registry probe) | medium/low |
| | AD-ADCS-016 | CA configuration could not be read (registry probe) | low |
| Permissions | AD-ACL-001 | Non-default principals with DCSync rights | high |
| | AD-ACL-002 | Non-default control over AdminSDHolder | high |
| | AD-ACL-003 | Non-default control over the domain object | high |
| | AD-ACL-004 | Takeover rights or ownership on tier-0 accounts, groups and DCs (shadow credentials, RBCD, members, password reset, SPN) | high |
| | AD-ACL-005 | AdminSDHolder inherits permissions | high |
| | AD-ACL-006 | gMSA passwords readable outside tier 0 | high |
| | AD-ACL-007 | Exchange groups with WriteDacl over the domain (PrivExchange); medium when only inherited | medium/high |
| | AD-ACL-008 | Entra Connect sync account or server controllable outside tier 0 | high |
| Group Policy | AD-GPO-001 | GPOs linked to the domain or DC OU editable outside tier 0 | high |
| | AD-GPO-002 | Non-tier-0 principals can link GPOs to the domain or DCs | high |
| | AD-GPO-003 | NTLMv1/LM, LM hashes, reversible encryption or dangerous privileges in those GPOs | medium/high |
| | AD-GPO-004 | Other GPOs editable outside tier 0 | medium |
| | AD-GPO-005 | GPOs make broad groups local administrators (Restricted Groups, GPP Local Groups) | high |
| | AD-GPO-006 | GPOs make non-tier-0 principals admins of tier-0 servers (DCs, CAs, Entra Connect, Exchange) | high |
| | AD-GPO-007 | GPOs grant RDP, WinRM or DCOM to broad groups (medium) or on tier-0 servers (high) | medium/high |
| | AD-GPP-001 | Passwords in Group Policy Preferences (MS14-025) | high |
| | AD-GPP-002 | Credentials in SYSVOL or NETLOGON scripts (values never reproduced) | high |
| Attack paths | AD-PATH-001 | Control paths from non-tier-0 principals to tier 0 | high |
| | AD-CHAIN-001 | Relay to RBCD (signing or channel binding off, plus machine account quota) | high |
| | AD-CHAIN-002 | Coercion plus unconstrained delegation | high |
| | AD-CHAIN-003 | Coercion plus web enrollment relay (ESC8) | high |
| | AD-CHAIN-004 | ESC6 plus ESC16 on the same CA (SID in a SAN under strong mapping) | high/medium |

Template checks fire only for templates published on an enterprise CA that issue without
manager approval or authorized signatures and that broad groups (Domain Users, Domain
Computers, Authenticated Users, Everyone) can enroll in. "Tier 0" means
Domain/Enterprise/Schema Admins, Administrators, the operator groups, domain controllers,
SYSTEM and the built-in Administrator; for the Group Policy local group checks, tier-0
servers are DCs, CA hosts, Entra Connect servers, Exchange servers and computers that are
in a tier-0 group or hold DCSync. Well-known delegations (SELF, Key Admins on
`msDS-KeyCredentialLink`, Cert Publishers and the CA server on PKI objects) are not
reported. Every finding carries its MITRE ATT&CK techniques (`ad-doctor checks -f json`).

The risk score adds 15 per high, 6 per medium and 2 per low finding, capped at 100;
grades run from A (10 or less) to F (above 70). It is meant for tracking one domain over
time, not for comparing domains.

## Documentation

Full docs, including a page for every check, are at
<https://brkozer.github.io/ad-doctor/> (published from `main` once the repo is public).
The same per-check explanation is available offline:

```bash
ad-doctor explain AD-ADCS-001      # by ID
ad-doctor explain esc1             # or by alias
ad-doctor explain AD-KRB-003 -f markdown
```

Every finding in a report links to its catalog page, and SARIF rules carry the
explanation and a `helpUri` so code-scanning alerts show it too.

## Usage

```bash
uv tool install git+https://github.com/brkozer/ad-doctor          # or: ... ad-doctor[kerberos]

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
AD_DOCTOR_REDACT_KEY=... ad-doctor redact 2026-11.json -o shareable.json

# the control graph for BloodHound CE (File Ingest accepts OpenGraph JSON)
ad-doctor export-graph 2026-11.json -o graph.json --paths-only
```

| Option | |
|---|---|
| `-f text\|json\|markdown\|html\|sarif\|junit`, `-o FILE` | report format and destination |
| `--fail-on high\|medium\|low` | exit 2 when a finding at that severity exists |
| `--baseline FILE` | mark findings missing from an earlier report or snapshot as new; `--fail-on` then considers only those |
| `--accept FILE` | accepted risks (see [`examples/accept.toml`](examples/accept.toml)) |
| `--invariants FILE` | declared state to enforce (see [`examples/invariants.toml`](examples/invariants.toml)) |
| `--fixes FILE` | write the PowerShell remediation script |
| `--only ID ...` | run a subset of checks (`ad-doctor checks` lists them) |
| `explain ID\|alias` | print a check's full explanation and fix offline (`-f text\|markdown\|json`, `--web`) |
| `-k`, `--kerberos` | bind with Kerberos instead of a password |
| `--no-sysvol`, `--smb-port` | skip or redirect the SMB part |
| `--no-probes`, `--http-port` | skip every probe (SMB, channel binding, ESC8, CA registry), or move the web enrollment port |
| `--no-ca-registry` | skip reading CA settings (ESC6/7/11/16) over `\pipe\winreg` |
| `--single-dc` | probe only the DC being scanned instead of every DC in the domain |
| `--signing-probe-port PORT` | plain LDAP port for the signing probe; `0` skips it |

Parts that cannot run (no AD CS, SYSVOL unreachable, Kerberos without an NTLM account for
the signing probes) become notes in the report instead of failing the scan. Domain
controllers that require LDAP signing (the default on Windows Server 2025) reject plain
LDAP binds, so use `--ldaps`.

### In CI

```yaml
- run: uvx --from git+https://github.com/brkozer/ad-doctor ad-doctor scan "$DC" --ldaps -u "$AD_USER" -f sarif -o ad.sarif --baseline last.json --fail-on high
  env: { AD_DOCTOR_PASSWORD: "${{ secrets.AD_PASSWORD }}" }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: ad.sarif }
```

## What it needs and what it reads

An enabled domain user is enough; no group memberships or delegated rights. ad-doctor
reads users, computers, groups, OUs, GPOs, trusts, AD CS templates, enrollment services
and OIDs, gMSAs, the replication metadata of the domain head (for the backup date) and
the owners and DACLs of the security-critical objects. Security descriptors are requested
with the SD flags control for owner and DACL, which ordinary users may read, and parsed
by a small built-in parser (`sd.py`). For Group Policy scope it also reads `gPLink` and
`gPOptions` on the domain, OUs and sites, the GPOs' status, version and extension
attributes, WMI filter names and which site each DC is in. From SYSVOL it reads Group
Policy Preferences (passwords and Local Groups), `GptTmpl.inf` security templates
(including Restricted Groups) and scripts, and keeps only paths, line numbers, account
names and setting values, never a secret.

Active probes, each one connection per DC: an unsigned NTLM bind on 389 (LDAP signing),
an NTLM bind on LDAPS without a channel binding token, an SMB negotiate plus an attempt
to open the `spoolss` pipe, and an unauthenticated `GET /certsrv/` on each CA. On each
enterprise CA it also reads the CA's own configuration (ESC6, ESC7, ESC11, ESC16) over
`\pipe\winreg` (MS-RRP) with a small built-in client: every call is a `KEY_READ`, nothing
is written. Opening that pipe trigger-starts the RemoteRegistry service on the CA host if
it is set to start on demand (a visible change of service state), and remote registry
access to `CertSvc` is the kind of thing EDR and Microsoft Defender for Identity may alert
on; `--no-ca-registry` skips just that read. The DC being scanned is reached through the
address and ports given on the command line, the others by their DNS names on the standard
ports. `--single-dc`, `--no-probes`, `--no-ca-registry` and `--signing-probe-port 0`
narrow or turn them off; [SECURITY.md](SECURITY.md) lists every probe.

## Limits

- One domain per run; trusts are inspected from this side only.
- The CA-side checks (ESC6, ESC7, ESC11, ESC16) read the CA's registry over
  `\pipe\winreg`, which needs TCP 445 to each CA and credentials; a run that cannot reach a
  CA, where RemoteRegistry is disabled, or where a GPO has removed `CertSvc` from the
  winreg AllowedPaths reports AD-ADCS-016 rather than a clean result. A third-party policy
  module leaves ESC6 and ESC16 unknown, and a value that is absent or unparseable leaves its
  check unknown (both reported by AD-ADCS-016, never "clean"). ESC7 reads the CA security
  descriptor: on a CA that is a member server, `BUILTIN\Administrators` there is that
  server's *local* Administrators group, whose members are invisible over LDAP. Deny ACEs
  in it are applied for the same SID, Everyone and Authenticated Users, not through other
  group memberships. The admins of other domains in the forest are expected CA managers
  when a within-forest trust object gives their domain's SID; on a CA outside the scanned
  domain with no such trust object, any other domain's Administrator and Domain Admins are
  accepted. ESC10 and ESC12 (DC certificate-mapping registry settings, a CA key on an HSM
  reachable from a shell on the CA) are not checked. EPA on
  HTTPS web enrollment, and host settings beyond what the DC probes see, remain out of
  scope: local group membership that Group Policy sets is covered, changes made directly
  in a computer's local SAM are not.
- Group Policy scope for local groups (AD-GPO-005 to -007 and the graph edges) is worked
  out offline and errs toward over-reporting. Links, Block Inheritance, Enforced, disabled
  links, the GPO status, an empty computer version or a missing client-side extension, and
  security filtering (Read plus Apply Group Policy for any SID in the computer's token,
  well-known SIDs and foreignSecurityPrincipals included) are evaluated. Not evaluated:
  WMI filters (assumed to match), item-level targeting (the item is listed as applying,
  with a caveat), Deny ACEs in GPO permissions, member computers' sites (with more than one site,
  every site's links are assumed to apply), removals and precedence between GPOs (the
  result is the union of additions, though a higher-precedence `X__Members` can remove
  what another GPO adds), groups of other domains in the token, user-side GPP groups
  (noted), and `SeDenyRemoteInteractiveLogonRight` (a deny-RDP setting does not silence
  AD-GPO-007). Remote Desktop Users counts only where `SeRemoteInteractiveLogonRight`
  includes it; without a GPO that sets it, the Windows default applies (Administrators
  only on DCs, Administrators and Remote Desktop Users elsewhere). A holder of that right
  named by an account name that cannot be resolved is assumed to include the member, with
  a caveat.
- Domain controllers have no local groups: Restricted Groups that reach a writable DC
  rewrite the *domain* group with that SID and are reported as such, and an empty
  `X__Members =` line there (GPMC writes one whenever only "This group is a member of" is
  set) empties domain group X, which the scan notes. GPP Local Groups items are processed
  on DCs but leave domain groups alone (checked on Windows Server 2025), so they are
  skipped with a note; RODCs are skipped with a note.
- AD-GPO-003 judges only GPOs Windows would apply: a GPO with computer version 0, without
  the security extension in `gPCMachineExtensionNames`, or with its computer side disabled
  is not reported, whatever its `GptTmpl.inf` says.
- Exchange and Entra Connect are recognised from their directory footprint (the groups
  Exchange setup creates, `MSOL_` sync accounts); the lab seeds that footprint without
  installing either product.
- Deny ACEs on directory objects are ignored, which can only over-report, never hide a
  finding (the CA's own descriptor is the exception, see above).
- An ordinary user cannot read fine-grained password policies; the report says so
  instead of assuming the default policy applies to admins.
- Some checks cannot be reproduced in a single lab DC and are covered by unit tests only:
  krbtgt, Seamless SSO and admin password age, SID history, trusts, RODCs, SMB signing
  off on a DC, the spooler on Server Core 2025 (which ships without it) and
  `unixUserPassword` (confidential on 2025).

## How it works

```mermaid
flowchart LR
    DC[(Domain controller)] -- "LDAP / LDAPS<br/>NTLM+CBT or Kerberos" --> C[collect.py]
    DC -- "SMB: SYSVOL" --> V[sysvol.py]
    DC -- "SMB, LDAP, HTTP probes" --> P[probes.py]
    C --> S[Snapshot<br/>accounts, groups, OUs, GPOs,<br/>templates, owners + DACLs]
    V --> S
    P --> S
    S -- "collect -o / redact" --> F[(snapshot.json)]
    F --> A
    S --> A[checks.py + paths.py<br/>87 pure functions]
    A --> I[invariants.py<br/>accept.py]
    I --> R[report.py<br/>text, JSON, Markdown,<br/>HTML, SARIF, JUnit]
    I --> X[fixes.py<br/>remediation script]
    A --> O[opengraph.py<br/>BloodHound OpenGraph]
```

Checks never touch the network, which keeps them fast and lets the unit tests run
without a domain controller; the collector itself is tested against a fake LDAP
connection and, through `tests/test_lab.py`, against the live lab DC.

## Performance

`scripts/bench.py` builds a synthetic enterprise domain (an OU tree of 8 regions, 80
sites and 480 departments, nested groups, delegated OU permissions that inherit, default
DACLs on every object, GPOs and templates) and times each stage. On one core of an Intel
Xeon Gold 6138 (2017), Python 3.12:

| Domain | Snapshot | Load | All checks + paths | OpenGraph export | Peak memory |
|---|---|---|---|---|---|
| 10,000 users, 3,300 computers, 19,000 ACEs | 12 MB | 0.4 s | 0.6 s | 0.7 s | 0.2 GB |
| 100,000 users, 33,000 computers, 127,000 ACEs | 111 MB | 3.3 s | 5.7 s | 6.3 s | 1.4 GB |
| 250,000 users, 83,000 computers, 308,000 ACEs | 277 MB | 8.1 s | 15.1 s | 16.8 s | 3.5 GB |

Analysis grows linearly with the size of the domain. Collection time is set by the DC:
the snapshot comes from a few paged LDAP searches, so it scales with the number of objects
and the network round trip, not with the number of checks.

```bash
uv run python scripts/bench.py --users 100000
```

## Development

```bash
uv sync
uv run ruff check . && uv run mypy && uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding a check and [SECURITY.md](SECURITY.md)
for reporting vulnerabilities. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

[`lab/`](lab) builds a disposable Windows Server 2025 evaluation DC under KVM and seeds
it; see [lab/README.md](lab/README.md). With the lab running:

```bash
AD_DOCTOR_LAB_HOST=127.0.0.1 AD_DOCTOR_LAB_PORT=10636 AD_DOCTOR_LAB_SMB_PORT=10445 \
AD_DOCTOR_LAB_PLAIN_PORT=10389 AD_DOCTOR_LAB_HTTP_PORT=10080 \
AD_DOCTOR_LAB_USER='ADLAB\adreader' AD_DOCTOR_PASSWORD=... uv run pytest -m lab

uv run python scripts/demo_svg.py docs/demo.svg   # regenerate the terminal screenshot
```

## License

MIT
