# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/). Check IDs are stable: a check may change its
logic or severity between versions, but an ID is never reused for something else.

## [Unreleased]

## [0.2.5] - 2026-11-10

### Added

- **Patch level** (AD-INF-029, AD-ADCS-022): each DC's and CA's build and UBR are read over the
  `winreg` pipe and compared with a dated table of Microsoft's fixed builds (`patches.toml`), including
  CVE-2026-54121 (Certighost). A version match never goes above medium, and `--no-patch-level` turns
  it off. A note says when the table is old or a build is not in it.
- **`--preflight FILE`**: a read-only PowerShell script for the first 10 fixes, run before the
  `--fixes` script, that looks each object up again and prints OK, WARN or STOP.
- **`ad-doctor rollup`**: one view over the JSON reports of several domains, without averaging
  scores and with not-judged checks listed as such.
- **`ad-doctor service-accounts` and `ad-doctor tier-scorecard`**: two views of a snapshot from
  data it already holds. The scorecard covers tier 0 only, since the directory does not record
  tier 1 or 2, and shows how many tier-0 members could not be read.
- **Configuration Manager.** AD-INF-022 reports the published site systems, and the computers
  with Full Control on the `System Management` container count as tier 0 in attack paths.
  AD-ACL-014 reports control over that container or those computers from outside tier 0.
- **Entra Cloud Sync and connector accounts.** AD-PRIV-016 reports a gMSA holding DCSync whose
  password can be read outside tier 0; the gMSA is found by its rights, not by name. AD-ACC-020
  reports connector passwords older than a year.
- **AD FS DKM.** AD-ACL-011 reads only the DACL of the DKM containers, never `thumbnailPhoto`. A
  plain user normally cannot read them, and the report then says the check was not judged.
- **Forest and OU permissions.** AD-ACL-012 reports writers outside tier 0 on the Schema and
  Configuration partitions and five containers under them. AD-ACL-013 reports extended rights
  over accounts for broad groups on OUs and containers, and all extended rights for a delegate.
- **Privileged leftovers.** AD-ACC-018 (RID 500 used recently), AD-ACC-019 (smart-card accounts
  with an unrotated hash), AD-PRIV-017 (mail on tier-0 accounts) and AD-PRIV-018 (group loops).
- **AD-GPO-017 and AD-GPO-018 follow only what an interpreter runs**: a log file or data path in
  the arguments is no longer reported, and a command line that does not say what runs is not judged.
  A password in a quoted argument or a `CmdLine` no longer reaches the snapshot or the report.
  A GPO with a WMI filter tops out at medium, a logon script that only loopback brings to users is
  judged from `UserPolicyMode`, and `\\NETBIOS\NETLOGON` counts as NETLOGON through the domain's
  real NetBIOS name. An unreadable `scripts.ini` or `ScheduledTasks.xml` now marks both as not
  judged, as a probe pack answer it could not get does for AD-INF-026 to AD-INF-028.
- **AD-ADCS-021** (weak published CA certificates), **AD-INF-023** (display specifiers that run
  something from another host) and **AD-INF-024** (dynamic objects and lowered TTL settings).
  Snapshots from earlier versions load and report the checks that need new data as not evaluated.
- **Scripts Group Policy runs.** `scripts.ini`, `psscripts.ini` and Preferences `ScheduledTasks.xml`
  are read, keeping the file each one runs and never its arguments. AD-GPO-017 reports a file in
  SYSVOL or NETLOGON, the file that lists it or a folder above them that can be changed outside
  tier 0; AD-GPO-018 reports a file served from a host outside tier 0. A descriptor that cannot be
  read or has a deny ACE is a note, not a pass. Writers and hosts get graph edges to where the GPO
  applies, except for item-level targeting and a task run as another account, and what-if takes
  them out with `script-ace` and `script-host`.
- **SMB signing on tier-0 member servers** (AD-INF-025): one negotiate per server, no credentials.
- **DC probe pack, `--dc-probes`, off by default**: AD-INF-026 (WebClient), AD-INF-027 (SMBv1) and
  AD-INF-028 (TLS 1.0 and 1.1 on LDAPS), each a read-only request.
- **Tier-0 logon restrictions, silos and change history.** **AD-PRIV-013** reports the
  computers, per OU, where Group Policy does not deny tier-0 accounts local logon, RDP,
  batch or service logon, using each computer's own processing order. **AD-PRIV-014** reports
  tier-0 accounts outside an enforced authentication policy silo whose user policy limits
  where they sign in, or that no silo exists. **AD-PRIV-015**, **AD-ACL-010** and
  **AD-ACC-017** read replication metadata for members added to tier-0 groups, a change to
  AdminSDHolder's ACL and `sIDHistory` writes in the 30 days before the snapshot, leaving out
  the domain's first 24 hours. Older snapshots load and report these as not evaluated, and
  so does a run where the data could not be read.
- **Declared tier 0.** `--tier0-file` (and `--tier0 NAME`) on `analyze`, `scan`, `paths` and
  `view` adds your own tier-0 assets as extended targets, in a set of their own: built-in paths,
  `exposed`, `users` and every other check stay as they were, paths that end at a declared asset
  carry `[declared tier 0]` and the report lists each asset (`declared_tier0` in the JSON). A
  path to one is an AD-PATH-001 object, so on a domain with no built-in path a declaration can
  raise that HIGH finding and the score. `diff` and `--baseline` keep a path to an asset only one
  run declared apart. A SID the snapshot does not hold is refused like a name. `collect`
  and `scan` read the owner and DACL of declared accounts; without that the asset is reported as
  **not evaluated**, with a note naming AD-PATH-001, and paths that need no DACL of its own are
  a lower bound. `whatif` and `plan` take the file too and use the same lookup and the same test.
- **Per-check status.** Every run now says, per check, whether it was judged, not applicable
  or not evaluated, with the reason (data unreadable, older snapshot, switched off). It is in
  the JSON report (`check_status`, `coverage`; `schema` is now 3), and in the text, Markdown,
  SARIF and JUnit output and the viewer's overview. The status is computed from the collection notes, so
  snapshots from earlier versions get one too. A check that was not evaluated never counts as
  passed: JUnit marks it skipped, its earlier findings stay out of "resolved" in `diff`,
  `--baseline` and the viewer, an acceptance of it is not reported as stale, and the risk score is
  then labelled a minimum. A check the older run did not evaluate is kept out of "new" the same
  way. `paths`, `whatif`, `plan` and the viewer say so when AD-PATH-001 could not judge everything,
  and `whatif --fail-if-exposed` fails on such a graph. Findings are unchanged. `--no-sysvol`, `--no-probes` and
  `--http-port 0` now leave a note saying what they skipped.

## [0.2.4] - 2026-11-09

### Added

- **Active Directory-integrated DNS zones (`AD-DNS-001` to `AD-DNS-003`).** The scan reads the
  `dnsZone` objects in the DomainDnsZones and ForestDnsZones partitions and in the domain
  partition, with a bounded parser for `dnsProperty` ([MS-DNSP] 2.3.2.1). AD-DNS-001 reports
  primary zones that accept nonsecure dynamic updates (high, medium when only reverse zones
  do). AD-DNS-002 reports zones whose ACL gives write control outside tier 0 and DnsAdmins
  (medium, high for a broad group on a forward zone). AD-DNS-003 reports, as information
  only, that authenticated users can add records, which is the default. An unreadable zone
  is a note and is not reported as passing, and snapshots from older versions say these
  checks were not evaluated. No zone transfer is attempted. On the lab: the two default zones
  use secure updates, neither check fires, and AD-DNS-003 lists both zones.
- **DNS records (`AD-DNS-004` to `AD-DNS-007`).** The scan walks the `dnsNode` objects of the
  forward zones one at a time, with a bounded parser for the `dnsRecord` header ([MS-DNSP]
  2.3.2.2), and keeps only the names a check needs. AD-DNS-004 reports names carrying
  marshaled target information (high, medium when all are tombstoned). AD-DNS-005 reports
  wildcards (high when an ordinary account owns one that answers address queries, low when
  unclear, information when an administrator owns it). AD-DNS-006 reports `wpad`, `isatap`
  and `autodiscover` owned by ordinary accounts (high, or low without an address or when a
  computer of the same name owns it, since an ordinary user may have created it). AD-DNS-007
  reports SPN hosts of accounts in use that have no DNS record, in zones where any domain
  user can add one; a wildcard does not hide such a name, because an explicit record takes
  precedence. It is about held SPNs and does not repeat AD-DEL-005. Unreadable zones, records
  and owners are notes and are not reported as passing, and snapshots from older versions say
  these checks were not evaluated. JUnit and SARIF treat a range of IDs in a note as naming
  every check in it. On the lab none of the four fires: the
  SPN hosts without a record belong to accounts that have never logged on.

## [0.2.3] - 2026-11-09

### Added

- **Registry policy from SYSVOL.** Each GPO's computer-side `Machine\Registry.pol` is read
  ([MS-GPREG] format, delete and soft markers included) and only the values the checks need are
  kept. A file that does not parse or cannot be read is a note and stays unknown. A value named
  like a password is reported by its location; its data is never read into the snapshot, and
  redaction replaces the location unless it is Winlogon's own `DefaultPassword`. Registry paths
  and value names over 1024 characters make the file malformed. An instruction with a missing or
  empty value, type or data only creates the key, as the format says.
- **Group Policy precedence for registry settings.** `gpo_scope` works out the effective value
  of a registry setting per computer from link order, Enforced, Block Inheritance and security
  filtering. A WMI filter, an assumed site, a filter group the snapshot does not hold or an
  unreadable GPO that could change the result leaves it undecided, with the reason.
- **AD-GPO-009** (LLMNR not turned off by Group Policy), **AD-GPO-010** (WSUS over HTTP),
  **AD-GPO-011** (PowerShell script block or module logging not set) and **AD-GPO-012** (UNC
  hardened paths for SYSVOL and NETLOGON missing or weak), for domain controllers and other
  Windows computers, Hyper-V Server included. "No GPO sets it" never claims what the computer's
  own registry holds, and AD-GPO-012 credits the Windows default only to names it recognises as
  Windows 10, Server 2016 or later.
  Snapshots from earlier versions load and report these four as not evaluated.
- **Advanced audit policy and Preferences registry items from SYSVOL.** `audit.csv` ([MS-GPAC])
  and `Machine\Preferences\Registry\Registry.xml` are read with the same precedence; a file
  that does not parse or cannot be read is a note and stays unknown. `Registry.xml` joins the
  credential scan. A password in it never reaches the snapshot, only the fact and the location.
- **AD-GPO-013** (domain controllers' audit policy below Microsoft's baseline), **AD-GPO-014**
  (automatic logon or a stored DefaultPassword in a GPO), **AD-GPO-015** (BlockNtlmv1SSO kept
  in audit mode), **AD-GPO-016** (DES or RC4 in DefaultDomainSupportedEncTypes) and
  **AD-ADCS-020** (ESC10: weak certificate mapping set by Group Policy on domain controllers).
  A value no GPO sets stays unknown and is reported as such where the check needs it. With no
  enterprise CA or template in the snapshot, AD-ADCS-020 reports only a weak value a GPO sets, as
  info. An `[Event Audit]` category set to 0 does not count as coverage in AD-GPO-013. Snapshots
  from earlier versions load and report these five as not evaluated.
- `ad-doctor view` with the full graph has an interactive What-if screen. It starts from
  the embedded plan, or from nothing; each change can be turned on and off, and new ones
  come from the edges and chokepoints on Control paths. Exposure, holders, routes and the
  paths closed, rerouted, open and new follow live, computed in the page on the
  same model as `whatif` and checked against it. The difference from the plan in the file
  is shown; changes that need a rebuild are unavailable with the reason and get no number.
  *Download plan.toml* writes a file `whatif --plan` accepts. Findings are not rechecked
  in the browser, and there is no interactive what-if above the full-graph limit.
- `whatif -f json` carries `goal`, the goal of the plan it ran, so a page built from it
  keeps `all-paths`.

## [0.2.2] - 2026-11-09

### Added

- **ESC13 and ESC6 in the control graph.** Two new edges in AD-PATH-001, `blast-radius`, the
  viewer and the BloodHound export: `enroll (ESC13)` from whoever holds the Enroll right on
  a template whose issuance policy is linked to a group, to that group (AD-ADCS-007), and
  `enroll (ESC6+ESC16)` from whoever enrolls in an authentication template on the CA that has
  both flags of AD-CHAIN-004, to the template. Both need an issuable authentication
  certificate and the Enroll right itself. The ESC6 edge needs the domain's only enterprise
  CA (a snapshot does not say which CA publishes a template; with several CAs that is a note
  and no edge) that does not hold every request for a manager; the ESC13 edge also goes when
  every enterprise CA was read and holds every request. ESC6 without ESC16 is blocked
  by strong mapping on a patched DC, ESC9 needs DCs out of full enforcement and ESC15 an
  unpatched CA: a snapshot holds neither patch level, so they stay findings, not edges. What-if and `plan` can remove each one: the new
  `oid-link` (`oid-link:<OID>`) and `ca-flag` (`ca-flag:<CA>:san-from-request|no-sid-extension`)
  changes with `-WhatIf` fix and rollback lines, `template-ace`, and `template-flag` for
  `require-approval` and `any-purpose-eku`. On the lab: Domain Computers gets a path through
  ESC6+ESC16 (13 principals with a path, from 12), the plan is 16 changes (cost 20; at least 14
  changes, cost 16, are needed: a template flag that closes an ESC1-3 and an ESC6 edge of its
  template joins routes the model cannot split, so it is not called the minimum), which now
  clears a CA flag, and the exposed users stay 25 of 26.
- **Delegation and SID history in the control graph.** Three new edges in AD-PATH-001,
  `blast-radius`, the viewer and the BloodHound export: `constrained delegation (protocol
  transition)` from the account to the computer holding the SPN, `resource-based delegation`
  from each principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` to the computer, and `SID
  history` from the account to the SID's principal. An edge is drawn only when the attack
  works with what the source holds: an enabled computer with an SPN, an admin the KDC lets
  a service impersonate (not sensitive, and not in Protected Users from the 2012 R2 domain
  functional level; a read-only DC needs such an admin, a writable DC's own account does not
  open it), protocol transition and a resolvable SPN for constrained delegation, a principal
  that can run S4U2self for resource-based: a listed computer or SPN holder, the members of a
  listed group that are one of those, and for the broad groups only what can really run it
  (Domain Computers, Everyone and Authenticated Users with a machine account quota, else their
  computers and SPN holders; Domain Users its SPN holders; never Anonymous Logon or Domain
  Guests). Unconstrained delegation, constrained delegation without protocol
  transition, delegation to `krbtgt` or a service account and resource-based delegation from
  an account with no SPN stay out, and the docs say why. The snapshot now keeps the
  resource-based principals (redacted like every SID); a snapshot from an older version has
  no list, so those edges are missing there, with a note. What-if and `plan` can remove each
  edge: `delegation`, the new `rbcd-principal` (`rbcd:<computer>:<principal>`) and
  `sid-history` (`sid-history:<account>[:<SID>]`) changes, with `-WhatIf` fix and rollback
  lines, and a membership that decides who can be impersonated goes through a rebuild. The
  viewer gets Delegation and SID history filters.
- **Domain controller and computer health checks.** AD-ACC-014 reports stale enabled computer
  accounts (AD-ACC-005 covers users only). AD-ACC-015 reports gMSAs whose password interval is
  over 90 days. AD-INF-018 reports DCs whose machine password is over 45 days old. AD-INF-019
  reports SYSVOL still on FRS or a migration that stopped. AD-INF-020 reports subnets mapped to
  no site, sites with no DC or no subnet, and DC sites in no site link. AD-INF-021 reports
  replication conflict objects (`CNF:`), `$DUPLICATE-` accounts and accounts that share a name
  or SID. Each check says in a note when it could not read its data, and older snapshots load
  with those parts marked as not evaluated. New snapshot fields are redacted.
- **Identity, password policy, dMSA and Entra Kerberos checks.** AD-ACC-016 asks for review of a
  UPN equal to another account's `sAMAccountName`, invisible Unicode in SPNs, and a
  `dNSHostName` that is not the computer's name. AD-POL-003 judges the fine-grained password
  policies the scan account can read, and works out which one is in force for privileged
  users. AD-ACL-009 reports who outside tier 0 controls a dMSA that replaces another account.
  AD-KRB-007 reports the age of the Entra Kerberos key and objects that only have its name. What
  an ordinary user cannot read is stated in a note and not reported as passing. `redact` now
  covers `userPrincipalName` and the new fields, and gives a computer's own host name the
  computer's token, so host name tokens differ from those of earlier versions. A snapshot
  redacted by an earlier version skips the `dNSHostName` part of AD-ACC-016, with a note.

### Changed

- **CI output says what was not judged.** In JUnit, a check that a collection note marks as
  not fully judged is skipped with that note as the message, instead of passing, and all notes
  are in `system-out`. SARIF carries them in `toolConfigurationNotifications`.

## [0.2.1] - 2026-11-09

### Fixed

- **What-if screen.** A result that failed `--check` now says so, with its problems and each
  change's plan status. Rerouted paths no longer show as blank rows. The screen states the
  plan's goal, says when findings were not rechecked, marks absent changes, and shows the
  blast radius of `--account`. Long names and titles no longer widen the page on a phone.
  The About screen lists the embedded plan.
- **`view --whatif` refuses a malformed file** with a message instead of a traceback or a
  blank screen. With `--fixes`, each change's label and fix lines are built from the snapshot
  for its ID and never read from the JSON, so an edited file cannot put its own command
  under a dry-run heading; an ID the snapshot does not have is refused.
- **`[expect] closes_all`** is judged on the graph after the changes. It no longer passes
  when a change takes a user out of tier 0 who still has a path, fails when a route ended
  at that user, or depends on whether a change forced a rebuild for accepted holders.
- **`plan --from NAME`** counts the routes through the account's implicit groups.
- **`plan --keep` and `--allow KIND`** no longer write a `closes_all` their own plan fails.

## [0.2.0] - 2026-11-08

### Added

- **`ad-doctor plan` and `ad-doctor whatif`.** `plan` computes the cheapest set of
  removals that closes every control path ad-doctor sees (a minimum cut of a flow network
  on the path subgraph), says "proven minimum" only when the model is exact or a lower
  bound meets it, reports the sources no removal can close with the suggestion to treat
  the node as tier 0, and orders the changes by a greedy that says it is a heuristic, with
  or without `--max-changes`. `whatif` evaluates removals named by change ID, finding
  fingerprint, path step, edge, chokepoint ID or typed spec: paths closed, rerouted or
  open, exposure, blast radius per `--account`, and the findings that would clear or
  appear, rechecked on the snapshot changed in memory; a disagreement between the graph and
  the recheck stops the run. Output as text, JSON, Markdown with a rollback line per change,
  a TOML plan file and PowerShell fix lines (`RemoveAccessRuleSpecific`, `Set-Acl -WhatIf`,
  never `dsacls /R`). The plan file tracks each change as done, open, overdue, stale or
  ineffective against a newer snapshot; `--check` exits 2 when its `[expect]` block fails
  and 3 on plan rot. The Entra sync account's DCSync, `[[keep]]` entries, accepted findings
  and declared invariants are never proposed. Nothing opens a connection to a directory.
  See `docs/whatif.md`.
- **What-if screen in the viewer.** `view --whatif plan.json` embeds a `plan -f json`
  or `whatif -f json` result of the same snapshot file: exposure before and after,
  the steps with their change IDs, fix lines with `--fixes`, the paths closed, open or
  new, the unclosable sources and the findings that would clear or appear.
- **What-if engine.** `paths.build(snap, provenance=True)` records the removable fact
  behind every edge where the edge is made; the graph is the same either way, and
  `analyze` and `paths` text output is byte for byte that of 0.1.5. SDProp copies go with
  the AdminSDHolder ACE, inherited copies with the OU they come from. Provenance costs
  about 4 s and 270 MB more at 250,000 users (graph build alone, in its own process).
- **`paths -f json`** gives each step the IDs of the changes that remove it, and each
  `--chokepoints` edge row an `id`, both accepted by `whatif --remove`.

### Changed

- **Snapshots keep the INHERITED_ACE flag** (`Ace.inherited`, and
  `ace_inheritance_checked` on the snapshot). Older snapshots still load; there an
  inherited copy cannot be told from an explicit ACE, and what-if output says so. The
  key is written only when true, so 0.1.5 still reads a snapshot with no inherited ACE;
  one that has them needs 0.2.0.
- **`scripts/bench.py`** lists nested Domain Admins members as tier 0, as a collection
  does, and times a plan. The benchmark rows in the README are measured again.

## [0.1.5] - 2026-11-07

### Changed

- **Less memory.** Four new `Account` fields in 0.1.0 took it to 30 attributes, where
  CPython stops sharing dict keys, so every account got a full dict of its own: 1.3 KB more
  each on Python 3.12. `Account`, `DirObject` and `Ace` now use slots. `view` lets go of
  the parsed file once the snapshot is built, loading shares equal ACEs and member DNs, the
  control graph shares node strings, `to_json` no longer makes a deep copy first, OpenGraph
  edges share repeated dicts, and `export-graph` writes the file in pieces. On the
  250,000-user bench domain on Python 3.12, `view` peaks at 1.43 GB instead of 2.35 GB,
  `scripts/bench.py` at 2.1 GB instead of about 4.9 GB, and `export-graph` at 1.8 GB where
  it did not fit in 5 GB before. Findings, fingerprints and every report and export are byte
  for byte the same.
- **`redact` no longer slows down with the square of the domain.** Each word is looked up
  instead of one pattern of every name running over every string: 1.4 s instead of 40 s at
  5,000 users, 4 s at 20,000, and 49 s with a 3.0 GB peak at 250,000 users, where it could
  not finish before.
- **GPO reach.** A disabled side stays in with a caveat, because the writer can flip it. A
  filter stops a writer of values, but an owner or DACL writer gets a path through a node
  `GPO ... with its filter changed`. User-side reach needs some computer able to read the
  GPO, as Windows has required since MS16-072. A filter on a group the snapshot does not
  hold, such as another domain's, is assumed to apply, with a caveat and a note.
- **AD-ACC-013.** Any key on a DC or RODC is high, and so is a second key on a computer. CA
  servers and Entra Connect sync accounts and servers are read too. A short hash now tells
  keys and mappings apart, so the object text and identities of this check differ from 0.1.2.
- **AD-DEL-005.** Graded by the delegating account rather than the host: medium, or high with
  protocol transition. `sPNMappings` changes only the service class, so ports and instance
  names are kept. Entries for another domain get their own wording.
- **AD-ADCS-019.** A URL the directory lists that refuses or answers with anything but 401
  gets a note that EPA and NTLM were not judged.

### Fixed

- **Redaction.** A comma in a name defeated it: `Doe\, John` stayed readable in every DN, and
  so did any name with a dotted capital I. Also covered now: enrollment URLs that exist only
  in a note, user names and passwords in such URLs, service classes outside a default
  `sPNMappings`, delegation targets with no `/`, and text around the tags of a malformed
  `altSecurityIdentities` value. An IP address in an enrollment URL no longer makes the output
  impossible to load, a host label such as `group` no longer changes findings, and the Entra
  Kerberos trust stays skipped after redaction.
- **`--no-probes` also skips the LDAP signing bind**, as the docs said. AD-INF-005 then says in
  a note that it did not judge. The SYSVOL read has its own `--no-sysvol`; the docs no longer
  put it under `--no-probes`.
- A control path now says in its text what an edge assumes, such as a WMI filter or a
  disabled side, instead of only in the OpenGraph export. Fingerprints are unchanged.
- A host with a space in `msPKI-Enrollment-Servers` no longer ends the scan with a traceback.
- Text reports show control characters in directory names as escapes, and Markdown reports
  escape `<` outside code spans.

## [0.1.4] - 2026-11-07

### Added

- **Trust hygiene: AD-INF-015, AD-INF-016, AD-INF-017.** `msDS-SupportedEncryptionTypes` and
  `whenChanged` are now read on trusts. AD-INF-015 reports downlevel (NT4 style) trusts and
  inbound trusts without AES, at low when AES is merely not set. AD-INF-016 reports trusts
  unchanged for over 40 days, the limit of PingCastle's T-Inactive, at low for realm trusts.
  AD-INF-017 reports outgoing forest trusts without Selective Authentication (DISA V-243485).
  The Entra Kerberos trust is skipped. AD-INF-006 keeps SID filtering and TGT delegation, so
  nothing is reported twice. An older snapshot says in a note what was not evaluated.
- **AD-DEL-005: constrained delegation to SPNs no account holds.** A target counts as held
  when an account has the exact SPN, or the SPN its class maps to through `sPNMappings`, which
  is now collected. Otherwise the host decides: no computer object is medium, or high with
  protocol transition; a host that exists is low; a host outside the scanned domain is low
  with review wording. No DNS query is made. `redact` now also covers the hosts of SPNs and
  delegation targets, which need not belong to a computer in the snapshot.

## [0.1.3] - 2026-11-07

### Added

- **AD-ADCS-019: HTTPS enrollment endpoints where EPA is not verified.** The enrollment probe
  now also asks `/certsrv/` over HTTPS and every URL in `msPKI-Enrollment-Servers` (CES) for
  their authentication methods, with one unauthenticated `GET` each. An endpoint that offers
  NTLM or Negotiate over HTTPS is listed with EPA as unknown, at low: IIS shows EPA only to a
  client that authenticates, and this probe sends no credentials, so a listed endpoint may or
  may not be relayable and an unlisted one is not proven safe. A CES URL over plain HTTP
  counts for AD-ADCS-010 and AD-CHAIN-003. New option `--https-port` (443, 0 skips it). An
  older snapshot says in a note that this was not evaluated.

## [0.1.2] - 2026-11-07

### Added

- **AD-ACC-013: key credentials and strong certificate mappings on tier 0.** For krbtgt, the
  built-in Administrator, DCs and tier-0 group members, the BASE read now also asks for
  `msDS-KeyCredentialLink` and `msDS-ReplValueMetaData`. The check shows each key's device ID,
  creation time and the time the directory added it, and each strong mapping's type; the
  key itself is not kept. A value the account may not read still shows in the metadata and is
  reported as present; where metadata does not come back, a note says the account was not
  judged. Windows Hello for Business and a computer's own key are told apart by shape only,
  so the finding asks a person to confirm each one. Older snapshots load with a note.

### Fixed

- **Redaction of `altSecurityIdentities`.** Serial numbers, key hashes, e-mail addresses and
  subjects of no known object stayed readable in a redacted snapshot. Every value in a
  mapping is now replaced and its type kept, so AD-ADCS-009 gives the same result.

## [0.1.1] - 2026-11-07

### Added

- **GPO reach in the control graph.** Whoever can write a GPO now controls what it
  applies to: from the GPO through its links on OUs, the domain head and sites, down the
  OU tree to computers and users. New edges `GPO applies to`, `GPO inherited by` and `GPO
  reaches` (`ADD_GPOAppliesTo`, `ADD_GPOInheritedBy`, `ADD_GPOReaches` in the OpenGraph
  export), in the viewer's Group Policy edge filter. Links, Enforced, Block Inheritance,
  disabled links, the GPO's user and computer side flags and security filtering count,
  through the same logic as `gpo_scope.py`. Reach runs through scope nodes rather than OU
  nodes, because an OU's `contains` edges stand for ACL inheritance: they lead to groups
  and through Block Inheritance, where Group Policy does not go, and they skip protected
  objects, where it does. Scope nodes are not counted as controlled objects. The graph
  grows with accounts, OUs, links and distinct security filters, not with GPOs times
  accounts: on the 250,000-user bench the new edges add 14%. With more than one site, a
  site link is followed only to the domain controllers of that site, since an ordinary
  user cannot place member computers or users in a site, and the scan says so in a note.

### Changed

- **AD-PATH-001 results change.** Principals that can write a GPO linked to an OU or a
  site now have a path when that GPO reaches a tier-0 account, so new objects can appear
  in a diff, the exposure figure can rise, an existing path can take another route, and
  blast radius counts and chokepoints can grow. Fingerprints are unchanged: a path is still
  identified by the principal it starts from.
- `scripts/bench.py` gives its GPOs links, filters and Block Inheritance, so the figures
  in the README now include GPO reach.

### Fixed

- A `linked to domain` or `linked to Domain Controllers OU` edge no longer counts as
  control of tier 0 when the GPO cannot reach a domain controller: its computer side is
  disabled, its security filter leaves every DC out, or Block Inheritance stops it. Such a
  path was false. Snapshots that hold no links keep the edge.

## [0.1.0] - 2026-11-06

First public release: 93 checks and 5 invariants, the control-path engine with
`blast-radius` and chokepoints, compound findings, policy as code, accepted risks with
owners and expiry, a reviewable fix script, redaction for sharing snapshots, the offline
HTML viewer, text, JSON, Markdown, SARIF and JUnit reports, BloodHound OpenGraph export,
NTLM with channel binding and Kerberos authentication, and a seeded lab.

### Added

- **`ad-doctor view`: the report as one offline HTML file.** It takes a snapshot or a
  JSON report (plus `--baseline`, `--accept`, `--invariants`, `--fixes`, `-o`, `--open`)
  and writes a single page with screens for the overview (tier-0 exposure first, score
  and grade, categories, compound findings, top actions, acceptance and invariant tiles),
  the findings (filters and search kept in the URL, objects with fingerprints, the
  catalog's explanation, fix-script lines, CSV and JSON export), the control paths (each
  drawn as a chain, a node inspector, the shared steps to break first, copy as Mermaid),
  the changes since a baseline, the acceptance and invariant state, and the file itself
  (contents, payload hash, the CSP and a self-check, a print view). Python computes
  everything; the vanilla JavaScript and CSS ship as package data and are inlined, the
  data is embedded escaped, gzip-compressed and base64-encoded, and a meta CSP allows only
  the inlined script and style by hash, with `connect-src 'none'` and Trusted Types. No
  runtime dependency was added. Browser tests (Playwright, `tests/browser/`, their own CI
  job) open every screen of a fixture whose directory names are XSS payloads and fail on
  any executed payload, any request or any console error; pytest greps the script for HTML
  sinks, storage and network APIs.
- **Viewer: trend, encryption, blast radius, drafts.** `ad-doctor view` gained:
  - `--history DIR` and a Trend screen: severity counts and tier-0 exposure per scan as
    inline SVG lines, category scores as a heat map, and markers where the ad-doctor
    version or the set of checks changed, from earlier JSON reports of the same domain.
  - Encryption: a file that embeds graph data is encrypted by default (AES-256-GCM, key
    from PBKDF2-HMAC-SHA256 with 600,000 iterations; pycryptodome writes it, WebCrypto
    reads it). The passphrase comes from `AD_DOCTOR_VIEW_PASSPHRASE` or a prompt, needs 14
    characters, is never written to the file, and the prompt offers a random seven-word
    passphrase. `--no-encrypt` must be explicit. An Unlock screen shows only the version,
    build time and encryption parameters (GCM additional data) and the ciphertext's size
    and SHA-256 (measured by the page, which refuses to unlock an edited file); no account
    name goes into the URL; Lock drops the decrypted data and reloads.
  - `--graph none|paths|full` (default `auto`: `full` up to 50,000 directory objects) and a
    Blast radius screen: account typeahead, verdict, tier-0 paths, everything else the
    account controls grouped by kind with the step that reaches it, and two accounts side
    by side. `full` embeds the control graph as a node table and integer edge arrays and
    searches it in the page with a JavaScript port of `paths.reachable`, checked against
    Python by Node tests (`tests/js/`), in CI on the fixtures and a 3,000-user bench
    domain, and locally also on the lab snapshot. `paths` (large domains) embeds the blast
    radius of the first 25 path holders (an account searched with its implicit groups, as
    `ad-doctor blast-radius` does) and of each `--blast-radius-for ACCOUNT`, computed at
    build time.
  - An acceptance draft builder (*Add to acceptance draft* on a finding, edited on the
    Policy screen) that downloads `accept-draft.toml` in the format `--accept` reads; a
    test parses the page's output with `accept.py`.
  - A drag-and-drop (or file picker) diff against any JSON report on the Changes screen.
  - Edge-kind filters on the Control paths screen.
- `paths.blast_radius()`: the account search behind `ad-doctor blast-radius`, shared with
  the viewer.
- The JSON report carries `"schema": 2` and `checks`, the IDs of the checks that ran.
- **`ad-doctor paths`** lists the control paths to tier 0 (`-f text|json|mermaid`), and
  `--chokepoints` ranks the edges and nodes that the most paths share (`paths.chokepoints`).
- AD-PATH-001 findings carry the paths as data (start principal and each step, with kind,
  its node ID (the SID where it has one) and whether it is tier 0) in a new `data` field of the JSON report, and
  each object's identity in `keys`.
- **Per-check documentation and `ad-doctor explain`.** Each check now has a catalog entry
  (`src/ad_doctor/catalog/<ID>.toml`, shipped in the wheel and read lazily through
  importlib.resources) holding its risk, detection, severity logic, remediation, MITRE
  techniques and references. `ad-doctor explain <ID|alias>` prints it offline as text,
  Markdown or JSON (`--web` opens the online page). SARIF rules gained `fullDescription`,
  `help.markdown` and a `helpUri`; Markdown and JUnit reports and the fix script link each
  finding to its page, and the HTML viewer shows the URL as text to copy. `checks.MITRE` is now derived from the catalog alone (every check and
  invariant has an entry, and a test fails when one is missing). A documentation site
  (Zensical) is generated by `scripts/gen_docs.py` and built with `zensical build --strict`;
  `ad-doctor checks -f json` adds each check's summary and docs URL.

- **CA-side AD CS checks.** ad-doctor reads each enterprise CA's own configuration over
  `\pipe\winreg` (a small MS-RRP client built on smbprotocol, no impacket) and reports
  ESC6 (AD-ADCS-012), ESC7 (AD-ADCS-013), ESC11 (AD-ADCS-014) and ESC16 (AD-ADCS-015),
  plus AD-ADCS-016 when a CA's configuration cannot be read and AD-CHAIN-004 for ESC6 and
  ESC16 on the same CA (a strong-mapping bypass). ESC6 and ESC16 alone are MEDIUM and the
  pair HIGH, matching KB5014754 strong-mapping enforcement, each one level lower when the CA
  holds every request for a manager; ESC7 ManageCA is HIGH, and ManageCertificates is
  graded by whether a published template makes it exploitable. Deny ACEs in the CA's
  descriptor are applied, the admins of the forest's other domains (from within-forest
  trust objects, whose SIDs are now collected) are expected CA managers, and a value that
  is absent or unparseable is reported by AD-ADCS-016 as unknown, never as clean. ESC7
  principals feed the control-path engine and the OpenGraph export. `--no-ca-registry`
  skips the read; opening the pipe trigger-starts RemoteRegistry on the CA and may be
  alerted on by EDR or Defender for Identity (see README and SECURITY.md).
- Snapshots, reports, redacted snapshots and fix scripts the CLI writes are created with
  mode 0600 on POSIX.
- **Local group membership set by Group Policy.** Restricted Groups (`[Group Membership]`
  in `GptTmpl.inf`, GPMC's empty `X__Members =` line included) and GPP Local Groups
  (`Machine\Preferences\Groups\Groups.xml`: actions, delete-all flags, member add/remove,
  disabled items, item-level targeting) are parsed, names resolved to SIDs, and a new pure
  module (`gpo_scope.py`) works out which computers each entry reaches: links on the
  domain, OUs and sites, Block Inheritance, Enforced, disabled links, GPO status, empty
  computer version or missing client-side extension, and security filtering against the
  computer's token (well-known SIDs and foreignSecurityPrincipals included). On writable
  DCs, Restricted Groups rewrite the domain group (reported as such; an entry that empties
  a domain group is noted); GPP Local Groups items are skipped there, as Windows ignores
  them (checked on Server 2025). New checks: AD-GPO-005 (broad groups made local admins),
  AD-GPO-006 (non-tier-0 principals made admins of DCs, CA, Entra Connect or Exchange
  servers) and AD-GPO-007 (RDP, WinRM or DCOM for broad groups or on tier-0 servers;
  Remote Desktop Users counts only where the remote logon right includes it, whose
  holders are resolved to SIDs like group members). Items with item-level targeting are
  listed as applying, with a caveat, and NT AUTHORITY\INTERACTIVE in a local group counts
  as a broad group. The
  control-path engine gains `admin to` / `backup operator on` / `Hyper-V admin on` and
  `member of via GPO` edges plus `hosts sync account` (Entra Connect server to its sync
  account); remote logon rights are separate logon edges the path search does not follow.
  OpenGraph exports them as `ADD_AdminTo`, `ADD_LocalBackupOperator`, `ADD_HyperVAdmin`,
  `ADD_MemberOfViaGPO`, `ADD_HostsSyncAccount`, `ADD_CanRDP`, `ADD_CanPSRemote` and
  `ADD_ExecuteDCOM`, with `gpo`, `caveats` and `traversable` properties. GPO links, WMI
  filter names and local group entries are redacted.

- **Every domain controller is probed.** LDAP signing, SMB signing, the Print Spooler and
  LDAPS channel binding are checked on each DC found in the directory, not only the one
  being scanned, and findings name the DCs that fail. `--single-dc` restores the old
  behaviour. AD-INF-013 lists DCs that could not be reached.
- **Exchange** (AD-ACL-007): Exchange groups holding WriteDacl over the domain
  (PrivExchange), or over every user and group through inheritance, with the Exchange
  servers behind them. Exchange servers are collected as sensitive objects, so control
  paths run through them.
- **Entra Connect** (AD-PRIV-011, AD-ACL-008): sync accounts that can DCSync, whether their
  server is protected like a DC, and who outside tier 0 controls the account or the server.
- **BloodHound OpenGraph export**: `ad-doctor export-graph` writes the control graph as an
  OpenGraph payload. Principals keep their SIDs, so the edges attach to an existing
  SharpHound graph; `--paths-only` keeps just the paths to tier 0.
- **Scale benchmark**: `scripts/bench.py` builds a synthetic enterprise domain and times
  every stage.
- CHANGELOG, SECURITY, CONTRIBUTING, issue and pull request templates, Dependabot.

- **AD-INF-014: rogue DC candidates.** `userAccountControl` is compared with the `server` and
  `nTDSDSA` objects under `CN=Sites`. A computer with a DC flag and no `nTDSDSA` object is
  reported, stays a tier-0 target, loses the DC exemptions in AD-DEL-001, AD-SEC-001, AD-ACC-010,
  AD-PRIV-006, AD-PRIV-007 and the local group logic, and is not probed. The Microsoft Entra
  Kerberos object is matched by structure and left out. Older snapshots keep the old behaviour
  and get a note.
- **AD-ADCS-017: ESC17.** Server Authentication template with an enrollee-supplied subject,
  medium. Templates AD-ADCS-001 or -002 already report are skipped.
- **AD-ACC-012: faked `pwdLastSet`.** For krbtgt, the built-in Administrator, DCs and tier-0
  group members, the BASE read ad-doctor already makes now also asks for
  `msDS-ReplAttributeMetaData`. `pwdLastSet` more than 5 seconds later than the last write of
  `unicodePwd` is a finding, high on krbtgt, medium otherwise. AD-KRB-001, AD-ACC-011 and
  AD-KRB-005 use the older of the two times. Metadata that does not come back gives a note.
- **AD-ADCS-018: CA audit filter.** `AuditFilter` is read with the other CA values. Medium when
  certificate requests are not audited or the value was never set, low when another category is
  off. A value that cannot be read goes to AD-ADCS-016.
- **AD-GPO-008: Onelogon.** `VulnerableChannelAllowList` is read from `GptTmpl.inf` in GPOs that
  reach DCs, with the existing scope logic, and the SDDL is resolved to principals. High for a
  DC, trust account, tier-0 principal or host, broad group, or a group holding any of those,
  medium otherwise. No finding means no GPO sets it; the scan says so in a note.
- **AD-PRIV-012: unreadable tier-0 members.** `member` values of tier-0 groups, nesting included,
  are compared with what the searches returned. A value that did not come back gets one BASE
  read. Foreign security principals, other domains and other naming contexts are skipped.

### Changed

- **AD-KRB-005 is now RC4 readiness.** It follows the CVE-2026-20833 changes and states that it
  reads configuration, not keys. Besides explicit values without AES (medium) it reports accounts
  with an SPN and no value set (low, new), passwords older than the Read-only Domain Controllers
  group, as suspected no AES keys (medium, new), and the same on DC accounts. Computers with an
  SPN are now included, and a value of 0 counts as not set; non-DC computers with no value share
  one line with a count. Domains can see new objects and a
  low finding they did not have. Object text changed to say which case applies, but the identity
  stays the account name, so **fingerprints, baselines and accepted risks are unchanged**. An
  accepted-risk entry that names the account keeps working. The fix script only changes explicit
  values on users with no password doubt; other lines are comments.
- **AD-ACC-011 and AD-KRB-001** use the older of `pwdLastSet` and the unicodePwd metadata, so an
  account with `pwdLastSet` 0 can now be reported when the metadata shows an old password.
- **AD-ADCS-016** also covers the audit filter. Existing lines and fingerprints stay as they were;
  the AuditFilter line is separate.
- **AD-CHAIN-002 and AD-CHAIN-003 no longer depend on the spooler.** A missing spooler used to
  silence them, although PetitPotam and DFSCoerce need none. They now fire with "coercion assumed
  possible" at medium, and at high with a confirmed spooler, so domains with the spooler off can
  see two findings they did not have. AD-CHAIN-003 reads `RestrictSendingNTLMTraffic` from GPOs
  that reach the DCs: denied on every DC gives medium, because a Kerberos relay stays possible,
  and anything else states "not denied" or "unknown". An unreadable GPO next to a deny, or
  exceptions in `ClientAllowedNTLMServers`, give unknown. A GPO with no `GptTmpl.inf` now counts
  as read and empty. AD-CHAIN-002 ignores it, because that path is Kerberos. Their objects and
  fingerprints are unchanged.
- **WriteAccountRestrictions.** A write to the User-Account-Restrictions property set on a computer
  now counts as "write RBCD" in AD-ACL-004, AD-ACL-008 and the graph.
- **AD-INF-004 reads more of dSHeuristics:** characters 3, 8, 21, 28, 29 and 31, with a new low
  grade. The object is still the string, so its fingerprint is unchanged.
- **Netlogon allow lists and other SDDL:** the alias `RO` now means Enterprise Read-only Domain
  Controllers (RID 498), as Microsoft defines it, and the rest of the documented aliases are known.
- **JUnit output** escapes characters XML does not allow.
- **AD-INF-007** says when no dMSA was visible to the scanning account (the default for an
  ordinary user), and no longer says the August 2025 updates close the abuse.
- **`docs/bloodhound.md` and the README** no longer imply that BloodHound walks the export: a
  generic OpenGraph payload gets Search and Cypher, not Pathfinding. The `traversable` property is
  ad-doctor's own marker. The export itself is unchanged.

- **`-f html` on `scan` and `analyze` now writes the viewer page** (the same builder as
  `ad-doctor view`, without fix lines), so there is one HTML code path. The previous
  static report is gone. Its escaping was audited before removal: every directory string
  went through `html.escape`, but the check ID of an accepted risk (read from the accept
  file) was inserted unescaped, and finding links pointed at external sites from a page
  without a CSP. The viewer has neither problem: it never parses markup and links nowhere.
- Well-known principals the snapshot holds no object for (Authenticated Users,
  Everyone, ...) are shown by name in paths and blast radius output instead of as a bare
  SID; AD-PATH-001 keys and fingerprints are unchanged.
- **AD-PATH-001 fingerprints are keyed by the path's start principal**, not by the whole
  rendered path. A path that gets longer or takes another route keeps its fingerprint, is
  not reported as new by `diff` or `--baseline`, and keeps its SARIF `partialFingerprints`.
  Every existing AD-PATH-001 fingerprint changes once with this release; other checks are
  unaffected. Baselines written by older versions still compare correctly: the start
  principal is read from the rendered path. An acceptance can name the start principal
  (`objects = ["Domain Users"]`) to accept that path.
- AD-INF-005, 008, 009 and 010 report DC names instead of the domain name.
- The control-path engine no longer compares every object with every OU: building the
  graph for 100,000 users went from minutes to about two seconds.
- AD-ACL-006 is always HIGH: its MEDIUM grade could never be reached.
- Redaction keeps more findings reproducible: OIDs are no longer rewritten as IPv4
  addresses, Exchange group names are kept, and a computer's `NAME$` and bare `NAME` share
  one token (computer names therefore get different tokens than in snapshots redacted by
  earlier builds). Site names, third-party CA policy module names and IPv6 addresses are
  now redacted too.
- DNs whose RDN value ends in a backslash (`OU=Lab\\,...`) are split correctly when
  working out GPO scope and OU inheritance.
- AD-GPO-003 only judges GPOs Windows would apply: a computer version of 0, a missing
  security extension or a disabled computer side now silences it. The lab's LabDCPolicy
  was such a GPO; the seed now gives it a version and the security extension.

### Security

- The fix script escapes control characters in everything it prints, so a newline in a
  GPO or CA name taken from the directory cannot end a comment and start a command. The
  Markdown report keeps finding objects inside code spans and flattens line breaks in
  directory-sourced text.
- Fix script lines quote directory names for PowerShell with every single-quote
  character it accepts (U+2018 to U+201B as well as `'`), so a name like `x’+$(calc)+’`
  can no longer close the string; AD-PRIV-007 looks the account up with `-LDAPFilter` in a
  verbatim string instead of putting the name in a double-quoted `-Filter`, where `$()`
  would run. A test feeds hostile names through every fix template.
