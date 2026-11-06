# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/). Check IDs are stable: a check may change its
logic or severity between versions, but an ID is never reused for something else.

## [Unreleased]

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
