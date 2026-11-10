---
title: Limits
---

# Limits

What ad-doctor does not see or does not judge, check by check. Where it cannot tell, a
report says **not evaluated** with the reason rather than passing the check.

- One domain per run unless `--forest` is given, and then the domains are still scanned apart:
  control paths, findings and scores are per domain, and only Enterprise Admins and Schema
  Admins are joined across domains ([what a forest scan does not join](forest.md#what-a-forest-scan-does-not-join)).
  Forest scanning has run only on a single-domain lab forest and unit tests against a fake
  forest, not against a real multi-domain forest.
- Trusts are inspected from this side only.
- CI runs on Python 3.12 and 3.13 only.
- The CA-side checks (ESC6, ESC7, ESC11, ESC16, audit filter) read the CA's registry over
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
  accepted. ESC10 is checked only as far as Group Policy shows it (AD-ADCS-020): both
  values are commonly set locally on a DC, where an ordinary user cannot read them. ESC12
  (a CA key on an HSM reachable from a shell on the CA) is not checked. HTTPS web enrollment and the CES URLs
  in the directory are found, but whether they enforce EPA is not determined: IIS shows that
  only to a client that authenticates, and the probe sends these endpoints no credentials,
  so AD-ADCS-019 lists them as unknown. Host settings beyond what the DC probes see remain
  out of scope: local group membership that Group Policy sets is covered, changes made
  directly in a computer's local SAM are not.
- GPO reach in the control graph uses the links, Enforced, Block Inheritance, the user and
  computer side flags and security filtering described below. An empty GPO counts,
  because its writer fills it in. Not evaluated: WMI filters (assumed to match, with a
  caveat), Deny ACEs, loopback processing, and whether a user in scope ever logs on. With
  more than one site, a site link is followed only to the domain controllers of that site
  (noted), so paths through member computers there are missed.
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
- AD-KRB-005 reads configuration, not keys: stored keys are not visible over LDAP, so
  "suspected no AES keys" is a heuristic based on the age of the password.
  `DefaultDomainSupportedEncTypes`, the DCs' update level and what clients ask for are
  not visible either.
- `pwdLastSet` is checked against replication metadata for tier 0 only (AD-ACC-012);
  elsewhere it is taken at face value. Metadata that does not come back is noted.
- AD-ACC-013 reads key credentials on tier 0 only, and cannot say who wrote a key: Windows
  Hello for Business looks the same as a planted key. A key this account may not read still
  shows through replication metadata; where that metadata does not come back, the account
  is named in a note and not judged.
- AD-GPO-008 only sees GPOs. No finding means no GPO reaching a DC sets
  `VulnerableChannelAllowList`: a value in a DC's own registry needs admin rights to read.
  Precedence between GPOs is not worked out, and a Deny for a group does not take its
  members off the list.
- AD-GPO-009 to -012 use the effective value of a registry policy per computer, worked out
  from `Registry.pol` with link order, Enforced, Block Inheritance and security filtering. A
  WMI filter, an assumed site or an unreadable GPO that could change the result gives an
  info row, not a verdict. Only GPOs are visible: "no GPO sets it" says nothing about a value
  in a computer's own registry or local policy. Registry items in Group Policy Preferences do
  not count for these four; a note names the GPOs that have them. Deny ACEs on a GPO are not
  read.
- AD-GPO-013 to -016 and AD-ADCS-020 read `audit.csv` and `Registry.xml` with the same
  precedence; `Registry.xml` is played after every `Registry.pol`. A file that does not parse
  is a note and leaves its checks undecided. Audit policy is judged against Microsoft's
  baseline for domain controllers; basic `[Event Audit]` policy alone gives an info row, as
  whether it applies depends on a value on the computer. These checks and AD-GPO-009 to -012
  see Group Policy only. Values set through `GptTmpl.inf` registry entries are not read for
  certificate mapping, BlockNtlmv1SSO or the default Kerberos types.
- AD-ADCS-018 reads the CA's audit filter only. Whether the Certification Services audit
  subcategory is on is not read, so 127 does not prove events are written. A CA where
  auditing was never configured has no such value, and is reported as not set.
- AD-ACC-014 treats the newest of logon, password change and creation as last activity,
  so a machine that stopped logging on but still rotates its password stays quiet. AD-INF-021
  searches the domain and Configuration partitions, not DNS or the schema, and only finds
  what the scan account can see. AD-INF-020 does not check DC addresses against subnets.
- AD-DNS-001 to AD-DNS-003 read the zones stored in Active Directory, not file-backed
  zones, and do not try a zone transfer. A DC that holds no copy of a DNS partition cannot
  answer for it: the report has a note and those zones are not judged. DnsAdmins holds
  every zone by default and is not reported by AD-DNS-002; its members are AD-PRIV-004.
- AD-DNS-004 to AD-DNS-007 read the `dnsNode` objects of forward zones. Names are read one
  at a time and only those a check needs are kept, so a large zone stays small in memory.
  AD-DNS-007 cannot see a name served by another DNS server or by a hosts file. It reports
  only accounts in use, and it complements AD-DEL-005, which is about delegation targets
  no account holds. A zone whose records cannot be listed is named in a note, not passed.
- AD-PRIV-012 compares `member` values with search results. A group whose `member`
  attribute is denied looks empty, and groups of other domains are not read.
- AD-PRIV-013 plays each computer's security templates with Group Policy precedence; a
  right is not merged across GPOs, the one applied last wins. A deny set in the computer's
  own local policy is not visible. An admin workstation you declare yourself is not known to
  the check: accept that OU by ID and fingerprint. On those computers a deny for Administrators
  names the computer's own group: it counts for Domain Admins only, assuming the default local
  membership. A member of a tier-0 group the scan cannot read leaves the check not evaluated,
  unless the deny names a group that holds it.
- AD-PRIV-014: the schema gives Authenticated Users read and list on silos and policies, and
  the lab returns the containers to `adreader`. It is reported as not evaluated when the
  container's DACL no longer lets ordinary users list it. The built-in Administrator is left
  out, and an authentication policy assigned to an account without a silo does not count. The
  user policy's sign-in limit counts unless it is an unconditional allow for Everyone or
  Authenticated Users; what a condition says is not evaluated. A member of a tier-0 group the
  scan cannot read leaves the check not evaluated.
- AD-PRIV-015, AD-ACL-010 and AD-ACC-017 are indicators from replication metadata, with a
  stated window: 30 days before the snapshot, not counting the domain's first 24 hours.
  The metadata says when, not who or what. The extra cost is one BASE read per tier-0 group,
  one for AdminSDHolder, up to four searches for silos and policies, and one per account with
  SID history, up to 500; none of it grows with the number of ordinary users.
- An ordinary user cannot read fine-grained password policies; the report says so
  instead of assuming the default policy applies to admins, and AD-POL-003 stays silent.
  With an account that can read them, a tie on precedence is not broken (Windows uses the
  GUID): a privileged user counts only when every tied policy is weak.
- An ordinary user cannot see dMSAs, so AD-ACL-009 normally reports only a link on the
  replaced account's side, and says who controls the dMSA is unknown. The exact conditions
  of the Ouroboros technique could not be confirmed, so the check tops out at medium.
- Configuration Manager is seen only as it publishes itself: AD-INF-022 and AD-ACL-014 read the
  `System Management` container, and every computer with Full Control on it is taken for a site
  server. The graph counts them as tier 0 whether or not the site manages tier-0 systems, which the
  directory does not show. The site database, SMS Providers and client settings are not visible.
- AD-ACL-011 normally reports "not judged": a plain user cannot read the DKM container, and a domain
  without AD FS looks the same. `thumbnailPhoto` is never requested. One non-tier-0 user or
  managed account with access is taken to be the farm's service account.
- AD-ACL-012 reads seven objects. Other Configuration objects, and the `defaultSecurityDescriptor`
  of schema classes, are not compared with a default, since none could be sourced. AD-ACL-013
  does not report a named delegate with Reset Password or Full Control over an OU, the normal
  shape of delegation.
- AD-ADCS-021 does not check elliptic curve keys, ROCA or revocation, and ignores the signature on
  a self-signed root. AD-INF-023 reports only UNC and URL commands: local commands exist by
  default. AD-INF-024 finds only the dynamic objects the scan account can see.
- AD-GPO-017 and AD-GPO-018 read the files a GPO names; a script that calls another script is not
  followed, a local path is out of scope, and the permissions of another host are not read. A Preferences
  item with item-level targeting, or a task that runs as another account, gets no graph edge, since
  the snapshot cannot tell whether it applies or whose rights it would give. A descriptor with a deny
  or conditional ACE is not judged.
- AD-INF-026 to AD-INF-028 need `--dc-probes`. The 1783 RPC port test of the same family is not
  implemented.
- AD-INF-029 and AD-ADCS-022 compare a build number with the table in `patches.toml`; they do not
  test the flaw, so they stay at medium or below. The table covers Windows Server 2016 to 2025 and
  uses the lowest fixed build Microsoft published, hotpatch included, so a monthly-update host
  between the hotpatch build and the update build is not reported. A note says when the table is
  old or a build is not in it.
- AD-KRB-007 takes `pwdLastSet` of the key account as the age of the key; the key version
  held by Microsoft Entra is not visible from the directory. AD-ACC-016 treats a host name
  whose first label starts with a 15-character computer name as matching.
- Some checks do not fire on the lab DC and are covered by unit tests only: stale accounts
  (AD-ACC-005 and AD-ACC-014 need 90 days to pass), an old DC password (AD-INF-018 needs 45
  days), a gMSA with a long interval (AD-ACC-015: the lab's has 30 days), FRS (AD-INF-019:
  the lab is DFS Replication only), sites and subnets (AD-INF-020: one site, no subnets),
  conflict objects and duplicates (AD-INF-021), identity collisions (AD-ACC-016),
  nonsecure DNS zones and zone ACLs outside tier 0 (AD-DNS-001, AD-DNS-002: the lab has the
  defaults), marshaled names, wildcards, shadowed names and ghost SPN hosts (AD-DNS-004 to
  AD-DNS-007: not seeded, because the lab DC is not changed for these),
  password policy settings (AD-POL-003: `adreader` cannot read them), dMSA control
  (AD-ACL-009: `adreader` cannot see the dMSA and the lab has no migration), key age and
  look-alikes (AD-KRB-007), a missing backup (AD-INF-011 needs a week), a domain
  below level 2016 (AD-INF-003: a 2025 DC needs that level), a DC or CA the probes cannot
  read (AD-INF-013, AD-ADCS-016), large tier-0 groups (AD-PRIV-001, not seeded),
  krbtgt, Seamless SSO and admin password age, the password and DC parts of AD-KRB-005,
  Configuration Manager (AD-INF-022, AD-ACL-014: no site in the lab), AD FS (AD-ACL-011: no
  AD FS, and `adreader` could not read it anyway), a Cloud Sync gMSA (AD-PRIV-016), an old
  connector password (AD-ACC-020), writers on the Configuration partition (AD-ACL-012),
  broad extended rights on an OU (AD-ACL-013), an old smart-card hash (AD-ACC-019), mail on
  admins (AD-PRIV-017: no account in the lab has one), group loops (AD-PRIV-018), weak CA
  certificates (AD-ADCS-021), remote display specifiers (AD-INF-023), dynamic objects
  (AD-INF-024), a GPO that runs a script or a task (AD-GPO-017, AD-GPO-018: none in the lab, whose
  NETLOGON script has default permissions), a tier-0 member server with a name in the directory
  (AD-INF-025), WebClient and SMBv1 on a DC (AD-INF-026, AD-INF-027),
  SID history (AD-ACC-017 needs a real one), an AdminSDHolder change after the domain's first
  day (AD-ACL-010: the lab's ACL was changed on the first day), silos that exist (AD-PRIV-014:
  the lab has none) and a deny logon GPO (AD-PRIV-013: none in the lab), trust SID filtering, the age of a trust (AD-INF-016 needs 40 days to pass;
  the lab test moves the snapshot's date instead), RODCs, SMB signing
  off on a DC, the spooler and the high grade of AD-CHAIN-002 and -003 on Server Core 2025
  (which ships without it), the Entra Kerberos object and
  `unixUserPassword` (confidential on 2025).
