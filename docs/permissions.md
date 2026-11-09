# Permissions needed

An enabled domain user is enough. ad-doctor needs no group memberships and no delegated
rights; it reads only what an ordinary authenticated user can read, and it never writes to
the directory.

## What it reads over LDAP

- users, computers, groups, OUs, GPOs and trusts
- AD CS certificate templates, enrollment services and issuance-policy OIDs
- gMSAs, their password-read permissions and password interval
- the replication metadata of the domain head (for the last backup date) and of tier-0
  accounts (for the last real password change, and key credentials that cannot be read)
- `msDS-KeyCredentialLink` of tier-0 accounts, CA servers and Entra Connect sync accounts
  and servers; the keys themselves are not kept
- `sPNMappings` on `CN=Directory Service`, to tell which SPNs `HOST/` answers for
- the owners and DACLs of the security-critical objects, and of the accounts given with
  `--tier0-file` ([declared tier 0](declared-tier0.md)), one BASE read each
- `server` and `nTDSDSA` objects under `CN=Sites`, and `crossRef` objects under `CN=Partitions`
- `site`, `server`, `subnet` and `siteLink` objects under `CN=Sites`; `msDFSR-Flags` of `CN=DFSR-GlobalSettings,CN=System` and the FRS and DFS Replication SYSVOL subscriptions under each DC; objects whose name holds `CNF:` and accounts named `$DUPLICATE-*`
- `userPrincipalName`, `msDS-KrbTgtLink` and the dMSA links on accounts (`msDS-ManagedAccountPrecededByLinkBL`, `msDS-SupersededManagedAccountLink`)
- fine-grained password policy settings and `msDS-PSOAppliesTo`, when the account may read them (an ordinary user normally cannot), with one BASE read of `groupType` for each linked group, at most 500 per scan
- dMSA owner, DACL, `msDS-DelegatedMSAState` and `msDS-GroupMSAMembership`, when the account may see them (an ordinary user normally cannot)
- `msDS-AllowedToActOnBehalfOfOtherIdentity` (who may delegate to a computer; a list the scan cannot parse is a note, and its edges are left out)
- `dnsZone` objects under `CN=MicrosoftDNS` in the DomainDnsZones and ForestDnsZones partitions and under `CN=System` (`name`, `dnsProperty`, owner and DACL), and the `objectSid` of DnsAdmins; no zone transfer is attempted
- `dnsNode` objects of forward zones (`name`, `dnsRecord`, `dNSTombstoned`), with one BASE read of the owner of each marshaled, wildcard or well-known name, at most 200 of each kind per scan
- one BASE read of each `member` value of a tier-0 group that no search returned, at most 500
  per scan
- `msDS-ReplValueMetaData` and `msDS-ReplAttributeMetaData` of each tier-0 group (at most 200), of
  `CN=AdminSDHolder,CN=System`, and of each account with `sIDHistory` (at most 500)
- `msDS-AuthNPolicySilo` and `msDS-AuthNPolicy` objects under `CN=AuthN Policy Configuration`
  (Authenticated Users may read them by the schema's default), and the DACL of `CN=AuthN Silos`
  when none comes back

Security descriptors are requested with the SD-flags control for owner and DACL, which
ordinary users may read, and parsed by a small built-in parser (`sd.py`).

## Group Policy scope

For the local-group and remote-logon checks (AD-GPO-005 to -007) ad-doctor also reads
`gPLink` and `gPOptions` on the domain, every OU and every site, each GPO's status, version
and client-side-extension attributes, WMI filter names, and which site each DC is in. From
SYSVOL it reads Group Policy Preferences (passwords and Local Groups), `GptTmpl.inf`
security templates (including Restricted Groups), `Machine\Registry.pol`, `audit.csv`, Preferences `Registry.xml` and logon scripts,
keeping only paths, line numbers, account names and setting values &mdash; never a secret. From
`Registry.pol` it keeps only the values its checks read; a value named like a password is
reported by location alone.

## Forest-wide objects and AD FS

The scan also reads, with an ordinary account: the DACLs of the Schema and Configuration
partition heads and five containers under them, `cACertificate` of the published CA certificates,
`adminContextMenu` and `shellContextMenu` of the display specifiers, `msDS-Other-Settings`,
objects with the `dynamicObject` class, and the `System Management` container with the
Configuration Manager objects in it. Of the AD FS DKM containers it asks for the DACL only: it
never requests `thumbnailPhoto`, the attribute that holds the key. A plain user normally cannot
read them, so that check is reported as not judged.

## Forest scan

With `--forest` the same account is used for every domain of the forest, so it must be able to
sign in to each of them; a forest's own trusts normally allow that, and no extra right is needed.
Besides the per-domain reads above it reads, as an ordinary user can:

- the `cn`, `nCName`, `dnsRoot`, `nETBIOSName`, `systemFlags` and `Enabled` attributes of the
  `crossRef` objects under `CN=Partitions`
- the `msDS-HasDomainNCs`, `hasMasterNCs`, `msDS-hasMasterNCs` and `objectCategory` attributes of
  `nTDSDSA` objects, and `dNSHostName` of `server` objects under `CN=Sites`
- `objectSid`, `objectClass`, `sAMAccountName`, `member` and `userAccountControl` of Enterprise
  Admins, of Schema Admins and of each of their members, with one BASE read each on a domain
  controller of the member's own domain, at most 2000 per group, and accounts whose
  `primaryGroupID` names one of these groups or a group nested in them

A domain or member the account cannot read is reported as not evaluated or not resolved, never
as clean. The account's credentials go to every domain controller named in the Configuration
partition, so use an account you would accept that for: see
[where the credentials go](forest.md#where-the-credentials-go).

## Scripts that GPOs run

From SYSVOL it also reads `scripts.ini`, `psscripts.ini` and Preferences `ScheduledTasks.xml`,
keeping the file each one runs and never its arguments. For the files in SYSVOL and NETLOGON it reads
the owner and DACL with `READ_CONTROL` only: an ordinary user can do that by default. A file it
cannot read, or a descriptor with a deny ACE, is reported in a note as not judged, not as passing.
Other hosts named in those files are not contacted.

## Patch level

Over `\pipe\winreg` it reads `CurrentBuildNumber` and `UBR` under
`SOFTWARE\Microsoft\Windows NT\CurrentVersion` on each DC and CA. An ordinary domain user could
read it on the lab; a host with a hardened `winreg` may refuse. A host where it cannot be read is
reported in a note as not judged, not as passing. `--no-patch-level` turns it off.

## Authentication

- **NTLM** with the account you give it, including channel binding where the DC enforces it.
- **Kerberos** from the current ticket cache (`-k`, after `kinit`); install the optional
  `kerberos` extra for this.

ad-doctor runs from any Linux box with an ordinary account: no domain-joined host, no RSAT
and no admin rights.

## What it never does

It does not modify any object, create accounts, or write to the CA, the CA database or any
registry. The only things it does beyond LDAP reads are the active [probes](probes.md), all
read-only. `--no-probes` turns them off, except the SYSVOL read, which has `--no-sysvol`.
