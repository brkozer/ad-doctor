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
