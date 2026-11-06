# Permissions needed

An enabled domain user is enough. ad-doctor needs no group memberships and no delegated
rights; it reads only what an ordinary authenticated user can read, and it never writes to
the directory.

## What it reads over LDAP

- users, computers, groups, OUs, GPOs and trusts
- AD CS certificate templates, enrollment services and issuance-policy OIDs
- gMSAs and their password-read permissions
- the replication metadata of the domain head (for the last backup date) and of tier-0
  accounts (for the last real password change, and key credentials that cannot be read)
- `msDS-KeyCredentialLink` of tier-0 accounts, CA servers and Entra Connect sync accounts
  and servers; the keys themselves are not kept
- `sPNMappings` on `CN=Directory Service`, to tell which SPNs `HOST/` answers for
- the owners and DACLs of the security-critical objects
- `server` and `nTDSDSA` objects under `CN=Sites`, and `crossRef` objects under `CN=Partitions`
- one BASE read of each `member` value of a tier-0 group that no search returned, at most 500
  per scan

Security descriptors are requested with the SD-flags control for owner and DACL, which
ordinary users may read, and parsed by a small built-in parser (`sd.py`).

## Group Policy scope

For the local-group and remote-logon checks (AD-GPO-005 to -007) ad-doctor also reads
`gPLink` and `gPOptions` on the domain, every OU and every site, each GPO's status, version
and client-side-extension attributes, WMI filter names, and which site each DC is in. From
SYSVOL it reads Group Policy Preferences (passwords and Local Groups), `GptTmpl.inf`
security templates (including Restricted Groups) and logon scripts, keeping only paths, line
numbers, account names and setting values &mdash; never a secret.

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
