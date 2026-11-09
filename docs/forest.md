# Forest scan

A normal scan reads one domain. `--forest` reads every domain of the forest, one domain at a
time, starting from one domain controller:

```bash
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor' --forest -o forest-2026-11/
ad-doctor rollup --forest forest-2026-11/
```

`collect --forest -o DIR` does the collection only. Analyze each snapshot to a
`<domain>.report.json` next to it, then roll up:

```bash
ad-doctor collect dc01.corp.example --ldaps -u 'CORP\auditor' --forest -o forest-2026-11/
for f in forest-2026-11/*.snapshot.json; do
  ad-doctor analyze "$f" -f json -o "${f%.snapshot.json}.report.json"
done
ad-doctor rollup --forest forest-2026-11/
```

Without `--forest`, every command behaves and prints exactly as before.

## What it writes

`-o` names a directory (created if needed, owner-only). A directory that already holds a forest
scan is refused, so use a new one for each run.

| File | Contents |
|---|---|
| `forest.json` | which domains were read, why any were not, and who holds the forest-root groups; rewritten after every domain, so a run that stops early still says what it did not reach |
| `<domain>.snapshot.json` | an ordinary snapshot: `analyze`, `diff`, `view`, `redact` and the others all take it |
| `<domain>.report.json` | an ordinary JSON report (`scan --forest` only) |
| `<domain>.report.<ext>` | the report in the format asked with `-f`, when that is not JSON |

Files are named by the domain's whole DNS name, so `corp.alpha.example` and `corp.beta.example`
stay apart. Treat the directory like a snapshot. `forest.json` names domains and domain
controllers and lists privileged accounts, and `redact` does not cover it.

`scan --forest` also prints the rollup.

## How the domains are found

- The domains are the `crossRef` objects under `CN=Partitions` in the Configuration partition,
  which every domain controller holds. Those flagged as a domain naming context count
  (`systemFlags` with `FLAG_CR_NTDS_NC` and `FLAG_CR_NTDS_DOMAIN`). The Configuration, Schema and
  application partitions (such as the DNS zones) are left out.
- A `crossRef` that does not mark a naming context of this forest is a referral to some other
  directory. It is listed, and not scanned.
- A domain controller of each domain comes from the `nTDSDSA` and `server` objects under
  `CN=Sites`, writable domain controllers first, with the domain's own DNS name as the fallback
  when no server object names one. DNS SRV records are not used.
- The domain scanned first uses the host, ports and flags you gave. Every other domain uses the
  standard LDAP, SMB and web ports, because `--port` and similar options usually describe a
  tunnel to one host. A probe you turned off (port 0, `--no-probes`) stays off.

## What can go wrong, and how it reads

A domain that cannot be reached, bound or read is **not evaluated**. It is listed with its reason
in `forest.json` and at the top of the rollup, and the rollup says `INCOMPLETE`. These all count:

- no domain controller answers (at most 5 are tried per domain)
- a domain controller turns out to serve some other domain; it is never collected from
- the bind is refused, which also stops trying other domain controllers of that domain, since
  each try counts against the account's lockout
- a disabled `crossRef`, a `crossRef` whose flags cannot be read, or a domain whose analysis
  failed
- a domain that was collected but has no report yet

Every check in the rollup that fired anywhere also lists the unread domains as not judged. There
is no forest score, and scores are never averaged.

| Exit code | Meaning |
|---|---|
| `0` | every domain and both groups were read, and the gate did not fire |
| `2` | `--fail-on` matched in a domain that was read |
| `3` | the run worked, but part of the forest was not read (`collect`, `scan` and `rollup --forest`) |
| `1` | it could not start, for example the first domain controller refused or the forest could not be listed |

## Forest-level facts

`Enterprise Admins` and `Schema Admins` exist only in the forest root but may hold accounts of
any domain. A per-domain scan sees only the members in its own domain, so the forest step reads
them directly: it takes the `member` values of each group, connects to a domain controller of
whichever domain holds each value, and follows nested groups across domains. It adds members
through `primaryGroupID`, which never shows in `member`.

Each holder is listed with its domain, its kind (user, computer or foreign principal), whether
it is enabled and the groups it came through. A foreign principal is named by SID and not
followed. A value that cannot be followed is listed as not resolved: a domain that was not read,
a value outside the forest, an entry not returned, a read refused, or a nesting past the limit of
2000 reads per group. A group then reads as partial. A group with no visible members also reads
as partial, because an empty list and a list hidden from this account look the same.

## What a forest scan does not join

The per-domain scans are the same scans, so these stay per domain:

- **Control paths and blast radius.** Each domain has its own graph. An access control entry,
  group membership or SID history that points into another domain is not an edge to that domain,
  so a path that crosses a domain boundary is not shown. The exposed-user figures are per domain.
- **Group membership across domains**, other than the two groups above. A domain's report lists
  members from that domain.
- **The same person in several domains.** Accounts are not correlated across domains.
- **Trusts.** Each domain reports its own trust objects. Paths through a chain of trusts are not
  worked out, and the forest scan does not cross into another forest.
- **Forest-wide objects.** The Configuration and Schema partitions are read again in each
  domain, so a finding about, for example, a certificate template appears in every domain's
  report, and the object counts in the rollup add those repeats.

## Options and credentials

`--only`, `-f` and `--fail-on` apply to every domain. `--baseline`, `--accept`, `--invariants`,
`--fixes`, `--preflight`, `--tier0` and `--tier0-file` describe a single domain and are refused
with `--forest`.

Credentials are the ones of the normal scan: `AD_DOCTOR_PASSWORD`, the usual prompt once at the
start when it is not set, or a Kerberos ticket. Each domain is bound with those same credentials,
so the account must be able to sign in to every domain, which a forest's own trusts normally
allow. Nothing further is asked, stored or printed. Connections in a forest scan do not follow
LDAP referrals, so a referral cannot send credentials to the host it names.

## How far this has been tested

The lab is a single-domain forest. There, `scan --forest` gives the same findings as a normal
scan. Multi-domain behaviour (child domains, more than one tree, unreachable domains, referrals)
is covered by unit tests against a fake forest and has not been run against a real multi-domain
forest. Please open an issue if yours behaves differently.
