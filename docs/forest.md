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

`-o` names a directory. One the run creates is owner-only. One that already exists keeps its
mode, and if other local users can read it, `forest.json` says so: the files in it are owner-only,
but their names show the names of the domains. A directory that already holds a forest scan is
refused, so use a new one for each run.

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
- Every such name is checked before anything connects to it: it must be a plain DNS name (no
  scheme, port, path or address) inside the DNS name of the domain it is listed for. Anything
  else gets no connection and is named in `forest.json`, and a domain left with no name to try is
  not evaluated. `--forest-allow-dns SUFFIX` replaces that rule (see
  [where the credentials go](#where-the-credentials-go)). The host you typed is not checked.
- The `objectSid` of the forest root is read once, from a DC of the root (the first DC if it is
  one), and given to each domain's collection, so that Enterprise Admins, Schema Admins and other
  principals of the root count as tier 0 in every domain. If it cannot be read, the forest reads
  as `INCOMPLETE` and the other domains' reports may list those principals as findings.
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
- a disabled `crossRef`, a `crossRef` whose flags cannot be read, one whose `nCName` is not made
  of `DC=` parts alone, or a domain whose analysis failed
- every domain controller name of the domain was refused by the check above
- a domain that was collected but has no report yet

Every check in the rollup that fired anywhere also lists the unread domains as not judged. There
is no forest score, and scores are never averaged.

The forest also reads as `INCOMPLETE` when a domain controller under `CN=Sites` holds a domain, or
the rootDSE names a forest root, that no `crossRef` lists. A `crossRef` hidden from the account
with no server object that names its domain leaves no trace and cannot be detected.

If the writable domain controllers of a domain do not answer, a read-only one is used. The
domain's row has `read_only: true`, the forest notes say so, and the snapshot carries a note that
marks AD-SEC-002 as not evaluated, because attributes in the RODC filtered attribute set, such as
LAPS passwords, are absent on such a DC whatever the account may read. The forest notes also say
when a domain was read from any DC other than the first candidate.

| Exit code | Meaning |
|---|---|
| `0` | every domain and both groups were read, and the gate did not fire |
| `2` | every domain and both groups were read, and `--fail-on` matched |
| `3` | the run worked, but part of the forest was not read (`collect`, `scan` and `rollup --forest`), whether or not `--fail-on` matched in what was read |
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

Each domain gets the same scan as on its own, with the forest root's SID supplied, so these stay
per domain:

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
allow. Nothing further is asked or stored, and nothing is printed.

## Where the credentials go

With `--forest` the credentials go to every host named by the `crossRef`, `server` and `nTDSDSA`
objects of the Configuration partition, as well as to the host you typed: a simple bind sends
the password, an NTLM bind sends a response that can be cracked or relayed. The probes and SYSVOL
reads of each domain also authenticate to that domain's hosts unless `--no-probes` and
`--no-sysvol` are given. Whoever can write those objects can receive the credentials. By default
that takes forest-level or delegated site rights, and a scan may run with an account that has less.

Connections in a forest scan do not follow LDAP referrals, so a referral cannot send credentials
to the host it names. That says nothing about the objects above, which are read on purpose.

What limits it:

- A name is used only if it is a plain DNS name inside the domain it is listed for. This stops a
  host in a foreign namespace, an address and a name with a port or scheme, which would otherwise
  override `--ldaps`. It does not stop a host inside the domain's own name, or a planted `crossRef`
  whose names agree with each other: they cannot be told from a real second tree. Which domain a
  host says it serves is checked only after the bind, so that check protects nothing.
- `--forest-allow-dns SUFFIX` (repeatable) replaces the rule with a list you choose: only hosts
  inside those suffixes get a connection. Use it for a disjoint namespace, or to name your real
  domains so that a planted one is refused.
- `--ldaps` does **not** authenticate the server by itself: any certificate is accepted, for the
  host you typed as for the others, so TLS keeps the password from eavesdroppers but not from the
  host it reaches. `--forest-ca-file PEM` validates the certificate and its name for every DC the
  directory named, and a DC that fails is not bound. It covers the LDAP bind only, not the probes
  or SMB, so use it with `--no-probes --no-sysvol` to send nothing unauthenticated. The host you
  typed is not checked, since it is often a tunnel under another name.
- With a Kerberos ticket no password or reusable response goes to the host, and a host with no
  matching service principal gets nothing.

## How far this has been tested

The lab is a single-domain forest. There, `scan --forest` gives the same findings as a normal
scan. Multi-domain behaviour (child domains, more than one tree, unreachable domains, referrals)
is covered by unit tests against a fake forest and has not been run against a real multi-domain
forest. Please open an issue if yours behaves differently. A scan without `--forest` of a DC
of a child domain ended in a connection error against a local test server, when ldap3 closed the
connection after following the referral for the root's SID; `--forest` is not affected.
