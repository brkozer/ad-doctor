# What-if and plan

Two commands answer two questions on a snapshot, never on AD:

- **`ad-doctor whatif`:** if these rights, memberships or links were gone, which tier-0
  paths close, which are rerouted, how does exposure change, and which findings would
  clear or appear?
- **`ad-doctor plan`:** what is the cheapest set of removals that closes every path
  ad-doctor sees, is it a proven minimum, and in which order should it go?

Neither command opens a connection to a directory. The snapshot is changed in memory to
recheck the findings and is never written back. Every fix line runs with `-WhatIf` or is
commented out.

```bash
ad-doctor plan snap.json                         # the plan, as text
ad-doctor plan snap.json -f toml -o plan.toml    # the plan file, kept in the repository
ad-doctor plan snap.json -f markdown -o plan.md  # one section per step, for tickets
ad-doctor plan snap.json -f ps1 -o plan.ps1      # the fix lines, all -WhatIf

ad-doctor whatif snap.json --remove adminsdholder:helpdesk --account alice
ad-doctor whatif new.json --plan plan.toml --check   # after the changes, in CI
```

## A plan on the lab

```text
Plan on the adlab.test snapshot of 2026-11-07 22:51 UTC (simulated; AD unchanged)

Goal: close the paths of enabled users outside tier 0.

Tier-0 paths:
                                before       after
  exposed users               25 of 26       1 of 26
                                   96%          3%
  principals with a path            12           4
  routes (changes needed)           15           0

Steps (heuristic order; each closes in the snapshot what it says):
   1. remove the ACEs of Domain Users on templates LabESC1, LabESC2, LabESC3  ->  exposed 8, ...
        c:2abd2340d93c  remove the ACEs of Domain Users on template LabESC1  (cost 1)
        ...
   8. take 6 rights away from helpdesk  ->  exposed 1, principals 4, routes 0
        c:798fc67fc112  remove the ACEs of helpdesk on AdminSDHolder  (cost 1)
          SDProp removes the copies on 20 protected objects at its next run (60 minutes)
        ...

15 changes (cost 17): proven minimum (for paths ad-doctor sees).
...
Cannot be closed by removing a right (needs a decision):
    MSOL_0a1b2c3d4e5f -[DCSync (kept: Entra Connect needs DCSync)]-> adlab.test
      -> treat MSOL_0a1b2c3d4e5f as tier 0 ([assume] tier0), or move what makes the route
```

The one user left exposed reaches tier 0 only through the Entra sync account, whose DCSync
is kept on purpose. The plan says so instead of proposing to break sync.

## Naming a change

Every form turns into change IDs before anything runs, and the output prints what each
one became.

| Form | Example |
|---|---|
| change ID | `c:5d1e0a7b2c44` |
| finding fingerprint | `fp:3fa1c2d4e5f60718` (a finding of the table below; a setting such as AD-KRB-003 is refused) |
| step of a path | `fp:<AD-PATH-001 fingerprint>#2`, `path:"Domain Users"#1` |
| edge | `edge:helpdesk->"Domain Admins":"full control"`, or the `edge:<12 hex>` ID of a `paths --chokepoints -f json` row |
| ACE | `ace:"OU=Team,DC=lab,DC=test":helpdesk`, `inherited-ace:...`, `adminsdholder:helpdesk` |
| owner | `owner:"CN=Owned,OU=Lab,DC=lab,DC=test"` |
| membership | `member:"Domain Admins":grp171` |
| Group Policy | `gplink:"<GPO>":"<container DN>"`, `gpo-entry:"<GPO>":Administrators:"Domain Users"` |
| AD CS | `template:LabESC1:enroll:"Domain Users"`, `template:LabESC1:enrollee-supplies-subject`, `pki:NTAuthCertificates:helpdesk`, `ca:<CA>:helpdesk:ManageCertificates` |
| gMSA, delegation | `gmsa:<gMSA>:<reader>`, `delegation:<account>:unconstrained` (or `protocol-transition`, `rbcd`, `constrained:<SPN>`) |
| every right of a trustee | `all-rights-of:helpdesk`, `all-rights-of:helpdesk:tier0` (only those on a path) |

Names are a sAMAccountName, a name, a DN or a SID. Two matches are an error that lists
them. No match means the change is **absent** in this snapshot: a status, not an error,
unless `--strict` or `--check` is given. Naming an SDProp copy or an inherited copy prints
**rewritten**: it resolves to the AdminSDHolder ACE or the container ACE it comes from,
because removing only the copy would not last. Edges that are not a change (an OU's
`contains`, GPO scope, a sync server holding its sync account, the nesting AD enforces)
are refused with where to cut instead.

## plan

The sources are the enabled users outside tier 0 and their implicit groups (Everyone,
Authenticated Users, Users, the primary group): the population of the exposure figure.
`--goal all-paths` uses every AD-PATH-001 holder instead, and `--from NAME` (repeatable)
named principals.

The plan is a minimum cut of a flow network built on the path subgraph, so its cost is
the cheapest in the model whenever the model is exact (see How it works). The output says
**proven minimum (for paths ad-doctor sees)** only when that holds or the lower bound
meets the plan; otherwise it says "plan of N changes" with the lower bound. The order of
the steps is a heuristic: each step takes the change or bundle that closes the most users
per cost, then principals, then routes (changes still needed). A bundle is "close this
node": the cheapest part of the plan that cuts one of the 20 nodes most paths run through,
which is how the three ESC templates that Domain Users enrolls in go together.

| Option | |
|---|---|
| `--near tier0` / `source` | of equal-cost cuts, the one nearest tier 0 (default: the rights over tier-0 objects ad-doctor already flags) or nearest the sources; the output says when the other one differs |
| `--max-changes K` | a budget: the same greedy over every change in the network, stopped at K; labelled heuristic, no guarantee |
| `--tier0 NAME` | treat a node as tier 0 (an assumption, never a change): the honest answer for an Entra Connect server, a jump host or a CA admin box |
| `--keep SPEC` | never propose this change (for this run; use `[[keep]]` in a plan file to keep it) |
| `--allow warn` | also propose the Entra sync account's DCSync |
| `--allow KIND` | propose only changes of these kinds (repeatable) |
| `--accept FILE` | accepted AD-PATH-001 holders are not sources; other accepted findings keep the changes behind them |
| `--invariants FILE` | `[dcsync] allowed` and the declared members of `[groups]` are kept |
| `--plan FILE` | take the `[[keep]]` entries and `[assume] tier0` of a plan file |
| `--paths-only` | skip the findings recheck |

`plan` rechecks the findings once, on the whole plan, and stops with "model mismatch"
if the AD-PATH-001 holders or the exposure of the changed snapshot differ from what the
masked graph predicted.

## whatif

`whatif` evaluates `--remove SPEC` (repeatable) and the open changes of `--plan FILE`.
It prints each change with its status, warnings and notes; the tier-0 paths before and
after (exposed users, principals with a path, routes); the principals whose paths close
in the snapshot, the ones **rerouted** (still a path, another one, same fingerprint) and
the ones still open; the sources no removal closes; the findings that would clear, appear
or change, rechecked on the changed snapshot; and, per `--account`, the blast radius
before and after. `--paths-only` skips the findings.

## The plan file

`plan -f toml` writes it. It holds decisions, never results: what to change, what to keep
and what to assume.

```toml
schema = 1

[plan]
domain = "adlab.test"
domain_sid = "S-1-5-21-..."
made_against = 2026-11-07T22:51:51Z
made_by = "ad-doctor 0.2.0 plan"
goal = "exposure"

[assume]
tier0 = ["ENTRA01$"]

[[change]]
id = "c:798fc67fc112"
kind = "adminsdholder-ace"
trustee = "S-1-5-21-...-1117"
label = "remove the ACEs of helpdesk on AdminSDHolder"
reason = "helpdesk needs password reset only"   # optional, like ticket, owner, due
due = 2026-11-30

[[keep]]
kind = "ace"
object = "dc=adlab,dc=test"
trustee = "S-1-5-21-...-1137"
reason = "Entra Connect needs DCSync"
expires = 2027-06-30                           # required, as in the accept file

[expect]
closes_all = true
max_exposed_percent = 4
max_holders = 4
```

The kind and its identity fields decide; `id` is a checksum of them, so an `id` that does
not match means the file was edited. Strings are escaped like the viewer's accept drafts.
`plan` writes `[expect]` from what the plan reaches. With `--keep` or `--allow KIND` it
leaves `closes_all` out, because the file does not record them.

Against any later snapshot each `[[change]]` is:

| Status | Meaning |
|---|---|
| done | the fact is gone from the snapshot |
| open | still there |
| overdue | open past its `due` date (compared with the snapshot's date) |
| stale | does not resolve in this domain: renamed, deleted or a typo |
| ineffective | open, but removing it closes nothing now on top of the other changes: the paths go around it |

An expired `[[keep]]` is a candidate again, with a note.

## CI

```yaml
- run: ad-doctor collect dc01 -u 'CORP\auditor' -o snap.json
- run: ad-doctor whatif snap.json --plan plan.toml --check -f json -o whatif.json
```

| Exit | |
|---|---|
| 0 | ok |
| 1 | error: usage, an ambiguous name, an absent change under `--strict` or `--check`, a model mismatch |
| 2 | a gate failed: `[expect]` under `--check`, `--fail-if-exposed N` (more than N users exposed after the changes), `--fail-on SEVERITY` (a finding at that level would appear) |
| 3 | plan rot under `--check`: a stale or ineffective change, an edited `id`, or a snapshot of another domain |

## Fix lines

`-f ps1` uses the framing of the remediation script `analyze` writes: a header,
`#Requires`, then one section per change with its lines and the findings it is expected to clear. An ACE removal reads the ACL,
takes out only the explicit rules with that SID, rights mask and object type
(`RemoveAccessRuleSpecific`) and writes it back with `Set-Acl -WhatIf`. It never uses
`dsacls /R`, which removes every ACE of the trustee on the object. An AdminSDHolder change
says how many protected objects hold a copy; an inherited-ACE change says how many objects
below lose it. Owner changes, CA rights and Restricted Groups entries have no dry run, so
their lines are comments. `-f markdown` adds a rollback line per change, written from the
snapshot's values.

## Changes

A change removes one snapshot fact; the control-graph edges it made go with it.
`paths.build(snapshot, provenance=True)` records, for every edge, the change that made it,
at the place where the edge is made. The graph itself is the same with and without it.

| Kind | Identity | Edges it removes | Cost |
|---|---|---|---|
| `ace` | object, trustee | the trustee's explicit-ACE edges on that object (rights, DCSync, link GPOs, the GPO with its filter changed) | 1 |
| `inherited-ace` | OU or container, trustee | the same, when the trustee has an inheritable ACE there, plus the `(inherited)` edges on every object below | 1 |
| `adminsdholder-ace` | trustee | its edge into AdminSDHolder and the equal ACE copies on every protected object | 1 |
| `owner` | object | `owns` (the new owner is a tier-0 principal of the operator's choice) | 1 |
| `member` | group, member | `member of` | 1, 5 into a tier-0 group |
| `gplink` | GPO, container | `linked to ...` and `GPO applies to` from that link | 3 |
| `gpo-entry` | GPO, group SID, member SID | `admin to via GPO`, `member of via GPO` | 2 |
| `template-ace` | template, trustee | `enroll (ESC1-3)`, `write template (ESC4)` | 1 |
| `template-flag` | template, flag | every `enroll (ESC1-3)` into the template when no other ESC condition is left | 10 (warn) |
| `pki-ace` | PKI object, trustee | ESC5 `full control` | 1 |
| `ca-right` | CA, trustee, right | ESC7 | 3 |
| `gmsa-reader` | gMSA, reader | `read gMSA password` | 1 |
| `delegation` | account, kind | none: delegation is not a graph edge, so only findings change | 1 |

The flags of `template-flag` are `require-approval`, `enrollee-supplies-subject`,
`any-purpose-eku` and `request-agent-eku` (an EKU only goes when another one stays,
because an empty list means any purpose).

A change ID is `c:` and the first 12 hex digits of a SHA-256 over the kind and the
identity fields, DNs in lower case and SIDs in upper case, like a finding fingerprint. It
stays the same while the fact exists. A redacted snapshot gives other IDs, so a plan made
from one does not resolve against the real snapshot.

**Not removable:** `contains` (ACL inheritance structure), GPO scope plumbing,
`hosts sync account`, the edges out of a GPO with its filter changed (the right into that
node is the change), the links of the two default domain policies, the nesting AD enforces
(Domain Admins and Enterprise Admins in Administrators), implicit membership (Everyone,
Authenticated Users, Users and primary groups are where paths start, not edges), and
everything out of a tier-0 node.

**Warn class** (cost 10, proposed only when nothing of equal cost avoids it, with a
warning): rights of Exchange Windows Permissions and Exchange Trusted Subsystem, of Key
Admins, default grants Windows expects (Pre-Windows 2000 Compatible Access, Cert
Publishers), taking the built-in Administrator out of a tier-0 group, and `template-flag`.

**Kept** changes are never proposed: the Entra sync account's DCSync by default (`--allow
warn` lifts it), `[[keep]]` entries, `--keep`, accepted findings, `[dcsync] allowed` and
the declared members of `[groups]` from an invariants file. Accepted AD-PATH-001 holders
are not sources.

**Not in this version:** disabling an account (an account that is disabled keeps its
rights in the model, and whoever controls it can enable it again), narrowing an ACE change
to some of its rights, and adding rights.

## Findings a change can clear

The recheck on the changed snapshot is the authority; this table is what `fp:` names
resolve through and what "expected to clear" in the output and fix lines come from.

| Change | Clears (for the object concerned) | Can appear |
|---|---|---|
| `ace` on the domain head | AD-ACL-001 (DCSync), AD-ACL-003, AD-ACL-007, AD-GPO-002 | |
| `adminsdholder-ace` | AD-ACL-002; AD-ACL-004 on the copies | |
| `ace` / `inherited-ace` on tier-0 objects | AD-ACL-004, AD-ACL-008 | |
| `gmsa-reader` | AD-ACL-006 | |
| `ace` on a GPO or OU | AD-GPO-001, AD-GPO-002, AD-GPO-004 | |
| `gpo-entry` | AD-GPO-005 to AD-GPO-007 | |
| `template-ace` | AD-ADCS-001 to AD-ADCS-004, AD-ADCS-006 to AD-ADCS-008, AD-ADCS-017 for that template | |
| `pki-ace` / `ca-right` | AD-ADCS-005 / AD-ADCS-013 | |
| `member` | AD-PRIV-003, AD-PRIV-004, AD-PRIV-006, AD-PRIV-008, AD-PRIV-009, AD-INV-001 | AD-ACC-006 |
| `delegation` | AD-DEL-001 to AD-DEL-005, AD-CHAIN-002 | |
| any | AD-PATH-001 objects whose holder loses its path | AD-INV-* |

Settings, probes, account hygiene, policies, trusts, CA registry flags and SYSVOL secrets
are never cleared by a removal; `--remove fp:` on them says so.

## Where the snapshot and AD differ

- **SDProp.** An ACE of a trustee on a protected object (adminCount, a protected group,
  Administrator, krbtgt, or a principal with inheritance turned off) that equals one of the
  trustee's ACEs on AdminSDHolder belongs to `adminsdholder-ace`. SDProp would put the copy
  back within the hour, so the copy is never a change of its own. Removing the
  AdminSDHolder ACE removes the copies too, as the next SDProp run would.
- **Inheritance.** Snapshots from this version keep the INHERITED_ACE flag
  (`ace_inheritance_checked` in the file). An inherited copy belongs to the nearest OU or
  container above it with an explicit inheritable ACE of the same trustee. Older snapshots
  cannot tell an inherited copy from an explicit ACE, so there the copy is a change of its
  own and the output says so: a plan can be too large, never too small.
- **One AD ACE, two lists.** A container ACE that applies to the container and is
  inherited is one change, as in AD.
- **GPO-enforced membership.** A member that Restricted Groups puts into a domain group
  has its own `member of via GPO` edge, so closing it takes both the `member` and the
  `gpo-entry` change. The cut finds that by itself.
- **Monotone.** Every change only removes facts; fewer facts never add an edge.

## How it works

**Forward.** Level 1 masks the graph: the edges of the changes are dropped and the rest
keep their order, so the shortest paths, ties included, are those of a graph built from
the changed snapshot. Changes that can move GPO scope are not masked but rebuilt: `gplink`,
and a membership or GPO ACE that a security filter reads. Level 2 takes the changes out of
the snapshot in place (one mutator per kind, each reporting what it removed) and runs every
check again. The AD-PATH-001 holders and exposure of both levels must agree; a difference
stops the run as a model mismatch, a bug to report.

**Reverse.** The flow network covers the path subgraph only: what a source reaches and
what reaches tier 0. Each change is one arc with its cost, an edge made by a change runs
through that arc, edges that cannot be removed and kept changes are infinite, and tier 0
is the sink. The maximum flow is the cost of the cheapest set of changes that closes every
source, in this model.

- **Exact when** every change is one arc that joins no routes that do not exist: all of
  its edges share a source node, or all share a target (tier 0 counts as one). The count of
  changes where that fails is reported; with any, the cut is still valid but is only called
  minimal when a lower bound (paths whose changes are pairwise disjoint) meets it, and
  changes it does not need are dropped one by one.
- **Cost first, then no warn class at equal cost, then fewest changes**, through the
  capacities.
- **Two cuts.** The cut nearest tier 0 (default) and the one nearest the sources are each
  unique; when they differ, another cut of equal cost exists.
- **Unclosable.** A source that reaches tier 0 over infinite arcs only is listed with the
  route and the suggestion to treat the node as tier 0.

## Measured

On one core of an Intel Xeon Gold 6138, Python 3.12, `scripts/bench.py` domains (the
generator now lists nested Domain Admins members as tier 0, as a collection does), one run
at a time under a 5 GB limit. Times are the whole command, loading included.

| Snapshot | Plan | Plan, paths only | What-if with findings (the plan file) | Peak | Result |
|---|---|---|---|---|---|
| lab (49 accounts) | 0.6 s | | 0.6 s | 50 MB | 15 changes, cost 17, proven minimum; 25 -> 1 users exposed |
| bench 10,000 users | 4.5 s | 3.4 s | 3.3 s | 0.13 GB | 29 changes, cost 29, proven minimum; 4,665 -> 0 users exposed |
| bench 250,000 users | 80 s | 46 s | 77 s | 1.9 GB | 23 changes, cost 23, proven minimum; 6,735 -> 0 users exposed |

At 250,000 users loading the snapshot and building the provenance graph take most of the
paths-only time; with findings, every check runs twice (before and after the changes).
The bench domain has few paths for its size, so its plan is one step of all its changes.

## In the viewer

The HTML viewer shows a plan or a what-if result on its What-if screen:

```bash
ad-doctor plan snap.json -f json -o plan.json
ad-doctor view snap.json --whatif plan.json
```

The JSON must come from the same snapshot file (its SHA-256 is checked) or, for a
JSON report, the same domain. The screen shows what was computed on the command line; it
does not run a new plan in the page.

## Limits

The commands work on the snapshot. What happens in AD after a change differs:

- SDProp runs every 60 minutes; inheritance changes at an OU reach every object below it.
- adminCount stays on removed members (AD-ACC-006).
- Group Policy applies at the next refresh, and local groups keep members a GPO added.
- Kerberos tickets keep group memberships until they expire (10 hours by default).
- Certificates already issued stay valid until they expire or are revoked.
- Other DCs see a change after replication.
- Edges ad-doctor does not see stay: sessions, local admin outside Group Policy,
  delegation as a path, trusts, Deny ACEs.
- What an attacker already planted (shadow credentials, added SPNs, other persistence) is
  not undone. Collect again and run `whatif --plan plan.toml --check`.
