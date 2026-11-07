# What-if engine

What-if answers two questions on a snapshot, never on AD:

- **Forward:** if these rights, memberships or links were gone, which tier-0 paths close,
  how does exposure change, and which findings would clear or appear?
- **Reverse:** what is the cheapest set of removals that closes every path ad-doctor sees,
  and in which order?

This version has the engine (`ad_doctor.provenance`, `changes`, `whatif` and `cut`). The
`whatif` and `plan` commands that print its results, the plan file and the fix lines are
not part of it yet. Nothing in it opens a connection to a directory.

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
stays the same while the fact exists.

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

**Kept** changes are never proposed: the Entra sync account's DCSync by default (`allow
warn` lifts it), `[[keep]]` entries, `[dcsync] allowed` and the declared members of
`[groups]` from an invariants file. Accepted AD-PATH-001 holders are not sources.

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
  own: a plan can be too large, never too small.
- **One AD ACE, two lists.** A container ACE that applies to the container and is
  inherited is one change, as in AD.
- **GPO-enforced membership.** A member that Restricted Groups puts into a domain group
  has its own `member of via GPO` edge, so closing it takes both the `member` and the
  `gpo-entry` change. The cut finds that by itself.
- **Monotone.** Every change only removes facts; fewer facts never add an edge.

## Forward

Level 1 masks the graph: the edges of the changes are dropped and the rest keep their
order, so the shortest paths, ties included, are those of a graph built from the changed
snapshot. Changes that can move GPO scope are not masked but rebuilt: `gplink`, and a
membership or GPO ACE that a security filter reads.

Level 2 takes the changes out of the snapshot in place (one mutator per kind, each
reporting what it removed, so a change that removes nothing is reported as absent) and
runs every check again. That also shows findings that would appear, such as AD-ACC-006
after a member leaves a protected group. The AD-PATH-001 holders and exposure of both
levels must agree; a difference stops the run as a model mismatch.

## Reverse

The flow network covers the path subgraph only: what a source reaches and what reaches
tier 0. Each change is one arc with its cost, an edge made by a change runs through that
arc, edges that cannot be removed and kept changes are infinite, and tier 0 is the sink.
The maximum flow is the cost of the cheapest set of changes that closes every source, in
this model.

- **Exact when** every change is one arc that joins no routes that do not exist: all of
  its edges share a source node, or all share a target (tier 0 counts as one). The count of
  changes where that fails is reported; with any, the cut is still valid but is only called
  minimal when a lower bound (paths whose changes are pairwise disjoint) meets it.
- **Cost first, then no warn class at equal cost, then fewest changes**, through the
  capacities.
- **Two cuts.** The cut nearest tier 0 (default) and the one nearest the sources are each
  unique; when they differ, another cut of equal cost exists.
- **Unclosable.** A source that reaches tier 0 over infinite arcs only is listed with the
  route and the suggestion to treat the node as tier 0 (`[assume] tier0`), which is the
  honest answer for an Entra Connect server, a jump host or a CA admin box.
- **Order (heuristic).** The cut is ordered by a greedy that takes, at each step, the
  candidate that clears the most users per cost, then holders, then routes (changes still
  needed). Candidates are each remaining change and, for the 20 nodes most paths run
  through, the cheapest bundle that cuts that node off. A budget (`max_changes`) uses the
  same greedy over every change in the network and makes no claim beyond "heuristic".

## Measured

On one core of an Intel Xeon Gold 6138, Python 3.12, one run at a time under a 5 GB limit:

| Snapshot | Build | Build with provenance | Plan | What-if with findings | Peak |
|---|---|---|---|---|---|
| lab (38 accounts) | 0.01 s | 0.01 s | 0.02 s, 12 changes | - | - |
| bench 10,000 users | 0.30 s | 0.51 s | 0.58 s, 1 change | 1.4 s | 95 MB |
| bench 250,000 users | 9.3 s | 13.9 s | 11.7 s, 1 change | 41.5 s | 1.76 GB |

Loading the 250,000-user snapshot takes another 9.4 s; with it, the plan run takes 41 s
and the what-if run 69 s. The bench domain funnels every path through one membership into Domain Admins, so its cut
is one change. Graph equality (masked against rebuilt, edge for edge and in order) holds
for every single change on two lab snapshots, for 200 random sets of up to 8 changes on
each, and on sampled changes of the bench domains.

## Limits

The engine works on the snapshot. What happens in AD after a change differs:

- SDProp runs every 60 minutes; inheritance changes at an OU reach every object below it.
- adminCount stays on removed members (AD-ACC-006).
- GPO refresh takes up to two hours, and local groups keep members a GPO added.
- Kerberos tickets keep group memberships until they expire (10 hours by default).
- Certificates already issued stay valid until they expire or are revoked.
- Other DCs see a change after replication.
- Edges ad-doctor does not see stay: sessions, local admin outside Group Policy,
  delegation as a path, trusts, Deny ACEs.
- What an attacker already planted (shadow credentials, added SPNs, other persistence) is
  not undone. Collect again and compare.
