# Declared tier 0

ad-doctor works out tier 0 from the directory: the admin groups and their members, domain
controllers, CA servers, the sync accounts and so on. Your own idea of tier 0 usually goes
further: a jump server, a backup account, a management host, a service account that runs on
domain controllers. Declare those and ad-doctor reports who can reach them too.

```toml
# tier0.toml
tier0 = ["JUMP01$", "svc_backup", "CN=Ops Admins,OU=Groups,DC=corp,DC=example"]
```

```bash
ad-doctor collect dc01.corp.example -u 'CORP\auditor' -o snap.json --tier0-file tier0.toml
ad-doctor analyze snap.json --tier0-file tier0.toml
ad-doctor paths snap.json --tier0-file tier0.toml
ad-doctor view snap.json --tier0-file tier0.toml
```

`scan` takes the same flag and does both steps. `--tier0 NAME` (repeatable) adds one name
on the command line. A name is a sAMAccountName (with or without the `$` of a computer), a
SID, a DN or an object's name; a name or SID the snapshot does not hold, or one that fits two
objects, stops the run with an error, so a typo cannot read as "nothing reaches it".

## Two sets

The built-in set and the declared set stay apart.

- **Built-in tier 0 does not change.** Every built-in path, and `exposed` and `users`, stay the
  same with the file, and every check other than AD-PATH-001 gives the same answer. A declared
  group does not become an allowed holder of anything, so a declaration can never silence a
  finding.
- **Paths to a declared asset are added**, and each one ends with `[declared tier 0]`:

  ```text
  outsider -[full control]-> JUMP01$ [declared tier 0]
  ```

- **A path to a declared asset is an ordinary AD-PATH-001 object.** The check is HIGH, so on a
  domain with no built-in path a declaration can raise it: the score goes up by 15, the grade can
  change and `--fail-on high` fails. Where a built-in path exists the check has fired already and
  counts once, so the score stays; the objects of the finding, and the object total of a trend
  point, go up by one per path.
- **Paths are searched separately.** Nothing passes through built-in tier 0 on the way to a
  declared asset (whoever gets that far already has a built-in path, which is listed), and
  a principal declared as tier 0 is not listed as a start. A principal can hold a path to each
  set; those are two objects with their own fingerprints.

In the JSON report the finding's `data` has `paths` (built-in only, as before) and
`declared_paths`, and a top-level `declared_tier0` block lists every asset with the set it
is in, its status and how many principals have a path to it. It also gives
`exposed_with_declared` of `users_with_declared`: the enabled users outside both sets with a
path to either (a declared user is left out, as a tier-0 user always is, so this count can be
lower than the built-in one). `exposed` and `users` in the finding's `data` stay built-in only,
so the exposure line of a trend does not jump when you add a line to the file.

A name that is built-in tier 0 already is listed as `built-in`, with no paths of its own.

## Not evaluated

A snapshot holds the owner and DACL of groups, OUs, the top-level containers, GPOs and
tier-0 accounts. It does not hold them for other users and computers. A declaration
cannot supply that afterwards, so **declaring a user or computer in a snapshot collected
without the file is not the same as a scan with it**.

Give `collect` or `scan` the same file and each declared account gets one more LDAP
read. Without that, the asset is reported as **not evaluated**: the report says so, the
JSON status is `not_evaluated` with the reason, and a note names AD-PATH-001, so that check
is not counted as a pass for it. The same happens when the owner or DACL could not be read at
collection time. Paths that need no DACL of the asset itself still appear (an inherited right
on its OU, a GPO, membership, delegation): they are real, but they are only a lower bound,
because a right on the object itself cannot be seen, and neither can the protection flag
that would stop inheritance. Treat them as a minimum.

Rights over a group, an OU, a GPO or a top-level container are collected anyway, so these
are evaluated from any snapshot. Names on the file that are not accounts do not change the
collection. Reading the DACL of an extra account can reveal a path to *built-in* tier 0 that runs
through that account: that is new information, and it appears as an ordinary built-in path.

## Comparing runs

A path to an asset that only one of two reports declared is a change in the declaration, not
in the domain. `diff`, `--baseline` and the viewer's Changes screen list it apart ("declared in
one run only") and keep it out of new, resolved and `--fail-on`. A path to an asset both runs
declared compares like any other.

## What-if and plan

`whatif` and `plan` take `--tier0-file` too, and use the same lookup and the same
"not evaluated" test (also for `--tier0` and `[assume] tier0` in a plan file). What differs is
what they are for: to compute a cut they count the asset as tier 0, as they always have, so a
path that passes through it ends there. The assumption is listed in the output, paths
that end at one are marked, and the exposure they print before any change equals
`exposed_with_declared` of the same declaration. A plan file written with `--tier0-file` carries
the names in its `[assume] tier0`.

## Not covered

`blast-radius` and `export-graph` take no declaration and the viewer's Blast radius screen
stays on built-in tier 0. The other checks stay on the built-in set: a right over a declared asset
shows up as a path of AD-PATH-001, and does not raise AD-ACL or AD-PRIV findings of its own.
