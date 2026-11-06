---
title: ad-doctor
hide: [navigation]
---

# ad-doctor

Read-only Active Directory security audit that fits in a pipeline.

ad-doctor binds as an ordinary domain user, takes one snapshot of the domain over LDAP
(plus SYSVOL and a few cheap probes of every DC over SMB, LDAP, HTTP and the CA registry)
and runs 95 checks for what attackers look for first: roastable accounts, risky delegation,
exploitable certificate templates and CA settings (ESC1-9, 11, 13-17), DCSync and other takeover
rights, shadow credentials, BadSuccessor, PrivExchange, exposed Entra Connect sync
accounts, editable GPOs on domain controllers, local admin and remote logon rights handed
out by Group Policy, passwords in Group Policy and scripts, relay-friendly DCs, weak trusts
and legacy configuration. It then finds every control path from a non-admin to tier 0.
**It writes nothing to the directory.**

![ad-doctor scanning the lab domain](demo.svg)

<div class="grid cards" markdown>

- **[Quick start](quickstart.md)**: install and run your first scan.
- **[Check catalog](checks/index.md)**: what each of the 95 checks and 5 invariants looks for and how to fix it.
- **[CI integration](ci.md)**: SARIF, JUnit, baselines and accepted risks.
- **[Permissions needed](permissions.md)**: an enabled domain user, nothing more.

</div>

## What sets it apart

- **Attack paths without a graph database.** `AD-PATH-001` builds the control graph from the
  snapshot and reports the shortest path from every non-tier-0 principal to tier 0;
  `ad-doctor blast-radius` answers "what does this account control if it is phished?".
- **Plays well with BloodHound.** The [OpenGraph export](bloodhound.md) keeps SIDs, so its
  edges attach to an existing SharpHound graph instead of building a second one. BloodHound
  offers Search and Cypher on it, not Pathfinding.
- **Every DC, not just one.** LDAP signing, SMB signing, the spooler and channel binding are
  [probed](probes.md) on each domain controller, and findings name the ones that drift.
- **Compound findings.** `AD-CHAIN-*` raise the alarm when individually medium findings add
  up to a known one-step compromise.
- **Built for CI.** SARIF 2.1.0, JUnit, JSON with stable fingerprints, `--fail-on` and
  `--baseline` so a scheduled job fails only on *new* findings.
- **Policy as code.** An [`invariants.toml`](invariants.md) declares the expected state; any
  drift becomes a finding.
- **Shareable snapshots.** [`redact`](snapshots.md) pseudonymizes names, hosts and the domain
  SID with a keyed HMAC, so a snapshot can go to a consultant and still produce the same
  findings.

Tools like PingCastle and Purple Knight cover more ground overall and Locksmith goes deeper
into AD CS; ad-doctor is the scriptable option, and the one that tests itself against a
live DC.
