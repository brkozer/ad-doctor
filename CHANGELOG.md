# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/). Check IDs are stable: a check may change its
logic or severity between versions, but an ID is never reused for something else.

## [Unreleased]

### Added

- **Every domain controller is probed.** LDAP signing, SMB signing, the Print Spooler and
  LDAPS channel binding are checked on each DC found in the directory, not only the one
  being scanned, and findings name the DCs that fail. `--single-dc` restores the old
  behaviour. AD-INF-013 lists DCs that could not be reached.
- **Exchange** (AD-ACL-007): Exchange groups holding WriteDacl over the domain
  (PrivExchange), or over every user and group through inheritance, with the Exchange
  servers behind them. Exchange servers are collected as sensitive objects, so control
  paths run through them.
- **Entra Connect** (AD-PRIV-011, AD-ACL-008): sync accounts that can DCSync, whether their
  server is protected like a DC, and who outside tier 0 controls the account or the server.
- **BloodHound OpenGraph export**: `ad-doctor export-graph` writes the control graph as an
  OpenGraph payload. Principals keep their SIDs, so the edges attach to an existing
  SharpHound graph; `--paths-only` keeps just the paths to tier 0.
- **Scale benchmark**: `scripts/bench.py` builds a synthetic enterprise domain and times
  every stage.
- CHANGELOG, SECURITY, CONTRIBUTING, issue and pull request templates, Dependabot.

### Changed

- AD-INF-005, 008, 009 and 010 report DC names instead of the domain name.
- The control-path engine no longer compares every object with every OU: building the
  graph for 100,000 users went from minutes to about two seconds.

## [0.1.0] - unreleased

First version: 74 checks, the control-path engine and `blast-radius`, compound findings,
policy as code (`--invariants`), accepted risks with owners and expiry, a reviewable fix
script, redaction for sharing snapshots, text, JSON, Markdown, HTML, SARIF and JUnit
reports, NTLM with channel binding and Kerberos authentication, and a seeded lab.
