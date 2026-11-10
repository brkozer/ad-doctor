# ad-doctor

[![ci](https://github.com/brkozer/ad-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/brkozer/ad-doctor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ad-doctor)](https://pypi.org/project/ad-doctor/)
![python](https://img.shields.io/badge/python-3.12%2B-3776AB)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A read-only Active Directory security audit that fits in a pipeline. It binds as an ordinary
domain user, takes one snapshot of the domain, runs 152 checks for what attackers look for
first, and finds every control path from a non-admin to tier 0. It writes nothing to the
directory.

<p align="center"><img src="https://raw.githubusercontent.com/brkozer/ad-doctor/main/docs/demo.svg" alt="ad-doctor scanning the lab domain: ESC8 web enrollment, a relay-to-RBCD chain, a password in a logon script, BadSuccessor rights and the control paths to tier 0" width="100%"></p>

A real scan of the seeded lab domain, taken with an earlier version, so it shows fewer checks
than a scan does today.

## What it does

**Finds what attackers use first.** Roastable accounts, risky delegation, certificate
templates and CA settings (ESC1–11 and 13–17), DCSync and other takeover rights, shadow credentials,
BadSuccessor, editable GPOs on domain controllers, passwords in Group Policy and scripts,
relay-friendly DCs, weak DNS zones, weak trusts and legacy configuration.

```bash
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor'
```

**Shows the paths to tier 0, without a graph database.** Every principal's shortest path to
Domain Admins and the rest of tier 0, the steps the most paths share, and what one account
controls if it is phished. The same graph exports to BloodHound.

```bash
ad-doctor paths snap.json --chokepoints
```

**Plans the fix, with a proof.** `plan` finds the cheapest set of removals that closes the
paths and says when it is a proven minimum; `whatif` shows what given removals would close,
on the snapshot, never on AD. Fix lines carry `-WhatIf` on every change.

```bash
ad-doctor plan snap.json -f ps1 -o plan.ps1
```

**A report you can hand over.** One offline HTML file with the findings, the paths drawn
step by step, blast radius, a live what-if, the changes since last time and the trend. It
loads nothing and cannot make a request, and it is encrypted when it maps the domain.

<p align="center"><img src="https://raw.githubusercontent.com/brkozer/ad-doctor/main/docs/viewer.png" alt="ad-doctor view on the lab domain: tier-0 exposure, risk score, findings by severity and category, top actions" width="85%"></p>

**Fits CI.** SARIF, JUnit and JSON with stable fingerprints, `--fail-on`, baselines so a job
fails only on new findings, accepted risks with owners and expiry, and an invariants file
for the state you expect.

## Why you can trust the results

- **Tested against a live domain controller.** A Windows Server 2025 lab DC, seeded with
  the misconfigurations in [`lab/`](lab), runs in the test suite: every check that can fire
  there must, with the objects it names.
- **Honest about what it could not see.** Each check reports judged, not applicable, or not
  evaluated with the reason. A check that could not read its data never counts as passed.
- **The what-if engine checks itself.** The graph after a change is compared edge for edge
  with a graph rebuilt from the changed snapshot; a disagreement stops the run.
- **Hostile names stay data.** The HTML report is tested with a domain whose names are XSS
  payloads, and the fix lines with names built to break PowerShell quoting.

The [limits page](https://brkozer.github.io/ad-doctor/limits/) lists, check by check, what
ad-doctor does not see.

## Get started

```bash
uv tool install ad-doctor        # or: pipx install ad-doctor; ad-doctor[kerberos] adds Kerberos
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor' -f html -o report.html
```

The password comes from `AD_DOCTOR_PASSWORD` or a prompt. An enabled domain user is enough:
no group memberships, no domain-joined host, no RSAT. Python 3.12 or newer.

## Documentation

Everything is at **[brkozer.github.io/ad-doctor](https://brkozer.github.io/ad-doctor/)**:

- [Quick start](https://brkozer.github.io/ad-doctor/quickstart/) and the
  [command line](https://brkozer.github.io/ad-doctor/cli/)
- [Permissions needed](https://brkozer.github.io/ad-doctor/permissions/) and
  [network probes](https://brkozer.github.io/ad-doctor/probes/)
- [Check catalog](https://brkozer.github.io/ad-doctor/checks/): a page for every check, also
  offline with `ad-doctor explain ID`
- [HTML viewer](https://brkozer.github.io/ad-doctor/viewer/),
  [what-if and plan](https://brkozer.github.io/ad-doctor/whatif/) and
  [declared tier 0](https://brkozer.github.io/ad-doctor/declared-tier0/)
- [CI integration](https://brkozer.github.io/ad-doctor/ci/),
  [invariants](https://brkozer.github.io/ad-doctor/invariants/),
  [snapshots and redaction](https://brkozer.github.io/ad-doctor/snapshots/) and the
  [forest scan](https://brkozer.github.io/ad-doctor/forest/)
- [BloodHound export](https://brkozer.github.io/ad-doctor/bloodhound/)
- [How it works](https://brkozer.github.io/ad-doctor/how-it-works/), with performance and
  development, and [limits](https://brkozer.github.io/ad-doctor/limits/)

See [CONTRIBUTING.md](CONTRIBUTING.md) to add a check and [SECURITY.md](SECURITY.md) to
report a vulnerability.

## License

MIT
