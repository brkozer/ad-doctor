# Invariants (policy as code)

An invariants file declares the state the team expects. Anything that drifts from it becomes
an `AD-INV-*` finding, so a review decision ("tier 0 is exactly these people") is enforced on
every scan instead of living in a wiki.

```bash
ad-doctor scan dc01.corp.example --ldaps -u 'CORP\auditor' --invariants invariants.toml
ad-doctor analyze 2026-11.json --invariants invariants.toml
```

Every section is optional. See
[`examples/invariants.toml`](https://github.com/brkozer/ad-doctor/blob/main/examples/invariants.toml).

```toml
[groups]
# exact membership (sAMAccountName of the users, transitive)
"Domain Admins" = ["Administrator", "adm_alice", "adm_bob"]
"Schema Admins" = []
"Enterprise Admins" = []

[limits]
tier0_users = 5            # at most this many distinct accounts across all tier-0 groups

[settings]
machine_account_quota = 0
min_pwd_length = 14        # at least
lockout_threshold = 10     # at least
recycle_bin = true
ldap_signing_required = true

[dcsync]
# principals allowed to replicate secrets besides the domain controllers and tier 0
allowed = ["MSOL_0123456789ab"]

[templates]
# the only certificate templates that may be published
published = ["User", "Machine", "DomainController", "KerberosAuthentication", "WebServer", "SubCA"]
```

## The invariant checks

| ID | Fires when |
|---|---|
| `AD-INV-001` | a declared group's membership differs from the list (missing or unexpected members) |
| `AD-INV-002` | more distinct accounts sit in tier-0 groups than `limits.tier0_users` allows |
| `AD-INV-003` | a declared domain setting does not hold |
| `AD-INV-004` | a principal outside the declared list can DCSync |
| `AD-INV-005` | a certificate template is published that the declared list does not allow |

These IDs are not in the normal check registry; they run only with `--invariants`. When one
fires it appears as a SARIF rule and a JUnit test case like any other finding (a passing
invariant adds neither), and each has a catalog page.
