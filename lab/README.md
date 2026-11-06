# Lab domain

A disposable Windows Server 2025 domain controller for ad-doctor's live tests, seeded
with the misconfigurations `seed.ps1` plants (what it leaves out is listed in the main
README's "Limits" and covered by unit tests).

The DC runs under KVM with QEMU user networking (`restrict=on`): it cannot open
connections anywhere, and its ports are forwarded to `127.0.0.1` on the host only.

| Host port | Guest | Use |
|---|---|---|
| 12222 | 22 | OpenSSH (key auth, PowerShell) |
| 10389 / 10636 | 389 / 636 | LDAP / LDAPS |
| 13268 / 13269 | 3268 / 3269 | Global catalog |
| 10088 | 88 | Kerberos |
| 10445 | 445 | SMB (SYSVOL, probes) |
| 10080 | 80 | CA web enrollment (ESC8) |
| 10053 | 53 | DNS |
| 15985 | 5985 | WinRM |

Port 443 is not forwarded. For the HTTPS enrollment probe, tunnel it over SSH and pass the
local port with `--https-port`, or to the live tests as `AD_DOCTOR_LAB_HTTPS_PORT`:

```bash
ssh -f -N -L 127.0.0.1:10443:127.0.0.1:443 -p 12222 -i ~/.ssh/adlab_ed25519 Administrator@127.0.0.1
```

## Build

Needs a Linux host with KVM, libvirt, `virt-install`, `qemu-img` and `xorriso`
(about 3 GB of RAM and 40 GB of disk for the guest).

1. Download the Windows Server 2025 evaluation ISO from the Microsoft Evaluation Center
   into `~/adlab/ws2025.iso` and copy this directory's files there.
2. Run `./build.sh`. It generates random passwords into `~/adlab/creds` (mode 600), an SSH
   key `~/.ssh/adlab_ed25519`, a config ISO with `autounattend.xml` and `setup.ps1`, and
   starts the VM.
3. Wait 20–30 minutes. Setup installs Windows Server Core unattended, enables OpenSSH,
   installs AD DS and promotes the server to the first DC of `adlab.test`, then reboots.
   It is ready when this prints `adlab.test`:

   ```bash
   ssh -i ~/.ssh/adlab_ed25519 -p 12222 Administrator@127.0.0.1 '(Get-ADDomain).DNSRoot'
   ```

4. Seed it (idempotent; run again after changing `seed.ps1`):

   ```bash
   . ~/adlab/creds
   scp -P 12222 -i ~/.ssh/adlab_ed25519 seed.ps1 Administrator@127.0.0.1:C:/seed.ps1
   ssh -p 12222 -i ~/.ssh/adlab_ed25519 Administrator@127.0.0.1 \
     "powershell -ExecutionPolicy Bypass -File C:\seed.ps1 -UserPassword $USER_PASSWORD -ReaderPassword $READER_PASSWORD"
   ```

   This installs an enterprise CA (which also gives the DC its LDAPS certificate) and web
   enrollment, then creates the vulnerable accounts, groups, templates, ACLs, GPOs, gMSA,
   LAPS permissions and SYSVOL files. `alice` is the clean control account; `adreader` is
   the unprivileged account the tests scan with.

5. Run the live tests from the repository root as shown in the main README.

## Kerberos

To test `-k`, point MIT Kerberos at the forwarded KDC and resolve the DC's name to the
forwarded ports:

```ini
# krb5.conf (use with KRB5_CONFIG=...)
[libdefaults]
    default_realm = ADLAB.TEST
    dns_lookup_kdc = false
    rdns = false
    udp_preference_limit = 1
[realms]
    ADLAB.TEST = { kdc = 127.0.0.1:10088 }
```

```bash
echo '127.0.0.1 dc01.adlab.test' | sudo tee -a /etc/hosts
uv sync --extra kerberos            # needs libkrb5-dev and python3-dev to build gssapi
kinit adreader@ADLAB.TEST
uv run ad-doctor scan dc01.adlab.test --ldaps --port 10636 --smb-port 10445 --http-port 10080 -k
```

## Notes

- libvirt's native `passt` user networking would be the obvious choice, but Ubuntu
  24.04's AppArmor profile blocks QEMU from reaching the passt socket; `build.sh` passes
  the slirp network on the QEMU command line instead.
- virt-install keeps a Windows guest's hardware clock in local time; `build.sh` switches
  it to UTC, otherwise the guest runs hours off and Kerberos fails on clock skew.
- The built-in OpenSSH firewall rule only covers the Private profile, and the lab NIC
  comes up as Public; `setup.ps1` widens it.
- Windows Server 2025 enforces LDAP signing through `LDAPServerEnforceIntegrity` on top of
  the classic `LDAPServerIntegrity`, and requires SSL on the CertSrv site by default;
  `seed.ps1` relaxes both so the probes have something to find.
- Server Core 2025 has no Print Spooler and the Print-Server role fails to install on it,
  so AD-INF-009 and the high grade of AD-CHAIN-002/003 are covered by unit tests only; the
  lab shows those two chains at medium, with coercion assumed.
- Seeding restarts NTDS once and asks SDProp to run immediately, so the AdminSDHolder ACL
  is copied onto protected objects before the tests.
- `veiled_admin` is a Domain Admin in `OU=Veiled`, where `adreader` is denied List Contents.
  The deny is on the OU because SDProp would take it off the user. Other accounts see it
  as usual, so AD-PRIV-012 only fires when the scan runs as `adreader`.
- A new CA has no `AuditFilter` value at all; `seed.ps1` sets it to 3 so that AD-ADCS-018 has
  something to read. Without that line AD-ADCS-018 reports the value as not set.
- Exchange and Entra Connect are seeded by their directory footprint only: the Exchange
  security groups with the pre-2019 WriteDacl on the domain head and a member server
  account, and an `MSOL_` sync account with DCSync and the description setup writes. Neither
  product is installed.
- `seed.ps1` adds an HTTPS binding and CES (Kerberos) to the DC and publishes the CES URL in
  `msPKI-Enrollment-Servers`. CertSrv has EPA required and CES has it off; the scan cannot
  tell them apart without authenticating, so AD-ADCS-019 lists both.
- The seeded Guest account changes what IIS does with an unknown user: NTLM falls back to
  Guest. Do not read a made-up user's result here as what a domain with Guest off would show.
- `seed.ps1` creates four trusts through `LsaCreateTrustedDomainEx`, since LDAP refuses the
  system-owned attributes of `trustedDomain`. They have no partner and no password, so none
  works, and they leave disabled trust accounts such as `FOREST$`. Their `whenChanged` is the
  seeding date until 40 days pass, so the live test of AD-INF-016 moves the snapshot's date.
- With one DC, the every-DC probes cover the scanned DC only; the multi-DC paths are
  unit-tested.
- The evaluation licence runs for 180 days. Rebuild from scratch rather than extend it.
