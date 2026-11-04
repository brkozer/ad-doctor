# Lab domain

A disposable Windows Server 2025 domain controller for ad-doctor's live tests, seeded
with one instance of every misconfiguration the tool checks for (except the few listed in
the main README's "Limits").

The DC runs under KVM with QEMU user networking (`restrict=on`): it cannot open
connections anywhere, and its ports are forwarded to `127.0.0.1` on the host only.

| Host port | Guest | Use |
|---|---|---|
| 12222 | 22 | OpenSSH (key auth, PowerShell) |
| 10389 / 10636 | 389 / 636 | LDAP / LDAPS |
| 13268 / 13269 | 3268 / 3269 | Global catalog |
| 10088 | 88 | Kerberos |
| 10445 | 445 | SMB (SYSVOL) |
| 10053 | 53 | DNS |
| 15985 | 5985 | WinRM |

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

   This installs an enterprise CA (which also gives the DC its LDAPS certificate) and
   creates the vulnerable accounts, templates, ACLs, GPO and SYSVOL file. `alice` is the
   clean control account; `adreader` is the unprivileged account the tests scan with.

5. Run the live tests from the repository root as shown in the main README.

## Notes

- libvirt's native `passt` user networking would be the obvious choice, but Ubuntu
  24.04's AppArmor profile blocks QEMU from reaching the passt socket; `build.sh` passes
  the slirp network on the QEMU command line instead.
- The built-in OpenSSH firewall rule only covers the Private profile, and the lab NIC
  comes up as Public; `setup.ps1` widens it.
- Windows Server 2025 enforces LDAP signing through `LDAPServerEnforceIntegrity` on top of
  the classic `LDAPServerIntegrity`; `seed.ps1` relaxes both so the signing probe has
  something to find.
- The evaluation licence runs for 180 days. Rebuild from scratch rather than extend it.
