# First logon: OpenSSH with key auth, then promote to the first DC of adlab.test.
$ErrorActionPreference = 'Stop'
Start-Transcript -Path C:\adlab-setup.log -Append
$cfg = (Get-Volume -FileSystemLabel ADLABCFG).DriveLetter + ':'

if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
New-Item -ItemType Directory -Force C:\ProgramData\ssh | Out-Null
Copy-Item "$cfg\authorized_keys" C:\ProgramData\ssh\administrators_authorized_keys -Force
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force
Restart-Service sshd
Get-NetFirewallRule -Name *OpenSSH* -ErrorAction SilentlyContinue | Enable-NetFirewallRule

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
$dsrm = ConvertTo-SecureString (Get-Content "$cfg\dsrm.txt" -Raw).Trim() -AsPlainText -Force
Install-ADDSForest -DomainName adlab.test -DomainNetbiosName ADLAB -InstallDns `
    -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion:$false -Force
