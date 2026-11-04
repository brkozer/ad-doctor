# Seed adlab.test with known misconfigurations for ad-doctor's live tests.
# Idempotent: safe to run again. Passwords come from the host's ~/adlab/creds.
param([Parameter(Mandatory)][string]$UserPassword, [Parameter(Mandatory)][string]$ReaderPassword)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# LDAPS: an enterprise CA makes the DC enroll a domain controller certificate.
if (-not (Get-WindowsFeature ADCS-Cert-Authority).Installed) {
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'adlab-CA' -Force | Out-Null
}

$dn = (Get-ADDomain).DistinguishedName
$ou = "OU=Lab,$dn"
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Lab'")) {
    New-ADOrganizationalUnit -Name Lab -Path $dn -ProtectedFromAccidentalDeletion $false
}
$pw = ConvertTo-SecureString $UserPassword -AsPlainText -Force

function Ensure-User([string]$Name, [hashtable]$Extra = @{}) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$Name'")) {
        New-ADUser -Name $Name -SamAccountName $Name -Path $ou -AccountPassword $pw -Enabled $true @Extra
    }
}
function Ensure-Computer([string]$Name) {
    if (-not (Get-ADComputer -Filter "Name -eq '$Name'")) {
        New-ADComputer -Name $Name -SamAccountName "$Name$" -Path $ou -Enabled $true
    }
}

# Read-only scanning account: an ordinary domain user.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'adreader'")) {
    New-ADUser -Name adreader -SamAccountName adreader -Path $ou -Enabled $true `
        -AccountPassword (ConvertTo-SecureString $ReaderPassword -AsPlainText -Force)
}

Ensure-User alice                                   # clean control account
Ensure-User svc_sql
Set-ADUser svc_sql -ServicePrincipalNames @{ Replace = 'MSSQLSvc/db01.adlab.test:1433' }
Add-ADGroupMember 'Domain Admins' svc_sql           # AD-KRB-003 high
Ensure-User svc_web
Set-ADUser svc_web -ServicePrincipalNames @{ Replace = 'HTTP/web01.adlab.test' }
Ensure-User legacy_app
Set-ADAccountControl legacy_app -DoesNotRequirePreAuth $true      # AD-KRB-002
Ensure-User blank_ok
Set-ADAccountControl blank_ok -PasswordNotRequired $true          # AD-ACC-001
Ensure-User old_vpn
Set-ADUser old_vpn -AllowReversiblePasswordEncryption $true       # AD-ACC-002
Ensure-User des_user
Set-ADAccountControl des_user -UseDESKeyOnly $true                # AD-KRB-004
Ensure-User adm_bob
Add-ADGroupMember 'Domain Admins' adm_bob
Set-ADUser adm_bob -PasswordNeverExpires $true                    # AD-ACC-003, AD-PRIV-002
Ensure-User svc_iis
Set-ADAccountControl svc_iis -TrustedToAuthForDelegation $true    # AD-DEL-002
Set-ADUser svc_iis -Replace @{ 'msDS-AllowedToDelegateTo' = 'cifs/fs01.adlab.test' }

Ensure-Computer APP01
Set-ADAccountControl 'APP01$' -TrustedForDelegation $true         # AD-DEL-001
Ensure-Computer FS01
Set-ADComputer FS01 -PrincipalsAllowedToDelegateToAccount (Get-ADComputer APP01)   # AD-DEL-003
Ensure-Computer WS01                                               # AD-SEC-001 (no LAPS)

Enable-ADAccount Guest                                             # AD-ACC-004
Set-ADDefaultDomainPasswordPolicy -Identity $dn -MinPasswordLength 7 -LockoutThreshold 0  # AD-POL-001
# ms-DS-MachineAccountQuota stays at the default 10                # AD-POL-002

certutil -pulse | Out-Null
'seeded'
