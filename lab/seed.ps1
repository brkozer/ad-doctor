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

# --- ACLs ---
function Grant-Ad([string]$Path, $Sid, [string]$Rights, [string]$Right = $null) {
    $acl = Get-Acl "AD:\$Path"
    $existing = $acl.Access | Where-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) -eq $Sid -and
        $_.ActiveDirectoryRights -match $Rights -and
        (-not $Right -or $_.ObjectType -eq [guid]$Right)
    }
    if ($existing) { return }
    $rule = if ($Right) {
        New-Object DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, 'Allow', [guid]$Right)
    } else {
        New-Object DirectoryServices.ActiveDirectoryAccessRule($Sid, $Rights, 'Allow')
    }
    $acl.AddAccessRule($rule)
    Set-Acl "AD:\$Path" $acl
}
Ensure-User svc_sync
Ensure-User helpdesk
$sync = (Get-ADUser svc_sync).SID
$helpdesk = (Get-ADUser helpdesk).SID
Grant-Ad $dn $sync ExtendedRight '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # AD-ACL-001
Grant-Ad $dn $sync ExtendedRight '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
Grant-Ad "CN=AdminSDHolder,CN=System,$dn" $helpdesk GenericAll         # AD-ACL-002
Grant-Ad $dn $helpdesk WriteDacl                                         # AD-ACL-003

# --- AD CS templates, copied from the built-in User template ---
$cfg = (Get-ADRootDSE).configurationNamingContext
$tplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
$copy = 'flags', 'pKIDefaultKeySpec', 'pKIKeyUsage', 'pKIMaxIssuingDepth', 'pKICriticalExtensions',
    'pKIExpirationPeriod', 'pKIOverlapPeriod', 'pKIExtendedKeyUsage', 'pKIDefaultCSPs',
    'msPKI-RA-Signature', 'msPKI-Enrollment-Flag', 'msPKI-Private-Key-Flag',
    'msPKI-Certificate-Name-Flag', 'msPKI-Minimal-Key-Size'
function New-LabTemplate([string]$Name, [hashtable]$Set = @{}, [string[]]$Clear = @()) {
    if (Get-ADObject -SearchBase $tplBase -Filter "cn -eq '$Name'") { return }
    $src = Get-ADObject "CN=User,$tplBase" -Properties $copy
    $attrs = @{}
    foreach ($a in $copy) {
        $v = $src.$a
        if ($null -eq $v -or $Clear -contains $a) { continue }
        if ($v -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
            $v = [string[]]@($v)
        }
        $attrs[$a] = $v
    }
    $attrs['displayName'] = $Name
    $attrs['revision'] = 100
    $attrs['msPKI-Template-Schema-Version'] = 2
    $attrs['msPKI-Template-Minor-Revision'] = 1
    $attrs['msPKI-Cert-Template-OID'] = '1.3.6.1.4.1.311.21.8.{0}.{1}' -f (Get-Random 9999999), (Get-Random 9999)
    foreach ($k in $Set.Keys) { $attrs[$k] = $Set[$k] }
    New-ADObject -Name $Name -Type pKICertificateTemplate -Path $tplBase -OtherAttributes $attrs
}
$domainUsers = (Get-ADGroup 'Domain Users').SID
$authUsers = New-Object Security.Principal.SecurityIdentifier('S-1-5-11')
$enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'

New-LabTemplate LabESC1 @{ 'msPKI-Certificate-Name-Flag' = 1; 'msPKI-Enrollment-Flag' = 0 }   # AD-ADCS-001
New-LabTemplate LabESC2 -Clear 'pKIExtendedKeyUsage'                                         # AD-ADCS-002
New-LabTemplate LabESC3 @{ 'pKIExtendedKeyUsage' = [string[]]'1.3.6.1.4.1.311.20.2.1' }      # AD-ADCS-003
New-LabTemplate LabESC4                                                                       # AD-ADCS-004
foreach ($t in 'LabESC1', 'LabESC2', 'LabESC3') { Grant-Ad "CN=$t,$tplBase" $domainUsers ExtendedRight $enroll }
Grant-Ad "CN=LabESC4,$tplBase" $authUsers GenericWrite

$ca = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" `
    -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties certificateTemplates
$missing = 'LabESC1', 'LabESC2', 'LabESC3' | Where-Object { $ca.certificateTemplates -notcontains $_ }
if ($missing) { Set-ADObject $ca -Add @{ certificateTemplates = [string[]]$missing } }

# --- SYSVOL: a Group Policy Preferences password (MS14-025) ---
# The value is the example from Microsoft's GPP documentation, not a real secret.
$gpo = "C:\Windows\SYSVOL\domain\Policies\{4B1D7A55-0C1E-4A3B-9D2F-7E6A5C3B2A10}"
$dir = "$gpo\Machine\Preferences\Groups"
New-Item -ItemType Directory -Force $dir | Out-Null
@'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="localadmin" image="2" changed="2014-01-01 00:00:00" uid="{00000000-0000-0000-0000-000000000001}">
    <Properties action="U" newName="" fullName="" description="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="localadmin"/>
  </User>
</Groups>
'@ | Set-Content -Encoding UTF8 "$dir\Groups.xml"                    # AD-GPP-001

certutil -pulse | Out-Null
'seeded'
