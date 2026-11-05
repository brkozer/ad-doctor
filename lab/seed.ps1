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
function New-LabTemplate([string]$Name, [hashtable]$Set = @{}, [string[]]$Clear = @(), [int]$SchemaVersion = 2) {
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
    $attrs['msPKI-Template-Schema-Version'] = $SchemaVersion
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
New-LabTemplate LabESC9 @{ 'msPKI-Enrollment-Flag' = 0x29 -bor 0x80000 }                    # AD-ADCS-006

# ESC13: an issuance policy linked to an (empty, universal) group
$pks = "CN=Public Key Services,CN=Services,$cfg"
if (-not (Get-ADGroup -Filter "Name -eq 'LabLinked'")) {
    New-ADGroup LabLinked -GroupScope Universal -GroupCategory Security -Path $ou
}
$policy = Get-ADObject -SearchBase "CN=OID,$pks" -Filter "displayName -eq 'LabIssuance'" `
    -Properties 'msPKI-Cert-Template-OID'
if (-not $policy) {
    $forestOid = (Get-ADObject "CN=OID,$pks" -Properties 'msPKI-Cert-Template-OID').'msPKI-Cert-Template-OID'
    $oid = '{0}.1337.{1}' -f $forestOid, (Get-Random 99999)
    New-ADObject -Name "1337.LabIssuance" -Type msPKI-Enterprise-Oid -Path "CN=OID,$pks" `
        -OtherAttributes @{ displayName = 'LabIssuance'; flags = 2; 'msPKI-Cert-Template-OID' = $oid }
    $policy = Get-ADObject -SearchBase "CN=OID,$pks" -Filter "displayName -eq 'LabIssuance'" `
        -Properties 'msPKI-Cert-Template-OID'
}
Set-ADObject $policy -Replace @{ 'msDS-OIDToGroupLink' = (Get-ADGroup LabLinked).DistinguishedName }
New-LabTemplate LabESC13 @{ 'msPKI-Certificate-Policy' = [string[]]$policy.'msPKI-Cert-Template-OID' }  # AD-ADCS-007

# ESC15: a schema v1 server template that lets the enrollee supply the subject
New-LabTemplate LabESC15 @{ 'msPKI-Certificate-Name-Flag' = 1; 'pKIExtendedKeyUsage' = [string[]]'1.3.6.1.5.5.7.3.1' } `
    -SchemaVersion 1                                                                         # AD-ADCS-008

$published = 'LabESC1', 'LabESC2', 'LabESC3', 'LabESC9', 'LabESC13', 'LabESC15'
foreach ($t in $published) { Grant-Ad "CN=$t,$tplBase" $domainUsers ExtendedRight $enroll }
Grant-Ad "CN=LabESC4,$tplBase" $authUsers GenericWrite
Grant-Ad "CN=NTAuthCertificates,$pks" $helpdesk GenericAll                                    # AD-ADCS-005

$ca = Get-ADObject -SearchBase "CN=Enrollment Services,$pks" `
    -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties certificateTemplates
$missing = $published | Where-Object { $ca.certificateTemplates -notcontains $_ }
if ($missing) { Set-ADObject $ca -Add @{ certificateTemplates = [string[]]$missing } }

# --- Accounts, groups and directory settings ---
Ensure-User ex_admin
Set-ADUser ex_admin -Replace @{ adminCount = 1 }                                             # AD-ACC-006
Ensure-Computer OLD2008
Set-ADComputer OLD2008 -OperatingSystem 'Windows Server 2008 R2 Standard'                     # AD-INF-001
Add-ADGroupMember DnsAdmins helpdesk                                                          # AD-PRIV-004
$pre2k = Get-ADGroup -Identity 'S-1-5-32-554' -Properties member
if (-not ($pre2k.member -match '^CN=S-1-5-7,')) {
    # binding by SID creates the ForeignSecurityPrincipal for Anonymous Logon
    ([ADSI]"LDAP://$($pre2k.DistinguishedName)").Add('LDAP://<SID=S-1-5-7>')                # AD-PRIV-005
}
Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" -Replace @{ dSHeuristics = '0000002' }  # AD-INF-004
# The Recycle Bin is off by default (AD-INF-002); Administrator stays in Schema/Enterprise Admins (AD-PRIV-003).

# LDAP signing: Server 2025 enforces it separately from the classic setting; relax both (AD-INF-005)
$ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$enforced = (Get-ItemProperty $ntds).LDAPServerEnforceIntegrity
Set-ItemProperty $ntds LDAPServerIntegrity 1
Set-ItemProperty $ntds LdapEnforceChannelBinding 0
Set-ItemProperty $ntds LDAPServerEnforceIntegrity 0 -Type DWord
if ($enforced -ne 0) { Restart-Service NTDS -Force }

# --- A GPO linked to the Domain Controllers OU that a non-admin can edit (AD-GPO-001) ---
Import-Module GroupPolicy
if (-not (Get-GPO -Name LabDCPolicy -ErrorAction SilentlyContinue)) {
    New-GPO -Name LabDCPolicy | New-GPLink -Target "OU=Domain Controllers,$dn" | Out-Null
}
Set-GPPermission -Name LabDCPolicy -TargetName helpdesk -TargetType User -PermissionLevel GpoEditDeleteModifySecurity | Out-Null

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

# --- Round 3 ---
# A logon script with a literal password (AD-GPP-002)
'net use z: \\fs01\share /user:ADLAB\svc_map S3cretPass!' |
    Set-Content -Encoding ASCII C:\Windows\SYSVOL\domain\scripts\map.bat

# Weak security settings in a GPO linked to the DCs (AD-GPO-003)
$labGpo = Get-GPO -Name LabDCPolicy
$secedit = "C:\Windows\SYSVOL\domain\Policies\{$($labGpo.Id.ToString().ToUpper())}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -ItemType Directory -Force $secedit | Out-Null
@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,1
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544,*S-1-5-11
'@ | Set-Content -Encoding Unicode "$secedit\GptTmpl.inf"

# An unlinked GPO a non-admin can edit (AD-GPO-004)
if (-not (Get-GPO -Name LabUserPolicy -ErrorAction SilentlyContinue)) { New-GPO -Name LabUserPolicy | Out-Null }
Set-GPPermission -Name LabUserPolicy -TargetName helpdesk -TargetType User -PermissionLevel GpoEditDeleteModifySecurity | Out-Null

# gPLink write on the Domain Controllers OU (AD-GPO-002)
Ensure-User gpo_linker
Grant-Ad "OU=Domain Controllers,$dn" (Get-ADUser gpo_linker).SID WriteProperty 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'

# Shadow credentials on the DC's computer object (AD-ACL-004)
Ensure-User kc_writer
Grant-Ad (Get-ADComputer DC01).DistinguishedName (Get-ADUser kc_writer).SID WriteProperty '5b47d60f-6090-40b2-9f37-2a4de88f3063'

# AdminSDHolder inheriting from its parent (AD-ACL-005)
$holderPath = "AD:\CN=AdminSDHolder,CN=System,$dn"
$holderAcl = Get-Acl $holderPath
if ($holderAcl.AreAccessRulesProtected) { $holderAcl.SetAccessRuleProtection($false, $true); Set-Acl $holderPath $holderAcl }

# A gMSA whose password every user can read (AD-ACL-006)
if (-not (Get-KdsRootKey)) { Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null }
if (-not (Get-ADServiceAccount -Filter "Name -eq 'gmsa_web'")) {
    New-ADServiceAccount gmsa_web -DNSHostName gmsa_web.adlab.test -PrincipalsAllowedToRetrieveManagedPassword 'Domain Users'
}

# Account hygiene (AD-ACC-008, -010) and Kerberos (AD-KRB-005, AD-DEL-004). AD-ACC-009 is
# unit-tested only: unixUserPassword is confidential on Server 2025, so no reader sees it.
Ensure-User notes_user
Set-ADUser notes_user -Description 'temp pwd: Welcome2026'
Ensure-Computer PRE2K
Set-ADAccountControl 'PRE2K$' -PasswordNotRequired $true
Set-ADUser svc_web -KerberosEncryptionType RC4
Ensure-User svc_dc
Set-ADUser svc_dc -Replace @{ 'msDS-AllowedToDelegateTo' = 'ldap/DC01.adlab.test' }

# Group hygiene (AD-PRIV-006, -007, -008, -009)
Ensure-User old_admin
Add-ADGroupMember 'Domain Admins' old_admin
Disable-ADAccount old_admin
Ensure-User hidden_admin
if ((Get-ADUser hidden_admin -Properties primaryGroupID).primaryGroupID -ne 512) {
    Add-ADGroupMember 'Domain Admins' hidden_admin
    Set-ADUser hidden_admin -Replace @{ primaryGroupID = 512 }
}
Ensure-User op_user
Add-ADGroupMember 'Backup Operators' op_user
Add-ADGroupMember 'Cert Publishers' helpdesk

# An account mapped to a certificate by subject only (AD-ADCS-009)
Ensure-User map_user
Set-ADUser map_user -Replace @{ altSecurityIdentities = 'X509:<I>DC=test,DC=adlab,CN=adlab-CA<S>CN=map_user' }

# A published template that allows 1024-bit keys (AD-ADCS-011)
New-LabTemplate LabWeakKey @{ 'msPKI-Minimal-Key-Size' = 1024 }
$ca = Get-ADObject -SearchBase "CN=Enrollment Services,$pks" -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties certificateTemplates
if ($ca.certificateTemplates -notcontains 'LabWeakKey') { Set-ADObject $ca -Add @{ certificateTemplates = 'LabWeakKey' } }

# BadSuccessor: CreateChild on an OU for a non-admin (AD-INF-007)
Ensure-User ou_admin
Grant-Ad $ou (Get-ADUser ou_admin).SID CreateChild

# Windows LAPS password readable by every user (AD-SEC-002)
if (-not (Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "name -eq 'ms-LAPS-Password'")) {
    Update-LapsADSchema -Confirm:$false
}
Set-LapsADReadPasswordPermission -Identity $ou -AllowedPrincipals 'ADLAB\Domain Users' | Out-Null
Set-ADComputer WS01 -Replace @{
    'msLAPS-Password' = '{"n":"Administrator","t":"1dc0000000000000","p":"NotARealSecret1"}'
    'msLAPS-PasswordExpirationTime' = (Get-Date).AddDays(30).ToFileTimeUtc()
}

# Print Spooler on the DC (AD-INF-009, AD-CHAIN-002). Server Core 2025 ships without the
# service and the Print-Server role fails to install on it (0x80070bc9, rolled back at the
# next boot), so on Core these checks are covered by the unit tests only.
if (Get-Service Spooler -ErrorAction SilentlyContinue) {
    Set-Service Spooler -StartupType Automatic
    Start-Service Spooler
} else {
    'spooler: not present on this edition, AD-INF-009 is not seeded'
}

# Web enrollment over HTTP with NTLM (AD-ADCS-010, AD-CHAIN-003). Feature installation can
# be blocked by a pending reboot; the unit tests cover these checks either way.
try {
    if (-not (Get-WindowsFeature ADCS-Web-Enrollment -ErrorAction Stop).Installed) {
        Install-WindowsFeature ADCS-Web-Enrollment -ErrorAction Stop | Out-Null
        Install-AdcsWebEnrollment -Force -ErrorAction Stop | Out-Null
    }
    # Server 2025 requires SSL on CertSrv out of the box; allow plain HTTP, the ESC8 setup
    Import-Module WebAdministration
    Set-WebConfigurationProperty -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv' `
        -Filter system.webServer/security/access -Name sslFlags -Value 'None'
} catch { "web enrollment not installed: $($_.Exception.Message)" }

# SDProp copies the AdminSDHolder ACL onto protected objects now instead of within the hour
$rootDse = [ADSI]'LDAP://RootDSE'
$rootDse.Put('runProtectAdminGroupsTask', 1)
$rootDse.SetInfo()

certutil -pulse | Out-Null
'seeded'
