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
function Ensure-Computer([string]$Name, [string]$Path = $ou) {
    if (-not (Get-ADComputer -Filter "Name -eq '$Name'")) {
        New-ADComputer -Name $Name -SamAccountName "$Name$" -Path $Path -Enabled $true
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
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList=1,"O:BAG:BAD:(A;;RC;;;DD)(A;;RC;;;HELPDESK_SID)"
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544,*S-1-5-11
'@.Replace('HELPDESK_SID', (Get-ADUser helpdesk).SID.Value) | Set-Content -Encoding Unicode "$secedit\GptTmpl.inf"

# An unlinked GPO a non-admin can edit (AD-GPO-004)
if (-not (Get-GPO -Name LabUserPolicy -ErrorAction SilentlyContinue)) { New-GPO -Name LabUserPolicy | Out-Null }
Set-GPPermission -Name LabUserPolicy -TargetName helpdesk -TargetType User -PermissionLevel GpoEditDeleteModifySecurity | Out-Null

# gPLink write on the Domain Controllers OU (AD-GPO-002)
Ensure-User gpo_linker
Grant-Ad "OU=Domain Controllers,$dn" (Get-ADUser gpo_linker).SID WriteProperty 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'

# Shadow credentials on the DC's computer object (AD-ACL-004)
Ensure-User kc_writer
Grant-Ad (Get-ADComputer DC01).DistinguishedName (Get-ADUser kc_writer).SID WriteProperty '5b47d60f-6090-40b2-9f37-2a4de88f3063'

# WriteAccountRestrictions: RBCD through the property set, on the DC (AD-ACL-004)
Ensure-User rbcd_writer
Grant-Ad (Get-ADComputer DC01).DistinguishedName (Get-ADUser rbcd_writer).SID WriteProperty '4c164200-20c0-11d0-a768-00aa006e0529'

# A computer with the DC flag and no nTDSDSA object (AD-INF-014); AD sets its primary group to
# Domain Controllers. In CN=Computers so that no lab GPO reaches it.
Ensure-Computer ROGUE01 "CN=Computers,$dn"
Set-ADComputer ROGUE01 -DNSHostName rogue01.adlab.test
if (-not ((Get-ADComputer ROGUE01 -Properties userAccountControl).userAccountControl -band 0x2000)) {
    Set-ADComputer ROGUE01 -Replace @{ userAccountControl = 0x2000 }
}

# AdminSDHolder inheriting from its parent (AD-ACL-005)
$holderPath = "AD:\CN=AdminSDHolder,CN=System,$dn"
$holderAcl = Get-Acl $holderPath
if ($holderAcl.AreAccessRulesProtected) { $holderAcl.SetAccessRuleProtection($false, $true); Set-Acl $holderPath $holderAcl }

# A gMSA whose password every user can read (AD-ACL-006)
if (-not (Get-KdsRootKey)) { Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null }
if (-not (Get-ADServiceAccount -Filter "Name -eq 'gmsa_web'")) {
    New-ADServiceAccount gmsa_web -DNSHostName gmsa_web.adlab.test -PrincipalsAllowedToRetrieveManagedPassword 'Domain Users'
}

# A dMSA, which an ordinary user cannot read (the note of AD-INF-007)
if (-not (Get-ADServiceAccount -Filter "Name -eq 'dmsa_lab'")) {
    New-ADServiceAccount dmsa_lab -DNSHostName dmsa_lab.adlab.test -CreateDelegatedServiceAccount -Path $ou
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

# Key credentials on tier 0 and a strong certificate mapping (AD-ACC-013): a user key on
# adm_bob, and on the DC the shape a computer writes for itself. The keys are random bytes:
# no private key exists, so they cannot log on.
function New-LabKeyEntry([int]$Id, [byte[]]$Value) {
    [byte[]]$head = @(($Value.Length -band 255), ($Value.Length -shr 8), $Id)
    return ,[byte[]]($head + $Value)
}
function New-LabKeyCredential([string]$Owner, [switch]$Computer) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $material = New-Object byte[] 270
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($material)
    $keyId = $sha.ComputeHash($material)
    $time = [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc())
    $device = [guid]::NewGuid().ToByteArray()
    [byte[]]$tail = (New-LabKeyEntry 3 $material) + (New-LabKeyEntry 4 @(1)) + (New-LabKeyEntry 5 @(0))
    if (-not $Computer) {
        $tail += (New-LabKeyEntry 6 $device) + (New-LabKeyEntry 7 @(1, 0)) + (New-LabKeyEntry 8 $time)
    }
    $tail += New-LabKeyEntry 9 $time
    $keyHash = $sha.ComputeHash($tail)
    [byte[]]$blob = @(0, 2, 0, 0) + (New-LabKeyEntry 1 $keyId) + (New-LabKeyEntry 2 $keyHash) + $tail
    $hex = -join ($blob | ForEach-Object { $_.ToString('X2') })
    return "B:$($hex.Length):${hex}:$Owner"
}
$keyUser = Get-ADUser adm_bob -Properties 'msDS-KeyCredentialLink'
if (-not $keyUser.'msDS-KeyCredentialLink') {
    Set-ADObject $keyUser.DistinguishedName -Add @{ 'msDS-KeyCredentialLink' = (New-LabKeyCredential $keyUser.DistinguishedName) }
}
$keyDc = Get-ADComputer $env:COMPUTERNAME -Properties 'msDS-KeyCredentialLink'
if (-not $keyDc.'msDS-KeyCredentialLink') {
    Set-ADObject $keyDc.DistinguishedName -Add @{ 'msDS-KeyCredentialLink' = (New-LabKeyCredential $keyDc.DistinguishedName -Computer) }
}
# a key the scan account may not read: the check must say so, not report a clean account.
# ROGUE01 counts as a DC but is in no protected group, so SDProp leaves this deny in place
$keyRogue = Get-ADComputer ROGUE01 -Properties 'msDS-KeyCredentialLink'
if (-not $keyRogue.'msDS-KeyCredentialLink') {
    Set-ADObject $keyRogue.DistinguishedName -Add @{ 'msDS-KeyCredentialLink' = (New-LabKeyCredential $keyRogue.DistinguishedName) }
}
$rogueAcl = Get-Acl "AD:\$($keyRogue.DistinguishedName)"
$rogueAcl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule(
    (Get-ADUser adreader).SID, 'ReadProperty', 'Deny', [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063')))
Set-Acl "AD:\$($keyRogue.DistinguishedName)" $rogueAcl
Set-ADUser svc_sql -Replace @{ altSecurityIdentities = 'X509:<I>DC=test,DC=adlab,CN=adlab-CA<SR>1200000000ac11000000002b' }

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

# The same site over HTTPS and the enrollment web service (CES) next to it (AD-ADCS-019).
# CertSrv keeps the Server 2025 default of EPA required; CES has EPA turned off, so the lab
# holds one HTTPS endpoint of each kind.
try {
    $fqdn = "$env:COMPUTERNAME.$((Get-ADDomain).DNSRoot)".ToLower()
    $tls = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=$fqdn" -and $_.HasPrivateKey } | Select-Object -First 1
    if (-not (Get-WebBinding -Name 'Default Web Site' -Protocol https)) {
        New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443
        (Get-WebBinding -Name 'Default Web Site' -Protocol https).AddSslCertificate($tls.Thumbprint, 'My')
    }
    if (-not (Get-WindowsFeature ADCS-Enroll-Web-Svc -ErrorAction Stop).Installed) {
        Install-WindowsFeature ADCS-Enroll-Web-Svc -ErrorAction Stop | Out-Null
    }
    if (-not (Get-WebApplication -Name 'adlab-CA_CES_Kerberos')) {
        Install-AdcsEnrollmentWebService -CAConfig "$fqdn\adlab-CA" -AuthenticationType Kerberos `
            -SSLCertThumbprint $tls.Thumbprint -ApplicationPoolIdentity -Force -ErrorAction Stop | Out-Null
    }
    Set-WebConfigurationProperty -PSPath 'IIS:\' -Location 'Default Web Site/adlab-CA_CES_Kerberos' `
        -Filter system.webServer/security/authentication/windowsAuthentication/extendedProtection `
        -Name tokenChecking -Value 'None'
    certutil -config "$fqdn\adlab-CA" -enrollmentServerURL `
        "https://$fqdn/adlab-CA_CES_Kerberos/service.svc/CES" Kerberos 1 | Out-Null
} catch { "HTTPS enrollment not set up: $($_.Exception.Message)" }

# --- Round 4 ---
# Exchange: the groups Exchange setup creates, with the pre-2019 WriteDacl on the domain head
# (PrivExchange, AD-ACL-007). No Exchange install: only the directory side matters here.
$exName = 'Microsoft Exchange Security Groups'
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$exName'")) {
    New-ADOrganizationalUnit -Name $exName -Path $dn -ProtectedFromAccidentalDeletion $false
}
foreach ($g in 'Exchange Windows Permissions', 'Exchange Trusted Subsystem') {
    if (-not (Get-ADGroup -Filter "Name -eq '$g'")) {
        New-ADGroup -Name $g -SamAccountName $g -GroupScope Universal -GroupCategory Security `
            -Path "OU=$exName,$dn"
    }
}
Ensure-Computer EXCH01
Add-ADGroupMember 'Exchange Trusted Subsystem' -Members (Get-ADComputer EXCH01)
Add-ADGroupMember 'Exchange Windows Permissions' -Members 'Exchange Trusted Subsystem'
Grant-Ad $dn (Get-ADGroup 'Exchange Windows Permissions').SID WriteDacl

# Entra Connect: a sync account with DCSync whose server is not tier 0 (AD-PRIV-011) and
# whose password helpdesk can reset (AD-ACL-008). The description is the one setup writes.
Ensure-Computer ENTRA01
Ensure-User MSOL_0a1b2c3d4e5f @{Description = 'Account created by Microsoft Azure Active ' +
    'Directory Connect with installation identifier 0a1b2c3d4e5f running on computer ENTRA01 ' +
    'configured to synchronize to tenant adlab.onmicrosoft.com.'}
$msol = Get-ADUser MSOL_0a1b2c3d4e5f
Grant-Ad $dn $msol.SID ExtendedRight '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
Grant-Ad $dn $msol.SID ExtendedRight '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
Grant-Ad $msol.DistinguishedName $helpdesk ExtendedRight '00299570-246d-11d0-a768-00aa006e0529'

# --- Round 5: the CA's own configuration (ESC6, ESC7, ESC11, ESC16) ---
# These are registry settings on the CA host, read over \pipe\winreg; they are invisible to
# LDAP. Seeding ESC6 together with ESC16 makes the lab CA exploitable under strong mapping
# on purpose (AD-CHAIN-004). Clearing IF_ENFORCEENCRYPTICERTREQUEST also drives AD-ADCS-014.
$caBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$caName = (Get-ItemProperty $caBase).Active
$caKey = "$caBase\$caName"
$policyKey = "$caKey\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
$sidExtOid = '1.3.6.1.4.1.311.25.2'
$caChanged = $false

# ESC6: accept a SAN from request attributes
if (-not ((Get-ItemProperty $policyKey).EditFlags -band 0x40000)) {
    certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
    $caChanged = $true
}
# ESC11: stop requiring packet privacy on ICPR requests
if ((Get-ItemProperty $caKey).InterfaceFlags -band 0x200) {
    certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST | Out-Null
    $caChanged = $true
}
# ESC16: drop the SID security extension from every issued certificate
$disabled = @((Get-ItemProperty $policyKey -Name DisableExtensionList -ErrorAction SilentlyContinue).DisableExtensionList)
if ($disabled -notcontains $sidExtOid) {
    certutil -setreg policy\DisableExtensionList +$sidExtOid | Out-Null
    $caChanged = $true
}

# ESC7: give the helpdesk group ManageCertificates (0x2) in the CA security descriptor.
# $helpdesk is the SecurityIdentifier created earlier in this script.
$caSecProp = Get-ItemProperty $caKey -Name Security
$caSd = New-Object Security.AccessControl.RawSecurityDescriptor($caSecProp.Security, 0)
$hasOfficer = $false
foreach ($aceEntry in $caSd.DiscretionaryAcl) {
    if ($aceEntry.SecurityIdentifier -eq $helpdesk -and ($aceEntry.AccessMask -band 0x2)) {
        $hasOfficer = $true
    }
}
if (-not $hasOfficer) {
    $caSd.DiscretionaryAcl.InsertAce(0, (New-Object Security.AccessControl.CommonAce(
        'ObjectInherit,ContainerInherit', 'AccessAllowed', 2, $helpdesk, $false, $null)))
    $caBytes = New-Object byte[] $caSd.BinaryLength
    $caSd.GetBinaryForm($caBytes, 0)
    Set-ItemProperty $caKey -Name Security -Value $caBytes
    $caChanged = $true
}

if ($caChanged) { Restart-Service certsvc }

# --- Round 5: local group membership set by Group Policy (AD-GPO-005..007) ---
# Windows ignores a GPO whose computer version is 0 or whose gPCMachineExtensionNames lacks
# the extension, so every file written here bumps the version and registers the CSE.
$CseSecurity = @{ '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}' }
$CseGroups = @{
    '{00000000-0000-0000-0000-000000000000}' = '{79F92669-4224-476C-9C5C-6EFB4D87DF4A}'
    '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = '{79F92669-4224-476C-9C5C-6EFB4D87DF4A}'
}
function Ensure-Gpo([string]$Name) {
    $g = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $g) { $g = New-GPO -Name $Name }
    $g
}
function Ensure-Link([string]$Name, [string]$Target, [string]$Enabled = 'Yes', [string]$Enforced = 'No') {
    $id = (Get-GPO -Name $Name).Id
    if ((Get-GPInheritance -Target $Target).GpoLinks.GpoId -notcontains $id) {
        New-GPLink -Name $Name -Target $Target | Out-Null
    }
    Set-GPLink -Name $Name -Target $Target -LinkEnabled $Enabled -Enforced $Enforced | Out-Null
}
function Get-Gpc($Gpo) {
    Get-ADObject "CN={$($Gpo.Id)},CN=Policies,CN=System,$dn" -Properties versionNumber, gPCMachineExtensionNames
}
function Step-GpoVersion($Gpo) {
    # +1 is the computer half (low 16 bits); GPT.INI must carry the same number
    $gpc = Get-Gpc $Gpo
    $ver = [int]$gpc.versionNumber + 1
    Set-ADObject $gpc -Replace @{ versionNumber = $ver }
    $root = "C:\Windows\SYSVOL\domain\Policies\{$($Gpo.Id.ToString().ToUpper())}"
    Set-Content -Encoding ASCII "$root\GPT.INI" "[General]`r`nVersion=$ver`r`ndisplayName=New Group Policy Object"
}
function Register-Cse($Gpo, [hashtable]$Cse) {
    # gPCMachineExtensionNames: brackets sorted by CSE GUID, tool GUIDs sorted inside each
    $gpc = Get-Gpc $Gpo
    $pairs = @{}
    foreach ($m in [regex]::Matches([string]$gpc.gPCMachineExtensionNames, '\[(\{[^}]+\})((?:\{[^}]+\})*)\]')) {
        $pairs[$m.Groups[1].Value.ToUpper()] = @([regex]::Matches($m.Groups[2].Value, '\{[^}]+\}') | ForEach-Object Value)
    }
    foreach ($k in $Cse.Keys) { $pairs[$k] = @(@($pairs[$k]) + $Cse[$k] | Where-Object { $_ } | Sort-Object -Unique) }
    $value = ($pairs.Keys | Sort-Object | ForEach-Object { "[$_$(($pairs[$_] | Sort-Object) -join '')]" }) -join ''
    if ($value -ne $gpc.gPCMachineExtensionNames) { Set-ADObject $gpc -Replace @{ gPCMachineExtensionNames = $value } }
}
function Set-GpoFile($Gpo, [string]$Rel, [string]$Text, [string]$Encoding, [hashtable]$Cse) {
    $Text = $Text -replace "`r?`n", "`r`n"
    $file = Join-Path "C:\Windows\SYSVOL\domain\Policies\{$($Gpo.Id.ToString().ToUpper())}" $Rel
    New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null
    $old = if (Test-Path $file) { Get-Content -Raw $file } else { $null }
    if ($old -ne $Text) {                       # bump only on change: idempotent
        Set-Content -NoNewline -Encoding $Encoding $file $Text
        Step-GpoVersion $Gpo
    }
    Register-Cse $Gpo $Cse
}
function Set-RestrictedGroups($Gpo, [string[]]$Lines) {
    $inf = "[Unicode]`nUnicode=yes`n[Version]`nsignature=`"`$CHICAGO`$`"`nRevision=1`n[Group Membership]`n" + ($Lines -join "`n") + "`n"
    Set-GpoFile $Gpo 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf' $inf Unicode $CseSecurity
}

# LabDCPolicy (AD-GPO-001, -003) has a GptTmpl.inf but was created with computer version 0
# and no CSE, which Windows reports as "Not Applied (Empty)": make it a GPO Windows applies.
$labGpo = Get-GPO -Name LabDCPolicy
if (((Get-Gpc $labGpo).versionNumber -band 0xFFFF) -eq 0) { Step-GpoVersion $labGpo }
Register-Cse $labGpo $CseSecurity

foreach ($name in 'Workstations', 'Isolated') {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$name'" -SearchBase $ou)) {
        New-ADOrganizationalUnit -Name $name -Path $ou -ProtectedFromAccidentalDeletion $false
    }
}
Ensure-Computer WS02 "OU=Workstations,$ou"
Ensure-Computer WS03 "OU=Isolated,$ou"
Set-GPInheritance -Target "OU=Isolated,$ou" -IsBlocked Yes | Out-Null
foreach ($name in 'LabServerAdmins', 'LabDcRdp', 'LabNobody') {
    if (-not (Get-ADGroup -Filter "Name -eq '$name'")) {
        New-ADGroup $name -GroupScope Global -GroupCategory Security -Path $ou
    }
}
$serverAdmins = (Get-ADGroup LabServerAdmins).SID.Value
$dcRdp = (Get-ADGroup LabDcRdp).SID.Value
$users = $domainUsers.Value

# A: a non-tier-0 group made local admin on every server in OU=Lab, Entra Connect and
# Exchange included (AD-GPO-006). Only "Member of" is set, as the seed writes it.
$gA = Ensure-Gpo LabLocalAdmins
Set-RestrictedGroups $gA @("*$serverAdmins`__Memberof = *S-1-5-32-544")
Ensure-Link LabLocalAdmins $ou

# B: GPP: Domain Users in Remote Desktop Users on OU=Workstations (AD-GPO-007 medium); an
# item behind item-level targeting and a disabled item stay silent.
$gB = Ensure-Gpo LabRdp
$groupsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Remote Desktop Users (built-in)" image="2" changed="2026-11-05 00:00:00" uid="{5C0E6A1D-1B2A-4C3D-8E4F-0A1B2C3D4E01}">
    <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-555" groupName="Remote Desktop Users (built-in)">
      <Members><Member name="ADLAB\Domain Users" action="ADD" sid="$users"/></Members>
    </Properties>
  </Group>
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2026-11-05 00:00:00" uid="{5C0E6A1D-1B2A-4C3D-8E4F-0A1B2C3D4E02}">
    <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members><Member name="ADLAB\Domain Users" action="ADD" sid="$users"/></Members>
    </Properties>
    <Filters><FilterComputer bool="AND" not="0" type="NETBIOS" name="WS02"/></Filters>
  </Group>
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2026-11-05 00:00:00" uid="{5C0E6A1D-1B2A-4C3D-8E4F-0A1B2C3D4E03}" disabled="1">
    <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members><Member name="Everyone" action="ADD" sid="S-1-1-0"/></Members>
    </Properties>
  </Group>
</Groups>
"@
Set-GpoFile $gB 'Machine\Preferences\Groups\Groups.xml' $groupsXml UTF8 $CseGroups
Ensure-Link LabRdp "OU=Workstations,$ou"

# C: a disabled link never applies
$gC = Ensure-Gpo LabDisabledLink
Set-RestrictedGroups $gC @("*$users`__Memberof = *S-1-5-32-544")
Ensure-Link LabDisabledLink "OU=Workstations,$ou" -Enabled No

# D: enforced at OU=Lab, so it reaches WS03 through the block on OU=Isolated (logon edge
# only), and ENTRA01/EXCH01, which are tier 0 (AD-GPO-007 high)
$gD = Ensure-Gpo LabEnforced
Set-RestrictedGroups $gD @("*$serverAdmins`__Memberof = *S-1-5-32-555")
Ensure-Link LabEnforced $ou -Enforced Yes

# E: security filtering: computers can read it, only the empty LabNobody may apply it
$gE = Ensure-Gpo LabFilteredOut
Set-RestrictedGroups $gE @("*$users`__Memberof = *S-1-5-32-544")
Ensure-Link LabFilteredOut "OU=Workstations,$ou"
Set-GPPermission -Name LabFilteredOut -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoRead -Replace | Out-Null
Set-GPPermission -Name LabFilteredOut -TargetName LabNobody -TargetType Group -PermissionLevel GpoApply | Out-Null

# F: computer side disabled (flags 2)
$gF = Ensure-Gpo LabComputerOff
Set-RestrictedGroups $gF @("*$users`__Memberof = *S-1-5-32-544")
Ensure-Link LabComputerOff "OU=Workstations,$ou"
if ($gF.GpoStatus -ne 'ComputerSettingsDisabled') { $gF.GpoStatus = 'ComputerSettingsDisabled' }

# G: on DCs Restricted Groups rewrite the domain's BUILTIN\Remote Desktop Users, which
# grants nothing there (DCs give the remote logon right to Administrators only). Harmless
# by design: nothing goes into Administrators or the operator groups on DCs.
$gG = Ensure-Gpo LabDcRdp
Set-RestrictedGroups $gG @("*$dcRdp`__Memberof = *S-1-5-32-555")
Ensure-Link LabDcRdp "OU=Domain Controllers,$dn"

# AD-ADCS-018: a CA that audits backups and service starts, but no certificate requests. A
# new CA has no AuditFilter value at all, which AD-ADCS-018 reports as not set.
certutil -setreg CA\AuditFilter 3 | Out-Null

# AD-ACC-012: pwdLastSet moved forward with no password change. Clearing and setting it is
# what 'User must change password' does; the wait keeps it past the 5 second tolerance.
Start-Sleep -Seconds 6
Set-ADUser adm_bob -Replace @{ pwdLastSet = 0 }
Set-ADUser adm_bob -Replace @{ pwdLastSet = -1 }

# AD-PRIV-012: a Domain Admin the reader cannot see. The deny sits on the OU because SDProp
# would remove it from the user; the group's member value stays readable.
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Veiled'" -SearchBase $ou)) {
    New-ADOrganizationalUnit -Name Veiled -Path $ou -ProtectedFromAccidentalDeletion $false
}
if (-not (Get-ADUser -Filter "SamAccountName -eq 'veiled_admin'")) {
    New-ADUser -Name veiled_admin -SamAccountName veiled_admin -Path "OU=Veiled,$ou" `
        -AccountPassword $pw -Enabled $true
}
Add-ADGroupMember 'Domain Admins' veiled_admin
dsacls "OU=Veiled,$ou" /D 'ADLAB\adreader:LC' | Out-Null

# GPO reach in the control graph (AD-PATH-001). Edit rights on a GPO linked to OU=Lab and on
# one linked to the site are paths to tier 0; gpo_ctl can edit only GPOs that stop short of
# it: a disabled link and a filter to nobody reach nothing, and the computer side off over an
# OU of computers reaches them only because an editor can turn it back on.
Ensure-User gpo_editor
Ensure-User gpo_site_editor
Ensure-User gpo_ctl
Ensure-Gpo LabOuReach | Out-Null
Ensure-Link LabOuReach $ou
Set-GPPermission -Name LabOuReach -TargetName gpo_editor -TargetType User -PermissionLevel GpoEdit | Out-Null
$gSite = Ensure-Gpo LabSiteReach
$site = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$dn"
# Get-GPInheritance, so Ensure-Link, does not take a site
if ((Get-ADObject $site -Properties gPLink).gPLink -notmatch $gSite.Id) {
    New-GPLink -Name LabSiteReach -Target $site | Out-Null
}
Set-GPPermission -Name LabSiteReach -TargetName gpo_site_editor -TargetType User -PermissionLevel GpoEdit | Out-Null
foreach ($name in 'LabDisabledLink', 'LabComputerOff', 'LabFilteredOut') {
    Set-GPPermission -Name $name -TargetName gpo_ctl -TargetType User -PermissionLevel GpoEdit | Out-Null
}

# AD-DEL-005: delegation targets no account holds. svc_iis's cifs/fs01 is the control: the
# class maps to HOST through sPNMappings, and FS01 holds the HOST SPNs a joined computer has.
Set-ADComputer FS01 -DNSHostName fs01.adlab.test
Set-ADObject (Get-ADComputer FS01) -Replace @{ servicePrincipalName = @('HOST/FS01', 'HOST/fs01.adlab.test') }
Set-ADComputer FS01 -KerberosEncryptionType AES128, AES256
Ensure-User svc_ghost
Set-ADUser svc_ghost -Replace @{ 'msDS-AllowedToDelegateTo' = @(
    'cifs/oldfs.adlab.test', 'cifs/fs01.adlab.test', 'MSSQLSvc/fs01.adlab.test:1433',
    'cifs/files.partner.test') }
Ensure-User svc_ghost_pt
Set-ADAccountControl svc_ghost_pt -TrustedToAuthForDelegation $true
Set-ADUser svc_ghost_pt -Replace @{ 'msDS-AllowedToDelegateTo' = 'http/oldweb.adlab.test' }

# AD-INF-015, -017: local halves of trusts, through LSA because LDAP refuses the system-owned
# attributes of trustedDomain. No partner and no password: none of these trusts works.
# selective.partner.test is the clean control.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LabTrust {
    [StructLayout(LayoutKind.Sequential)]
    struct Str { public ushort Length; public ushort Max; [MarshalAs(UnmanagedType.LPWStr)] public string Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct Attrs { public int Length; public IntPtr Root; public IntPtr Name; public int Flags; public IntPtr Sd; public IntPtr Qos; }
    [StructLayout(LayoutKind.Sequential)]
    struct Info { public Str Name; public Str Flat; public IntPtr Sid; public int Direction; public int Type; public int Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct Auth { public int InCount; public IntPtr InNew; public IntPtr InOld; public int OutCount; public IntPtr OutNew; public IntPtr OutOld; }
    [DllImport("advapi32.dll")] static extern int LsaOpenPolicy(IntPtr system, ref Attrs attrs, int access, out IntPtr policy);
    [DllImport("advapi32.dll")] static extern int LsaCreateTrustedDomainEx(IntPtr policy, ref Info info, ref Auth auth, int access, out IntPtr domain);
    [DllImport("advapi32.dll")] static extern int LsaClose(IntPtr handle);
    [DllImport("advapi32.dll")] static extern int LsaNtStatusToWinError(int status);
    static Str S(string v) { return new Str { Length = (ushort)(v.Length * 2), Max = (ushort)(v.Length * 2), Buffer = v }; }
    public static int Create(string name, string flat, byte[] sid, int direction, int type, int attributes) {
        Attrs attrs = new Attrs(); attrs.Length = Marshal.SizeOf(typeof(Attrs));
        IntPtr policy;
        int status = LsaOpenPolicy(IntPtr.Zero, ref attrs, 0xF0FFF, out policy);
        if (status != 0) return LsaNtStatusToWinError(status);
        IntPtr raw = Marshal.AllocHGlobal(sid.Length);
        Marshal.Copy(sid, 0, raw, sid.Length);
        Info info = new Info { Name = S(name), Flat = S(flat), Sid = raw, Direction = direction, Type = type, Attributes = attributes };
        Auth auth = new Auth();
        IntPtr domain;
        status = LsaCreateTrustedDomainEx(policy, ref info, ref auth, 0xF007F, out domain);
        if (status == 0) LsaClose(domain);
        LsaClose(policy);
        Marshal.FreeHGlobal(raw);
        return LsaNtStatusToWinError(status);
    }
}
'@
function Ensure-Trust($Name, $Type, $Attributes, $Enc, $Rid) {
    $system = "CN=System,$dn"
    $filter = "objectClass -eq 'trustedDomain' -and trustPartner -eq '$Name'"
    if (-not (Get-ADObject -Filter $filter -SearchBase $system)) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-21-1000-2000-$Rid"
        $bytes = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($bytes, 0)
        $flat = ($Name -split '\.')[0].ToUpper()
        $code = [LabTrust]::Create($Name, $flat, $bytes, 3, $Type, $Attributes)
        if ($code) { throw "trust $Name`: Windows error $code" }
    }
    # LDAP refuses this attribute on a trust too
    if ($Enc) { ksetup /setenctypeattr $Name @Enc | Out-Null }
}
Ensure-Trust forest.partner.test 2 0x8 $null 3001         # AD-INF-015 low, AD-INF-017
Ensure-Trust rc4.partner.test 2 0x4 @('RC4-HMAC-MD5') 3002         # AD-INF-015 medium
Ensure-Trust nt4.partner.test 1 0x4 $null 3003         # AD-INF-015 medium, downlevel
Ensure-Trust selective.partner.test 2 0x18 @('AES128-CTS-HMAC-SHA1-96', 'AES256-CTS-HMAC-SHA1-96') 3004    # clean

# SDProp copies the AdminSDHolder ACL onto protected objects now instead of within the hour
$rootDse = [ADSI]'LDAP://RootDSE'
$rootDse.Put('runProtectAdminGroupsTask', 1)
$rootDse.SetInfo()

certutil -pulse | Out-Null
'seeded'
