#####################################################################
# 
# basicPolicy.ps1
# 
# Enforces a few universal policy changes or vulnerability patches and 
# includes additional optional changes based on flags.
# 
# Flags: -all, -audit, -ldap, -rdp, -pswd
# 
# Base changes:
#  - Disable print spooler
#  - Disable guest accout
#  - Disable EternalBlue
#  - Disable ZeroLogon
#  - Enforce NTLMv2
#  - Do not store LM hash
#  - Do not allow enumeration of SAM accounts and shares
#  - Do not allow enumeration of SAM accounts
#  - Do not allow anonymous SID/Name translation
#  - Rename admin account
#  - Set logon banner
#  - Disable WDigest - TODO
#  - Require SMB signing
#  - Disable anonymous access to shares
#
# Audit changes: -audit
#  - Enable detailed logging
#
# Password changes: -pswd
#  - Enforce password complexity
#
# Notes:
#  - Registry-backed settings go into a GPO when run on a DC (they get
#    re-applied every ~90 min). On a non-DC they are written locally.
#  - Logs/backups are written to $logDir.
#
#####################################################################

param(
        [switch]$all,
        [switch]$audit,
        [switch]$ldap,
        [switch]$rdp,
        [switch]$pswd
    )

#####################################################################
# Variables
#####################################################################
$zerologonRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$lsaRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$bannerRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$newAdminName = "Administrator"
$bannerCaption = 'Authorized Use Only'
$bannerText = 'Yo shit has been pwned 2'
$gpoName = '49sd'
$logDir = 'C:\ccdc-logs'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$secInf = "$env:windir\Temp\s.inf"
$secDb = "$env:windir\Temp\s.sdb"
$backupKeys = @(
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
)

$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
if ($isDC) {
    Import-Module ActiveDirectory, GroupPolicy                # [NEW] make sure AD and GPO cmdlets are loaded
    $domainDN = (Get-ADDomain).DistinguishedName              # [NEW] GPO gets linked at the domain root
}

#####################################################################
# Helper functions
#####################################################################

# Print success or error messages for each step
function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    try {
        $ErrorActionPreference = 'Stop'
        & $Action | Out-Null
        Write-Host "[OK]   $Name" -ForegroundColor Green
    }
    catch {
        Write-Host "[FAIL] $Name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Write policy into gpo or registry as needed
function Set-PolicyValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if ($isDC) {
        # Set-GPRegistryValue wants "HKLM\..." not "HKLM:\..."
        Set-GPRegistryValue -Name $gpoName -Key ($Path -replace '^HKLM:\\', 'HKLM\') -ValueName $Name -Type $Type -Value $Value | Out-Null
    }
    else {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }   # create the key if it is missing
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

#####################################################################
# Logging and backup
#####################################################################
New-Item -ItemType Directory -Path $logDir -Force | Out-Null           # create log folder if needed
Start-Transcript -Path "$logDir\basicPolicy-$stamp.txt" | Out-Null     # full record of everything this run does (useful for injects)
foreach ($k in $backupKeys) {
    $file = "$logDir\backup-$stamp-" + ($k -replace '[\\:]', '_') + '.reg'   # one .reg file per key, restore with: reg import <file>
    reg export $k $file /y | Out-Null                                        # snapshot the key before we touch it
}
secedit /export /cfg "$logDir\secpol-before-$stamp.inf" | Out-Null     # snapshot local security policy (admin rename, SID lookup, etc.)

#####################################################################
# Create and link GPO
#####################################################################
Invoke-Step "Create/link GPO '$gpoName'" {
    if (-not $isDC) { Write-Host "  Not a DC: settings will be written locally instead of to a GPO."; return }
    if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) { New-GPO -Name $gpoName | Out-Null }   # create only if missing
    $linked = (Get-GPInheritance -Target $domainDN).GpoLinks | Where-Object DisplayName -eq $gpoName         # already linked?
    if (-not $linked) { New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes -Enforced Yes | Out-Null } # link at domain root, enforced
}

#####################################################################
# Disable print spooler
#####################################################################
Invoke-Step 'Disable print spooler' {                                 # [CHANGED] try/catch replaced by Invoke-Step
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue   # fine if it is already stopped
    Set-Service -Name Spooler -StartupType Disabled
}

#####################################################################
# Disable guest account
#####################################################################
Invoke-Step 'Disable Guest account' {                                 # [CHANGED] looks up by RID 501 instead of the name "Guest"
    if ($isDC) {
        Disable-ADAccount -Identity ((Get-ADDomain).DomainSID.Value + '-501')   # domain Guest, found by SID so renames do not matter
    }
    else {
        Get-LocalUser | Where-Object SID -like '*-501' | Disable-LocalUser      # local Guest on member servers/workstations
    }
}

#####################################################################
# Disable EternalBlue
#####################################################################
Invoke-Step 'Disable SMBv1' {
    Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force      # turn off SMBv1 server immediately
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue   # [NEW] remove the feature entirely (restart finishes it); ignore if already removed
}

#####################################################################
# Disable ZeroLogon
#####################################################################
Invoke-Step 'Disable ZeroLogon' {                                     # [CHANGED] value now goes through the GPO
    Set-PolicyValue $zerologonRegistryPath 'FullSecureChannelProtection' 1   # enforce secure channel (needs Aug 2020+ patches on the DC)
    Remove-ItemProperty $zerologonRegistryPath -Name VulnerableChannelAllowList -ErrorAction SilentlyContinue   # [NEW] remove a possible red-team allow-list backdoor
}

#####################################################################
# Enforce NTLMv2
#####################################################################
Invoke-Step 'Enforce NTLMv2' {
    Set-PolicyValue $lsaRegistryPath 'LmCompatibilityLevel' 5         # [CHANGED] via GPO; 5 = NTLMv2 only, refuse LM and NTLM
}

#####################################################################
# Disable storing LM hash
#####################################################################
Invoke-Step 'Disable storing LM hash' {
    Set-PolicyValue $lsaRegistryPath 'NoLMHash' 1                     # [CHANGED] via GPO; only affects future password changes
}

#####################################################################
# Disable anonymous enumeration of SAM accounts and shares
#####################################################################
Invoke-Step 'Disable anonymous enumeration of SAM accounts and shares' {
    Set-PolicyValue $lsaRegistryPath 'RestrictAnonymous' 1            # [CHANGED] via GPO
}

#####################################################################
# Disable anonymous enumeration of SAM accounts
#####################################################################
Invoke-Step 'Disable anonymous enumeration of SAM accounts' {
    Set-PolicyValue $lsaRegistryPath 'RestrictAnonymousSAM' 1         # [CHANGED] via GPO
}

#####################################################################
# Disable anonymous SID/name translation
#####################################################################
Invoke-Step 'Disable anonymous SID/name translation' {                # [CHANGED] secedit exit codes are now checked
    secedit /export /cfg $secInf /areas SECURITYPOLICY | Out-Null     # dump current local policy
    if ($LASTEXITCODE -ne 0) { throw 'secedit export failed' }        # secedit never throws, so check the exit code
    (Get-Content $secInf) -replace 'LSAAnonymousNameLookup\s*=\s*1', 'LSAAnonymousNameLookup = 0' | Set-Content $secInf -Encoding Unicode   # flip the value; Unicode is required for secedit
    secedit /configure /db $secDb /cfg $secInf /areas SECURITYPOLICY | Out-Null   # re-apply the edited policy
    if ($LASTEXITCODE -ne 0) { throw 'secedit configure failed' }
    Remove-Item $secInf, $secDb -ErrorAction SilentlyContinue         # clean up temp files
}

#####################################################################
# Rename admin account
#####################################################################
Invoke-Step 'Rename built-in Administrator' {                         # [CHANGED] branches on DC vs non-DC
    $users = Get-CimInstance Win32_Service | Where-Object StartName -like '*Administrator*'   # [NEW] services that log on as Administrator will break
    if ($users) { Write-Host "  WARNING: services run as Administrator: $($users.Name -join ', ')" -ForegroundColor Yellow }
    if ($isDC) {
        $a = Get-ADUser -Identity ((Get-ADDomain).DomainSID.Value + '-500')   # RID 500, works even if already renamed
        Set-ADUser $a -SamAccountName $newAdminName -UserPrincipalName "$newAdminName@$((Get-ADDomain).DNSRoot)"   # change logon names
        Rename-ADObject $a.DistinguishedName -NewName $newAdminName           # change the AD object name
    }
    else {
        Get-LocalUser | Where-Object SID -like '*-500' | Rename-LocalUser -NewName $newAdminName   # local admin by RID 500
    }
}

#####################################################################
# Add banner message
#####################################################################
Invoke-Step 'Add banner message' {
    Set-PolicyValue $bannerRegistryPath 'legalnoticecaption' $bannerCaption 'String'   # [CHANGED] via GPO; title shown at logon
    Set-PolicyValue $bannerRegistryPath 'legalnoticetext' $bannerText 'String'         # [CHANGED] via GPO; message body
}

#####################################################################
# Optional: audit logging (-audit)  [NEW EMPTY BUCKET]
#####################################################################
if ($audit -or $all) {
    Write-Host "[SKIP] Audit bucket selected but nothing implemented yet." -ForegroundColor Yellow
    # TODO: enable detailed audit policy (auditpol), command-line logging in event 4688, bigger Security log
}

#####################################################################
# Optional: LDAP hardening (-ldap)  [NEW EMPTY BUCKET]
#####################################################################
if ($ldap -or $all) {
    Write-Host "[SKIP] LDAP bucket selected but nothing implemented yet." -ForegroundColor Yellow
    # TODO: LDAP signing / channel binding
}

#####################################################################
# Optional: RDP hardening (-rdp)  [NEW EMPTY BUCKET]
#####################################################################
if ($rdp -or $all) {
    Write-Host "[SKIP] RDP bucket selected but nothing implemented yet." -ForegroundColor Yellow
    # TODO: require NLA, restrict who can log on via RDP
}

#####################################################################
# Optional: password policy (-pswd)  [NEW EMPTY BUCKET]
#####################################################################
if ($pswd -or $all) {
    Write-Host "[SKIP] Password bucket selected but nothing implemented yet." -ForegroundColor Yellow
    # TODO: enforce password complexity / minimum length (and rotate passwords)
}

#####################################################################
# Push policy updates to entire forest
#####################################################################
Invoke-Step 'Refresh local policy' {
    gpupdate /force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'gpupdate failed' }
}

if ($isDC) {
    Get-ADComputer -Filter 'Enabled -eq $true' | ForEach-Object {
        $name = $_.Name
        Invoke-Step "GPUpdate on $name" {
            if (-not (Test-Connection $name -Count 1 -Quiet)) { throw 'offline/unreachable' }
            Invoke-GPUpdate -Computer $name -Force -RandomDelayInMinutes 0
        }
    }
}

Stop-Transcript | Out-Null