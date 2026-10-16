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
#####################################################################

param(
        [switch]$all,
        [switch]$ldap,
        [switch]$rdp,
        [switch]$pswd
    )

$zerologonRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$lsaRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$bannerRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$newAdminName = "AM"

#####################################################################
# Disable print spooler
#####################################################################
try {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue 
    Set-Service -Name Spooler -StartupType Disabled
    Write-Host "Print spooler has been disabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable print spooler."
}

#####################################################################
# Disable guest account
#####################################################################
try {
    $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
    Disable-ADAccount -Identity $guestAccount.SamAccountName
    Write-Host "Guest account has been disabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable Guest account."
}

#####################################################################
# Disable EternalBlue
#####################################################################
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force
    Write-Host "SMBv1 has been disabled" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable SMBv1"
}

#####################################################################
# Disable ZeroLogon
#####################################################################
try {
    if (-not (Test-Path $zerologonRegistryPath)) {
        New-Item -Path $zerologonRegistryPath -Force | Out-Null
    }
    New-ItemProperty -Path $zerologonRegistryPath -Name "FullSecureChannelProtection" -Value 1 -PropertyType DWord -Force
    Write-Host "ZeroLogon has been disabled" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable ZeroLogon"
}

#####################################################################
# Enforce NTLMv2
#####################################################################
try {
    Set-ItemProperty $lsaRegistryPath -Name LmCompatibilityLevel -Value 5 -Type DWord
    Write-Host "NTLMv2 has been enforced" -ForegroundColor Green
}
catch {
    Write-Error "Failed to enforce NTLMv2"
}

#####################################################################
# Disable storing LM hash
#####################################################################
try {
    Set-ItemProperty $lsaRegistryPath -Name NoLMHash -Value 1 -Type DWord
    Write-Host "Storing LM hash has been disabled" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable storing LM hash"
}

#####################################################################
# Disable anonymous enumeration of SAM accounts and shares
#####################################################################
try {
    Set-ItemProperty $lsaRegistryPath -Name RestrictAnonymous -Value 1 -Type DWord
    Write-Host "Anonymous enumeration of SAM accounts and shares has been disabled" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable anonymous enumeration of SAM accounts and shares"
}

#####################################################################
# Disable anonymous enumeration of SAM accounts
#####################################################################
try {
    Set-ItemProperty $lsaRegistryPath -Name RestrictAnonymousSAM -Value 1 -Type DWord
    Write-Host "Anonymous enumeration of SAM accounts has been disabled" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable anonymous enumeration of SAM accounts"
}

#####################################################################
# Disable anonymous SID/name translation
#####################################################################
try {
    secedit /export /cfg C:\Windows\Temp\s.inf /areas SECURITYPOLICY | Out-Null; (Get-Content C:\Windows\Temp\s.inf) -replace 'LSAAnonymousNameLookup\s*=\s*1','LSAAnonymousNameLookup = 0' | Set-Content C:\Windows\Temp\s.inf -Encoding Unicode; secedit /configure /db C:\Windows\Temp\s.sdb /cfg C:\Windows\Temp\s.inf /areas SECURITYPOLICY | Out-Null
    Write-Host "Anonymous SID/name translation has been disabled" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable anonymous SID/name translation"
}

#####################################################################
# Rename admin account
#####################################################################
try {
    Get-LocalUser | Where-Object SID -like '*-500' | Rename-LocalUser -NewName $newAdminName
    Write-Host "Admin account has been renamed to: $newAdminName" -ForegroundColor Green
    $a = Get-ADUser -Identity ((Get-ADDomain).DomainSID.Value + '-500'); Set-ADUser $a -SamAccountName $newAdminName -UserPrincipalName "$newAdminName@$((Get-ADDomain).DNSRoot)"; Rename-ADObject $a.DistinguishedName -NewName $newAdminName
}
catch {
    Write-Error "Failed to rename admin account"
}

#####################################################################
# Add banner message
#####################################################################
try {
    $p=$bannerRegistryPath; Set-ItemProperty $p -Name legalnoticecaption -Value 'Authorized Use Only'; Set-ItemProperty $p -Name legalnoticetext -Value "yo shit has been pwned"
    Write-Host "Banner message has been added" -ForegroundColor Green
}
catch {
    Write-Error "Failed to add banner message"
}

#####################################################################
# Push policy updates to entire forest
#####################################################################
try {
    Get-ADComputer -Filter * | ForEach-Object { Invoke-GPUpdate -Computer $_.Name -Force -RandomDelayInMinutes 0 }
    Write-Host "Policy updates pushed to forest." -ForegroundColor Green
}
catch {
    Write-Error "Policy updates failed to push."
}

Read-Host -Prompt "Press Enter to exit."