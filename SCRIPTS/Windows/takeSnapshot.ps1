#####################################################################
# Create a baseline hash of services for later comparison
#####################################################################

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $env:SystemDrive 'CCDC_Baseline'),
    [switch]$SkipSignature
)

$ErrorActionPreference = 'Continue'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this from an elevated (Administrator) prompt.' -ForegroundColor Red
    exit 2
}

$script:hashCache = @{}
$script:sigCache  = @{}

function Get-ExePath([string]$p) {
    if (-not $p) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($p.Trim())
    if ($p -match '^\\SystemRoot\\') { $p = $p -replace '^\\SystemRoot', $env:SystemRoot }
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 0) { return $p.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($p, '^(.*?\.(exe|sys|dll|bat|cmd))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $p
}

function Get-FileSha256([string]$f) {
    if (-not $f) { return '' }
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { return 'MISSING' }
    if ($script:hashCache.ContainsKey($f)) { return $script:hashCache[$f] }
    $h = 'ERROR'
    try {
        $fs = [IO.File]::Open($f, 'Open', 'Read', 'ReadWrite')
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            $h = [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '')
        } finally { $fs.Close() }
    } catch { $h = 'ERROR' }
    $script:hashCache[$f] = $h
    return $h
}

function Get-FileSig([string]$f, [bool]$skip) {
    if ($skip) { return 'Skipped' }
    if (-not $f) { return '' }
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { return 'N/A' }
    if ($script:sigCache.ContainsKey($f)) { return $script:sigCache[$f] }
    try { $v = (Get-AuthenticodeSignature -LiteralPath $f -ErrorAction Stop).Status.ToString() }
    catch { $v = 'ERROR' }
    $script:sigCache[$f] = $v
    return $v
}

function Get-ServiceDllPath([string]$name) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name\Parameters"
    try {
        $v = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).ServiceDll
        if ($v) { return [Environment]::ExpandEnvironmentVariables([string]$v) }
    } catch { }
    return ''
}

function Get-ServiceInventory([bool]$skipSig) {
    $out = @()
    foreach ($w in (Get-WmiObject -Class Win32_Service)) {
        $exe = Get-ExePath $w.PathName
        $dll = Get-ServiceDllPath $w.Name
        $dllHash = ''; $dllSig = ''
        if ($dll) { $dllHash = Get-FileSha256 $dll; $dllSig = Get-FileSig $dll $skipSig }
        $out += New-Object PSObject -Property @{
            Name = $w.Name; DisplayName = $w.DisplayName
            StartMode = $w.StartMode; State = $w.State; StartName = $w.StartName
            PathName = $w.PathName; ExePath = $exe
            ExeSHA256 = (Get-FileSha256 $exe); ExeSignature = (Get-FileSig $exe $skipSig)
            ServiceDll = $dll; ServiceDllSHA256 = $dllHash; ServiceDllSignature = $dllSig
        }
    }
    $out | Select-Object Name, DisplayName, StartMode, State, StartName, PathName, ExePath,
        ExeSHA256, ExeSignature, ServiceDll, ServiceDllSHA256, ServiceDllSignature | Sort-Object Name
}

function Get-Suspicion($s) {
    $r = @()
    $stage = '(?i)\\(users|temp|appdata|programdata|public|perflogs|\$recycle\.bin)\\'
    if ($s.ExePath) {
        if ($s.ExeSHA256 -eq 'MISSING') { $r += 'binary file is missing on disk' }
        if (@('Valid', 'Skipped', 'N/A', '') -notcontains [string]$s.ExeSignature) { $r += ('binary signature: ' + $s.ExeSignature) }
        if ($s.ExePath -match $stage -and $s.ExePath -notmatch '(?i)\\ProgramData\\Microsoft\\Windows Defender\\') { $r += 'binary lives in a user-writable / staging path' }
        if ($s.PathName -and $s.PathName -notmatch '^\s*"' -and $s.ExePath -match '\s') { $r += 'UNQUOTED service path containing spaces (privilege-escalation risk)' }
    }
    if ($s.PathName -match '(?i)(^|[\\ "])(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|bitsadmin|certutil)(\.exe)?(["\s]|$)') {
        $r += 'service launches a shell / LOLBin (cmd, powershell, rundll32, ...)'
    }
    if ($s.StartName -and $s.StartName -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') { $r += ('runs as account: ' + $s.StartName) }
    if ($s.ServiceDll) {
        if ($s.ServiceDll -notlike "$env:SystemRoot\System32\*") { $r += 'ServiceDll is outside System32' }
        if ($s.ServiceDllSHA256 -eq 'MISSING') { $r += 'ServiceDll file is missing on disk' }
        if (@('Valid', 'Skipped', 'N/A', '') -notcontains [string]$s.ServiceDllSignature) { $r += ('ServiceDll signature: ' + $s.ServiceDllSignature) }
    }
    return $r
}

Write-Host "Collecting services on $env:COMPUTERNAME (hashing binaries; signature check may take a minute)..." -ForegroundColor Cyan
$inv = @(Get-ServiceInventory $SkipSignature.IsPresent)

if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
try { & icacls.exe $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null } catch { }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$file  = Join-Path $OutDir ("services_{0}_{1}.csv" -f $env:COMPUTERNAME, $stamp)
$inv | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
$hash = Get-FileSha256 $file
Set-Content -LiteralPath ($file + '.sha256') -Value $hash

$flagged = @()
foreach ($s in $inv) {
    $why = @(Get-Suspicion $s)
    if ($why.Count -gt 0) { $flagged += New-Object PSObject -Property @{ S = $s; Why = $why } }
}

Write-Host ''
Write-Host ('Services captured : {0}' -f $inv.Count)
Write-Host ('Running           : {0}' -f @($inv | Where-Object { $_.State -eq 'Running' }).Count)
Write-Host ('Flagged for review: {0}' -f $flagged.Count) -ForegroundColor Yellow
Write-Host ''

foreach ($f in ($flagged | Sort-Object { $_.S.State -ne 'Running' }, { $_.S.Name })) {
    Write-Host ('{0}  [{1}/{2}]' -f $f.S.Name, $f.S.State, $f.S.StartMode) -ForegroundColor White
    Write-Host ('   Path: {0}' -f $f.S.PathName)
    if ($f.S.ServiceDll) { Write-Host ('   Dll : {0}' -f $f.S.ServiceDll) }
    foreach ($w in $f.Why) { Write-Host ('   - {0}' -f $w) -ForegroundColor Yellow }
}

Write-Host ''
Write-Host "Baseline : $file"
Write-Host "SHA-256  : $hash" -ForegroundColor Green
Write-Host 'Write that hash somewhere OFF this machine (teammate chat, paper, USB). If the CSV is edited later you can prove it.'
Write-Host ''
Write-Host 'Cleanup reminders:' -ForegroundColor Cyan
Write-Host '  - Check what depends on a service first:  Get-Service <name> -DependentServices'
Write-Host '  - Disable + stop before deleting (reversible):  Set-Service <name> -StartupType Disabled; Stop-Service <name> -Force'
Write-Host '  - Never disable a service your scoring checks depend on. Confirm with your team lead / scored-services list first.'
Write-Host '  - Only delete (sc.exe delete <name>) once you are sure it is malicious; keep a copy of the binary for the incident report.'
Write-Host '  - When cleanup is done, re-run this script to create the baseline you will actually compare against.'