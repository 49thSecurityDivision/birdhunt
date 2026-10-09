<#
.SYNOPSIS
  Compare the CURRENT services on this host to a baseline made by Snapshot-Services.ps1 and flag differences.

.USAGE (elevated prompt)
  powershell -ExecutionPolicy Bypass -File .\Compare-Services.ps1
  powershell -ExecutionPolicy Bypass -File .\Compare-Services.ps1 -Scored W3SVC,DNS,MSSQLSERVER
  powershell -ExecutionPolicy Bypass -File .\Compare-Services.ps1 -Watch 60       # re-check every 60 s, only prints NEW findings
  powershell -ExecutionPolicy Bypass -File .\Compare-Services.ps1 -BaselineFile C:\CCDC_Baseline\services_HOST_20261008_093000.csv

  Exit code: 0 = no CRIT/WARN findings, 1 = findings, 2 = could not run.

.PARAMETERS
  -Scored       Service names your scoring checks depend on; flagged CRIT if they stop.
  -Watch        Seconds between checks (0 = run once).
  -ShowInfo     Also print INFO-level changes (service state flapping, display name changes).
  -SkipSignature  Must match how the baseline was taken, or signature fields are ignored.
#>
[CmdletBinding()]
param(
    [string]$BaselineDir = (Join-Path $env:SystemDrive 'CCDC_Baseline'),
    [string]$BaselineFile,
    [string[]]$Scored = @(),
    [int]$Watch = 0,
    [switch]$ShowInfo,
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

$watchList = @('EventLog', 'MpsSvc', 'WinDefend', 'WdNisSvc', 'Sysmon', 'Sysmon64',
               'NTDS', 'DNS', 'Netlogon', 'KDC', 'DFSR', 'W32Time')

$fieldDefs = @(
    @{ F = 'PathName';            S = 'CRIT'; L = 'command line / binary path changed' },
    @{ F = 'ExeSHA256';           S = 'CRIT'; L = 'binary contents changed (legit after patching - verify)' },
    @{ F = 'ServiceDll';          S = 'CRIT'; L = 'ServiceDll path changed' },
    @{ F = 'ServiceDllSHA256';    S = 'CRIT'; L = 'ServiceDll contents changed (legit after patching - verify)' },
    @{ F = 'StartName';           S = 'CRIT'; L = 'logon account changed' },
    @{ F = 'StartMode';           S = 'WARN'; L = 'start mode changed' },
    @{ F = 'ExeSignature';        S = 'WARN'; L = 'binary signature status changed' },
    @{ F = 'ServiceDllSignature'; S = 'WARN'; L = 'ServiceDll signature status changed' },
    @{ F = 'DisplayName';         S = 'INFO'; L = 'display name changed' }
)

if (-not $BaselineFile) {
    $cand = @(Get-ChildItem -LiteralPath $BaselineDir -Filter ("services_{0}_*.csv" -f $env:COMPUTERNAME) -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending)
    if ($cand.Count -eq 0) {
        Write-Host "No baseline for $env:COMPUTERNAME in $BaselineDir. Run Snapshot-Services.ps1 first." -ForegroundColor Red
        exit 2
    }
    $BaselineFile = $cand[0].FullName
}
if (-not (Test-Path -LiteralPath $BaselineFile)) { Write-Host "Baseline not found: $BaselineFile" -ForegroundColor Red; exit 2 }

$logFile = Join-Path (Split-Path -Parent $BaselineFile) ("compare_{0}.log" -f $env:COMPUTERNAME)

$baseTime = (Get-Item -LiteralPath $BaselineFile).LastWriteTime
$tm = [regex]::Match((Split-Path -Leaf $BaselineFile), '_(\d{8}_\d{6})\.csv$')
if ($tm.Success) {
    try { $baseTime = [datetime]::ParseExact($tm.Groups[1].Value, 'yyyyMMdd_HHmmss', $null) } catch { }
}

Write-Host ("Baseline : {0}" -f $BaselineFile)
Write-Host ("Taken    : {0}  ({1:N0} min ago)" -f $baseTime, ((Get-Date) - $baseTime).TotalMinutes)

$hashFile = $BaselineFile + '.sha256'
$actual   = Get-FileSha256 $BaselineFile
if (Test-Path -LiteralPath $hashFile) {
    $expected = ([string](Get-Content -LiteralPath $hashFile -ErrorAction SilentlyContinue | Select-Object -First 1)).Trim()
    if ($expected -ne $actual) {
        Write-Host '[CRIT] BASELINE FILE HAS BEEN MODIFIED since it was created (hash mismatch). Do not trust this comparison.' -ForegroundColor Red
    } else {
        Write-Host 'Baseline hash matches the stored .sha256 file (compare it to the copy you saved off-box).' -ForegroundColor Green
    }
} else {
    Write-Host '[WARN] No .sha256 file next to the baseline - cannot verify integrity.' -ForegroundColor Yellow
}
Write-Host ("SHA-256  : {0}" -f $actual)
Write-Host ''

$baseline = @(Import-Csv -LiteralPath $BaselineFile)
$baseMap  = @{}
foreach ($b in $baseline) { $baseMap[$b.Name] = $b }

$script:seen = @{}

function New-Finding($sev, $key, [string[]]$lines) {
    New-Object PSObject -Property @{ Sev = $sev; Key = $key; Lines = $lines }
}

function Get-EventFindings {
    $f = @()
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $baseTime } -ErrorAction SilentlyContinue)
        foreach ($e in $ev) {
            $p = $e.Properties
            $f += New-Finding 'CRIT' ("EVT|7045|{0}" -f $e.RecordId) @(
                ("SERVICE INSTALLED (event 7045) at {0}: {1}" -f $e.TimeCreated, $p[0].Value),
                ("   Image path: {0}" -f $p[1].Value),
                ("   Account   : {0}" -f $p[4].Value))
        }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; StartTime = $baseTime } -ErrorAction SilentlyContinue)
        foreach ($e in $ev) {
            $f += New-Finding 'CRIT' ("EVT|104|{0}" -f $e.RecordId) @(("SYSTEM EVENT LOG WAS CLEARED (event 104) at {0}" -f $e.TimeCreated))
        }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $baseTime } -ErrorAction SilentlyContinue)
        foreach ($e in $ev) {
            $f += New-Finding 'CRIT' ("EVT|1102|{0}" -f $e.RecordId) @(("SECURITY EVENT LOG WAS CLEARED (event 1102) at {0}" -f $e.TimeCreated))
        }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040; StartTime = $baseTime } -ErrorAction SilentlyContinue)
        foreach ($e in $ev) {
            $f += New-Finding 'INFO' ("EVT|7040|{0}" -f $e.RecordId) @(("Start type changed (event 7040) at {0}: {1}" -f $e.TimeCreated, ($e.Message -replace '\s+', ' ')))
        }
    } catch { }
    return $f
}

function Invoke-Compare {
    $script:hashCache = @{}
    $script:sigCache  = @{}
    $cur = @(Get-ServiceInventory $SkipSignature.IsPresent)
    $curMap = @{}
    foreach ($c in $cur) { $curMap[$c.Name] = $c }
    $findings = @()

    foreach ($c in $cur) {
        $b = $baseMap[$c.Name]

        if (-not $b) {
            $lines = @(
                ("NEW SERVICE: {0}  [{1}/{2}] runs as {3}" -f $c.Name, $c.State, $c.StartMode, $c.StartName),
                ("   Path: {0}" -f $c.PathName))
            if ($c.ServiceDll) { $lines += ("   Dll : {0}" -f $c.ServiceDll) }
            $lines += ("   SHA256: {0}  Sig: {1}" -f $c.ExeSHA256, $c.ExeSignature)
            foreach ($w in @(Get-Suspicion $c)) { $lines += ("   - {0}" -f $w) }
            $findings += New-Finding 'CRIT' ("NEW|{0}" -f $c.Name) $lines
            continue
        }

        $serious = $false
        $changeLines = @()
        $worst = 'INFO'
        foreach ($d in $fieldDefs) {
            $fld = $d.F
            $old = [string]$b.$fld
            $new = [string]$c.$fld
            if ($fld -like '*Signature' -and ($old -eq 'Skipped' -or $new -eq 'Skipped')) { continue }
            if ($old -eq $new) { continue }
            $sev = $d.S
            if ($fld -eq 'StartMode' -and $old -eq 'Disabled' -and $new -ne 'Disabled') { $sev = 'CRIT' }
            $key = "CHG|{0}|{1}|{2}" -f $c.Name, $fld, $new
            $lines = @(("CHANGED: {0} - {1}" -f $c.Name, $d.L), ("   was: {0}" -f $old), ("   now: {0}" -f $new))
            if ($sev -ne 'INFO') { foreach ($w in @(Get-Suspicion $c)) { $lines += ("   - {0}" -f $w) } }
            $findings += New-Finding $sev $key $lines
        }

        if ($b.State -ne $c.State) {
            $sev = 'INFO'
            if ($b.State -eq 'Running' -and $c.State -ne 'Running') {
                $sev = 'WARN'
                if (($watchList -contains $c.Name) -or ($Scored -contains $c.Name)) { $sev = 'CRIT' }
            }
            $findings += New-Finding $sev ("STATE|{0}|{1}" -f $c.Name, $c.State) @(
                ("STATE: {0}  {1} -> {2}  (start mode {3})" -f $c.Name, $b.State, $c.State, $c.StartMode))
        }
    }

    foreach ($b in $baseline) {
        if (-not $curMap.ContainsKey($b.Name)) {
            $findings += New-Finding 'WARN' ("GONE|{0}" -f $b.Name) @(
                ("REMOVED: {0} ({1}) existed in baseline, is gone now" -f $b.Name, $b.PathName))
        }
    }

    foreach ($n in $Scored) {
        $c = $curMap[$n]
        if ($c -and $c.State -ne 'Running') {
            $findings += New-Finding 'CRIT' ("SCORED|{0}|{1}" -f $n, $c.State) @(("SCORED SERVICE NOT RUNNING: {0} is {1}" -f $n, $c.State))
        } elseif (-not $c) {
            $findings += New-Finding 'CRIT' ("SCORED|{0}|absent" -f $n) @(("SCORED SERVICE NOT FOUND: {0}" -f $n))
        }
    }

    $findings += @(Get-EventFindings)
    return $findings
}

function Show-Findings($findings) {
    $shown = 0; $serious = 0
    foreach ($x in ($findings | Sort-Object @{ Expression = { switch ($_.Sev) { 'CRIT' { 0 } 'WARN' { 1 } default { 2 } } } })) {
        if ($script:seen.ContainsKey($x.Key)) { continue }
        $script:seen[$x.Key] = 1
        if ($x.Sev -eq 'INFO' -and -not $ShowInfo) { continue }
        $color = 'Cyan'
        if ($x.Sev -eq 'CRIT') { $color = 'Red' } elseif ($x.Sev -eq 'WARN') { $color = 'Yellow' }
        Write-Host ("[{0}] {1}" -f $x.Sev, $x.Lines[0]) -ForegroundColor $color
        for ($i = 1; $i -lt $x.Lines.Count; $i++) { Write-Host $x.Lines[$i] }
        $shown++
        if ($x.Sev -ne 'INFO') { $serious++ }
        try {
            Add-Content -LiteralPath $logFile -Value ("{0} [{1}] {2}" -f (Get-Date -Format 's'), $x.Sev, ($x.Lines -join ' | '))
        } catch { }
    }
    if ($serious -gt 0) { try { [Console]::Beep(1000, 300) } catch { } }
    return $serious
}

$anySerious = $false
do {
    $stampNow = Get-Date -Format 'HH:mm:ss'
    $f = @(Invoke-Compare)
    $n = Show-Findings $f
    $activeSerious = @($f | Where-Object { $_.Sev -ne 'INFO' }).Count
    if ($activeSerious -gt 0) { $anySerious = $true }
    if ($n -eq 0) {
        if ($activeSerious -eq 0) { Write-Host ("[{0}] no differences from baseline" -f $stampNow) -ForegroundColor Green }
        else { Write-Host ("[{0}] no NEW findings ({1} previously reported items still unresolved)" -f $stampNow, $activeSerious) -ForegroundColor DarkYellow }
    }
    if ($Watch -gt 0) { Start-Sleep -Seconds $Watch }
} while ($Watch -gt 0)

Write-Host ''
if ($anySerious) { exit 1 } else { exit 0 }