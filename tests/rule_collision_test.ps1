#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]:$')]
    [string]$TestDrive = 'X:'
)

$ErrorActionPreference = 'Stop'
$vg = (Resolve-Path (Join-Path $PSScriptRoot '..\bin\vg.exe')).Path
$driveRoot = "$TestDrive\"
$runtimeRoot = Join-Path $driveRoot 'vg_collision'
$execRoot = Join-Path $driveRoot 'vg_collision_exec'
$resultFile = Join-Path $PSScriptRoot 'collision_results.txt'
$script:pass = 0
$script:fail = 0
$script:lines = [Collections.Generic.List[string]]::new()

function Write-Result([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    $script:lines.Add($Text)
    Write-Host $Text -ForegroundColor $Color
}

function Pass([string]$Text) {
    $script:pass++
    Write-Result "  [PASS] $Text" Green
}

function Fail([string]$Text) {
    $script:fail++
    Write-Result "  [FAIL] $Text" Red
}

function Section([string]$Text) {
    Write-Result ''
    Write-Result "  $Text" Cyan
    Write-Result ('-' * 72) DarkGray
}

function Assert-Equal([string]$Label, [string]$Actual, [string]$Expected) {
    if ($Actual -eq $Expected) { Pass "$Label = $Actual" }
    else { Fail "$Label = $Actual (expected $Expected)" }
}

function Invoke-Vg([string[]]$Arguments) {
    & $vg @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "vg.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-ConfigCount([string]$Subkey) {
    $item = Get-ItemProperty -Path "HKCU:\Software\VG\$Subkey" -ErrorAction SilentlyContinue
    if (-not $item) { return 0 }
    @($item.PSObject.Properties | Where-Object Name -notmatch '^PS').Count
}

function Clear-Rules {
    Remove-Item -LiteralPath 'HKCU:\Software\VG\Paths' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'HKCU:\Software\VG\Trusted' -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-Vg @('/protection', 'on')
}

function Test-DirectRead([string]$Path) {
    try { [void][IO.File]::ReadAllText($Path); 'ALLOW' } catch { 'DENY' }
}

function Test-DirectWrite([string]$Directory) {
    $target = Join-Path $Directory ("write_$([Guid]::NewGuid().ToString('N')).tmp")
    try {
        [IO.File]::WriteAllText($target, 'write')
        'ALLOW'
    } catch { 'DENY' }
    finally { if ([IO.File]::Exists($target)) { [IO.File]::Delete($target) } }
}

function Test-ProbeRead([string]$Exe, [string]$Path) {
    try {
        $process = Start-Process -FilePath $Exe -ArgumentList @('/d', '/c', 'type', $Path) -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -eq 0) { 'ALLOW' } else { 'DENY' }
    } catch { 'DENY' }
}

function Test-ProbeStart([string]$Exe) {
    try {
        $process = Start-Process -FilePath $Exe -ArgumentList @('/d', '/c', 'exit', '0') -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -eq 0) { 'ALLOW' } else { 'DENY' }
    } catch { 'DENY' }
}

function Wait-DriverStopped {
    for ($i = 0; $i -lt 30; $i++) {
        $query = (& sc.exe query clrcd 2>$null) -join "`n"
        if ($query -notmatch 'STATE\s+:\s+4\s+RUNNING') { return }
        Start-Sleep -Milliseconds 100
    }
    throw 'clrcd did not stop in time'
}

if (-not (Test-Path $driveRoot)) { throw "$driveRoot is not mounted" }
$volume = Get-Volume -DriveLetter $TestDrive.Substring(0, 1) -ErrorAction Stop
if ($volume.FileSystem -ne 'NTFS') { throw "$driveRoot must be an isolated NTFS test volume" }
if ((Get-ConfigCount 'Paths') -ne 0 -or (Get-ConfigCount 'Trusted') -ne 0) {
    throw 'HKCU\Software\VG must be empty before this destructive collision test'
}
$runningQuery = (& sc.exe query clrcd 2>$null) -join "`n"
if ($runningQuery -match 'STATE\s+:\s+4\s+RUNNING') {
    throw 'clrcd must be stopped before this destructive collision test'
}
$initialDriver = Get-CimInstance Win32_SystemDriver -Filter "Name='clrcd'" -ErrorAction SilentlyContinue

$pathA = Join-Path $runtimeRoot 'protected_a'
$pathB = Join-Path $runtimeRoot 'protected_b'
$child = Join-Path $pathA 'child'
$sibling = Join-Path $pathA 'sibling'
$fileA = Join-Path $pathA 'a.txt'
$fileB = Join-Path $pathB 'b.txt'
$childFile = Join-Path $child 'child.txt'
$siblingFile = Join-Path $sibling 'sibling.txt'
$execA = Join-Path $execRoot 'a'
$execB = Join-Path $execRoot 'b'
$sameA = Join-Path $execA 'collisionprobe.exe'
$sameB = Join-Path $execB 'collisionprobe.exe'
$otherProbe = Join-Path $execA 'otherprobe.exe'
$insideSelf = Join-Path $pathA 'selflocked.exe'
$outsideSelf = Join-Path $execA 'selflocked.exe'
$insideRun = Join-Path $child 'childrun.exe'
$manyPaths = 0..6 | ForEach-Object { Join-Path $runtimeRoot "many_path_$_" }
$manyFiles = 0..6 | ForEach-Object { Join-Path $manyPaths[$_] "file_$_.txt" }
$manyProbes = 0..5 | ForEach-Object { Join-Path $execA "vgcol$_.exe" }

try {
    foreach ($directory in @($pathA, $pathB, $child, $sibling, $execA, $execB) + $manyPaths) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    [IO.File]::WriteAllText($fileA, 'a')
    [IO.File]::WriteAllText($fileB, 'b')
    [IO.File]::WriteAllText($childFile, 'child')
    [IO.File]::WriteAllText($siblingFile, 'sibling')
    for ($i = 0; $i -lt $manyFiles.Count; $i++) { [IO.File]::WriteAllText($manyFiles[$i], "$i") }
    foreach ($destination in @($sameA, $sameB, $otherProbe, $insideSelf, $outsideSelf, $insideRun) + $manyProbes) {
        [IO.File]::Copy((Join-Path $env:WINDIR 'System32\cmd.exe'), $destination, $true)
    }

    Clear-Rules

    Section 'Last-rule and complete-list transitions'
    Invoke-Vg @('/setitem', $pathA, 'Locked')
    Assert-Equal 'one path locked' (Test-DirectRead $fileA) 'DENY'
    Invoke-Vg @('/setitem', $pathB, 'Locked')
    Assert-Equal 'adding B keeps A locked' (Test-DirectRead $fileA) 'DENY'
    Assert-Equal 'B is locked' (Test-DirectRead $fileB) 'DENY'
    Invoke-Vg @('/setitem', $pathA, 'Disabled')
    Assert-Equal 'disabling A lifts A' (Test-DirectRead $fileA) 'ALLOW'
    Assert-Equal 'disabling A keeps B locked' (Test-DirectRead $fileB) 'DENY'
    Invoke-Vg @('/setitem', $pathB, 'Disabled')
    Assert-Equal 'disabling last path lifts B' (Test-DirectRead $fileB) 'ALLOW'
    for ($cycle = 1; $cycle -le 3; $cycle++) {
        Invoke-Vg @('/setitem', $pathA, 'Locked')
        Assert-Equal "last-path cycle $cycle locked" (Test-DirectRead $fileA) 'DENY'
        Invoke-Vg @('/setitem', $pathA, 'Disabled')
        Assert-Equal "last-path cycle $cycle disabled" (Test-DirectRead $fileA) 'ALLOW'
    }

    Section 'More records than the original five-slot client'
    Clear-Rules
    foreach ($path in $manyPaths) { Invoke-Vg @('/setitem', $path, 'Locked') }
    Assert-Equal '7 paths: first active' (Test-DirectRead $manyFiles[0]) 'DENY'
    Assert-Equal '7 paths: middle active' (Test-DirectRead $manyFiles[3]) 'DENY'
    Assert-Equal '7 paths: last active' (Test-DirectRead $manyFiles[6]) 'DENY'
    Invoke-Vg @('/setitem', $manyPaths[3], 'Disabled')
    Assert-Equal '7 paths: middle disabled' (Test-DirectRead $manyFiles[3]) 'ALLOW'
    Assert-Equal '7 paths: first survives middle change' (Test-DirectRead $manyFiles[0]) 'DENY'
    Assert-Equal '7 paths: last survives middle change' (Test-DirectRead $manyFiles[6]) 'DENY'

    Section 'Global trusted-name behavior and update order'
    Clear-Rules
    Invoke-Vg @('/setitem', $pathA, 'Locked')
    Invoke-Vg @('/setitem', $pathB, 'Locked')
    Assert-Equal 'untrusted same-name copy A' (Test-ProbeRead $sameA $fileA) 'DENY'
    Assert-Equal 'untrusted same-name copy B' (Test-ProbeRead $sameB $fileB) 'DENY'
    Invoke-Vg @('/settrusted', 'collisionprobe.exe', 'Enabled')
    Assert-Equal 'trusted basename copy A -> path A' (Test-ProbeRead $sameA $fileA) 'ALLOW'
    Assert-Equal 'trusted basename copy A -> path B' (Test-ProbeRead $sameA $fileB) 'ALLOW'
    Assert-Equal 'trusted basename copy B -> path A' (Test-ProbeRead $sameB $fileA) 'ALLOW'
    Assert-Equal 'trusted basename copy B -> path B' (Test-ProbeRead $sameB $fileB) 'ALLOW'
    Invoke-Vg @('/settrusted', 'otherprobe.exe', 'Enabled')
    Invoke-Vg @('/settrusted', 'collisionprobe.exe', 'Disabled')
    Assert-Equal 'disabled collision basename denied' (Test-ProbeRead $sameA $fileA) 'DENY'
    Assert-Equal 'other trusted survives disable' (Test-ProbeRead $otherProbe $fileA) 'ALLOW'
    Invoke-Vg @('/settrusted', 'C:\irrelevant\CoLlIsIoNpRoBe', 'Enabled')
    Assert-Equal 'path/case/extension normalization' (Test-ProbeRead $sameB $fileB) 'ALLOW'

    Clear-Rules
    Invoke-Vg @('/settrusted', 'collisionprobe.exe', 'Enabled')
    Invoke-Vg @('/setitem', $pathA, 'Locked')
    Invoke-Vg @('/setitem', $pathB, 'Locked')
    Assert-Equal 'trusted-first then path A' (Test-ProbeRead $sameA $fileA) 'ALLOW'
    Assert-Equal 'trusted-first then path B' (Test-ProbeRead $sameB $fileB) 'ALLOW'

    Section 'Six trusted entries and removal from the middle'
    Clear-Rules
    Invoke-Vg @('/setitem', $pathA, 'Locked')
    for ($i = 0; $i -lt $manyProbes.Count; $i++) { Invoke-Vg @('/settrusted', "vgcol$i.exe", 'Enabled') }
    Assert-Equal '6 trusted: first active' (Test-ProbeRead $manyProbes[0] $fileA) 'ALLOW'
    Assert-Equal '6 trusted: last active' (Test-ProbeRead $manyProbes[5] $fileA) 'ALLOW'
    Invoke-Vg @('/settrusted', 'vgcol3.exe', 'Disabled')
    Assert-Equal '6 trusted: middle removed' (Test-ProbeRead $manyProbes[3] $fileA) 'DENY'
    Assert-Equal '6 trusted: first survives' (Test-ProbeRead $manyProbes[0] $fileA) 'ALLOW'
    Assert-Equal '6 trusted: last survives' (Test-ProbeRead $manyProbes[5] $fileA) 'ALLOW'

    Section 'Executable is both protected and trusted'
    Clear-Rules
    Invoke-Vg @('/setitem', $insideSelf, 'Locked')
    Invoke-Vg @('/setitem', $pathB, 'Locked')
    Invoke-Vg @('/settrusted', 'selflocked.exe', 'Enabled')
    Assert-Equal 'protected executable cannot bootstrap itself' (Test-ProbeStart $insideSelf) 'DENY'
    Assert-Equal 'same basename outside protected path is trusted' (Test-ProbeRead $outsideSelf $fileB) 'ALLOW'
    Invoke-Vg @('/setitem', $insideSelf, 'Disabled')
    Assert-Equal 'after lifting executable path it can start and read' (Test-ProbeRead $insideSelf $fileB) 'ALLOW'

    Section 'Parent/child precedence and No-execution collision'
    Clear-Rules
    Invoke-Vg @('/setitem', $runtimeRoot, 'Locked')
    Invoke-Vg @('/setitem', $child, 'Disabled')
    Assert-Equal 'parent Locked then child Disabled' (Test-DirectRead $childFile) 'DENY'
    Clear-Rules
    Invoke-Vg @('/setitem', $child, 'Disabled')
    Invoke-Vg @('/setitem', $runtimeRoot, 'Locked')
    Assert-Equal 'child Disabled then parent Locked' (Test-DirectRead $childFile) 'DENY'

    Clear-Rules
    Invoke-Vg @('/setitem', $pathA, 'No-execution')
    Invoke-Vg @('/setitem', $child, 'Disabled')
    Assert-Equal 'parent No-exec then child Disabled' (Test-ProbeStart $insideRun) 'DENY'
    Clear-Rules
    Invoke-Vg @('/setitem', $child, 'Disabled')
    Invoke-Vg @('/setitem', $pathA, 'No-execution')
    Assert-Equal 'child Disabled then parent No-exec' (Test-ProbeStart $insideRun) 'DENY'
    Invoke-Vg @('/setitem', $pathA, 'Disabled')
    Assert-Equal 'lifting parent No-exec allows start' (Test-ProbeStart $insideRun) 'ALLOW'

    Clear-Rules
    Invoke-Vg @('/setitem', $pathA, 'Read-only')
    Invoke-Vg @('/setitem', $child, 'Locked')
    Assert-Equal 'child Locked overrides parent Read-only for read' (Test-DirectRead $childFile) 'DENY'
    Assert-Equal 'parent Read-only permits sibling read' (Test-DirectRead $siblingFile) 'ALLOW'
    Assert-Equal 'parent Read-only blocks sibling write' (Test-DirectWrite $sibling) 'DENY'

    Section 'Protection toggle and driver restart persistence'
    Clear-Rules
    Invoke-Vg @('/setitem', $pathA, 'Locked')
    Invoke-Vg @('/setitem', $pathB, 'Locked')
    Invoke-Vg @('/settrusted', 'collisionprobe.exe', 'Enabled')
    Invoke-Vg @('/settrusted', 'otherprobe.exe', 'Enabled')
    Invoke-Vg @('/protection', 'off')
    Assert-Equal 'global off raw path A' (Test-DirectRead $fileA) 'ALLOW'
    Assert-Equal 'global off raw path B' (Test-DirectRead $fileB) 'ALLOW'
    Invoke-Vg @('/protection', 'on')
    Assert-Equal 'global on raw path A' (Test-DirectRead $fileA) 'DENY'
    Assert-Equal 'global on trusted A' (Test-ProbeRead $sameA $fileA) 'ALLOW'

    Invoke-Vg @('/driver', 'stop')
    Wait-DriverStopped
    Invoke-Vg @('/driver', 'start')
    Invoke-Vg @('/protection', 'on')
    Assert-Equal 'restart raw path A restored' (Test-DirectRead $fileA) 'DENY'
    Assert-Equal 'restart raw path B restored' (Test-DirectRead $fileB) 'DENY'
    Assert-Equal 'restart trusted collision restored' (Test-ProbeRead $sameA $fileA) 'ALLOW'
    Assert-Equal 'restart trusted other restored' (Test-ProbeRead $otherProbe $fileB) 'ALLOW'

    Section 'Registry counts after collision matrix'
    Assert-Equal 'configured path count' ([string](Get-ConfigCount 'Paths')) '2'
    Assert-Equal 'configured trusted count' ([string](Get-ConfigCount 'Trusted')) '2'
} finally {
    try {
        Remove-Item -LiteralPath 'HKCU:\Software\VG\Paths' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'HKCU:\Software\VG\Trusted' -Recurse -Force -ErrorAction SilentlyContinue
        Invoke-Vg @('/protection', 'on')
        Invoke-Vg @('/protection', 'off')
        Invoke-Vg @('/driver', 'stop')
        Wait-DriverStopped
    } catch {}
    if ($null -eq $initialDriver) {
        try { Invoke-Vg @('/driver', 'uninstall') } catch {}
    }
    if ([IO.Directory]::Exists($runtimeRoot)) { [IO.Directory]::Delete($runtimeRoot, $true) }
    if ([IO.Directory]::Exists($execRoot)) { [IO.Directory]::Delete($execRoot, $true) }
}

$total = $script:pass + $script:fail
Write-Result ''
if ($script:fail -eq 0) { Write-Result "  ALL PASS   $($script:pass) / $total" Green }
else { Write-Result "  $($script:fail) FAILED   [$($script:pass) / $total passed]" Red }
$script:lines | Set-Content -Path $resultFile -Encoding UTF8
Write-Result "  Results written to: $resultFile" DarkGray
exit $script:fail
