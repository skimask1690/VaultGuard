#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = Join-Path $PSScriptRoot 'runtime_protocol_probe'
$execRoot = Join-Path $PSScriptRoot 'runtime_protocol_probe_exec'
$child = Join-Path $root 'child'
$other = Join-Path $root 'other'
$childFile = Join-Path $child 'child.txt'
$otherFile = Join-Path $other 'other.txt'
$probeA = Join-Path $execRoot 'vgscopea.exe'
$probeB = Join-Path $execRoot 'vgscopeb.exe'
$vg = (Resolve-Path (Join-Path $PSScriptRoot '..\bin\vg.exe')).Path
$initialService = (Get-Service clrcd -ErrorAction SilentlyContinue).Status

if ($initialService -eq 'Running') {
    throw 'Stop clrcd before running this destructive protocol probe; it replaces the active in-memory rule lists.'
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class VgProbeNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFile(
        string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        IntPtr device, uint code, byte[] input, int inputSize,
        byte[] output, int outputSize, out int bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(
        string deviceName, StringBuilder targetPath, int maxChars);
}
'@

$IOCTL_ADD_PATH = [uint32]0x9C402400L
$IOCTL_ENUM_PATHS = [uint32]0x9C402404L
$IOCTL_SET_TRUSTED = [uint32]0x9C402408L
$IOCTL_ENUM_TRUSTED = [uint32]0x9C40240CL
$PATH_RECORD = 0x1404
$TRUST_RECORD = 0x0D94
$INVALID_HANDLE = [IntPtr](-1)
$device = [IntPtr]::Zero

function Invoke-Vg([string[]]$Arguments) {
    $p = Start-Process -FilePath $vg -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) {
        throw "vg.exe $($Arguments -join ' ') failed with exit code $($p.ExitCode)"
    }
}

function Invoke-Ioctl {
    param(
        [uint32]$Code,
        [byte[]]$InputBuffer,
        [int]$OutputSize = 0
    )
    $out = if ($OutputSize -gt 0) { [byte[]]::new($OutputSize) } else { $null }
    $returned = 0
    $inSize = if ($null -eq $InputBuffer) { 0 } else { $InputBuffer.Length }
    $ok = [VgProbeNative]::DeviceIoControl(
        $device, $Code, $InputBuffer, $inSize, $out, $OutputSize,
        [ref]$returned, [IntPtr]::Zero)
    if (-not $ok) {
        throw ('DeviceIoControl 0x{0:X8} failed: Win32 {1}' -f $Code, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    [pscustomobject]@{ Buffer = $out; Bytes = $returned }
}

function Convert-ToNtPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $drive = $full.Substring(0, 2)
    $target = [Text.StringBuilder]::new(1024)
    if ([VgProbeNative]::QueryDosDevice($drive, $target, $target.Capacity) -eq 0) {
        throw "QueryDosDevice($drive) failed"
    }
    $target.ToString() + $full.Substring(2)
}

function Copy-WideString([byte[]]$Buffer, [int]$Offset, [int]$CapacityBytes, [string]$Value) {
    $bytes = [Text.Encoding]::Unicode.GetBytes($Value + [char]0)
    if ($bytes.Length -gt $CapacityBytes) { throw "String does not fit at offset $Offset" }
    [Array]::Copy($bytes, 0, $Buffer, $Offset, $bytes.Length)
}

function New-PathBuffer([object[]]$Rules) {
    if ($Rules.Count -gt 5) { throw 'The original path input buffer holds at most five records' }
    # The original client always submits exactly 0x6414 bytes (5 * 0x1404),
    # even when fewer records are populated.
    $buffer = [byte[]]::new($PATH_RECORD * 5)
    for ($i = 0; $i -lt $Rules.Count; $i++) {
        $base = $i * $PATH_RECORD
        [Array]::Copy([BitConverter]::GetBytes([uint32]$Rules[$i].Flags), 0, $buffer, $base, 4)
        Copy-WideString $buffer ($base + 4) 0x800 (Convert-ToNtPath $Rules[$i].Path)
    }
    $buffer
}

function New-TrustBuffer([object[]]$Rules) {
    $buffer = [byte[]]::new($TRUST_RECORD * $Rules.Count)
    for ($i = 0; $i -lt $Rules.Count; $i++) {
        $base = $i * $TRUST_RECORD
        [Array]::Copy([BitConverter]::GetBytes([uint32]$Rules[$i].Flags), 0, $buffer, $base, 4)
        Copy-WideString $buffer ($base + 4) 0x190 $Rules[$i].Name
        if ($Rules[$i].Field2) { Copy-WideString $buffer ($base + 0x194) 0x800 $Rules[$i].Field2 }
        if ($Rules[$i].Field3) { Copy-WideString $buffer ($base + 0x994) 0x400 $Rules[$i].Field3 }
    }
    $buffer
}

function Set-Paths([object[]]$Rules) {
    [void](Invoke-Ioctl $IOCTL_ADD_PATH (New-PathBuffer $Rules))
}

function Set-Trusted([object[]]$Rules) {
    [void](Invoke-Ioctl $IOCTL_SET_TRUSTED (New-TrustBuffer $Rules))
}

function Test-DirectRead([string]$Path) {
    try {
        [void][IO.File]::ReadAllText($Path)
        'ALLOW'
    } catch {
        'DENY'
    }
}

function Test-ProbeRead([string]$Exe, [string]$Path) {
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList @('/d', '/c', 'type', $Path) -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        if ($p.ExitCode -eq 0) { 'ALLOW' } else { "DENY($($p.ExitCode))" }
    } catch {
        'DENY(start)'
    }
}

[IO.Directory]::CreateDirectory($child) | Out-Null
[IO.Directory]::CreateDirectory($other) | Out-Null
[IO.Directory]::CreateDirectory($execRoot) | Out-Null
[IO.File]::WriteAllText($childFile, 'child')
[IO.File]::WriteAllText($otherFile, 'other')
[IO.File]::Copy((Join-Path $env:WINDIR 'System32\cmd.exe'), $probeA, $true)
[IO.File]::Copy((Join-Path $env:WINDIR 'System32\cmd.exe'), $probeB, $true)

$results = [Collections.Generic.List[object]]::new()

try {
    Invoke-Vg @('/driver', 'start')
    # Use the production wrapper once to establish the global active state;
    # raw probes below still supply every path/trusted record directly.
    Invoke-Vg @('/protection', 'on')
    $device = [VgProbeNative]::CreateFile(
        '\\.\BE79F7D853E643089D51EDCDA79805C4',
        ([uint32]0xC0000000L), 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($device -eq $INVALID_HANDLE) {
        throw "CreateFile(device) failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    Set-Paths @([pscustomobject]@{ Path=$childFile; Flags=2 })
    $results.Add([pscustomobject]@{ Test='exact file Locked'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    # Parent Locked and child Read-only reveal precedence for overlapping paths.
    Set-Paths @(
        [pscustomobject]@{ Path=$root; Flags=2 },
        [pscustomobject]@{ Path=$child; Flags=4 }
    )
    $results.Add([pscustomobject]@{ Test='paths parent->child'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    Set-Paths @(
        [pscustomobject]@{ Path=$child; Flags=4 },
        [pscustomobject]@{ Path=$root; Flags=2 }
    )
    $results.Add([pscustomobject]@{ Test='paths child->parent'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    # A non-empty zero-flags child tests whether the driver supports an explicit allow rule.
    Set-Paths @(
        [pscustomobject]@{ Path=$root; Flags=2 },
        [pscustomobject]@{ Path=$child; Flags=0 }
    )
    $results.Add([pscustomobject]@{ Test='zero child parent->child'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    Set-Paths @(
        [pscustomobject]@{ Path=$child; Flags=0 },
        [pscustomobject]@{ Path=$root; Flags=2 }
    )
    $results.Add([pscustomobject]@{ Test='zero child child->parent'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    # Each SET call replaces the complete path list rather than appending to it.
    Set-Paths @([pscustomobject]@{ Path=$root; Flags=2 })
    $results.Add([pscustomobject]@{ Test='replace paths: root only'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })
    Set-Paths @([pscustomobject]@{ Path=$child; Flags=4 })
    $results.Add([pscustomobject]@{ Test='replace paths: child only'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    Set-Paths @([pscustomobject]@{ Path=$root; Flags=2 })
    Set-Paths @([pscustomobject]@{ Path=$root; Flags=0 })
    $results.Add([pscustomobject]@{ Test='replace paths: zero-only'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    # Both folders locked; trusted probe behavior is tested below.
    Set-Paths @(
        [pscustomobject]@{ Path=$child; Flags=2 },
        [pscustomobject]@{ Path=$other; Flags=2 }
    )

    Set-Trusted @([pscustomobject]@{ Name='vgscopea.exe'; Flags=0; Field2=$null; Field3=$null })
    $results.Add([pscustomobject]@{ Test='replace trusted: A only/A'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })
    $results.Add([pscustomobject]@{ Test='replace trusted: A only/B'; Child=(Test-ProbeRead $probeB $childFile); Other=(Test-ProbeRead $probeB $otherFile) })

    Set-Trusted @([pscustomobject]@{ Name='vgscopeb.exe'; Flags=0; Field2=$null; Field3=$null })
    $results.Add([pscustomobject]@{ Test='replace trusted: B only/A'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })
    $results.Add([pscustomobject]@{ Test='replace trusted: B only/B'; Child=(Test-ProbeRead $probeB $childFile); Other=(Test-ProbeRead $probeB $otherFile) })

    Set-Trusted @([pscustomobject]@{ Name='vgscopea.exe'; Flags=0; Field2=$child; Field3=$null })
    $results.Add([pscustomobject]@{ Test='trusted field2 DOS child'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    Set-Trusted @([pscustomobject]@{ Name='vgscopea.exe'; Flags=0; Field2=(Convert-ToNtPath $child); Field3=$null })
    $results.Add([pscustomobject]@{ Test='trusted field2 NT child'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    Set-Trusted @([pscustomobject]@{ Name='vgscopea.exe'; Flags=0; Field2=$null; Field3=$child })
    $results.Add([pscustomobject]@{ Test='trusted field3 DOS child'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })

    Set-Trusted @(
        [pscustomobject]@{ Name='vgscopea.exe'; Flags=0; Field2=$null; Field3=$null },
        [pscustomobject]@{ Name='vgscopeb.exe'; Flags=0; Field2=$null; Field3=$null }
    )
    $results.Add([pscustomobject]@{ Test='trusted array A'; Child=(Test-ProbeRead $probeA $childFile); Other=(Test-ProbeRead $probeA $otherFile) })
    $results.Add([pscustomobject]@{ Test='trusted array B'; Child=(Test-ProbeRead $probeB $childFile); Other=(Test-ProbeRead $probeB $otherFile) })

    $enumPaths = Invoke-Ioctl $IOCTL_ENUM_PATHS $null 65536
    $enumTrusted = Invoke-Ioctl $IOCTL_ENUM_TRUSTED $null 65536
    $results.Add([pscustomobject]@{ Test='enum sizes'; Child="paths=$($enumPaths.Bytes)"; Other="trusted=$($enumTrusted.Bytes)" })

    $results | Format-Table -AutoSize
} finally {
    if ($device -ne [IntPtr]::Zero -and $device -ne $INVALID_HANDLE) {
        try { [void](Invoke-Ioctl $IOCTL_ADD_PATH ([byte[]]::new($PATH_RECORD * 5))) } catch {}
        try { [void](Invoke-Ioctl $IOCTL_SET_TRUSTED $null) } catch {}
        [void][VgProbeNative]::CloseHandle($device)
        $device = [IntPtr]::Zero
    }
    try { Invoke-Vg @('/protection', 'off') } catch {}
    try { Invoke-Vg @('/driver', 'stop') } catch {}
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
    if ([IO.Directory]::Exists($execRoot)) {
        [IO.Directory]::Delete($execRoot, $true)
    }
}
