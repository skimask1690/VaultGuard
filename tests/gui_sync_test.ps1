#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$vg = (Resolve-Path (Join-Path $PSScriptRoot '..\bin\vg.exe')).Path
$runtimeRoot = Join-Path $PSScriptRoot 'runtime_gui_sync'
$pathA = Join-Path $runtimeRoot 'a'
$pathB = Join-Path $runtimeRoot 'b'
$fileA = Join-Path $pathA 'a.txt'
$fileB = Join-Path $pathB 'b.txt'
$exeA = Join-Path $runtimeRoot 'vguitesta.exe'
$exeB = Join-Path $runtimeRoot 'vguitestb.exe'
$exeC = Join-Path $runtimeRoot 'vguitestc.exe'
$gui = $null

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class VgGuiNative {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);

    [DllImport("user32.dll", EntryPoint = "SendMessageW", SetLastError = true)]
    public static extern IntPtr SendMessageValue(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageText(IntPtr window, uint message, IntPtr wParam, string text);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, UIntPtr size, uint allocationType, uint protection);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr written);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr process, IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "GUI sync test failed: $Message" }
}

function Invoke-Vg([string[]]$Arguments) {
    & $vg @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "vg.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Test-DriverRunning {
    $query = (& sc.exe query clrcd 2>$null) -join "`n"
    $query -match 'STATE\s+:\s+4\s+RUNNING'
}

function Get-ConfigMap([string]$Subkey) {
    $item = Get-ItemProperty -Path "HKCU:\Software\VG\$Subkey" -ErrorAction SilentlyContinue
    $map = @{}
    if ($item) {
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -notmatch '^PS') { $map[$property.Name] = [uint32]$property.Value }
        }
    }
    $map
}

function Remove-TestRegistryResidue {
    $pathsKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VG\Paths', $true)
    if ($pathsKey) {
        try {
            foreach ($name in $pathsKey.GetValueNames()) {
                if ($name -like '*\tests\runtime_gui_probe\*' -or $name -like '*\tests\runtime_gui_sync\*') {
                    $pathsKey.DeleteValue($name, $false)
                }
            }
        } finally { $pathsKey.Dispose() }
    }
    $trustedKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VG\Trusted', $true)
    if ($trustedKey) {
        try {
            foreach ($name in 'vguitesta.exe', 'vguitestb.exe', 'vguitestc.exe') {
                $trustedKey.DeleteValue($name, $false)
            }
        } finally { $trustedKey.Dispose() }
    }
}

function Wait-Until([scriptblock]$Condition, [string]$Description) {
    for ($i = 0; $i -lt 40; $i++) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Description"
}

function Set-ListCheckState([IntPtr]$List, [uint32]$ProcessId, [int]$Row, [bool]$Checked) {
    # LVM_SETITEMSTATE consumes an LVITEM pointer in the target process. Sending
    # it this way exercises the real ListView -> LVN_ITEMCHANGED GUI path without
    # depending on foreground-window focus in an unattended test session.
    $process = [VgGuiNative]::OpenProcess(0x0438, $false, $ProcessId)
    Assert-True ($process -ne [IntPtr]::Zero) 'cannot open GUI process for ListView state message'
    $remote = [IntPtr]::Zero
    try {
        $item = [byte[]]::new(88)
        [Array]::Copy([BitConverter]::GetBytes([uint32]8), 0, $item, 0, 4)       # LVIF_STATE
        $state = if ($Checked) { [uint32]0x2000 } else { [uint32]0x1000 }
        [Array]::Copy([BitConverter]::GetBytes($state), 0, $item, 12, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0xF000), 0, $item, 16, 4)
        $remote = [VgGuiNative]::VirtualAllocEx($process, [IntPtr]::Zero, [UIntPtr]$item.Length, 0x3000, 4)
        Assert-True ($remote -ne [IntPtr]::Zero) 'cannot allocate remote LVITEM'
        $written = [UIntPtr]::Zero
        Assert-True ([VgGuiNative]::WriteProcessMemory($process, $remote, $item, [UIntPtr]$item.Length, [ref]$written)) 'cannot write remote LVITEM'
        $before = [VgGuiNative]::SendMessageValue($List, 0x102C, [IntPtr]$Row, [IntPtr]0xF000).ToInt32()
        $setResult = [VgGuiNative]::SendMessageValue($List, 0x102B, [IntPtr]$Row, $remote).ToInt32()
        $after = [VgGuiNative]::SendMessageValue($List, 0x102C, [IntPtr]$Row, [IntPtr]0xF000).ToInt32()
        Assert-True ($setResult -ne 0) "ListView rejected state update (before=0x$($before.ToString('X')), after=0x$($after.ToString('X')))"
        Assert-True ($after -eq [int]$state) "ListView state mismatch (before=0x$($before.ToString('X')), after=0x$($after.ToString('X')))"
    } finally {
        if ($remote -ne [IntPtr]::Zero) { [void][VgGuiNative]::VirtualFreeEx($process, $remote, [UIntPtr]::Zero, 0x8000) }
        [void][VgGuiNative]::CloseHandle($process)
    }
}

function Test-Read([string]$Path) {
    try { [void][IO.File]::ReadAllText($Path); 'ALLOW' } catch { 'DENY' }
}

function Test-TrustedRead([string]$Exe, [string]$Path) {
    try {
        $process = Start-Process -FilePath $Exe -ArgumentList @('/d', '/c', 'type', $Path) -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -eq 0) { 'ALLOW' } else { 'DENY' }
    } catch { 'DENY' }
}

Remove-TestRegistryResidue
$existingPaths = Get-ConfigMap 'Paths'
$existingTrusted = Get-ConfigMap 'Trusted'
Assert-True (($existingPaths.Count + $existingTrusted.Count) -eq 0) 'HKCU\Software\VG must be empty before this destructive GUI test'
Assert-True (-not (Test-DriverRunning)) 'clrcd must be stopped before this destructive GUI test'

$results = [Collections.Generic.List[object]]::new()

try {
    [IO.Directory]::CreateDirectory($pathA) | Out-Null
    [IO.Directory]::CreateDirectory($pathB) | Out-Null
    [IO.File]::WriteAllText($fileA, 'a')
    [IO.File]::WriteAllText($fileB, 'b')
    foreach ($destination in $exeA, $exeB, $exeC) {
        [IO.File]::Copy((Join-Path $env:WINDIR 'System32\cmd.exe'), $destination, $true)
    }

    Invoke-Vg @('/setitem', $pathA, 'Locked')
    Invoke-Vg @('/setitem', $pathB, 'Locked')
    Invoke-Vg @('/settrusted', 'vguitesta.exe', 'Enabled')
    Invoke-Vg @('/settrusted', 'vguitestb.exe', 'Enabled')
    Invoke-Vg @('/protection', 'on')

    $results.Add([pscustomobject]@{ Step='initial raw'; A=(Test-Read $fileA); B=(Test-Read $fileB) })
    $results.Add([pscustomobject]@{ Step='initial trusted A'; A=(Test-TrustedRead $exeA $fileA); B=(Test-TrustedRead $exeA $fileB) })
    $results.Add([pscustomobject]@{ Step='initial trusted B'; A=(Test-TrustedRead $exeB $fileA); B=(Test-TrustedRead $exeB $fileB) })

    Assert-True (($results[0].A -eq 'DENY') -and ($results[0].B -eq 'DENY')) 'both seeded paths should be locked'
    Assert-True (($results[1].A -eq 'ALLOW') -and ($results[1].B -eq 'ALLOW')) 'trusted A should bypass both paths'
    Assert-True (($results[2].A -eq 'ALLOW') -and ($results[2].B -eq 'ALLOW')) 'trusted B should bypass both paths'

    $gui = Start-Process -FilePath $vg -PassThru
    Wait-Until { $gui.Refresh(); $gui.MainWindowHandle -ne [IntPtr]::Zero } 'VaultGuard main window'
    Start-Sleep -Milliseconds 500
    $main = $gui.MainWindowHandle
    $pathsList = [VgGuiNative]::GetDlgItem($main, 200)
    $trustedList = [VgGuiNative]::GetDlgItem($main, 201)
    $trustedEdit = [VgGuiNative]::GetDlgItem($main, 214)
    $trustedAdd = [VgGuiNative]::GetDlgItem($main, 204)
    Assert-True (($pathsList -ne [IntPtr]::Zero) -and ($trustedList -ne [IntPtr]::Zero)) 'ListView controls not found'

    # Click the Locked column in the first visible path row. The registry tells
    # us which row the driver/UI enumeration placed first; exactly one path must
    # become inactive, while the other one must remain locked.
    Set-ListCheckState $pathsList ([uint32]$gui.Id) 0 $false
    Wait-Until { ((Get-ConfigMap 'Paths').Values | Where-Object { ($_ -band 0x80) -ne 0 }).Count -eq 1 } 'GUI path checkbox update'
    $pathMap = Get-ConfigMap 'Paths'
    $disabledPath = @($pathMap.Keys | Where-Object { ($pathMap[$_] -band 0x80) -ne 0 })[0]
    $activePath = @($pathMap.Keys | Where-Object { $pathMap[$_] -eq 2 })[0]
    $disabledFile = if ($disabledPath -eq $pathA) { $fileA } else { $fileB }
    $activeFile = if ($activePath -eq $pathA) { $fileA } else { $fileB }
    $results.Add([pscustomobject]@{ Step='GUI toggle one path'; A=(Test-Read $disabledFile); B=(Test-Read $activeFile) })
    Assert-True (($results[3].A -eq 'ALLOW') -and ($results[3].B -eq 'DENY')) 'GUI path update lost or retained the wrong rules'

    # Toggle the first trusted row through its real ListView checkbox.
    Set-ListCheckState $trustedList ([uint32]$gui.Id) 0 $false
    Wait-Until { ((Get-ConfigMap 'Trusted').Values | Where-Object { $_ -eq 0 }).Count -eq 1 } 'GUI trusted checkbox update'
    $trustedMap = Get-ConfigMap 'Trusted'
    $disabledName = @($trustedMap.Keys | Where-Object { $trustedMap[$_] -eq 0 })[0]
    $enabledName = @($trustedMap.Keys | Where-Object { $trustedMap[$_] -eq 1 })[0]
    $disabledExe = if ($disabledName -eq 'vguitesta.exe') { $exeA } else { $exeB }
    $enabledExe = if ($enabledName -eq 'vguitesta.exe') { $exeA } else { $exeB }
    $results.Add([pscustomobject]@{ Step='GUI disable one trusted'; A=(Test-TrustedRead $disabledExe $activeFile); B=(Test-TrustedRead $enabledExe $activeFile) })
    Assert-True (($results[4].A -eq 'DENY') -and ($results[4].B -eq 'ALLOW')) 'disabling one trusted entry removed or retained the wrong entries'

    # Add a third entry through the edit box and Add button.
    [void][VgGuiNative]::SendMessageText($trustedEdit, 0x000C, [IntPtr]::Zero, 'vguitestc.exe')
    [void][VgGuiNative]::SendMessageValue($trustedAdd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
    Wait-Until { (Get-ConfigMap 'Trusted')['vguitestc.exe'] -eq 1 } 'GUI trusted Add button'
    $results.Add([pscustomobject]@{ Step='GUI add third trusted'; A=(Test-TrustedRead $exeC $activeFile); B=(Test-TrustedRead $enabledExe $activeFile) })
    Assert-True (($results[5].A -eq 'ALLOW') -and ($results[5].B -eq 'ALLOW')) 'adding a trusted entry replaced a previously enabled entry'

    $results | Format-Table -AutoSize
} finally {
    if ($gui -and -not $gui.HasExited) {
        $gui.CloseMainWindow() | Out-Null
        if (-not $gui.WaitForExit(2000)) { Stop-Process -Id $gui.Id -Force -ErrorAction SilentlyContinue }
    }
    try { Invoke-Vg @('/protection', 'off') } catch {}
    try { Invoke-Vg @('/driver', 'stop') } catch {}
    for ($i = 0; $i -lt 20 -and (Test-DriverRunning); $i++) { Start-Sleep -Milliseconds 100 }
    Remove-TestRegistryResidue
    if ([IO.Directory]::Exists($runtimeRoot)) { [IO.Directory]::Delete($runtimeRoot, $true) }
    $oldRuntime = Join-Path $PSScriptRoot 'runtime_gui_probe'
    if ([IO.Directory]::Exists($oldRuntime)) { [IO.Directory]::Delete($oldRuntime, $true) }
    $oldScreenshot = Join-Path $PSScriptRoot 'runtime_gui.png'
    if ([IO.File]::Exists($oldScreenshot)) { [IO.File]::Delete($oldScreenshot) }
}
