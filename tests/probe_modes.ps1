#Requires -Version 5.1
# Empirical probe: what does each flag (Hidden / Locked / Read-only) actually block?
# Tests: visibility, list-by-known-path, mkdir, copy file in.

$VG = "$PSScriptRoot\..\bin\vg.exe"
$H = 'D:\vg_probe_h'
$L = 'D:\vg_probe_l'
$R = 'D:\vg_probe_r'

function reset_dir($p) {
    Remove-Item $p -Recurse -Force -EA SilentlyContinue
    New-Item -ItemType Directory $p -Force | Out-Null
    "seed" | Set-Content "$p\seed.txt" -Encoding ASCII
}

function probe([string]$label, [string]$path, [scriptblock]$op) {
    try {
        & $op | Out-Null
        Write-Host ("  {0,-32} ALLOWED" -f $label) -F Yellow
    } catch {
        $msg = ($_.Exception.Message -split "`n")[0]
        if ($msg.Length -gt 60) { $msg = $msg.Substring(0,60) + '...' }
        Write-Host ("  {0,-32} DENIED   ({1})" -f $label, $msg) -F Green
    }
}

# Setup
reset_dir $H
reset_dir $L
reset_dir $R

& $VG /protection on | Out-Null
& $VG /setitem $H Hidden    | Out-Null
& $VG /setitem $L Locked    | Out-Null
& $VG /setitem $R Read-only | Out-Null

Write-Host "`n=== HIDDEN ($H) ===" -F Cyan
$vis = @(Get-ChildItem D:\ -Force -EA SilentlyContinue | Where-Object { $_.Name -eq 'vg_probe_h' }).Count
if ($vis -eq 0) { Write-Host "  visibility in parent listing  HIDDEN" -F Green }
else            { Write-Host "  visibility in parent listing  VISIBLE" -F Yellow }
probe "list by known path"  $H  { Get-ChildItem $H -EA Stop }
probe "read seed file"      $H  { Get-Content "$H\seed.txt" -EA Stop }
probe "mkdir subdir"        $H  { New-Item -ItemType Directory "$H\subA" -EA Stop }
probe "copy file in"        $H  { "x" | Set-Content "$H\newfile.txt" -EA Stop }
probe "delete seed file"    $H  { Remove-Item "$H\seed.txt" -EA Stop }

Write-Host "`n=== LOCKED ($L) ===" -F Cyan
probe "list by known path"  $L  { Get-ChildItem $L -EA Stop }
probe "read seed file"      $L  { Get-Content "$L\seed.txt" -EA Stop }
probe "mkdir subdir"        $L  { New-Item -ItemType Directory "$L\subA" -EA Stop }
probe "copy file in"        $L  { "x" | Set-Content "$L\newfile.txt" -EA Stop }
probe "delete seed file"    $L  { Remove-Item "$L\seed.txt" -EA Stop }

Write-Host "`n=== READ-ONLY ($R) ===" -F Cyan
probe "list by known path"  $R  { Get-ChildItem $R -EA Stop }
probe "read seed file"      $R  { Get-Content "$R\seed.txt" -EA Stop }
probe "mkdir subdir"        $R  { New-Item -ItemType Directory "$R\subA" -EA Stop }
probe "copy file in"        $R  { "x" | Set-Content "$R\newfile.txt" -EA Stop }
probe "delete seed file"    $R  { Remove-Item "$R\seed.txt" -EA Stop }

# Cleanup
& $VG /setitem $H Disabled | Out-Null
& $VG /setitem $L Disabled | Out-Null
& $VG /setitem $R Disabled | Out-Null
Remove-Item $H, $L, $R -Recurse -Force -EA SilentlyContinue
