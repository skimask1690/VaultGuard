#Requires -Version 5.1
# VaultGuard regression + enforcement test suite.
# Verifies: CLI exit codes, registry state, CSV content, driver enforcement.
# Requirements: vg.exe in bin\, vg.sys loaded, Administrator context.
# Output: console (colored) + tests\results.txt

param(
    [switch]$KeepOutput,
    [switch]$SkipEnforcement   # skip driver enforcement sections 14-16
)

$ErrorActionPreference = 'Stop'
$VG     = "$PSScriptRoot\..\bin\vg.exe"
$OUT    = "$PSScriptRoot\out"
$RESULT = "$PSScriptRoot\results.txt"

$script:PASS  = 0
$script:FAIL  = 0
$script:SKIP  = 0
$script:FullUninstallRan = $false
$script:Lines = [System.Collections.Generic.List[string]]::new()

# test dirs
$PA  = "C:\temp\vg_test_a"
$PB  = "C:\temp\vg_test_b"
$DR  = "D:\"
$DS  = "D:\vg_test_sub"
$DE  = "D:\vg_enforce"

# -- output --------------------------------------------------------------------

function tee_line([string]$s, [string]$fg = '') {
    $script:Lines.Add($s)
    if ($fg) { Write-Host $s -ForegroundColor $fg } else { Write-Host $s }
}

function banner([string]$t) {
    tee_line ""
    tee_line ("  $t") 'Cyan'
    tee_line ("-" * 64) 'DarkGray'
}

function ok([string]$msg) {
    $script:PASS++
    tee_line "  [PASS] $msg" 'Green'
}

function fail([string]$msg) {
    $script:FAIL++
    tee_line "  [FAIL] $msg" 'Red'
}

function skip_test([string]$reason) {
    $script:SKIP++
    tee_line "  [SKIP] $reason" 'Yellow'
}

# -- registry ------------------------------------------------------------------

function reg_paths   { Get-ItemProperty "HKCU:\Software\VG\Paths"   -EA SilentlyContinue }
function reg_trusted { Get-ItemProperty "HKCU:\Software\VG\Trusted" -EA SilentlyContinue }

function clean_registry {
    Remove-Item "HKCU:\Software\VG\Paths"   -Recurse -Force -EA SilentlyContinue
    Remove-Item "HKCU:\Software\VG\Trusted" -Recurse -Force -EA SilentlyContinue
}

function reg_key_names([object]$reg) {
    if ($null -eq $reg) { return @() }
    return @($reg.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -Exp Name)
}

function save_restore_trusted {
    # Returns a hashtable of current trusted entries for later restore.
    $r = reg_trusted
    if ($null -eq $r) { return @{} }
    $h = @{}
    $r.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $h[$_.Name] = $_.Value }
    return $h
}

function restore_trusted([hashtable]$saved) {
    Remove-Item "HKCU:\Software\VG\Trusted" -Recurse -Force -EA SilentlyContinue
    foreach ($k in $saved.Keys) { vg @("/settrusted", $k, "Enabled") | Out-Null }
}

# -- vg.exe runner -------------------------------------------------------------

function vg([string[]]$a) {
    $tmp = New-TemporaryFile
    try {
        $p = Start-Process -FilePath $VG -ArgumentList $a -Wait -PassThru `
             -WindowStyle Hidden -RedirectStandardOutput $tmp.FullName
        $out = Get-Content $tmp.FullName -Raw
        if ($out) { Write-Host $out.TrimEnd() }
        return $p.ExitCode
    } finally { Remove-Item $tmp.FullName -EA SilentlyContinue }
}

function vg_out([string[]]$a) {
    $tmp = New-TemporaryFile
    try {
        Start-Process -FilePath $VG -ArgumentList $a `
            -RedirectStandardOutput $tmp.FullName -WindowStyle Hidden -Wait | Out-Null
        $c = Get-Content $tmp.FullName -Raw -Encoding Default
        if ($null -ne $c) { return $c.Trim() } else { return "" }
    } finally { Remove-Item $tmp.FullName -EA SilentlyContinue }
}

# -- CSV helpers ---------------------------------------------------------------

function csv_rows([string]$file) {
    if (-not (Test-Path $file)) { return @() }
    $lines = Get-Content $file -Encoding Unicode
    if ($null -eq $lines -or $lines.Count -le 1) { return @() }
    return @($lines[1..($lines.Count - 1)])
}

# -- enforcement helpers -------------------------------------------------------

function expect_denied([string]$label, [scriptblock]$op) {
    try {
        & $op | Out-Null
        fail "$label  -  expected ACCESS_DENIED, op succeeded"
    } catch {
        $msg = $_.Exception.Message
        $cat = $_.CategoryInfo.Category
        if ($msg -match 'denied|Unauthorized' -or $cat -eq 'PermissionDenied' -or $cat -eq 'NotSpecified') {
            ok "$label  -  access denied (enforced)"
        } else {
            fail "$label  -  unexpected error: $msg"
        }
    }
}

function expect_allowed([string]$label, [scriptblock]$op) {
    try {
        & $op | Out-Null
        ok "$label  -  succeeded (protection lifted)"
    } catch {
        fail "$label  -  expected success, got: $($_.Exception.Message)"
    }
}

# -- service check -------------------------------------------------------------

function driver_loaded {
    $svc = Get-Service -Name 'clrcd' -EA SilentlyContinue
    return ($null -ne $svc -and $svc.Status -eq 'Running')
}

function driver_service {
    Get-CimInstance Win32_SystemDriver -Filter "Name='clrcd'" -EA SilentlyContinue
}

function app_service {
    Get-CimInstance Win32_Service -Filter "Name='VaultGuard'" -EA SilentlyContinue
}

function clean_driver_service {
    $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='clrcd'" -EA SilentlyContinue
    if ($null -ne $svc) {
        if ($svc.State -eq 'Running') {
            Invoke-CimMethod -InputObject $svc -MethodName StopService | Out-Null
            Start-Sleep -Milliseconds 300
        }
        Invoke-CimMethod -InputObject $svc -MethodName Delete | Out-Null
    }
    Remove-Item "$env:SystemRoot\System32\drivers\vg.sys" -Force -EA SilentlyContinue
}

# -- preflight -----------------------------------------------------------------

if (-not (Test-Path $VG)) { Write-Host "ERROR: $VG not found" -ForegroundColor Red; exit 1 }

$hasDrive = Test-Path $DR
if (-not (Test-Path $OUT)) { New-Item -ItemType Directory $OUT | Out-Null }

$null = New-Item -ItemType Directory $PA -Force -EA SilentlyContinue
$null = New-Item -ItemType Directory $PB -Force -EA SilentlyContinue
if ($hasDrive) { $null = New-Item -ItemType Directory $DS -Force -EA SilentlyContinue }

clean_registry

$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
tee_line ("=" * 64) 'DarkGray'
tee_line "  VaultGuard regression tests   $stamp" 'White'
tee_line ("=" * 64) 'DarkGray'

# ==============================================================================
banner "[1] Help  -  stdout content"
# ==============================================================================

$h = vg_out @("/?")
if ($h -match 'VaultGuard CLI')  { ok "/?  contains 'VaultGuard CLI'"  } else { fail "/?  header missing: $h" }
if ($h -match 'Commands:')        { ok "/?  contains 'Commands:'"        } else { fail "/?  Commands: missing" }
if ($h -match '/enumitems')       { ok "/?  lists /enumitems"            } else { fail "/?  /enumitems missing" }
if ($h -match '/settrusted')      { ok "/?  lists /settrusted"           } else { fail "/?  /settrusted missing" }
if ($h -match '/driver')          { ok "/?  lists /driver"               } else { fail "/?  /driver missing" }
if ($h -match '/uninstall')       { ok "/?  lists /uninstall"            } else { fail "/?  /uninstall missing" }

# ==============================================================================
banner "[1b] /driver lifecycle  -  API-backed clrcd service"
# ==============================================================================

clean_driver_service

$ec = vg @("/driver", "install")
if ($ec -eq 0) { ok "driver install: exit 0" } else { fail "driver install: exit $ec" }
$d = driver_service
if ($null -ne $d) { ok "driver install: clrcd exists" } else { fail "driver install: clrcd missing" }
if ($null -ne $d -and $d.StartMode -eq 'Manual') { ok "driver install: default Manual" } else { fail "driver install: StartMode=$($d.StartMode) (expected Manual)" }

$ec = vg @("/driver", "startup", "auto")
$d = driver_service
if ($ec -eq 0) { ok "driver startup auto: exit 0" } else { fail "driver startup auto: exit $ec" }
if ($null -ne $d -and $d.StartMode -eq 'Auto') { ok "driver startup auto: StartMode Auto" } else { fail "driver startup auto: StartMode=$($d.StartMode)" }

$ec = vg @("/driver", "startup", "manual")
$d = driver_service
if ($ec -eq 0) { ok "driver startup manual: exit 0" } else { fail "driver startup manual: exit $ec" }
if ($null -ne $d -and $d.StartMode -eq 'Manual') { ok "driver startup manual: StartMode Manual" } else { fail "driver startup manual: StartMode=$($d.StartMode)" }

$ec = vg @("/driver", "install", "auto")
$d = driver_service
if ($ec -eq 0) { ok "driver install auto: exit 0" } else { fail "driver install auto: exit $ec" }
if ($null -ne $d -and $d.StartMode -eq 'Auto') { ok "driver install auto: StartMode Auto" } else { fail "driver install auto: StartMode=$($d.StartMode)" }

$ec = vg @("/driver", "start")
if ($ec -eq 0) { ok "driver start: exit 0" } else { fail "driver start: exit $ec" }

$ec = vg @("/driver", "stop")
if ($ec -eq 0) { ok "driver stop: exit 0" } else { fail "driver stop: exit $ec" }

$ec = vg @("/driver", "uninstall")
$d = driver_service
if ($ec -eq 0) { ok "driver uninstall: exit 0" } else { fail "driver uninstall: exit $ec" }
if ($null -eq $d) { ok "driver uninstall: clrcd removed" } else { fail "driver uninstall: clrcd still present" }

$ec = vg @("/driver", "install")
if ($ec -eq 0) { ok "driver reinstall for remaining tests: exit 0" } else { fail "driver reinstall for remaining tests: exit $ec" }

# ==============================================================================
banner "[2] /setitem  -  individual flags -> registry"
# ==============================================================================

vg @("/setitem", $PA, "Hidden")      | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x1)) { ok "setitem Hidden:       flag 0x1 set" } else { fail "setitem Hidden:       registry=$($r.$PA)" }

vg @("/setitem", $PA, "Locked")      | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x2)) { ok "setitem Locked:       flag 0x2 set" } else { fail "setitem Locked:       registry=$($r.$PA)" }

vg @("/setitem", $PA, "Read-only")   | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x4)) { ok "setitem Read-only:    flag 0x4 set" } else { fail "setitem Read-only:    registry=$($r.$PA)" }

vg @("/setitem", $PA, "No-execution") | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x8)) { ok "setitem No-execution: flag 0x8 set" } else { fail "setitem No-execution: registry=$($r.$PA)" }

# ==============================================================================
banner "[3] /setitem Disabled  -  path kept, flags=0"
# ==============================================================================

vg @("/setitem", $PA, "Disabled") | Out-Null
$r   = reg_paths
$val = if ($null -ne $r) { $r.$PA } else { $null }
if ($null -ne $val) { ok "setitem Disabled: path stays in registry" } else { fail "setitem Disabled: path removed" }
if ($val -eq 0)     { ok "setitem Disabled: flags = 0"              } else { fail "setitem Disabled: flags=$val (expected 0)" }

# ==============================================================================
banner "[4] /setitem overwrite  -  last flag wins"
# ==============================================================================

clean_registry
vg @("/setitem", $PA, "Hidden")  | Out-Null
vg @("/setitem", $PA, "Locked")  | Out-Null
$r = reg_paths
$v = if ($null -ne $r) { $r.$PA } else { $null }
if ($v -eq 2) { ok "setitem overwrite: Locked (0x2) replaced Hidden (0x1)" } else { fail "setitem overwrite: value=$v (expected 2)" }

vg @("/setitem", $PA, "Read-only") | Out-Null
$r = reg_paths
if ($r.$PA -eq 4) { ok "setitem overwrite: Read-only (0x4) replaced Locked (0x2)" } else { fail "setitem overwrite: value=$($r.$PA) (expected 4)" }

# ==============================================================================
banner "[5] /enumitems  -  CSV content"
# ==============================================================================

clean_registry
vg @("/setitem", $PA, "Hidden")  | Out-Null
vg @("/setitem", $PB, "Locked")  | Out-Null

$csv = "$OUT\items.csv"
vg @("/enumitems", $csv) | Out-Null

if (Test-Path $csv)     { ok "enumitems: CSV file created"           } else { fail "enumitems: CSV not created" }

$rows = csv_rows $csv
if ($rows.Count -eq 2)  { ok "enumitems: 2 data rows"                } else { fail "enumitems: $($rows.Count) rows (expected 2)" }

$rA = @($rows | Where-Object { $_ -match [regex]::Escape($PA) })
if ($rA.Count -gt 0 -and $rA[0] -match '1,0,0,0') { ok "enumitems: vg_test_a Hidden=1" } else { fail "enumitems: vg_test_a row: $($rA -join '|')" }

$rB = @($rows | Where-Object { $_ -match [regex]::Escape($PB) })
if ($rB.Count -gt 0 -and $rB[0] -match '0,1,0,0') { ok "enumitems: vg_test_b Locked=1" } else { fail "enumitems: vg_test_b row: $($rB -join '|')" }

vg @("/setitem", $PA, "Read-only")  | Out-Null
vg @("/setitem", $PB, "No-execution") | Out-Null
$csv2 = "$OUT\items2.csv"
vg @("/enumitems", $csv2) | Out-Null
$rows2 = csv_rows $csv2
$rA2 = @($rows2 | Where-Object { $_ -match [regex]::Escape($PA) })
$rB2 = @($rows2 | Where-Object { $_ -match [regex]::Escape($PB) })
if ($rA2.Count -gt 0 -and $rA2[0] -match '0,0,1,0') { ok "enumitems: vg_test_a ReadOnly=1" } else { fail "enumitems: vg_test_a ReadOnly row: $($rA2 -join '|')" }
if ($rB2.Count -gt 0 -and $rB2[0] -match '0,0,0,1') { ok "enumitems: vg_test_b NoExec=1"  } else { fail "enumitems: vg_test_b NoExec row: $($rB2 -join '|')" }

# Disabled: still appears, all-zero flags
vg @("/setitem", $PA, "Disabled") | Out-Null
$csv3 = "$OUT\items_dis.csv"
vg @("/enumitems", $csv3) | Out-Null
$rDis = @(csv_rows $csv3 | Where-Object { $_ -match [regex]::Escape($PA) })
if ($rDis.Count -gt 0 -and $rDis[0] -match '0,0,0,0') { ok "enumitems: Disabled path present with 0,0,0,0" } else { fail "enumitems: Disabled row: $($rDis -join '|')" }

# ==============================================================================
banner "[6] /settrusted + /enumtrusted"
# ==============================================================================

clean_registry
vg @("/setitem", $PA, "Hidden")              | Out-Null
vg @("/settrusted", "totalcmd64.exe", "Enabled") | Out-Null
$r = reg_trusted
if ($null -ne $r -and $null -ne $r.'totalcmd64.exe') { ok "settrusted: first entry in registry" }  else { fail "settrusted: first entry missing" }

vg @("/settrusted", "explorer.exe", "Enabled") | Out-Null
$r = reg_trusted
if ($null -ne $r -and $null -ne $r.'explorer.exe') { ok "settrusted: second entry in registry" } else { fail "settrusted: second entry missing" }

$csv4 = "$OUT\trusted.csv"
vg @("/enumtrusted", $csv4) | Out-Null
if (Test-Path $csv4) { ok "enumtrusted: CSV file created" } else { fail "enumtrusted: CSV not created" }

$tr = @(csv_rows $csv4)
if ($tr.Count -eq 2)                { ok "enumtrusted: 2 rows"                      } else { fail "enumtrusted: $($tr.Count) rows (expected 2)" }
if ($tr -contains 'totalcmd64.exe') { ok "enumtrusted: totalcmd64.exe present"       } else { fail "enumtrusted: totalcmd64.exe missing; rows=$($tr -join '|')" }
if ($tr -contains 'explorer.exe')   { ok "enumtrusted: explorer.exe present"         } else { fail "enumtrusted: explorer.exe missing" }

# ==============================================================================
banner "[7] /settrusted Disabled  -  removes from registry"
# ==============================================================================

vg @("/settrusted", "explorer.exe", "Disabled") | Out-Null
$r = reg_trusted
if ($null -eq $r -or $null -eq $r.'explorer.exe')       { ok "settrusted Disabled: entry removed"      } else { fail "settrusted Disabled: still in registry" }
if ($null -ne $r -and $null -ne $r.'totalcmd64.exe')    { ok "settrusted Disabled: other entry intact"  } else { fail "settrusted Disabled: totalcmd64 also removed" }

$csv5 = "$OUT\trusted_after.csv"
vg @("/enumtrusted", $csv5) | Out-Null
$tr2 = @(csv_rows $csv5)
if ($tr2.Count -eq 1)               { ok "enumtrusted after remove: 1 row"            } else { fail "enumtrusted after remove: $($tr2.Count) rows" }
if ($tr2 -contains 'totalcmd64.exe') { ok "enumtrusted after remove: totalcmd64 stays" } else { fail "enumtrusted after remove: totalcmd64 missing" }

# ==============================================================================
banner "[8] /protection on | off"
# ==============================================================================

$ec = vg @("/protection", "off")
if ($ec -eq 0) { ok "protection off: exit 0"         } else { fail "protection off: exit $ec" }
$ec = vg @("/protection", "on")
if ($ec -eq 0) { ok "protection on:  exit 0"          } else { fail "protection on: exit $ec" }
$ec = vg @("/protection", "badarg")
if ($ec -eq 1) { ok "protection bad arg: exit 1"      } else { fail "protection bad arg: exit $ec (expected 1)" }

# ==============================================================================
banner "[9] Error cases  -  exit 1"
# ==============================================================================

$ec = vg @("/setitem")
if ($ec -eq 1) { ok "setitem no args: exit 1"          } else { fail "setitem no args: exit $ec" }
$ec = vg @("/setitem", $PA, "BadMode")
if ($ec -eq 1) { ok "setitem bad mode: exit 1"         } else { fail "setitem bad mode: exit $ec" }
$ec = vg @("/settrusted")
if ($ec -eq 1) { ok "settrusted no args: exit 1"       } else { fail "settrusted no args: exit $ec" }

# ==============================================================================
banner "[10] Registry consistency  -  remove-one keeps others"
# ==============================================================================

clean_registry
vg @("/setitem", $PA, "Hidden")               | Out-Null
vg @("/settrusted", "notepad.exe",    "Enabled") | Out-Null
vg @("/settrusted", "totalcmd64.exe", "Enabled") | Out-Null
vg @("/settrusted", "notepad.exe",    "Disabled") | Out-Null

$r    = reg_trusted
$keys = reg_key_names $r
if ('notepad.exe' -notin $keys -and 'totalcmd64.exe' -in $keys) {
    ok "trusted: remove-one keeps the other"
} else {
    fail "trusted: keys=$($keys -join ', ')"
}

$csv6 = "$OUT\trusted_cons.csv"
vg @("/enumtrusted", $csv6) | Out-Null
$tr3 = @(csv_rows $csv6)
if ($tr3.Count -eq 1 -and $tr3[0] -eq 'totalcmd64.exe') {
    ok "registry->CSV consistent: 1 entry correct"
} else {
    fail "registry->CSV: rows=$($tr3 -join '|')"
}

# ==============================================================================
banner "[11] D:\ root drive  -  registry round-trip"
# ==============================================================================

if (-not $hasDrive) {
    1..5 | ForEach-Object { skip_test "D:\ not available" }
} else {
    clean_registry

    vg @("/setitem", $DR, "Hidden") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DR } else { $null }
    if ($null -ne $v -and ($v -band 0x1)) { ok "D:\ setitem Hidden:       0x1" } else { fail "D:\ setitem Hidden: v=$v" }

    vg @("/setitem", $DR, "Locked") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DR } else { $null }
    if ($null -ne $v -and ($v -band 0x2)) { ok "D:\ setitem Locked:       0x2" } else { fail "D:\ setitem Locked: v=$v" }

    vg @("/setitem", $DR, "Read-only") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DR } else { $null }
    if ($null -ne $v -and ($v -band 0x4)) { ok "D:\ setitem Read-only:    0x4" } else { fail "D:\ setitem Read-only: v=$v" }

    vg @("/setitem", $DR, "No-execution") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DR } else { $null }
    if ($null -ne $v -and ($v -band 0x8)) { ok "D:\ setitem No-execution: 0x8" } else { fail "D:\ setitem No-execution: v=$v" }

    vg @("/setitem", $DR, "Disabled") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DR } else { $null }
    if ($null -ne $v -and $v -eq 0) { ok "D:\ setitem Disabled:     flags=0" } else { fail "D:\ setitem Disabled: v=$v" }

    clean_registry
}

# ==============================================================================
banner "[12] D:\vg_test_sub  -  registry round-trip"
# ==============================================================================

if (-not $hasDrive) {
    1..5 | ForEach-Object { skip_test "D:\ not available" }
} else {
    vg @("/setitem", $DS, "Hidden") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DS } else { $null }
    if ($null -ne $v -and ($v -band 0x1)) { ok "D:\vg_test_sub Hidden:       0x1" } else { fail "D:\vg_test_sub Hidden: v=$v" }

    vg @("/setitem", $DS, "Locked") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DS } else { $null }
    if ($null -ne $v -and ($v -band 0x2)) { ok "D:\vg_test_sub Locked:       0x2" } else { fail "D:\vg_test_sub Locked: v=$v" }

    vg @("/setitem", $DS, "Read-only") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DS } else { $null }
    if ($null -ne $v -and ($v -band 0x4)) { ok "D:\vg_test_sub Read-only:    0x4" } else { fail "D:\vg_test_sub Read-only: v=$v" }

    vg @("/setitem", $DS, "No-execution") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DS } else { $null }
    if ($null -ne $v -and ($v -band 0x8)) { ok "D:\vg_test_sub No-execution: 0x8" } else { fail "D:\vg_test_sub No-execution: v=$v" }

    vg @("/setitem", $DS, "Disabled") | Out-Null
    $r = reg_paths; $v = if ($null -ne $r) { $r.$DS } else { $null }
    if ($null -ne $v -and $v -eq 0) { ok "D:\vg_test_sub Disabled:     flags=0" } else { fail "D:\vg_test_sub Disabled: v=$v" }

    clean_registry
}

# ==============================================================================
banner "[13] D:\ in /enumitems CSV"
# ==============================================================================

if (-not $hasDrive) {
    1..4 | ForEach-Object { skip_test "D:\ not available" }
} else {
    clean_registry
    vg @("/setitem", $DR, "Locked")    | Out-Null
    vg @("/setitem", $DS, "Read-only") | Out-Null

    $csv7 = "$OUT\items_d.csv"
    vg @("/enumitems", $csv7) | Out-Null

    $rows7 = csv_rows $csv7
    if ($rows7.Count -eq 2) { ok "enumitems D: 2 rows"                        } else { fail "enumitems D: $($rows7.Count) rows (expected 2)" }

    $rDR = @($rows7 | Where-Object { $_ -match [regex]::Escape($DR) })
    if ($rDR.Count -gt 0 -and $rDR[0] -match '0,1,0,0') { ok "enumitems: D:\ Locked=1 in CSV" } else { fail "enumitems: D:\ row: $($rDR -join '|')" }

    $rDS = @($rows7 | Where-Object { $_ -match [regex]::Escape($DS) })
    if ($rDS.Count -gt 0 -and $rDS[0] -match '0,0,1,0') { ok "enumitems: D:\vg_test_sub ReadOnly=1 in CSV" } else { fail "enumitems: D:\vg_test_sub row: $($rDS -join '|')" }

    clean_registry
}

# ==============================================================================
banner "[14] Driver enforcement  -  Read-only on D:\vg_enforce"
# ==============================================================================

$runEnforce = (-not $SkipEnforcement) -and $hasDrive -and (driver_loaded)

if (-not $runEnforce) {
    $why = if ($SkipEnforcement) { '-SkipEnforcement flag' } elseif (-not $hasDrive) { 'D:\ missing' } else { 'driver not running' }
    1..7 | ForEach-Object { skip_test "enforcement skipped ($why)" }
} else {
    # Create test dir with a file to try deleting
    $null = New-Item -ItemType Directory $DE -Force -EA SilentlyContinue
    "test" | Set-Content "$DE\existing.txt" -Encoding ASCII

    # Clear trusted list (save for restore) so powershell.exe is not bypassed
    $savedTrusted = save_restore_trusted
    clean_registry

    vg @("/protection", "on")                 | Out-Null
    vg @("/setitem", $DE, "Read-only")        | Out-Null

    # Write must fail
    expect_denied "Read-only: New-Item $DE\new.txt" {
        New-Item -Path "$DE\new.txt" -ItemType File -Force -EA Stop
    }

    # Delete must fail
    expect_denied "Read-only: Remove-Item $DE\existing.txt" {
        Remove-Item -Path "$DE\existing.txt" -Force -EA Stop
    }

    # Read must succeed (Read-only doesn't block reads)
    expect_allowed "Read-only: Get-Content $DE\existing.txt" {
        Get-Content -Path "$DE\existing.txt" -EA Stop
    }

    # List must succeed
    expect_allowed "Read-only: Get-ChildItem $DE" {
        Get-ChildItem -Path $DE -EA Stop
    }

    # Disable -> write must now succeed
    vg @("/setitem", $DE, "Disabled") | Out-Null
    expect_allowed "Read-only lifted: New-Item $DE\new.txt" {
        New-Item -Path "$DE\new.txt" -ItemType File -Force -EA Stop
    }

    # Verify file actually exists after lifting
    if (Test-Path "$DE\new.txt") { ok "Read-only lifted: file created and visible" } else { fail "Read-only lifted: file not found after creation" }

    restore_trusted $savedTrusted
    clean_registry
}

# ==============================================================================
banner "[15] Driver enforcement  -  Locked on D:\vg_enforce"
# ==============================================================================

if (-not $runEnforce) {
    1..5 | ForEach-Object { skip_test "enforcement skipped" }
} else {
    $savedTrusted = save_restore_trusted
    clean_registry

    vg @("/protection", "on")          | Out-Null
    vg @("/setitem", $DE, "Locked")    | Out-Null

    # List must fail
    expect_denied "Locked: Get-ChildItem $DE" {
        Get-ChildItem -Path $DE -EA Stop
    }

    # Read must fail
    expect_denied "Locked: Get-Content $DE\existing.txt" {
        Get-Content -Path "$DE\existing.txt" -EA Stop
    }

    # Write must fail
    expect_denied "Locked: New-Item $DE\lock_test.txt" {
        New-Item -Path "$DE\lock_test.txt" -ItemType File -Force -EA Stop
    }

    # Disable -> list must succeed
    vg @("/setitem", $DE, "Disabled") | Out-Null
    expect_allowed "Locked lifted: Get-ChildItem $DE" {
        Get-ChildItem -Path $DE -EA Stop
    }

    # Double-check: write succeeds after lifting
    expect_allowed "Locked lifted: New-Item $DE\after_lock.txt" {
        New-Item -Path "$DE\after_lock.txt" -ItemType File -Force -EA Stop
    }

    restore_trusted $savedTrusted
    clean_registry
}

# ==============================================================================
banner "[16] Driver enforcement  -  Read-only on D:\ root"
# ==============================================================================

if (-not $runEnforce) {
    1..3 | ForEach-Object { skip_test "enforcement skipped" }
} else {
    $savedTrusted = save_restore_trusted
    clean_registry

    vg @("/protection", "on")           | Out-Null
    vg @("/setitem", $DR, "Read-only")  | Out-Null

    # Write to D:\ root must fail
    expect_denied "D:\ Read-only: New-Item D:\vg_root_test.txt" {
        New-Item -Path "D:\vg_root_test.txt" -ItemType File -Force -EA Stop
    }

    # Read from D:\ root must still work
    expect_allowed "D:\ Read-only: Get-ChildItem D:\" {
        Get-ChildItem -Path $DR -EA Stop
    }

    # Disable -> write must succeed
    vg @("/setitem", $DR, "Disabled") | Out-Null
    expect_allowed "D:\ Read-only lifted: New-Item D:\vg_root_test.txt" {
        New-Item -Path "D:\vg_root_test.txt" -ItemType File -Force -EA Stop
    }
    Remove-Item "D:\vg_root_test.txt" -Force -EA SilentlyContinue

    restore_trusted $savedTrusted
    clean_registry
}

# ==============================================================================
banner "[17] /uninstall  -  full product cleanup"
# ==============================================================================

vg @("/setitem", $PA, "Hidden") | Out-Null
vg @("/settrusted", "notepad.exe", "Enabled") | Out-Null
vg @("/service", "install") | Out-Null
vg @("/driver", "install", "auto") | Out-Null

$ec = vg @("/uninstall")
$script:FullUninstallRan = ($ec -eq 0)
if ($ec -eq 0) { ok "full uninstall: exit 0" } else { fail "full uninstall: exit $ec" }

$appSvcAfter = app_service
$drvSvcAfter = driver_service
if ($null -eq $appSvcAfter) { ok "full uninstall: app service removed" } else { fail "full uninstall: app service still present" }
if ($null -eq $drvSvcAfter) { ok "full uninstall: clrcd service removed" } else { fail "full uninstall: clrcd still present" }
if (-not (Test-Path "HKCU:\Software\VG")) { ok "full uninstall: HKCU Software\\VG removed" } else { fail "full uninstall: HKCU Software\\VG still present" }

# ==============================================================================
# cleanup
# ==============================================================================

clean_registry
if (-not $script:FullUninstallRan) {
    vg @("/protection", "on") | Out-Null    # leave protection on unless /uninstall was verified
}

if (-not $KeepOutput) { Remove-Item $OUT -Recurse -Force -EA SilentlyContinue }

Remove-Item $PA  -Recurse -Force -EA SilentlyContinue
Remove-Item $PB  -Recurse -Force -EA SilentlyContinue
if ($hasDrive) {
    Remove-Item $DS  -Recurse -Force -EA SilentlyContinue
    Remove-Item $DE  -Recurse -Force -EA SilentlyContinue
}

# -- summary -------------------------------------------------------------------

$total = $script:PASS + $script:FAIL
tee_line ""
tee_line ("=" * 64) 'DarkGray'
if ($script:FAIL -eq 0) {
    tee_line "  ALL PASS   $($script:PASS) / $total  (skipped: $($script:SKIP))" 'Green'
} else {
    tee_line "  $($script:FAIL) FAILED   [$($script:PASS) / $total passed]  (skipped: $($script:SKIP))" 'Red'
}
tee_line ("=" * 64) 'DarkGray'

# write results.txt (plain text, no ANSI)
$script:Lines | ForEach-Object {
    $_ -replace '\x1b\[[0-9;]*m', ''
} | Set-Content -Path $RESULT -Encoding UTF8
tee_line "  Results written to: $RESULT" 'DarkGray'

exit $script:FAIL
