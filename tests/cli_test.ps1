#Requires -Version 5.1
# VaultGuard CLI regression tests.
# vg.exe uses WriteConsoleW which bypasses PS capture, so text output is NOT
# checked. Tests verify registry state and CSV file content only.
# Requires: vg.exe built, SF driver loaded, admin context.

param([switch]$KeepOutput)

$ErrorActionPreference = 'Stop'
$SF   = "$PSScriptRoot\..\bin\vg.exe"
$OUT  = "$PSScriptRoot\out"
$PASS = 0
$FAIL = 0
$PA   = "C:\temp\sf_test_a"
$PB   = "C:\temp\sf_test_b"

# ── helpers ───────────────────────────────────────────────────────────────────

function banner([string]$t) {
    Write-Host ""
    Write-Host ("  " + $t) -ForegroundColor Cyan
    Write-Host ("-" * 52) -ForegroundColor DarkGray
}

function ok([string]$msg)   { $script:PASS++; Write-Host "  [PASS] $msg" -ForegroundColor Green }
function fail([string]$msg) { $script:FAIL++; Write-Host "  [FAIL] $msg" -ForegroundColor Red  }

function reg_paths   { Get-ItemProperty "HKCU:\Software\SF\Paths"   -EA SilentlyContinue }
function reg_trusted { Get-ItemProperty "HKCU:\Software\SF\Trusted" -EA SilentlyContinue }

function sf([string[]]$sfargs) {
    # Run vg.exe, output to console, return exit code.
    $p = Start-Process -FilePath $SF -ArgumentList $sfargs -NoNewWindow -Wait -PassThru
    return $p.ExitCode
}

function sf_out([string[]]$sfargs) {
    # Capture vg.exe stdout. Start-Process -RedirectStandardOutput creates a
    # pipe so WriteConsoleW inside vg.exe fails and falls back to WriteFile,
    # which is captured correctly.
    $tmp = New-TemporaryFile
    try {
        Start-Process -FilePath $SF -ArgumentList $sfargs `
            -RedirectStandardOutput $tmp.FullName -NoNewWindow -Wait | Out-Null
        $c = Get-Content $tmp.FullName -Raw -Encoding Default
        if ($null -ne $c) { return $c.Trim() } else { return "" }
    } finally {
        Remove-Item $tmp.FullName -EA SilentlyContinue
    }
}

function clean_registry {
    Remove-Item "HKCU:\Software\SF\Paths"   -Recurse -Force -EA SilentlyContinue
    Remove-Item "HKCU:\Software\SF\Trusted" -Recurse -Force -EA SilentlyContinue
}

function csv_rows([string]$file) {
    if (-not (Test-Path $file)) { return @() }
    $lines = Get-Content $file -Encoding Unicode
    if ($lines.Count -le 1) { return @() }
    return @($lines[1..($lines.Count - 1)])
}

function reg_key_names([object]$reg) {
    if ($null -eq $reg) { return @() }
    return @($reg.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -Exp Name)
}

# ── setup ─────────────────────────────────────────────────────────────────────

if (-not (Test-Path $SF))  { Write-Host "ERROR: vg.exe not found at $SF" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $OUT)) { New-Item -ItemType Directory $OUT | Out-Null }

$null = New-Item -ItemType Directory $PA -Force -EA SilentlyContinue
$null = New-Item -ItemType Directory $PB -Force -EA SilentlyContinue

clean_registry

Write-Host ("=" * 52) -ForegroundColor DarkGray
Write-Host "  VaultGuard CLI regression tests" -ForegroundColor White
Write-Host ("=" * 52) -ForegroundColor DarkGray

# ==============================================================================
banner "[1] Help text visible on stdout"
# ==============================================================================

# sf_out goes through cmd /c redirect so WriteConsoleW -> WriteFile fallback
$h = sf_out @("/?")
if ($h -match 'VaultGuard CLI')  { ok "/?    contains header"   } else { fail "/?    header missing: $h" }
if ($h -match 'Commands:')          { ok "/?    contains Commands:" } else { fail "/?    Commands: missing" }
if ($h -match '/enumitems')         { ok "/?    lists /enumitems"   } else { fail "/?    /enumitems missing" }
if ($h -match '/settrusted')        { ok "/?    lists /settrusted"  } else { fail "/?    /settrusted missing" }

# ==============================================================================
banner "[2] /setitem -- individual flags -> registry"
# ==============================================================================

sf @("/setitem", $PA, "Hidden") | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x1)) { ok "setitem Hidden: flag 0x1 in registry" } else { fail "setitem Hidden: registry=$($r.$PA)" }

sf @("/setitem", $PA, "Locked") | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x2)) { ok "setitem Locked: flag 0x2 in registry" } else { fail "setitem Locked: registry=$($r.$PA)" }

sf @("/setitem", $PA, "Read-only") | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x4)) { ok "setitem Read-only: flag 0x4 in registry" } else { fail "setitem Read-only: registry=$($r.$PA)" }

sf @("/setitem", $PA, "No-execution") | Out-Null
$r = reg_paths
if ($null -ne $r -and ($r.$PA -band 0x8)) { ok "setitem No-execution: flag 0x8 in registry" } else { fail "setitem No-execution: registry=$($r.$PA)" }

# ==============================================================================
banner "[3] /setitem Disabled -- path stays in registry, flags=0"
# ==============================================================================

sf @("/setitem", $PA, "Disabled") | Out-Null
$r   = reg_paths
$val = if ($null -ne $r) { $r.$PA } else { $null }

if ($null -ne $val)  { ok "setitem Disabled: path stays in registry" }  else { fail "setitem Disabled: path removed from registry" }
if ($val -eq 0)      { ok "setitem Disabled: flags=0" }                  else { fail "setitem Disabled: flags=$val expected 0" }

# ==============================================================================
banner "[4] /enumitems -- CSV content"
# ==============================================================================

clean_registry
sf @("/setitem", $PA, "Hidden") | Out-Null
sf @("/setitem", $PB, "Locked") | Out-Null

$csv = "$OUT\items.csv"
sf @("/enumitems", $csv) | Out-Null

if (Test-Path $csv)     { ok "enumitems: CSV file created" } else { fail "enumitems: CSV file NOT created" }

$rows = csv_rows $csv
if ($rows.Count -eq 2)  { ok "enumitems: 2 data rows" } else { fail "enumitems: $($rows.Count) rows, expected 2" }

$rA = @($rows | Where-Object { $_ -match [regex]::Escape($PA) })
if ($rA.Count -gt 0 -and $rA[0] -match '1,0,0,0') { ok "enumitems: sf_test_a Hidden=1" } else { fail "enumitems: sf_test_a row: $($rA -join '|')" }

$rB = @($rows | Where-Object { $_ -match [regex]::Escape($PB) })
if ($rB.Count -gt 0 -and $rB[0] -match '0,1,0,0') { ok "enumitems: sf_test_b Locked=1" } else { fail "enumitems: sf_test_b row: $($rB -join '|')" }

# Disabled: still appears in CSV with all-zero flags
sf @("/setitem", $PA, "Disabled") | Out-Null
$csv2 = "$OUT\items_disabled.csv"
sf @("/enumitems", $csv2) | Out-Null
$rows2 = csv_rows $csv2
$rDis  = @($rows2 | Where-Object { $_ -match [regex]::Escape($PA) })
if ($rDis.Count -gt 0 -and $rDis[0] -match '0,0,0,0') { ok "enumitems: Disabled path present, flags all-zero" } else { fail "enumitems: Disabled row: $($rDis -join '|')" }

# ==============================================================================
banner "[5] /settrusted + /enumtrusted"
# ==============================================================================

clean_registry
sf @("/setitem", $PA, "Hidden") | Out-Null   # driver needs active path

sf @("/settrusted", "totalcmd64.exe", "Enabled") | Out-Null
$r = reg_trusted
if ($null -ne $r -and $r.'totalcmd64.exe')       { ok "settrusted: first entry in registry" }  else { fail "settrusted: first entry missing" }

sf @("/settrusted", "explorer.exe", "Enabled") | Out-Null
$r = reg_trusted
if ($null -ne $r -and $null -ne $r.'explorer.exe') { ok "settrusted: second entry in registry" } else { fail "settrusted: second entry missing" }

$csv3 = "$OUT\trusted.csv"
sf @("/enumtrusted", $csv3) | Out-Null
if (Test-Path $csv3)  { ok "enumtrusted: CSV file created" } else { fail "enumtrusted: CSV file NOT created" }

$tr = @(csv_rows $csv3)
if ($tr.Count -eq 2)                   { ok "enumtrusted: 2 rows" }                          else { fail "enumtrusted: $($tr.Count) rows, expected 2" }
if ($tr -contains 'totalcmd64.exe')    { ok "enumtrusted: totalcmd64.exe present" }           else { fail "enumtrusted: totalcmd64.exe missing; rows=$($tr -join '|')" }
if ($tr -contains 'explorer.exe')      { ok "enumtrusted: explorer.exe present" }             else { fail "enumtrusted: explorer.exe missing" }

# ==============================================================================
banner "[6] /settrusted Disabled -- removes from registry"
# ==============================================================================

sf @("/settrusted", "explorer.exe", "Disabled") | Out-Null
$r = reg_trusted
if ($null -eq $r -or $null -eq $r.'explorer.exe') { ok "settrusted Disabled: entry removed from registry" } else { fail "settrusted Disabled: still in registry" }
if ($null -ne $r -and $null -ne $r.'totalcmd64.exe') { ok "settrusted Disabled: other entry untouched" }    else { fail "settrusted Disabled: totalcmd64 also removed" }

$csv4 = "$OUT\trusted_after_remove.csv"
sf @("/enumtrusted", $csv4) | Out-Null
$tr2 = @(csv_rows $csv4)
if ($tr2.Count -eq 1)                    { ok "enumtrusted after remove: 1 row" }             else { fail "enumtrusted after remove: $($tr2.Count) rows" }
if ($tr2 -contains 'totalcmd64.exe')     { ok "enumtrusted after remove: totalcmd64 remains" } else { fail "enumtrusted after remove: totalcmd64 missing" }

# ==============================================================================
banner "[7] /protection on|off"
# ==============================================================================

$ec = sf @("/protection", "off")
if ($ec -eq 0)  { ok "protection off: exit 0" } else { fail "protection off: exit $ec" }
$ec = sf @("/protection", "on")
if ($ec -eq 0)  { ok "protection on: exit 0"  } else { fail "protection on: exit $ec"  }
$ec = sf @("/protection", "badarg")
if ($ec -eq 1)  { ok "protection bad arg: exit 1" } else { fail "protection bad arg: exit $ec (expected 1)" }

# ==============================================================================
banner "[8] Error cases -- exit code 1"
# ==============================================================================

$ec = sf @("/setitem")                          # missing args
if ($ec -eq 1) { ok "setitem no args: exit 1" } else { fail "setitem no args: exit $ec" }

$ec = sf @("/setitem", $PA, "BadMode")
if ($ec -eq 1) { ok "setitem bad mode: exit 1" } else { fail "setitem bad mode: exit $ec" }

$ec = sf @("/settrusted")
if ($ec -eq 1) { ok "settrusted no args: exit 1" } else { fail "settrusted no args: exit $ec" }

# ==============================================================================
banner "[9] Registry<->driver consistency: remove-one keeps others"
# ==============================================================================

clean_registry
sf @("/setitem", $PA, "Hidden")            | Out-Null
sf @("/settrusted", "notepad.exe",    "Enabled") | Out-Null
sf @("/settrusted", "totalcmd64.exe", "Enabled") | Out-Null

sf @("/settrusted", "notepad.exe", "Disabled") | Out-Null

$r    = reg_trusted
$keys = reg_key_names $r

if ('notepad.exe' -notin $keys -and 'totalcmd64.exe' -in $keys) {
    ok "remove-one trusted: registry has 1 entry, correct one remains"
} else {
    fail "remove-one trusted: registry keys=$($keys -join ', ')"
}

$csv5 = "$OUT\trusted_consistency.csv"
sf @("/enumtrusted", $csv5) | Out-Null
$tr3 = @(csv_rows $csv5)
if ($tr3.Count -eq 1 -and $tr3[0] -eq 'totalcmd64.exe') {
    ok "registry->CSV consistent: 1 entry, correct name"
} else {
    fail "registry->CSV: rows=$($tr3 -join '|')"
}

# ==============================================================================
# cleanup
# ==============================================================================

clean_registry
if (-not $KeepOutput) { Remove-Item $OUT -Recurse -Force -EA SilentlyContinue }
Remove-Item $PA -Force -EA SilentlyContinue
Remove-Item $PB -Force -EA SilentlyContinue

# ── result ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host ("=" * 52) -ForegroundColor DarkGray
$total = $PASS + $FAIL
if ($FAIL -eq 0) {
    Write-Host "  ALL PASS  $PASS / $total" -ForegroundColor Green
} else {
    Write-Host "  $FAIL FAILED  [$PASS / $total passed]" -ForegroundColor Red
}
Write-Host ("=" * 52) -ForegroundColor DarkGray
exit $FAIL
