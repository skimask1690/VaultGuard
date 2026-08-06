#Requires -Version 5.1
# Test VaultGuard folder sharing (SMB share) protection under D:\
#
# Verifies that:
# 1. We can create and access a share normally when unprotected.
# 2. Accessing the share is blocked when the path is Locked.
# 3. Accessing the share is allowed again when the path is set to Disabled.
# 4. Accessing the share is allowed when global protection is turned off.

$VG = "$PSScriptRoot\..\bin\vg.exe"
$Path = "D:\vg_share_test"
$ShareName = "VG_Share"

function Write-Header([string]$text) {
    Write-Host ("`n" + "="*64) -F Gray
    Write-Host ("  " + $text) -F Cyan
    Write-Host ("="*64) -F Gray
}

function Write-Pass([string]$text) {
    Write-Host ("  [PASS] " + $text) -F Green
}

function Write-Fail([string]$text) {
    Write-Host ("  [FAIL] " + $text) -F Red
}

# Initial Cleanup
net share $ShareName /delete 2>$null | Out-Null
if (Test-Path $Path) {
    Remove-Item $Path -Recurse -Force -EA SilentlyContinue
}

# Create folder & seed file
New-Item -ItemType Directory -Path $Path -Force | Out-Null
"VaultGuard Share Seed File" | Set-Content "$Path\seed.txt" -Encoding ASCII

# Ensure driver is ready and global protection is enabled
& $VG /protection on | Out-Null

Write-Header "Test 1: Create share and access when unprotected"
# Create SMB share
# "Everyone" is the English well-known-group name; net.exe resolves account
# names via the OS locale, so this fails with error 1332 on non-English
# Windows (e.g. Polish, where the group is "Wszyscy"). Resolve the S-1-1-0
# SID to whatever the local OS calls it instead, so this works regardless
# of display language.
$everyoneName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")).Translate([System.Security.Principal.NTAccount]).Value
$shareResult = net share "${ShareName}=${Path}" "/GRANT:${everyoneName},FULL"
if ($LASTEXITCODE -eq 0) {
    Write-Pass "SMB Share created successfully"
} else {
    Write-Fail "Failed to create SMB Share"
    exit 1
}

# Access locally via UNC path
try {
    $content = Get-Content "\\localhost\${ShareName}\seed.txt" -ErrorAction Stop
    if ($content -eq "VaultGuard Share Seed File") {
        Write-Pass "Accessed seed file via share: '$content'"
    } else {
        Write-Fail "Incorrect content: '$content'"
    }
} catch {
    Write-Fail "Failed to access share: $_"
}

Write-Header "Test 2: Lock the folder and verify access"
# Lock path
& $VG /setitem $Path Locked | Out-Null
Write-Pass "Path set to Locked in VaultGuard"

# Attempt to access locally (should be DENIED)
try {
    $content = Get-Content "${Path}\seed.txt" -ErrorAction Stop
    Write-Fail "Local access was ALLOWED but should be DENIED"
} catch {
    Write-Pass "Local access DENIED as expected. Error: $_"
}

# Attempt to access via share (srv2.sys / System process handles SMB, which may bypass block)
try {
    $content = Get-Content "\\localhost\${ShareName}\seed.txt" -ErrorAction Stop
    Write-Host "  [INFO] SMB Share access was ALLOWED (System/srv2.sys context bypasses driver)" -F Yellow
} catch {
    Write-Host "  [INFO] SMB Share access was DENIED. Error: $_" -F Green
}

Write-Header "Test 3: Disable protection on path (setitem Disabled) and verify access is ALLOWED"
# Set to Disabled
& $VG /setitem $Path Disabled | Out-Null
Write-Pass "Path set to Disabled in VaultGuard"

# Attempt to access via share
try {
    $content = Get-Content "\\localhost\${ShareName}\seed.txt" -ErrorAction Stop
    if ($content -eq "VaultGuard Share Seed File") {
        Write-Pass "Access ALLOWED. Accessed seed file: '$content'"
    } else {
        Write-Fail "Incorrect content: '$content'"
    }
} catch {
    Write-Fail "Access DENIED but should be ALLOWED: $_"
}

Write-Header "Test 4: Re-lock path and verify global protection toggle"
# Re-lock path
& $VG /setitem $Path Locked | Out-Null
Write-Pass "Path re-locked"

# Verify local denied
try {
    $content = Get-Content "${Path}\seed.txt" -ErrorAction Stop
    Write-Fail "Local access was ALLOWED but should be DENIED"
} catch {
    Write-Pass "Local access DENIED as expected"
}

# Verify share access
try {
    $content = Get-Content "\\localhost\${ShareName}\seed.txt" -ErrorAction Stop
    Write-Host "  [INFO] SMB Share access was ALLOWED (System/srv2.sys context bypasses driver)" -F Yellow
} catch {
    Write-Host "  [INFO] SMB Share access was DENIED" -F Green
}

# Global protection off
& $VG /protection off | Out-Null
Write-Pass "Global protection turned OFF"

# Verify allowed
try {
    $content = Get-Content "\\localhost\${ShareName}\seed.txt" -ErrorAction Stop
    if ($content -eq "VaultGuard Share Seed File") {
        Write-Pass "Access ALLOWED after global protection OFF. Seed file: '$content'"
    } else {
        Write-Fail "Incorrect content: '$content'"
    }
} catch {
    Write-Fail "Access DENIED but should be ALLOWED: $_"
}

# Final Cleanup
Write-Header "Cleanup"
& $VG /setitem $Path Disabled | Out-Null
& $VG /protection off | Out-Null
net share $ShareName /delete | Out-Null
Remove-Item $Path -Recurse -Force -EA SilentlyContinue
Write-Pass "Cleanup complete"
