# Installs iFoxy into %ProgramFiles%\iFoxy with an ACL that only
# Administrators and SYSTEM can modify. Run from an elevated PowerShell.
#
# Why: the app runs elevated and loads DLLs from its own directory. If that
# directory were writable by a normal user, any local process could replace
# a DLL or the executable and gain Administrator rights.
param([string]$Source = ".\dist")
$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an elevated (Administrator) PowerShell." }
if (-not (Test-Path "$Source\ifoxy_app.exe")) { throw "Missing $Source\ifoxy_app.exe - run build-release.ps1 first." }

# Verify the executable against its SHA-256 sidecar when one is present
# (release builds ship ifoxy_app.exe.sha256 next to the exe in dist). The
# install target is admin-writable-only precisely because the elevated app
# loads DLLs from it; a tampered or corrupted download must never land there.
$sidecar = "$Source\ifoxy_app.exe.sha256"
if (Test-Path $sidecar) {
    $expected = (Get-Content $sidecar -Raw).Trim()
    $actual = (Get-FileHash "$Source\ifoxy_app.exe" -Algorithm SHA256).Hash
    if ($expected -ne $actual) {
        throw "SHA-256 mismatch for ifoxy_app.exe (expected $expected, got $actual). Refusing to install."
    }
    Write-Host "SHA-256 verified: $actual"
} else {
    Write-Warning "No ifoxy_app.exe.sha256 sidecar found - installing WITHOUT integrity verification."
}

$dest = Join-Path $env:ProgramFiles "iFoxy"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item "$Source\*" $dest -Recurse -Force

# Remove inherited permissions, then grant: Administrators + SYSTEM full
# control, Users read & execute only.
icacls $dest /inheritance:r | Out-Null
icacls $dest /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null

# Start Menu shortcut
$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\iFoxy.lnk"
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath = Join-Path $dest "ifoxy_app.exe"
$sc.WorkingDirectory = $dest
$sc.Save()

Write-Host "Installed to $dest" -ForegroundColor Green
