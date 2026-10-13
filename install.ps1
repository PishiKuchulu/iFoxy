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
