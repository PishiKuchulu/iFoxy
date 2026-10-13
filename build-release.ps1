# Release build helper for iFoxy for Windows.
# Uses whatever Rust toolchain is installed (MSVC recommended:
#   rustup default stable-x86_64-pc-windows-msvc
# ). No machine-specific paths are baked in.
$ErrorActionPreference = "Stop"

Write-Host "[1/3] cargo build --release --bin ifoxy_app" -ForegroundColor Yellow
cargo build --release --bin ifoxy_app
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

# The target directory depends on the active toolchain/target triple.
$exe = Get-ChildItem -Path "target" -Recurse -Filter "ifoxy_app.exe" |
    Where-Object { $_.FullName -match "\\release\\" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $exe) { throw "ifoxy_app.exe not found under target\...\release" }

Write-Host "[2/3] Collecting files into .\dist" -ForegroundColor Yellow
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
New-Item -ItemType Directory -Path "dist" | Out-Null
Copy-Item $exe.FullName "dist\ifoxy_app.exe"
# WebView2 is statically linked — WebView2Loader.dll is NOT needed next to the exe.
# wintun.dll is embedded in the executable and hash-verified at runtime.

Write-Host "[3/3] Done: .\dist\ifoxy_app.exe is a single-file portable app" -ForegroundColor Green
Write-Host "Install securely (admin-only writable location) with: .\install.ps1" -ForegroundColor White
