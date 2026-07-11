# install-tools.ps1 – Windows installer for the external scan binaries Synapse shells
# out to, at PINNED versions with sha256 verification. The bash installer
# (scripts/install-tools.sh) is for Linux/macOS; this is the native-Windows equivalent.
#
# Installs syft + grype (the SCA essentials) into .\bin by downloading the pinned
# release asset from GitHub and verifying it against the release checksums file.
# Recon tools + the execution sandbox are Linux-only (kernel features) and are NOT
# installed here – on Windows, use Docker for those (see README "Run anywhere via Docker").
#
# Usage:
#   pwsh scripts/install-tools.ps1
#   $env:SYFT_VERSION='v1.45.1'; $env:GRYPE_VERSION='v0.115.0'; pwsh scripts/install-tools.ps1
#   $env:BINDIR='C:\tools'; pwsh scripts/install-tools.ps1
$ErrorActionPreference = 'Stop'

$SyftVersion  = if ($env:SYFT_VERSION)  { $env:SYFT_VERSION }  else { 'v1.45.1' }   # matches deploy/Dockerfile
$GrypeVersion = if ($env:GRYPE_VERSION) { $env:GRYPE_VERSION } else { 'v0.115.0' }
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BinDir   = if ($env:BINDIR) { $env:BINDIR } else { Join-Path $RepoRoot 'bin' }

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Write-Host "Installing Synapse tools into: $BinDir" -ForegroundColor Cyan

function Install-AnchoreTool {
    param([string]$Tool, [string]$Version)

    $ver  = $Version.TrimStart('v')
    $base = "https://github.com/anchore/$Tool/releases/download/$Version"
    $zip  = "${Tool}_${ver}_windows_amd64.zip"
    $sums = "${Tool}_${ver}_checksums.txt"
    $tmp  = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "synapse-$Tool-$ver")

    Write-Host "▸ $Tool $Version" -ForegroundColor Cyan
    $zipPath  = Join-Path $tmp $zip
    $sumsPath = Join-Path $tmp $sums
    Invoke-WebRequest -Uri "$base/$zip"  -OutFile $zipPath
    Invoke-WebRequest -Uri "$base/$sums" -OutFile $sumsPath

    # Verify sha256 against the release checksums file (supply-chain integrity).
    $want = (Select-String -Path $sumsPath -Pattern ([regex]::Escape($zip)) | Select-Object -First 1).Line -split '\s+' | Select-Object -First 1
    $got  = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
    if (-not $want) { throw "$Tool: $zip not found in $sums" }
    if ($got -ne $want.ToLower()) { throw "$Tool: checksum mismatch (want $want, got $got)" }

    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    Copy-Item -Path (Join-Path $tmp "$Tool.exe") -Destination (Join-Path $BinDir "$Tool.exe") -Force
    Remove-Item -Recurse -Force $tmp
    Write-Host "  installed $BinDir\$Tool.exe (sha256 verified)" -ForegroundColor Green
}

Install-AnchoreTool -Tool 'syft'  -Version $SyftVersion
Install-AnchoreTool -Tool 'grype' -Version $GrypeVersion

Write-Host ""
Write-Host "! The execution sandbox + live recon are Linux-only (kernel features) and are NOT" -ForegroundColor Yellow
Write-Host "  available on native Windows. Run those via Docker (see README), or use WSL2." -ForegroundColor Yellow
Write-Host ""
Write-Host "Done. Add $BinDir to PATH, or point Synapse at the binaries explicitly:" -ForegroundColor Cyan
Write-Host "    `$env:PATH = `"$BinDir;`$env:PATH`""
Write-Host "    # or: `$env:SYNAPSE_SYFT_BIN='$BinDir\syft.exe'; `$env:SYNAPSE_GRYPE_BIN='$BinDir\grype.exe'"
