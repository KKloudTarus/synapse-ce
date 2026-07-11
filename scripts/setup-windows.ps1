# setup-windows.ps1 – Windows-native one-shot bootstrap for Synapse SCA.
#
# Verifies the Go/Node/pnpm/JDK/Maven/Gradle toolchain (user-installed, see REQUIREMENTS.md),
# calls scripts/install-tools.ps1 to install syft + grype (pinned, sha256-verified) into .\bin,
# generates .env from .env.example (prompting or auto-generating SYNAPSE_API_TOKEN), and builds
# the Go binaries + web dashboard.
#
# Idempotent: safe to re-run. Re-running skips steps that are already complete and refuses to
# overwrite a populated .env.
#
# Usage:
#   pwsh scripts/setup-windows.ps1
#   pwsh scripts/setup-windows.ps1 -SkipBuild          # verify + .env only, skip Go build
#   pwsh scripts/setup-windows.ps1 -SkipWebBuild       # skip web (re)build
#   pwsh scripts/setup-windows.ps1 -ForceEnv           # overwrite existing .env
#   pwsh scripts/setup-windows.ps1 -ApiToken <hex>     # non-interactive token
#   pwsh scripts/setup-windows.ps1 -NonInteractive     # auto-generate token, no prompts
#
# Does NOT require admin elevation. Does NOT install Go/Node/JDK/Maven/Gradle – those are
# user-installed per REQUIREMENTS.md §2.
$ErrorActionPreference = 'Stop'

[CmdletBinding()]
param(
    [switch] $SkipBuild,
    [switch] $SkipWebBuild,
    [switch] $ForceEnv,
    [switch] $NonInteractive,
    [string] $ApiToken,
    [string] $RepoRoot,
    [string] $BinDir
)

# ---- defaults ----
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
if (-not $BinDir) {
    $BinDir = Join-Path $RepoRoot 'bin'
}

# ---- helpers ----
function Write-Step { param([string]$Msg) Write-Host "▸ $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "  ✓ $Msg" -ForegroundColor Green }
function Write-Warn2 { param([string]$Msg) Write-Host "  ! $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "  ✗ $Msg" -ForegroundColor Red }

# Probe a command, capture its version line, parse a Major version.
# Returns a PSCustomObject: {Found, Path, Version, Major}. Never throws.
function Get-CommandVersion {
    param(
        [string] $Cmd,
        [string[]] $VersionArgs = @('--version'),
        [string] $StdErrRedirect = '2>&1'
    )
    $cmdPath = (Get-Command $Cmd -ErrorAction SilentlyContinue).Path
    if (-not $cmdPath) {
        return [pscustomobject]@{ Found = $false; Path = $null; Version = $null; Major = 0 }
    }
    try {
        $out = & $Cmd @VersionArgs 2>&1 | Select-Object -First 1
        $verLine = if ($out) { $out.ToString() } else { '' }
        # Extract the first numeric "X.Y..." or "vX.Y..." in the line.
        $m = [regex]::Match($verLine, '(\d+)\.(\d+)')
        $major = if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }
        $minor = if ($m.Success) { [int]$m.Groups[2].Value } else { 0 }
        return [pscustomobject]@{
            Found    = $true
            Path     = $cmdPath
            Version  = $verLine.Trim()
            Major    = $major
            Minor    = $minor
        }
    } catch {
        return [pscustomobject]@{ Found = $true; Path = $cmdPath; Version = "error: $_"; Major = 0; Minor = 0 }
    }
}

# ---- banner ----
Write-Host ""
Write-Host "=== Synapse Windows setup ===" -ForegroundColor Magenta
Write-Host "Repo root: $RepoRoot"
Write-Host "Bin dir:   $BinDir"
Write-Host ""

# ===========================================================================
# Section A – Verify prerequisites
# ===========================================================================
Write-Step "A. Verifying toolchain"

# Tool spec: Cmd, VersionArgs, MinMajor, MinMinor, Hard
$tools = @(
    @{ Cmd = 'go';     Args = @('version');                    MinMajor = 1; MinMinor = 26; Hard = $true;  Label = 'Go' },
    @{ Cmd = 'node';   Args = @('--version');                  MinMajor = 22; MinMinor = 0;  Hard = $true;  Label = 'Node.js' },
    @{ Cmd = 'pnpm';   Args = @('--version');                  MinMajor = 11; MinMinor = 0;  Hard = $true;  Label = 'pnpm' },
    @{ Cmd = 'java';   Args = @('-version');                   MinMajor = 17; MinMinor = 0;  Hard = $true;  Label = 'JDK' },
    @{ Cmd = 'mvn';    Args = @('--version');                  MinMajor = 3;  MinMinor = 9;  Hard = $true;  Label = 'Maven' },
    @{ Cmd = 'gradle'; Args = @('--version');                  MinMajor = 8;  MinMinor = 10; Hard = $true;  Label = 'Gradle' },
    @{ Cmd = 'git';    Args = @('--version');                  MinMajor = 2;  MinMinor = 0;  Hard = $false; Label = 'git' }
)

$hardMissing = @()
foreach ($t in $tools) {
    $info = Get-CommandVersion -Cmd $t.Cmd -VersionArgs $t.Args
    if (-not $info.Found) {
        $line = "$($t.Label) NOT FOUND"
        if ($t.Hard) { Write-Err  $line; $hardMissing += $t.Label }
        else         { Write-Warn2 $line }
        continue
    }
    $ok = ($info.Major -gt $t.MinMajor) -or (($info.Major -eq $t.MinMajor) -and ($info.Minor -ge $t.MinMinor))
    if ($ok) {
        Write-Ok ("{0,-10} {1}" -f $t.Label, $info.Version)
    } else {
        $need = "$($t.MinMajor).$($t.MinMinor)+"
        $line = "$($t.Label) $($info.Version) – need $need"
        if ($t.Hard) { Write-Err  $line; $hardMissing += $t.Label }
        else         { Write-Warn2 $line }
    }
}

# Section A – external scan binaries (syft + grype) – soft; section B installs them
$syftExe  = Join-Path $BinDir 'syft.exe'
$grypeExe = Join-Path $BinDir 'grype.exe'
$syftInfo  = if (Test-Path $syftExe)  { Get-CommandVersion -Cmd $syftExe  -VersionArgs @('version') } else { $null }
$grypeInfo = if (Test-Path $grypeExe) { Get-CommandVersion -Cmd $grypeExe -VersionArgs @('version') } else { $null }
if ($syftInfo -and $syftInfo.Found)  { Write-Ok  ("syft       {0}" -f $syftInfo.Version) }  else { Write-Warn2 "syft       NOT FOUND (section B will install)" }
if ($grypeInfo -and $grypeInfo.Found){ Write-Ok  ("grype      {0}" -f $grypeInfo.Version) } else { Write-Warn2 "grype      NOT FOUND (section B will install)" }

if ($hardMissing.Count -gt 0) {
    Write-Host ""
    Write-Err "Hard requirements missing: $($hardMissing -join ', ')"
    Write-Host ""
    Write-Host "  See REQUIREMENTS.md §2 for the pinned versions and install commands," -ForegroundColor Yellow
    Write-Host "  then re-run this script." -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# ===========================================================================
# Section B – Install external scan binaries (delegate to install-tools.ps1)
# ===========================================================================
Write-Step "B. Installing external scan binaries (syft + grype)"
$needInstall = $false
if (-not (Test-Path $syftExe))  { $needInstall = $true }
if (-not (Test-Path $grypeExe)) { $needInstall = $true }

if (-not $needInstall) {
    Write-Ok "syft + grype already present in $BinDir – skipping (delete them to force reinstall)"
} else {
    $childScript = Join-Path $RepoRoot 'scripts\install-tools.ps1'
    if (-not (Test-Path $childScript)) {
        throw "Cannot find $childScript – clone the repo again, or run scripts/install-tools.ps1 manually."
    }
    Write-Host "  Delegating to scripts/install-tools.ps1 ..."
    & pwsh -NoProfile -File $childScript -BINDIR $BinDir
    if ($LASTEXITCODE -ne 0) { throw "install-tools.ps1 failed (exit $LASTEXITCODE)" }
    Write-Ok "syft + grype installed"
}
Write-Host ""

# ===========================================================================
# Section C – Generate .env
# ===========================================================================
Write-Step "C. Configuring .env"
$envPath  = Join-Path $RepoRoot '.env'
$tmplPath = Join-Path $RepoRoot '.env.example'
if (-not (Test-Path $tmplPath)) { throw ".env.example not found at $tmplPath – repo corrupt?" }

if ((Test-Path $envPath) -and -not $ForceEnv) {
    Write-Warn2 ".env already exists at $envPath – leaving it alone (use -ForceEnv to overwrite)"
} else {
    if ((Test-Path $envPath) -and $ForceEnv) {
        Write-Warn2 "Overwriting existing .env (per -ForceEnv)"
    }
    Copy-Item $tmplPath $envPath -Force

    # Token: explicit -> prompt -> auto-generate
    if (-not $ApiToken) {
        if ($NonInteractive -or -not [Environment]::UserInteractive -or $env:CI) {
            $bytes = New-Object byte[] 32
            (New-Object Random).NextBytes($bytes)
            $ApiToken = [Convert]::ToHexString($bytes)
            Write-Host "  Auto-generated SYNAPSE_API_TOKEN (32 bytes hex)."
        } else {
            $prompt = Read-Host "  Enter SYNAPSE_API_TOKEN (Enter = auto-generate 32 random bytes)"
            if ([string]::IsNullOrWhiteSpace($prompt)) {
                $bytes = New-Object byte[] 32
                (New-Object Random).NextBytes($bytes)
                $ApiToken = [Convert]::ToHexString($bytes)
                Write-Host "  Auto-generated SYNAPSE_API_TOKEN (32 bytes hex)."
            } else {
                $ApiToken = $prompt.Trim()
            }
        }
    }

    # Inject token – replace the first empty SYNAPSE_API_TOKEN= line.
    $content = Get-Content $envPath
    $idx = -1
    for ($i = 0; $i -lt $content.Count; $i++) {
        if ($content[$i] -match '^SYNAPSE_API_TOKEN=\s*$') { $idx = $i; break }
    }
    if ($idx -lt 0) {
        # Not found empty – append.
        Add-Content $envPath "SYNAPSE_API_TOKEN=$ApiToken"
    } else {
        $content[$idx] = "SYNAPSE_API_TOKEN=$ApiToken"
        Set-Content -Path $envPath -Value $content
    }

    # Append bin paths (idempotent: skip if already present)
    $content = Get-Content $envPath
    $syftLine  = "SYNAPSE_SYFT_BIN=$BinDir\syft.exe"
    $grypeLine = "SYNAPSE_GRYPE_BIN=$BinDir\grype.exe"
    $addSyft  = -not ($content | Where-Object { $_ -match '^SYNAPSE_SYFT_BIN=' })
    $addGrype = -not ($content | Where-Object { $_ -match '^SYNAPSE_GRYPE_BIN=' })
    if ($addSyft -or $addGrype) {
        Add-Content $envPath ""
        if ($addSyft)  { Add-Content $envPath $syftLine  }
        if ($addGrype) { Add-Content $envPath $grypeLine }
    }

    Write-Ok ".env written (token prefix: $($ApiToken.Substring(0, [Math]::Min(8, $ApiToken.Length)))...)"
}

# Fail-closed verify – server refuses to start with empty token.
$verify = Select-String -Path $envPath -Pattern '^SYNAPSE_API_TOKEN=(.+)$' | Select-Object -First 1
if (-not $verify -or [string]::IsNullOrWhiteSpace($verify.Matches.Groups[1].Value)) {
    throw "SYNAPSE_API_TOKEN is empty in .env – refusing to continue (server would fail-closed at startup)."
}
Write-Host ""

# ===========================================================================
# Section D – Build
# ===========================================================================
if (-not $SkipBuild) {
    Write-Step "D1. Building Go binaries (go build -o bin\ .\cmd\...)"
    Push-Location $RepoRoot
    try {
        # Use cmd.exe for the build so `.\cmd\...` expands on Windows without quoting gymnastics.
        cmd.exe /c "go build -o bin\ .\cmd\..."
        if ($LASTEXITCODE -ne 0) { throw "go build failed (exit $LASTEXITCODE)" }
    } finally { Pop-Location }
    $bins = Get-ChildItem $BinDir -Filter 'synapse-*.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    if ($bins) {
        Write-Ok "Built: $($bins -join ', ')"
    } else {
        Write-Warn2 "No synapse-*.exe found in $BinDir after build – check Go output above"
    }
} else {
    Write-Warn2 "D1. Skipped Go build (-SkipBuild)"
}
Write-Host ""

if (-not $SkipWebBuild) {
    Write-Step "D2. Building web dashboard (pnpm install --frozen-lockfile && pnpm build)"
    Push-Location (Join-Path $RepoRoot 'web')
    try {
        pnpm install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw "pnpm install failed (exit $LASTEXITCODE)" }
        pnpm build
        if ($LASTEXITCODE -ne 0) { throw "pnpm build failed (exit $LASTEXITCODE)" }
    } finally { Pop-Location }
    Write-Ok "web built (web\dist\)"
} else {
    Write-Warn2 "D2. Skipped web build (-SkipWebBuild)"
}
Write-Host ""

# ===========================================================================
# Section E – Final report
# ===========================================================================
Write-Host "=== Synapse is ready ===" -ForegroundColor Green
Write-Host ""
Write-Host "  Repo root:  $RepoRoot"
Write-Host "  Binaries:   $BinDir\synapse-api.exe, $BinDir\synapse-cli.exe"
Write-Host "  External:   $BinDir\syft.exe, $BinDir\grype.exe"
Write-Host "  Config:     $envPath"
Write-Host ""
Write-Host "Next steps (pick one):" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. SCA CLI only – fastest, no Postgres, no server" -ForegroundColor Cyan
Write-Host "       cd $RepoRoot"
Write-Host "       `$env:PATH = `"$BinDir;`$env:PATH`""
Write-Host "       .\bin\synapse-cli.exe scan C:\path\to\project --mode licenses"
Write-Host ""
Write-Host "  2. Full stack – API (:8080) + Web (:5173) + Postgres/MinIO via Docker" -ForegroundColor Cyan
Write-Host "       Terminal 1:" -ForegroundColor Cyan
Write-Host "           cd $RepoRoot"
Write-Host "           Get-Content .env | ForEach-Object { if (`$_ -match '^\s*([^#][^=]*)=(.*)$') { [System.Environment]::SetEnvironmentVariable(`$matches[1].Trim(), `$matches[2].Trim(), 'Process') } }"
Write-Host "           docker compose -f deploy\docker-compose.yml up -d"
Write-Host "           .\bin\synapse-api.exe"
Write-Host "       Terminal 2:" -ForegroundColor Cyan
Write-Host "           cd $RepoRoot\web"
Write-Host "           pnpm dev"
Write-Host "           # → http://localhost:5173"
Write-Host ""
Write-Host "Verify:" -ForegroundColor Cyan
Write-Host "       curl.exe http://localhost:8080/healthz                          # expect 200 `{"`"status`":"`"ok`"}`"  }
Write-Host ""
Write-Host "See SETUP-WINDOWS.md §5 for the three run flavors (CLI / CLI+Postgres / full stack)" -ForegroundColor Yellow
Write-Host "and §7 for troubleshooting. §8 lists what is NOT supported on Windows." -ForegroundColor Yellow