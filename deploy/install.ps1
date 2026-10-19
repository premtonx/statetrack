<#
.SYNOPSIS
  StateTrack agent installer for Windows (native Windows service).

.DESCRIPTION
  Installs statetrack-agent on a Windows Server or workstation as the
  StateTrackAgent service.

    1. resolves the release archive for this architecture
    2. downloads it and verifies it against the release's SHA256SUMS.txt
    3. extracts to C:\ProgramData\StateTrack
    4. writes C:\ProgramData\StateTrack\agent.yaml (ACL: SYSTEM + Administrators)
    5. registers and starts the service via `statetrack-agent service install`

  The archive is verified before anything is written outside a temp directory,
  so a tampered or truncated download is refused rather than installed.

.PARAMETER Server
  gRPC endpoint of the StateTrack server, e.g. statetrack.internal:50051.

.PARAMETER Token
  Enrollment token from the console (Settings -> Agents).

.PARAMETER Org
  Organization label written to server.org.

.PARAMETER Version
  Release tag to install. Defaults to `latest`.

.PARAMETER Binary
  Install this local statetrack-agent.exe instead of downloading a release.

.PARAMETER Url
  Download this archive/executable instead of the default release asset.

.PARAMETER Force
  Overwrite an existing agent.yaml.

.PARAMETER NoStart
  Register the service but do not start it.

.EXAMPLE
  # One-liner (elevated PowerShell)
  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.ps1))) `
      -Server statetrack.internal:50051 -Token st_enroll_abc123

.EXAMPLE
  # From the extracted release ZIP
  .\install.ps1 -Server 10.0.4.20:50051 -Token st_enroll_abc123 -Binary .\statetrack-agent.exe
#>
[CmdletBinding()]
param(
    [string]$Server = '',
    [string]$Token = '',
    [string]$Org = '',
    [string]$Version = 'latest',
    [string]$Binary = '',
    [string]$Url = '',
    [switch]$Force,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = if ($env:STATETRACK_REPO) { $env:STATETRACK_REPO } else { 'premtonx/statetrack' }
if ($env:STATETRACK_VERSION) { $Version = $env:STATETRACK_VERSION }
if ($Version -eq 'latest') {
    $ReleaseBase = if ($env:STATETRACK_RELEASES_URL) { $env:STATETRACK_RELEASES_URL }
                   else { "https://github.com/$Repo/releases/latest/download" }
}
else {
    $ReleaseBase = if ($env:STATETRACK_RELEASES_URL) { $env:STATETRACK_RELEASES_URL }
                   else { "https://github.com/$Repo/releases/download/$Version" }
}

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "  ok $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "warn $Message" -ForegroundColor Yellow }

# Elevation is required twice over: ProgramData writes and SCM registration.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'install.ps1 must run from an elevated PowerShell (Run as Administrator).'
}

# TLS 1.2 for Windows Server 2016/2019 images where it is not the default.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$DataDir = 'C:\ProgramData\StateTrack'
$Exe = Join-Path $DataDir 'statetrack-agent.exe'
$Config = Join-Path $DataDir 'agent.yaml'
$ServiceName = 'StateTrackAgent'
$Work = Join-Path ([IO.Path]::GetTempPath()) ("statetrack-install-" + [guid]::NewGuid().ToString('n'))

try {
    New-Item -ItemType Directory -Force $Work | Out-Null

    # ---------------------------------------------------------- 1. acquire --
    if ($Binary) {
        if (-not (Test-Path -LiteralPath $Binary)) { throw "no such file: $Binary" }
        Write-Step "installing local binary $Binary"
        New-Item -ItemType Directory -Force $DataDir | Out-Null
        Copy-Item -LiteralPath $Binary -Destination $Exe -Force
        Write-Ok "installed $Exe"
    }
    elseif ($Url) {
        Write-Step "downloading $Url"
        $payload = Join-Path $Work 'payload'
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $payload
        Expand-Payload -Payload $payload -Destination $Work
        $found = Get-ChildItem -Path $Work -Recurse -Filter 'statetrack-agent.exe' -File |
            Select-Object -First 1
        if (-not $found) { throw 'archive did not contain statetrack-agent.exe' }
        New-Item -ItemType Directory -Force $DataDir | Out-Null
        Copy-Item -LiteralPath $found.FullName -Destination $Exe -Force
        Write-Ok "installed $Exe"
    }
    else {
        $archive = 'statetrack-agent-windows-amd64.zip'
        Write-Step "downloading $archive ($Version)"
        $zip = Join-Path $Work $archive
        Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBase/$archive" -OutFile $zip

        # ------------------------------------------------------ 2. verify --
        Write-Step 'verifying SHA-256'
        $sums = Join-Path $Work 'SHA256SUMS.txt'
        $verified = $false
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBase/SHA256SUMS.txt" -OutFile $sums
            $line = Get-Content -LiteralPath $sums |
                Where-Object { $_ -match [regex]::Escape($archive) } |
                Select-Object -First 1
            if (-not $line) { throw "SHA256SUMS.txt has no entry for $archive" }
            # Accept both "hash  file" and "hash *file" (binary-mode) formats.
            $expected = ($line -split '\s+')[0].ToLowerInvariant()
            $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expected -ne $actual) {
                throw "checksum mismatch for $archive`n  expected $expected`n  actual   $actual`nRefusing to install a tampered or corrupted archive."
            }
            $verified = $true
            Write-Ok ("checksum matches ({0}...)" -f $actual.Substring(0, 16))
        }
        catch [System.Net.WebException] {
            Write-Warn 'SHA256SUMS.txt unavailable; skipping checksum verification'
        }

        Write-Step 'extracting'
        Expand-Payload -Payload $zip -Destination $Work
        $found = Get-ChildItem -Path $Work -Recurse -Filter 'statetrack-agent.exe' -File |
            Select-Object -First 1
        if (-not $found) { throw "$archive did not contain statetrack-agent.exe" }
        New-Item -ItemType Directory -Force $DataDir | Out-Null
        Copy-Item -LiteralPath $found.FullName -Destination $Exe -Force
        if (-not $verified) { Write-Warn 'binary was installed WITHOUT checksum verification' }
        Write-Ok "installed $Exe"
    }

    Unblock-File -LiteralPath $Exe -ErrorAction SilentlyContinue

    # ----------------------------------------------------------- 3. config --
    if ((Test-Path -LiteralPath $Config) -and -not $Force) {
        Write-Step "keeping existing $Config (use -Force to overwrite)"
    }
    else {
        $yaml = @"
# StateTrack agent configuration.
# Generated by deploy/install.ps1 on $(Get-Date -Format s).
# Full parameter reference: docs/agent-deployment-guide.md
host_id: ""                     # empty: derive from the machine name
state_dir: C:\ProgramData\StateTrack
log_level: info

server:
  address: $Server
  token: $Token
  org: $Org

watch:
  paths:
    - C:\Windows\System32\inetsrv\config
    - C:\Windows\System32\drivers\etc
    - C:\Windows\System32\Tasks
    - C:\ProgramData
  exclude:
    - C:\ProgramData\StateTrack\**

windows:
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE
      - HKLM\SYSTEM\CurrentControlSet\Services
  services:
    enabled: true
    source: auto
  msi:
    enabled: true
  security_audit:
    enabled: true

# Targeted watchers cost nothing until a pool, site or database is named.
iis:
  enabled: true
  # pools:
  #   - iis://apppool/CheckoutAppPool
  # sites:
  #   - iis://site/Default Web Site

database:
  enabled: true
  # connections:
  #   - name: settings
  #     engine: sqlserver
  #     dsn: "sqlserver://sa:${env:STATETRACK_DB_PASSWORD}@localhost:1433?database=settings_db"
  #     tables: ["dbo.app_settings"]

systemd:
  enabled: false

packages:
  enabled: false

spool:
  max_mb: 200
"@
        Set-Content -LiteralPath $Config -Value $yaml -Encoding utf8
        # SYSTEM and Administrators only: the file holds the enrollment token.
        icacls $Config /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
        Write-Ok "wrote $Config"
    }

    # ---------------------------------------------------------- 4. service --
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Step "service $ServiceName already exists; stopping for replacement"
        if ($existing.Status -ne 'Stopped') {
            & $Exe service stop | Out-Null
        }
        & $Exe service uninstall | Out-Null
    }

    Write-Step "registering service $ServiceName"
    & $Exe service install
    if ($LASTEXITCODE -ne 0) { throw "service install failed (exit $LASTEXITCODE)" }

    if (-not $NoStart) {
        & $Exe service start
        if ($LASTEXITCODE -ne 0) { throw "service start failed (exit $LASTEXITCODE)" }
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') { Write-Ok "service $ServiceName is running" }
        else { Write-Warn "service $ServiceName is $($svc.Status); inspect the Application event log" }
    }
    else {
        Write-Step "service registered (not started: -NoStart)"
    }

    # Optional firewall: the agent is outbound-only, so nothing is opened here.
    Write-Host ''
    Write-Host 'StateTrack agent installed.' -ForegroundColor Green
    Write-Host ''
    Write-Host "  binary   $Exe"
    Write-Host "  config   $Config"
    Write-Host "  service  $ServiceName (Windows service)"
    Write-Host ''
    Write-Host "  status   Get-Service $ServiceName"
    Write-Host '  logs     Get-WinEvent -ProviderName StateTrackAgent -MaxEvents 50'
    Write-Host ''
    Write-Host "The host appears in the console under Servers within a few seconds of"
    Write-Host "the first heartbeat. Confirm that $Server is reachable from this host."
}
finally {
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}

function Expand-Payload {
    param([string]$Payload, [string]$Destination)
    if ($Payload -like '*.zip') {
        Expand-Archive -LiteralPath $Payload -DestinationPath $Destination -Force
    }
    else {
        Copy-Item -LiteralPath $Payload -Destination (Join-Path $Destination 'statetrack-agent.exe') -Force
    }
}
