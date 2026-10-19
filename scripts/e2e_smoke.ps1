<#
.SYNOPSIS
  Full-stack automated smoke test for StateTrack (Windows).

.DESCRIPTION
  Verifies the whole distributed loop: docker stack health -> server ->
  Postgres + SeaweedFS + Grafana annotations -> REST, plus the real agent's
  secret scrubbing. Exits 0 on success.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\e2e_smoke.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host '== 1/4: docker stack'
# Run docker via cmd so its stderr (progress lines) is merged into stdout and
# does not surface as a terminating NativeCommandError under ErrorActionPreference=Stop.
& cmd /c "docker compose up -d 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (exit $LASTEXITCODE)" }

Write-Host '== 2/4: migrations'
& $PSScriptRoot/dev.ps1 migrate

Write-Host '== 3/4: build'
& $PSScriptRoot/dev.ps1 build

Write-Host '== 4/4: smoke test (waits for the stack to become healthy)'
& go run ./server/cmd/statetrack-smoke
if ($LASTEXITCODE -ne 0) { throw "smoke test failed (exit $LASTEXITCODE)" }

Write-Host ''
Write-Host 'Smoke test passed: full distributed loop verified.'
