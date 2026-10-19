<#
.SYNOPSIS
  Bring up the local Checkmk demo and provision StateTrack into it.

.DESCRIPTION
  Starts the `checkmk` compose service (behind the `monitoring` profile, so a
  normal `docker compose up` does not spend a minute creating a site nobody
  asked for), waits for the site to answer, then runs the provisioning script
  inside the container.

  What ends up configured, per host:
    * the Checkmk host object;
    * a datasource program -> check_statetrack.py --mode local
      ("StateTrack Changes");
    * an active check       -> check_statetrack.py --mode nagios
      ("StateTrack Active Check");
  plus one activation and one forced check cycle, so the GUI is populated when
  the script returns instead of up to a minute later.

  Idempotent: re-running updates the objects it owns and leaves the rest of the
  site alone. Safe to run before every recording.

.EXAMPLE
  .\scripts\provision_checkmk.ps1

.EXAMPLE
  .\scripts\provision_checkmk.ps1 -NoStart    # site already running

.EXAMPLE
  .\scripts\provision_checkmk.ps1 -Recreate   # wipe the cmkdata volume first
#>
[CmdletBinding()]
param(
    [string]$Site = 'cmk',
    [string]$Password = 'statetrack',
    [int]$Port = 5000,
    [string]$StateTrackUrl = '',
    [switch]$NoStart,
    [switch]$Recreate,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Container = 'statetrack-checkmk-1'
$Service = 'checkmk'
$BaseUrl = "http://localhost:$Port"

# Inside the container, StateTrack on the host is host.docker.internal. Derived
# from the port in docker-compose.yml rather than hard-coded, so a developer who
# runs the server on 8081 only has to pass one flag.
if (-not $StateTrackUrl) { $StateTrackUrl = 'http://host.docker.internal:8080' }

function Invoke-Native {
    # Local copy rather than a dot-source of dev.ps1: that script parses a
    # mandatory positional Task and would run its own switch on import.
    param([string]$Exe, [string[]]$ArgumentList)
    & $Exe @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($ArgumentList -join ' ') failed with exit code $LASTEXITCODE" }
}

function Test-SiteReady {
    # The login page answers 200 once the site's Apache and web app are both up.
    # Three deliberate choices:
    #  * Both 127.0.0.1 and localhost are tried. Docker publishes on 0.0.0.0 and
    #    [::], but a host that resolves localhost to ::1 first can fail against a
    #    stack that only bound IPv4 — and the failure looks identical to "still
    #    booting".
    #  * The proxy is bypassed. Invoke-WebRequest honours the system proxy in
    #    PowerShell 5.1, so a corporate proxy turns a perfectly healthy loopback
    #    site into a 4-minute timeout.
    #  * No redirect handling games: the login page itself is a 200.
    foreach ($addr in @('127.0.0.1', 'localhost')) {
        try {
            $req = [System.Net.HttpWebRequest]::Create("http://${addr}:$Port/$Site/check_mk/login.py")
            $req.Proxy = $null
            $req.Timeout = 5000
            $req.ReadWriteTimeout = 5000
            $req.UserAgent = 'statetrack-provisioner'
            $resp = $req.GetResponse()
            try {
                if ([int]$resp.StatusCode -eq 200) { return $true }
            }
            finally { $resp.Close() }
        }
        catch {
            # Try the next address; a genuine outage fails on both.
        }
    }
    return $false
}

function Wait-Site {
    param([int]$TimeoutSeconds = 360)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $start = Get-Date
    while ((Get-Date) -lt $deadline) {
        if (Test-SiteReady) {
            $took = [int]((Get-Date) - $start).TotalSeconds
            if ($took -gt 5) { Write-Host " (ready after ${took}s)" } else { Write-Host ' ok' }
            return $true
        }
        Write-Host -NoNewline '.'
        Start-Sleep -Seconds 5
    }
    return $false
}

# --------------------------------------------------------------------------- #
# 1. Container                                                                #
# --------------------------------------------------------------------------- #
if ($Recreate) {
    Write-Host 'removing the Checkmk container and its volume...'
    # The volume holds the OMD site; deleting it is what forces a clean re-create
    # of the admin password after a change to CMK_PASSWORD.
    & docker compose --profile monitoring rm -sf checkmk 2>$null
    & docker volume rm statetrack_cmkdata 2>$null
}

if (-not $NoStart) {
    Write-Host "starting Checkmk (site '$Site', port $Port)..."
    # Naming the service explicitly bypasses the compose profile, so this works
    # without --profile on the command line.
    Invoke-Native docker @('compose', '--profile', 'monitoring', 'up', '-d', '--wait', 'checkmk')

    Write-Host -NoNewline 'waiting for the site to initialise...'
    if (-not (Wait-Site)) {
        $logs = & docker logs --tail 30 $Container 2>&1 | Out-String
        throw @"
Checkmk did not answer on http://127.0.0.1:$Port/$Site/check_mk/login.py within 6 minutes.

Last container log lines:
$logs

Diagnose with:
  docker ps --filter name=$Container
  docker logs --tail 200 $Container
  docker exec $Container curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/$Site/check_mk/login.py
"@
    }
}

# Verify the container is actually running before trying to exec into it. A
# stopped container produces a confusing "No such container" from docker exec.
$running = & docker inspect -f '{{.State.Running}}' $Container 2>$null
if ($running -ne 'true') {
    throw "container $Container is not running. Start it with: docker compose --profile monitoring up -d checkmk"
}

# --------------------------------------------------------------------------- #
# 2. Provision                                                                #
# --------------------------------------------------------------------------- #
# Copied in rather than bind-mounted: the compose file already mounts the check
# and the wrapper, and adding a third mount for a script that only runs during
# setup would put dev tooling permanently inside a production-shaped container.
Write-Host 'copying provisioning scripts into the container...'
# `docker compose cp` addresses the service, not the container name.
& docker compose --profile monitoring cp `
    integrations/checkmk/provision_checkmk.py "${Service}:/tmp/provision_checkmk.py"
& docker compose --profile monitoring cp `
    integrations/checkmk/verify_checkmk_livestatus.py "${Service}:/tmp/verify_checkmk_livestatus.py"
if ($LASTEXITCODE -ne 0) { throw 'failed to copy provisioning scripts into the container' }

Write-Host "provisioning StateTrack into Checkmk (StateTrack at $StateTrackUrl)..."
& docker exec `
    -e "STATETRACK_URL=$StateTrackUrl" `
    -e "STATETRACK_WINDOW=7d" `
    -e "CMK_SITE_ID=$Site" `
    -e "CMK_PASSWORD=$Password" `
    $Container python3 /tmp/provision_checkmk.py --site $Site --url "http://localhost:$Port" --password $Password
if ($LASTEXITCODE -ne 0) {
    throw "provisioning failed (exit $LASTEXITCODE). Check StateTrack is running at $StateTrackUrl"
}

# --------------------------------------------------------------------------- #
# 3. Verify                                                                   #
# --------------------------------------------------------------------------- #
if (-not $SkipVerify) {
    Write-Host ''
    Write-Host 'verifying the live services via Livestatus...'
    # 120s: the active checks are scheduled by the Nagios core, not by the
    # provisioning script, so a freshly activated site can sit at PENDING for
    # one check interval. The verifier re-reads until the deadline and reports
    # exactly which host/service is still missing.
    & docker exec -u $Site $Container python3 /tmp/verify_checkmk_livestatus.py $Site --wait 120
    if ($LASTEXITCODE -ne 0) {
        throw 'verification failed: not every host reports both StateTrack services with perfdata'
    }
}

Write-Host ''
Write-Host 'Checkmk demo is ready.'
Write-Host "  URL:      $BaseUrl/$Site/"
Write-Host '  User:     cmkadmin'
Write-Host "  Password: $Password"
Write-Host '  Hosts:    prod-web-01, prod-web-02, win-app-02, prod-k8s-01'
Write-Host '  Services: StateTrack Changes (local check), StateTrack Active Check (Nagios)'
Write-Host ''
Write-Host 'Open: http://localhost:5000/cmk/check_mk/login.py'
