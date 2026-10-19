<#
.SYNOPSIS
  Windows developer workflow for StateTrack (mirrors the Makefile used on Linux/CI).

.EXAMPLE
  .\scripts\dev.ps1 check        # gofmt + vet + unit tests + cross-compiled builds
  .\scripts\dev.ps1 up; .\scripts\dev.ps1 migrate; .\scripts\dev.ps1 test-integration
  .\scripts\dev.ps1 up; .\scripts\dev.ps1 migrate; .\scripts\dev.ps1 seed   # realistic demo timeline for today
  .\scripts\dev.ps1 up; .\scripts\dev.ps1 seed; .\scripts\dev.ps1 grafana-seed   # Grafana dashboard + annotations for a screen recording
    .\scripts\dev.ps1 run-web      # start the Vite dev server (proxies /api -> :8080)
    .\scripts\dev.ps1 run-server   # start the Go backend in demo mode (seeded hosts report online)
    .\scripts\dev.ps1 sync-assets  # copy integrations/* assets into web/public for the console
  .\scripts\dev.ps1 test-linux   # run agent tests as static linux/amd64+arm64 binaries in Alpine
  .\scripts\dev.ps1 test-race    # go test -race ./... inside a Linux golang container (CGO only there)
  .\scripts\dev.ps1 test-e2e     # Linux collector end-to-end tests (unprivileged + privileged containers)
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'tools', 'proto', 'fmt', 'vet', 'test', 'test-integration', 'test-linux', 'test-race',
        'test-e2e', 'build', 'run-web', 'run-server', 'run-all', 'web-build', 'sync-assets', 'up', 'down', 'migrate', 'seed', 'grafana-seed', 'demo-traffic', 'checkmk', 'check', 'clean')]
    [string]$Task = 'help',

    # Options for the demo-traffic task. PowerShell binds these even though the
    # task is positional; they are ignored by every other task. Named (not bare
    # passthrough) because PowerShell would otherwise try to bind an unknown
    # `-duration` as a script parameter and fail before the switch is reached.
    [string]$Duration,
    [string]$Interval,
    [double]$L1Ratio = -1,
    [int]$Burst = 0,
    [switch]$Foreground,
    [switch]$DryRun,

    # Options for the checkmk task. Named rather than passed through: PowerShell
    # would otherwise reject an unknown -switch before the task switch is
    # reached, so `dev.ps1 checkmk -NoStart` would fail to bind.
    [switch]$NoStart,
    [switch]$Recreate,
    [string]$StateTrackUrl
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$GoPackages = @('./pkg/...', './agent/...', './server/...')
$ModulePb = 'github.com/statetrack/statetrack/pkg/pb'
$BinDir = Join-Path $Root 'bin'
$PgUser = if ($env:POSTGRES_USER) { $env:POSTGRES_USER } else { 'statetrack' }
$PgDb = if ($env:POSTGRES_DB) { $env:POSTGRES_DB } else { 'statetrack' }
$TestDsn = "postgres://${PgUser}:statetrack@localhost:5432/${PgDb}?sslmode=disable"

# Pick up tools installed since this shell started (winget, go install).
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
    [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + (Join-Path (go env GOPATH) 'bin')

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

function Invoke-Fmt {
    $files = & gofmt -l pkg agent server
    if ($files) { throw "gofmt needed for:`n$($files -join "`n")`nRun: gofmt -w pkg agent server" }
}

function Invoke-Build {
    New-Item -ItemType Directory -Force $BinDir | Out-Null
    $targets = @(
        @{ OS = 'linux'; Arch = 'amd64'; Ext = '' },
        @{ OS = 'linux'; Arch = 'arm64'; Ext = '' },
        @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe' }
    )
    $saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
    try {
        $env:CGO_ENABLED = '0'
        foreach ($t in $targets) {
            $env:GOOS = $t.OS; $env:GOARCH = $t.Arch
            $out = Join-Path $BinDir "statetrack-agent-$($t.OS)-$($t.Arch)$($t.Ext)"
            Invoke-Native go @('build', '-trimpath', '-ldflags', '-s -w', '-o', $out, './agent/cmd/statetrack-agent')
            Write-Host ("built {0} ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB))
        }
        $env:GOOS = $saved.GOOS; $env:GOARCH = $saved.GOARCH
        $out = Join-Path $BinDir 'statetrack-server.exe'
        Invoke-Native go @('build', '-trimpath', '-ldflags', '-s -w', '-o', $out, './server/cmd/statetrack-server')
        Write-Host "built $out"
        # The stdio MCP server desktop clients launch. Built alongside the
        # server so a client config that points at bin/statetrack-mcp.exe works
        # straight after a checkout + build.
        $out = Join-Path $BinDir 'statetrack-mcp.exe'
        Invoke-Native go @('build', '-trimpath', '-ldflags', '-s -w', '-o', $out, './server/cmd/statetrack-mcp')
        Write-Host "built $out"
        # The Grafana demo seeder, so a screen-recording session can start from
        # bin/ without a `go run` (which would rebuild on every call).
        $out = Join-Path $BinDir 'statetrack-grafana-seed.exe'
        Invoke-Native go @('build', '-trimpath', '-ldflags', '-s -w', '-o', $out, './server/cmd/statetrack-grafana-seed')
        Write-Host "built $out"
        # The live-traffic generator: it drives changes through the real ingest
        # API so the Grafana rate/increase panels (the hero panel's red L1 bars)
        # actually move during a recording.
        $out = Join-Path $BinDir 'statetrack-demo-traffic.exe'
        Invoke-Native go @('build', '-trimpath', '-ldflags', '-s -w', '-o', $out, './server/cmd/statetrack-demo-traffic')
        Write-Host "built $out"
    }
    finally {
        foreach ($k in $saved.Keys) { Set-Item "env:$k" $saved[$k] -ErrorAction SilentlyContinue }
        if (-not $saved.GOOS) { Remove-Item env:GOOS -ErrorAction SilentlyContinue }
        if (-not $saved.GOARCH) { Remove-Item env:GOARCH -ErrorAction SilentlyContinue }
        if (-not $saved.CGO_ENABLED) { Remove-Item env:CGO_ENABLED -ErrorAction SilentlyContinue }
    }
}

function Invoke-TestLinux {
    $outDir = Join-Path $BinDir 'xtest'
    New-Item -ItemType Directory -Force $outDir | Out-Null
    $pkgs = & go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./agent/...
    $saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
    try {
        $env:CGO_ENABLED = '0'; $env:GOOS = 'linux'
        foreach ($arch in 'amd64', 'arm64') {
            $env:GOARCH = $arch
            $names = @()
            foreach ($p in $pkgs) {
                $name = ($p -split '/')[-1]
                Invoke-Native go @('test', '-c', '-o', (Join-Path $outDir "$name-linux-$arch"), $p)
                $names += $name
            }
            $script = ($names | ForEach-Object { "echo -n '$_ '; /x/$_-linux-$arch -test.count=1 2>&1 | tail -1" }) -join '; '
            Write-Host "== linux/$arch"
            $out = docker run --rm --platform "linux/$arch" -v "${outDir}:/x:ro" alpine:3 sh -c $script
            $out | Write-Host
            if ($LASTEXITCODE -ne 0 -or ($out | Select-String -NotMatch ' PASS$')) { throw "linux/$arch tests failed" }
        }
    }
    finally {
        foreach ($k in $saved.Keys) {
            if ($saved[$k]) { Set-Item "env:$k" $saved[$k] } else { Remove-Item "env:$k" -ErrorAction SilentlyContinue }
        }
    }
}

# The race detector needs cgo, so -race runs only inside this Linux container;
# release builds stay CGO_ENABLED=0.
$GoImage = 'golang:1.26'
$GoDockerArgs = @('run', '--rm', '-v', "${Root}:/src", '-w', '/src',
    '-v', 'statetrack-gomod:/go/pkg/mod', '-v', 'statetrack-gocache:/root/.cache/go-build',
    '-e', 'GOFLAGS=-buildvcs=false')

function Invoke-TestRace {
    Invoke-Native docker ($GoDockerArgs + @('-e', 'CGO_ENABLED=1', $GoImage,
            'go', 'test', '-race', '-count=1') + $GoPackages)
}

function Invoke-TestE2E {
    $runs = @(
        @{ Name = 'unprivileged'; Args = @() },
        @{ Name = 'privileged (CAP_SYS_ADMIN, NET_ADMIN, AUDIT_CONTROL, host PID)'
            Args = @('--cap-add', 'SYS_ADMIN', '--cap-add', 'NET_ADMIN', '--cap-add', 'AUDIT_CONTROL',
                '--cap-add', 'AUDIT_READ', '--pid=host') }
    )
    foreach ($r in $runs) {
        Write-Host "== e2e: $($r.Name)"
        Invoke-Native docker ($GoDockerArgs + $r.Args + @('-e', 'CGO_ENABLED=1', '-e', 'STATETRACK_E2E=1', $GoImage,
                'go', 'test', '-race', '-count=1', '-v', '-run', 'E2E', './agent/internal/app/'))
    }
}

function Invoke-SyncAssets {
    # The provisioned integration assets live in integrations/ at the repo root,
    # next to the docs they are described in. The console needs them under
    # web/public/ to serve them for copy/download. Copying keeps integrations/
    # the single source of truth; -Check turns a drift into a build failure
    # rather than a console that hands out a stale template.
    param([switch]$Check)
    $pairs = @(
        @{ Src = 'integrations/grafana/statetrack-overview-dashboard.json'; Dst = 'web/public/integration-assets/grafana/statetrack-overview-dashboard.json' },
        @{ Src = 'integrations/prometheus/prometheus_alerts.yml';          Dst = 'web/public/integration-assets/prometheus/prometheus_alerts.yml' },
        @{ Src = 'integrations/checkmk/check_statetrack.py';               Dst = 'web/public/integration-assets/checkmk/check_statetrack.py' },
        @{ Src = 'integrations/zabbix/zabbix_template_statetrack.yaml';    Dst = 'web/public/integration-assets/zabbix/zabbix_template_statetrack.yaml' }
    )
    $drift = @()
    foreach ($p in $pairs) {
        $src = Join-Path $Root $p.Src
        $dst = Join-Path $Root $p.Dst
        if (-not (Test-Path $src)) { throw "missing integration asset $($p.Src)" }
        if ($Check) {
            if (-not (Test-Path $dst) -or
                (Get-FileHash $src).Hash -ne (Get-FileHash $dst).Hash) {
                $drift += $p.Dst
            }
            continue
        }
        New-Item -ItemType Directory -Force (Split-Path -Parent $dst) | Out-Null
        Copy-Item -Force $src $dst
        Write-Host "sync   $($p.Dst)"
    }
    if ($Check -and $drift.Count -gt 0) {
        throw "integration assets are out of sync with integrations/:`n$($drift -join "`n")`nRun: dev.ps1 sync-assets"
    }
}

function Invoke-Psql {
    param([string]$Sql)
    $out = $Sql | docker compose exec -T postgres psql -U $PgUser -d $PgDb -v ON_ERROR_STOP=1 -tA -q -f -
    if ($LASTEXITCODE -ne 0) { throw 'psql failed' }
    return $out
}

function Invoke-Migrate {
    Invoke-Psql 'CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());' | Out-Null
    foreach ($f in Get-ChildItem server/migrations/*.sql | Sort-Object Name) {
        $version = $f.BaseName
        if ((Invoke-Psql "SELECT 1 FROM schema_migrations WHERE version = '$version';") -eq '1') {
            Write-Host "skip   $($f.Name) (already applied)"
            continue
        }
        Write-Host "apply  $($f.Name)"
        $sql = (Get-Content -Raw $f.FullName) + "`nINSERT INTO schema_migrations (version) VALUES ('$version');"
        $sql | docker compose exec -T postgres psql -U $PgUser -d $PgDb -v ON_ERROR_STOP=1 --single-transaction -q -f -
        if ($LASTEXITCODE -ne 0) { throw "migration $($f.Name) failed" }
    }
}

switch ($Task) {
    'tools' {
        Invoke-Native go @('install', 'google.golang.org/protobuf/cmd/protoc-gen-go@latest')
        Invoke-Native go @('install', 'google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest')
    }
    'proto' {
        $protos = Get-ChildItem -Recurse proto -Filter *.proto | ForEach-Object { Resolve-Path -Relative $_.FullName }
        Invoke-Native protoc (@('-I', 'proto',
                '--go_out=pkg/pb', "--go_opt=module=$ModulePb",
                '--go-grpc_out=pkg/pb', "--go-grpc_opt=module=$ModulePb") + $protos)
    }
    'fmt' { Invoke-Fmt }
    'vet' { Invoke-Native go (@('vet') + $GoPackages) }
    'test' { Invoke-Native go (@('test') + $GoPackages) }
    'test-integration' {
        $env:STATETRACK_TEST_DATABASE_URL = $TestDsn
        try { Invoke-Native go (@('test', '-count=1') + $GoPackages) }
        finally { Remove-Item env:STATETRACK_TEST_DATABASE_URL }
    }
    'test-linux' { Invoke-TestLinux }
    'test-race' { Invoke-TestRace }
    'test-e2e' { Invoke-TestE2E }
    'build' { Invoke-Build }
    'run-web' { Invoke-Native npm @('--prefix', 'web', 'run', 'dev') }
    'run-server' {
        # Demo mode keeps the seeded fleet (prod-web-01, prod-web-02, win-app-02)
        # reporting online even though no agent process is actually running, so
        # the console and the Checkmk/Zabbix summary endpoints agree.
        $env:STATETRACK_DEMO_MODE = '1'
        Write-Host 'demo mode: hosts will be marked online at startup'
        Invoke-Native (Join-Path $BinDir 'statetrack-server.exe') @()
    }
    'web-build' { Invoke-SyncAssets; Invoke-Native npm @('--prefix', 'web', 'run', 'build') }
    'sync-assets' { Invoke-SyncAssets }
    'up' { Invoke-Native docker @('compose', 'up', '-d', '--wait') }
    'down' { Invoke-Native docker @('compose', 'down') }
    'migrate' { Invoke-Migrate }
    'seed' { Invoke-Native go @('run', './server/cmd/statetrack-seed') }
    'demo-traffic' {
        # Drive changes through the real ingest API so the Grafana counter (and
        # therefore every rate/increase panel, including the hero panel's red L1
        # bars) moves. Needs the server running.
        #
        #   dev.ps1 demo-traffic                          # background, until stopped
        #   dev.ps1 demo-traffic -Duration 5m             # bounded, foreground
        #   dev.ps1 demo-traffic -Interval 1s -L1Ratio .7 # denser red bars
        #   dev.ps1 demo-traffic -DryRun                  # print, send nothing
        $genArgs = @()
        if ($Duration) { $genArgs += @('-duration', $Duration) }
        if ($Interval) { $genArgs += @('-interval', $Interval) }
        if ($L1Ratio -ge 0) { $genArgs += @('-l1-ratio', $L1Ratio.ToString([Globalization.CultureInfo]::InvariantCulture)) }
        if ($Burst -gt 0) { $genArgs += @('-burst', $Burst.ToString()) }
        if ($DryRun) { $genArgs += '-dry-run' }

        $exe = Join-Path $BinDir 'statetrack-demo-traffic.exe'
        $useExe = Test-Path $exe

        # A bounded or dry run finishes on its own, so keep it in the foreground.
        $bounded = $DryRun -or $Duration -or $Foreground
        if ($bounded) {
            if ($useExe) { Invoke-Native $exe $genArgs }
            else { Invoke-Native go (@('run', './server/cmd/statetrack-demo-traffic') + $genArgs) }
        }
        else {
            if ($useExe) {
                $proc = Start-Process -FilePath $exe -ArgumentList $genArgs -PassThru -WindowStyle Hidden
            }
            else {
                $proc = Start-Process -FilePath 'go' -ArgumentList (@('run', './server/cmd/statetrack-demo-traffic') + $genArgs) -PassThru -WindowStyle Hidden
            }
            Write-Host ''
            Write-Host "demo traffic generator started (pid $($proc.Id))"
            Write-Host 'It drives changes through the ingest API so the Grafana panels move.'
            Write-Host "Stop it with:  Stop-Process -Id $($proc.Id)"
            Write-Host ''
        }
    }
    'grafana-seed' {
        # Import the provisioned dashboard into the Docker Grafana and push one
        # annotation per seeded Level 1 change, so the hero panel's metric line,
        # its red L1 bars and the StateTrack flags all sit on one clock for a
        # screen recording. Idempotent: re-running replaces the flags rather
        # than stacking duplicates. Needs `up` first; `seed` makes the
        # annotations match a timeline.
        $exe = Join-Path $BinDir 'statetrack-grafana-seed.exe'
        if (Test-Path $exe) { Invoke-Native $exe @() }
        else { Invoke-Native go @('run', './server/cmd/statetrack-grafana-seed') }
    }
    'checkmk' {
        # Bring up the Checkmk Raw container and provision the four demo hosts
        # into it, so `http://localhost:5000/cmk/` is ready to film. The
        # container is behind the `monitoring` compose profile: a plain `up`
        # should not block the change timeline on a monitoring demo.
        #
        #   dev.ps1 checkmk                  # start + provision + verify
        #   dev.ps1 checkmk -NoStart         # provision into a running site
        #   dev.ps1 checkmk -Recreate        # wipe the site volume first
        #
        # Extra arguments after the task name are forwarded to the provisioning
        # script, e.g.  dev.ps1 checkmk -StateTrackUrl http://host.docker.internal:8081
        # The flags are rebuilt explicitly rather than forwarding $args: the
        # switches have to be re-emitted by name for the child PowerShell.
        $script = Join-Path $PSScriptRoot 'provision_checkmk.ps1'
        $extra = @()
        if ($NoStart) { $extra += '-NoStart' }
        if ($Recreate) { $extra += '-Recreate' }
        if ($StateTrackUrl) { $extra += @('-StateTrackUrl', $StateTrackUrl) }
        Invoke-Native powershell (@('-ExecutionPolicy', 'Bypass', '-File', $script) + $extra)
    }
    'run-all' {
        # One-shot demo bring-up: build, seed, and wire Grafana, then run both
        # servers in demo mode.
        Invoke-Build
        Invoke-SyncAssets
        Invoke-Native go @('run', './server/cmd/statetrack-seed')
        try { Invoke-Native (Join-Path $BinDir 'statetrack-grafana-seed.exe') @() }
        catch { Write-Warning "grafana seeding skipped (is the stack up?): $_" }
        Write-Host ''
        Write-Host 'Starting backend in demo mode; open http://localhost:5173/integrations'
        Write-Host 'Run .\scripts\dev.ps1 run-web in a second shell.'
        Write-Host ''
        Write-Host 'For a recording, start the live-traffic generator in another shell:'
        Write-Host '    .\scripts\dev.ps1 demo-traffic'
        Write-Host 'It drives changes through the ingest API so the Grafana rate panels'
        Write-Host 'including the red L1 bars on the hero panel, move instead of sitting at 0.'
        Write-Host ''
        $env:STATETRACK_DEMO_MODE = '1'
        Invoke-Native (Join-Path $BinDir 'statetrack-server.exe') @()
    }
    'check' {
        Invoke-Fmt
        Invoke-Native go (@('vet') + $GoPackages)
        Invoke-Native go (@('test') + $GoPackages)
        Invoke-Build
        Invoke-SyncAssets -Check
    }
    'clean' { Remove-Item -Recurse -Force $BinDir -ErrorAction SilentlyContinue }
    default { Get-Help $PSCommandPath -Detailed }
}
