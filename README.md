





<div align="center">

# StateTrack

**Infrastructure Change Intelligence — git history for live servers.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/premtonx/statetrack?sort=semver&color=1a73e8)](https://github.com/premtonx/statetrack/releases)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](go.work)
[![Container](https://img.shields.io/badge/ghcr.io-premtonx%2Fstatetrack-2496ED?logo=docker&logoColor=white)](https://github.com/premtonx/statetrack/pkgs/container/statetrack)
[![Platforms](https://img.shields.io/badge/agents-Linux%20%C2%B7%20Windows%20%C2%B7%20Kubernetes-1e8e3e)](#install-an-agent)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-7c3aed)](CONTRIBUTING.md)

StateTrack answers the only question that matters at 3am: **what changed?**

It records every meaningful change to your Linux and Windows hosts — who changed
what, from where, with which tool, and what the file looked like before — and
puts that change on the same timeline as your CPU, latency and error-rate graphs.
A config edit, a package upgrade, a stopped IIS app pool, or a row flipped in
`settings_db` is captured as a reviewable diff with an actor attached, seconds
after it happens.

</div>

https://github.com/user-attachments/assets/ed657d6d-69cc-4711-937c-3996005ab4c5

**The console** — fleet pulse, change activity and the latest changes timeline.
<img width="1920" height="1473" alt="StateTrack console overview — fleet pulse, change impact and change activity" src="https://github.com/user-attachments/assets/265aeb47-7816-40ea-86a0-7a767fca9cca" />

**Grafana** — the same Level 1/2 changes as point annotations on your metric graphs.
<img width="1920" height="911" alt="StateTrack changes overlaid on Grafana" src="https://github.com/user-attachments/assets/98a00f5f-e613-43e6-b3ef-453dc249ab46" />


---

## Why this exists

An outage is almost always preceded by a change. When it is, the answer is
scattered across shell histories, `/var/log/dpkg.log`, an Ansible log nobody
kept, and three people's memory — or it is gone.

Existing tools answer *"is it up?"*. StateTrack answers *"what is different, who
did it, and what did it look like before?"*

| | |
| --- | --- |
| **Day-0 baseline** | The agent fingerprints every watched file on first start, so only real diffs are ever reported — never a filesystem dump. |
| **Impact classification** | Level 0–4 decides what to drop, what to diff and what to page on. A package install collapses into **one** parent event. |
| **Secrets never leave the host** | Credentials are scrubbed **on the monitored machine** into `[REDACTED:sha256:…]` before hashing, spooling or transmitting. |
| **Diff, not just a flag** | Every Level 1 change carries a scrubbed unified diff with actor, tool, PID and process ancestry. |
| **One clock with your metrics** | Level 1/2 changes are pushed to Grafana as point annotations and exposed at `/metrics`, so the spike and the cause share an x-axis. |
| **Read-only by construction** | The database watcher issues `SELECT` only. The agent opens no inbound port: one outbound gRPC stream, nothing listening. |

### Architecture

```
┌───────────────────────── Host (Linux / Windows / K8s) ─────────────────────────┐
│  statetrack-agent     < 25 MB RSS · < 1% CPU · zero inbound ports              │
│                                                                                │
│  collectors    filesystem · registry · SCM · systemd · packages · IIS · DB · k8s│
│       │                                                                        │
│       ▼                                                                        │
│  classifier (L0–L4) → storm breaker → shadow diff → secret scrubber (on host)  │
│       │                                                                        │
│       ▼                                                                        │
│  debouncer (3 s sliding window → parent event) → SQLite spool (200 MB)         │
│       │                                                                        │
└───────┼──────────────── outbound gRPC 50051 (mTLS) + discovery heartbeat ──────┘
        ▼
┌──────────────────────────── statetrack-server ─────────────────────────────────┐
│  gRPC ingest → Postgres (partitioned events) → S3/SeaweedFS (large diffs)      │
│              → Grafana · Slack · Teams · PagerDuty · SIEM · Jira · ServiceNow  │
│              → AI gateway (offline heuristics / Ollama / OpenAI / Azure / Claude)│
│              → MCP server (JSON-RPC 2.0)  →  Prometheus /metrics               │
│              → REST + WebSocket  →  embedded React console on the same origin  │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of contents

**Getting started**
1. [Run the server — 3 ways](#1-run-the-server--3-ways)
2. [Install an agent](#2-install-an-agent) — [direct downloads](#direct-downloads--release-artifacts)
3. [Configuration: `agent.yaml` & targeted watchers](#3-configuration-agentyaml--targeted-watchers)
4. [Integrations](#4-integrations)

**Reference**
5. [Architecture & runtime components](#5-architecture--runtime-components)
6. [Impact levels & anti-flood defenses](#6-impact-levels--anti-flood-defenses)
7. [Secret scrubber](#7-secret-scrubber)
8. [Auto-discovery & the enterprise catalog](#8-auto-discovery--the-enterprise-catalog)
9. [The web console](#9-the-web-console)
10. [AI provider gateway](#10-ai-provider-gateway)
11. [Model Context Protocol (MCP) server](#11-model-context-protocol-mcp-server)
12. [Enterprise security](#12-enterprise-security)
13. [REST, WebSocket & gRPC API](#13-rest-websocket--grpc-api)
14. [Metrics & alerting](#14-metrics--alerting)
15. [Development, build & verification](#15-development-build--verification)

---

## 1. Run the server — 3 ways

A fresh StateTrack install is **empty by design**: 0 hosts, 0 events, no demo
data. The console shows `0 / 0 agents online` and an onboarding card until you
enrol your first host. Demo data is opt-in (`make seed`), never a default.

The first administrator is created on first boot. Its password is generated and
printed **once**:

```bash
docker compose logs statetrack | grep administrator
```

…or choose it yourself with `STATETRACK_ADMIN_EMAIL` / `STATETRACK_ADMIN_PASSWORD`.

### Option A — 1-command quickstart (no clone, no toolchain)

```bash
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/docker-compose.quickstart.yml \
  -o docker-compose.yml
docker compose up -d
```

Open **http://localhost:8080**. That file is self-contained: Postgres 17 with a
health check and a persistent volume, plus the pre-built
`ghcr.io/premtonx/statetrack` image. Nothing is compiled, nothing else is
needed. Migrations run automatically on first boot.

Change `POSTGRES_PASSWORD` and set `STATETRACK_SESSION_SECRET` before exposing
the port beyond localhost.

### Option B — single `docker run` (bring your own Postgres)

```bash
docker run -d --name statetrack \
  -p 8080:8080 -p 50051:50051 \
  -e DATABASE_URL='postgres://user:pass@db.internal:5432/statetrack?sslmode=disable' \
  -e STATETRACK_SESSION_SECRET='change-me-to-a-long-random-string' \
  -v statetrack-data:/var/lib/statetrack \
  --restart unless-stopped \
  ghcr.io/premtonx/statetrack:latest
```

`8080` serves the console, the REST/WS API, `/metrics` and `/healthz`; `50051`
is agent gRPC ingestion. Large diffs are stored inline in Postgres unless you
point `S3_ENDPOINT` at an S3-compatible store.

### Option C — clone, build and run with Docker Compose

```bash
git clone https://github.com/premtonx/statetrack.git
cd statetrack
docker compose up -d --build
```

The multi-stage `Dockerfile` builds the React console (`node:20-alpine`),
compiles a static server with the console and the SQL migrations embedded
(`golang:1.26-alpine`, `CGO_ENABLED=0`), and copies one binary into an
`alpine:3.20` runtime with a built-in `HEALTHCHECK`.

Optional profiles and demo data:

```bash
# Grafana :3000, Prometheus :9090, node_exporter :9100, Checkmk :5000/cmk
docker compose --profile monitoring up -d

# or, from a checkout: seed a realistic demo timeline anchored to today
make seed                       # Windows: .\scripts\dev.ps1 seed
make grafana-seed               # import the dashboard + push annotations
```

Everything the server reads from the environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `postgres://statetrack:statetrack@localhost:5432/statetrack?sslmode=disable` | Postgres DSN. |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:50051` | API+console + metrics / agent ingestion. |
| `STATETRACK_DEMO_MODE` | `0` | `1` = demo heartbeat, auto-login, anonymous datasource reads. **Off in production.** |
| `STATETRACK_AUTO_MIGRATE` | `1` | Apply pending SQL migrations on boot. |
| `STATETRACK_SERVE_UI` | `1` | Serve the embedded console on `/`. |
| `STATETRACK_SESSION_SECRET` | random per boot | Signs console sessions. Set it for long-lived sessions. |
| `STATETRACK_ADMIN_EMAIL` / `STATETRACK_ADMIN_PASSWORD` | generated | Bootstrap administrator. |
| `STATETRACK_UI_URL` | `http://localhost:5173` | Base URL for Grafana/notification deep links. |
| `S3_ENDPOINT` | `none` | `none` stores large diffs inline in Postgres. Set an S3-compatible endpoint to offload diffs > 2 KB. |
| `S3_BUCKET` · `S3_REGION` · `S3_ACCESS_KEY` · `S3_SECRET_KEY` | `statetrack-diffs` · `us-east-1` | Blob store for diffs > 2 KB. |
| `STATETRACK_AUTH_DISABLED` | `false` | Bypass authentication. Never in production. |

`GET /api/v1/system` reports the running version, commit, build date, Go
runtime, database version and storage backend — the console's Settings page
reads it, so nothing in the UI hardcodes a build string.

---

## 2. Install an agent

### Direct downloads — release artifacts

Every artifact below is attached to the **[latest release](https://github.com/premtonx/statetrack/releases/latest)**. The `latest/download` links are stable: they always resolve to the newest published version, so a script written today keeps working after an upgrade.

| Component | OS / Arch | Package | Direct download |
| :--- | :--- | :--- | :--- |
| **StateTrack Agent** | Linux x86_64 | `.tar.gz` | [Download Linux amd64](https://github.com/premtonx/statetrack/releases/latest/download/statetrack-agent-linux-amd64.tar.gz) |
| **StateTrack Agent** | Linux ARM64 | `.tar.gz` | [Download Linux arm64](https://github.com/premtonx/statetrack/releases/latest/download/statetrack-agent-linux-arm64.tar.gz) |
| **StateTrack Agent** | Windows x86_64 | `.zip` | [Download Windows amd64](https://github.com/premtonx/statetrack/releases/latest/download/statetrack-agent-windows-amd64.zip) |
| **StateTrack Server** | Linux x86_64 | `.tar.gz` | [Download Server Linux](https://github.com/premtonx/statetrack/releases/latest/download/statetrack-server-linux-amd64.tar.gz) |
| **StateTrack Server** | Windows x86_64 | `.zip` | [Download Server Windows](https://github.com/premtonx/statetrack/releases/latest/download/statetrack-server-windows-amd64.zip) |
| **Checkmk & Monitoring** | Multiplatform | `.zip` | [Download Integrations Bundle](https://github.com/premtonx/statetrack/releases/latest/download/statetrack-integrations-bundle.zip) |
| **Checksums** | All | `.txt` | [Download SHA256SUMS.txt](https://github.com/premtonx/statetrack/releases/latest/download/SHA256SUMS.txt) |

**Verify before you run.** Every archive is listed in `SHA256SUMS.txt`. Download both into the same directory and check them — a mismatch means the file is corrupt or was tampered with in transit:

```bash
sha256sum -c --ignore-missing SHA256SUMS.txt    # Linux
```

```powershell
# Windows
$want = (Select-String -Path SHA256SUMS.txt -Pattern 'statetrack-agent-windows-amd64.zip' |
         ForEach-Object { $_.Line.Split(' ')[0] })
$got  = (Get-FileHash statetrack-agent-windows-amd64.zip -Algorithm SHA256).Hash.ToLower()
if ($want -eq $got) { 'OK' } else { throw 'checksum mismatch' }
```

The sections below install the agent as a service, which is what you want on a
monitored host.

The agent is one static binary with no runtime dependencies: no JVM, no Python,
no sidecar. It dials **out** to `:50051` and keeps one stream open, so a
monitored host has **no inbound port** and a compromised server cannot use the
fleet as an ingress path.

Before installing, create an enrollment token in **Settings → Agents**. The
console shows the exact command for this deployment, with the server address
already filled in.

### Linux — option 1: one-line installer

```bash
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
  | sudo bash -s -- \
      --server statetrack.internal.example.com:50051 \
      --token  st_enroll_xxxxxxxxxxxxxxxx \
      --org    production
```

The script detects `x86_64`/`aarch64`, downloads
`statetrack-agent-linux-<arch>.tar.gz` from the latest GitHub release, **verifies
it against the release's `SHA256SUMS.txt`** and refuses to install on a mismatch,
then writes `/etc/statetrack/agent.yaml` (mode `0600`), installs the hardened
systemd unit and starts it.

Useful flags: `--version v0.1.0` to pin a release, `--binary ./statetrack-agent`
for an air-gapped host, `--url` for an internal mirror, `--force` to overwrite an
existing config, `--no-start` to stage without starting.

### Linux — option 2: download the package and set up systemd yourself

```bash
# 1. Download and unpack the release archive
cd /tmp
curl -fsSLO https://github.com/premtonx/statetrack/releases/latest/download/statetrack-agent-linux-amd64.tar.gz
curl -fsSLO https://github.com/premtonx/statetrack/releases/latest/download/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt          # must print: OK
tar -xzf statetrack-agent-linux-amd64.tar.gz
# → statetrack-agent  install.sh  statetrack-agent.service  agent.yaml.example

# 2. Install the binary
sudo install -m 0755 statetrack-agent /usr/local/bin/statetrack-agent
/usr/local/bin/statetrack-agent --version

# 3. Write the configuration
sudo mkdir -p /etc/statetrack
sudo install -m 0600 -o root -g root agent.yaml.example /etc/statetrack/agent.yaml
sudoedit /etc/statetrack/agent.yaml     # set server.address, server.token, server.org

# 4. Install and start the service
sudo install -m 0644 statetrack-agent.service /etc/systemd/system/statetrack-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now statetrack-agent

# 5. Verify
systemctl status statetrack-agent
journalctl -u statetrack-agent -f
```

The unit runs as root with exactly three capabilities
(`CAP_SYS_ADMIN` for fanotify, `CAP_AUDIT_READ` for attribution,
`CAP_DAC_READ_SEARCH` for `/etc/shadow`), `ProtectSystem=full`, a private
`/tmp`, and no new privileges.

The host appears under **Servers** within seconds of the first heartbeat.

### Windows — option 1: one-line PowerShell installer

In an **elevated** PowerShell:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.ps1))) `
    -Server statetrack.internal.example.com:50051 `
    -Token  st_enroll_xxxxxxxxxxxxxxxx `
    -Org    production
```

It downloads `statetrack-agent-windows-amd64.zip`, verifies the SHA-256, extracts
to `C:\ProgramData\StateTrack`, writes `agent.yaml` with an ACL limited to
`SYSTEM` and `Administrators`, then registers and starts the `StateTrackAgent`
service.

### Windows — option 2: download the ZIP and install the service

```powershell
# 1. Download, verify and extract
$dir = 'C:\ProgramData\StateTrack'
New-Item -ItemType Directory -Force $dir | Out-Null
$base = 'https://github.com/premtonx/statetrack/releases/latest/download'
Invoke-WebRequest "$base/statetrack-agent-windows-amd64.zip" -OutFile "$env:TEMP\agent.zip"
Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile "$env:TEMP\SHA256SUMS.txt"

$expected = (Select-String -Path "$env:TEMP\SHA256SUMS.txt" -Pattern 'agent-windows-amd64').Line.Split(' ')[0]
$actual   = (Get-FileHash "$env:TEMP\agent.zip" -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { throw 'checksum mismatch — refusing to install' }

Expand-Archive "$env:TEMP\agent.zip" -DestinationPath $dir -Force
# → statetrack-agent.exe  install.ps1  agent.yaml.example

# 2. Write the configuration
Copy-Item "$dir\agent.yaml.example" "$dir\agent.yaml" -Force
notepad "$dir\agent.yaml"        # set server.address, server.token, server.org
icacls "$dir\agent.yaml" /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"

# 3. Install and start the Windows service
& "$dir\statetrack-agent.exe" service install
& "$dir\statetrack-agent.exe" service start

# 4. Verify
Get-Service StateTrackAgent
Get-WinEvent -ProviderName StateTrackAgent -MaxEvents 20
```

The binary manages its own service; `sc.exe` is not involved. Also available:
`statetrack-agent.exe service stop` and `service uninstall`.

### Kubernetes

`deploy/k8s/` deploys the agent as **two halves of one picture**, sharing one
read-only service account:

```bash
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset.yaml     # per-node OS-level timeline
kubectl apply -f deploy/k8s/deployment.yaml    # one cluster-scoped watcher
kubectl -n statetrack logs -l app.kubernetes.io/component=kubernetes-watcher -f
```

- The **DaemonSet** reads host paths (`/etc`, `/var/lib/kubelet`, CNI config,
  container runtime state) through read-only `hostPath` mounts. Node identity
  comes from the Downward API (`spec.nodeName`), so a rescheduled pod keeps the
  same identity.
- The **Deployment** watches ConfigMaps, Secrets, Deployments, StatefulSets and
  Ingresses through the API server, once per cluster rather than once per node.
- The **RBAC** grants `get`/`list`/`watch` only — no write verb exists in the
  file — with a commented namespace-scoped `Role` alternative.

Every Secret value is redacted **in the cluster** before the object is hashed,
diffed or transmitted.

### Uninstall

```bash
# Linux
sudo systemctl disable --now statetrack-agent
sudo rm -f /usr/local/bin/statetrack-agent /etc/systemd/system/statetrack-agent.service
sudo rm -rf /etc/statetrack /var/lib/statetrack

# Windows (elevated)
C:\ProgramData\StateTrack\statetrack-agent.exe service uninstall
Remove-Item -Recurse -Force C:\ProgramData\StateTrack
```

---

## 3. Configuration: `agent.yaml` & targeted watchers

The agent loads zero-config defaults, overlays the YAML file
(`/etc/statetrack/agent.yaml`, `C:\ProgramData\StateTrack\agent.yaml`), then
overlays `STATETRACK_*` environment variables. Watch rules, `log_level` and the
forensic window hot-reload; `server`, `spool`, `host_id` and the collector
toggles need a restart.

📘 **Every key and every `STATETRACK_*` override:**
[`docs/agent-deployment-guide.md`](docs/agent-deployment-guide.md).

### Files & directories

```yaml
host_id: ""                       # empty → /etc/machine-id, then hostname
state_dir: /var/lib/statetrack
log_level: info
reload_interval: 30s

server:
  address: statetrack.internal.example.com:50051
  token: st_enroll_xxxxxxxxxxxxxxxx
  org: production

watch:
  # `paths` REPLACES the defaults; `extra_paths` appends to them. Globs allowed.
  paths:
    - /etc
    - /etc/systemd/system
    - /var/spool/cron
    - /root/.ssh
    - /home/*/.ssh
  exclude:                        # Level 0: never read, never report
    - /etc/ssl/certs/**
    - /var/lib/statetrack/**
  critical:                       # forced Level 1
    - /etc/sudoers
    - /etc/ssh/sshd_config

spool:
  max_mb: 200                     # offline queue cap, oldest-first eviction

baseline:
  pace: 1ms                       # sleep per file during the Day-0 walk
```

Default watch roots — Linux: `/etc`, `/usr/local/etc`, `/etc/systemd/system`,
`/var/spool/cron`, `/root/.ssh`, `/home/*/.ssh`. Windows:
`C:\Windows\System32\inetsrv\config`, `…\drivers\etc`, `…\Tasks`,
`C:\ProgramData`.

### Custom classification rules

Rules are matched against a change's target. Exact patterns are tried before
globs, and the first declared match wins. `level: 0` drops the event.

```yaml
rules:
  - name: nginx-edge-config
    target_type: file             # file | registry | service | package | process | iis | db
    pattern: /etc/nginx/nginx.conf
    level: 1
    diff: true
    tags: [network, edge]

  - name: nginx-vhosts
    pattern: "/etc/nginx/conf.d/*.conf"
    level: 2
    diff: true

  - name: web-content
    pattern: "/var/www/**"
    level: 3                      # hash + size only, no diff

  - name: certbot-noise
    pattern: "/etc/letsencrypt/**"
    level: 0                      # drop
```

Matched events carry `metadata.rule_name` and `metadata.rule_tags`, which the
timeline renders as a `⚡ Rule: nginx-edge-config (L1)` badge.

### Windows IIS application pools & sites

A file watcher sees `applicationHost.config` change. It cannot see a pool that
stopped while the config stayed identical — which is exactly what rapid-fail
protection and an idle recycle look like. This watcher polls the runtime state
and renders one canonical YAML document per target, so a stop becomes a diffable
event.

```yaml
iis:
  enabled: true
  # pools and sites accept a name, an iis:// URI, or a glob — all equivalent
  pools:
    - iis://apppool/CheckoutAppPool
    - OrderWorkerPool
  sites:
    - iis://site/Default Web Site
  watch_all: false                # off: IIS recycles idle pools every 20 min
  interval: 30s
```

Tracked paths: `iis://apppool/<Pool>` and `iis://site/<Site>`. The document
captures state, identity, process model, rapid-fail protection, recycling and
bindings. Tracked: `Started → Stopped`, identity switches, a changed
`idleTimeout`. Actor attribution prefers a recently started management process
(`appcmd.exe`, `InetMgr.exe`, `powershell.exe`).

### Windows registry & services

```yaml
windows:
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE
      - HKLM\SYSTEM\CurrentControlSet\Services
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  services:
    enabled: true
    source: auto                  # auto | eventlog (System 7036) | poll (SCM diff)
    poll_interval: 5s
  msi:
    enabled: true                 # MsiInstaller 1033/1034 installs & removals
  security_audit:
    enabled: true                 # Security 4657/4663 → attribute a change to an account
```

Registry changes are reported on `/registry/HKLM/...` paths with the value-level
before/after; service changes on `/service/<name>` with start type and state.

### Read-only PostgreSQL & SQL Server tables

Answers *"who changed the setting in `settings_db`?"* with a row-level diff
instead of a ticket trail. Every statement this collector issues is a `SELECT`.

```yaml
database:
  enabled: true
  interval: 60s
  connections:
    - name: settings
      engine: postgres            # postgres | sqlserver
      dsn: "postgres://statetrack_ro:CHANGEME@db.internal:5432/settings_db?sslmode=verify-full"
      database: settings_db
      tables:
        - public.app_settings
        - public.feature_flags
      watch_schema: true          # ALTER TABLE, grants, column changes
      watch_server_params: true   # ALTER SYSTEM / sp_configure
      row_limit: 500

    - name: billing
      engine: sqlserver
      dsn: "sqlserver://statetrack_ro:CHANGEME@sql.internal:1433?database=billing&encrypt=true"
      tables: [dbo.tariffs]
      interval: 120s
```

A least-privilege account is enough:

```sql
-- PostgreSQL
CREATE ROLE statetrack_ro LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE settings_db TO statetrack_ro;
GRANT SELECT ON public.app_settings, public.feature_flags TO statetrack_ro;

-- SQL Server
CREATE LOGIN statetrack_ro WITH PASSWORD = '...';
GRANT CONNECT SQL TO statetrack_ro;
GRANT VIEW DEFINITION TO statetrack_ro;         -- schema snapshot
GRANT SELECT ON dbo.app_settings TO statetrack_ro;
```

Prefer the environment over a literal DSN on disk, since a DSN is a credential:

```bash
STATETRACK_DATABASE_DSN='postgres://statetrack_ro:...@db:5432/settings_db'
STATETRACK_DATABASE_ENGINE=postgres
STATETRACK_DATABASE_NAME=settings_db
STATETRACK_DATABASE_TABLES=public.app_settings,public.feature_flags
```

Tracked paths: `db://<engine>/<db>/tables/<schema>.<table>`,
`…/schema`, `…/server_params`. Rows are ordered by primary key (or every column)
so an unchanged table produces a byte-identical document. Secret-named columns
(`password`, `secret`, `api_key`, `token`, `dsn`, `connection_string`) render as
`[REDACTED:sha256:…]`. Actor attribution comes from `pg_stat_activity` /
`sys.dm_exec_sessions`: user, client tool, client IP.

### Kubernetes object watcher

```yaml
kubernetes:
  enabled: true                   # cluster watcher only, not per-node
  cluster: prod-k8s-01
  namespaces: [default, production, payments]
  resync_interval: 10m
```

In-cluster credentials come from the mounted service account, so no endpoint,
token or kubeconfig belongs in the file.

### Adding a watched target from the console

You do not need to edit YAML on each host. **Servers → Watched Targets → +
Add Watched Target** stores a `host_policy_rules` row — host-scoped or *All
Hosts* — audits the creation (`rule.watch_created`) and pushes it to agents on
the next heartbeat. Collectors re-read the rule set every poll, so a new pool or
table starts reporting within one interval, with no restart.

The same card lists every active custom target with its level, host scope and
target kind, and can remove one (`rule.watch_deleted`, also audited).

See [§5.4 of the deployment guide](docs/agent-deployment-guide.md#54-adding-a-watched-target-in-the-console)
for the builder's fields and the document lifecycle.

---

## 4. Integrations

Every connection is configured in **Integrations** in the console, tested from
the UI, and stored server-side. Provisioned assets live in
[`integrations/`](integrations/) and are downloadable from the hub.

### Grafana — annotations on your existing dashboards

```bash
# Push: register a service-account token (Administration → Service accounts,
# role Editor, scope annotations) on the Observability tab.
# Pull: import the bundled dashboard
integrations/grafana/statetrack-overview-dashboard.json
```

Levels at or below `min_impact_level` become **point** annotations tagged
`statetrack`, `host:<name>`, `level:L1|L2`, `category:<cat>`, with a clickable
*Inspect Diff & Actor ↗* deep link. Two annotation layers (L1 red, L2 amber),
both scoped to the hero panel.

Pull endpoints for a datasource: `GET /api/v1/grafana/annotations` and
`GET /api/v1/grafana/events`. Guide:
[`integrations/grafana/README.md`](integrations/grafana/README.md).

**Local demo:** `docker compose --profile monitoring up -d` starts Grafana
(`:3000`, admin/admin) with the Prometheus and Postgres datasources provisioned;
`make grafana-seed` imports the dashboard and pushes annotations.

### Prometheus — `/metrics` on the main listener

```yaml
scrape_configs:
  - job_name: statetrack
    static_configs:
      - targets: ["statetrack.internal:8080"]
    metrics_path: /metrics
```

Alert rules ship in
[`integrations/prometheus/prometheus_alerts.yml`](integrations/prometheus/prometheus_alerts.yml):
critical mutation, change storm, agent offline, fleet drift, ingest-latency SLI.
Labels are closed enumerations or bounded fleet dimensions — no label carries a
per-event value, so a hostile environment cannot mint one series per event.

### Checkmk — `--mode local` and `--mode nagios`

```bash
# Local check (agent-based): drop the plugin into the site's local checks
cp integrations/checkmk/check_statetrack.py \
   /omd/sites/<site>/local/lib/python3/cmk/base/plugins/agent_based/

# Active/Nagios check (MRPE, Icinga2, standalone)
python3 integrations/checkmk/check_statetrack.py --mode nagios \
  --url http://statetrack.internal:8080 --host prod-web-01 --window 15m \
  --token st_live_...
```

Local mode emits CRIT/WARN/OK with five perfdata metrics; Nagios mode uses
standard exit codes, so it drops into any poller. Requires a `read:summary` API
key. Guide: [`integrations/checkmk/README.md`](integrations/checkmk/README.md).

**Local Checkmk site:** `docker compose --profile monitoring up -d checkmk` then
`.\scripts\dev.ps1 checkmk` provisions four demo hosts; open
<http://localhost:5000/cmk/> (`cmkadmin` / `statetrack`).

### Zabbix 7.0

```bash
# Data collection → Templates → Import
integrations/zabbix/zabbix_template_statetrack.yaml
```

One HTTP-agent master item per host plus ten zero-I/O dependent items and three
triggers. Guide: [`integrations/zabbix/README.md`](integrations/zabbix/README.md).

### Slack, Microsoft Teams, PagerDuty, SIEM

Configure each channel on the **ChatOps** tab with independent L1 / change-storm
triggers and a delivery log:

| Provider | Wire format | Notes |
| --- | --- | --- |
| Slack | Block Kit | Webhook URL + display channel; one-click *Inspect Diff*. |
| Microsoft Teams | MessageCard | Incoming webhook or Power Automate Workflows URL. |
| PagerDuty | Events API v2 | Routing key; deduplicated per change so a retry cannot re-page. |
| Generic SIEM | JSON | Signed `X-StateTrack-Signature: sha256=<hmac>` for log shippers and SOAR. |

### ServiceNow & Jira — change-ticket correlation

The compliance half of the product: *was this change authorised?* Tickets are
mirrored into `change_tickets` (sync job, inbound webhook, CSV or by hand) and
correlated as a pure function over local state, so it works air-gapped and is
exhaustively testable. Matching is scoped by hosts / environments / paths and
bounded by a window — an approved 30-minute maintenance window is not a
permanent licence to edit production.

Every L1 production change therefore carries a verdict: `CHG-1042 · Approved` or
`Unapproved Change`.

### MCP server — Claude Desktop, Cursor, Windsurf

Two transports, one implementation:

```bash
# stdio adapter (no database credentials in the client config)
statetrack-mcp
```

```json
{
  "mcpServers": {
    "statetrack": {
      "command": "/usr/local/bin/statetrack-mcp",
      "env": {
        "STATETRACK_URL": "http://localhost:8080",
        "STATETRACK_API_KEY": "st_live_..."
      }
    }
  }
}
```

…or the hosted HTTP transport at `POST /api/v1/mcp` with a bearer key. Requires
the `read:mcp` scope. Tools: `statetrack_list_changes`, `statetrack_get_diff`,
`statetrack_get_host_summary`, `statetrack_analyze_and_rollback`,
`statetrack_export_postmortem`. See [§11](#11-model-context-protocol-mcp-server).

---

## 5. Architecture & runtime components

| Binary | Purpose |
| --- | --- |
| `statetrack-agent` | Per-host collector. Static, no inbound ports, linux/amd64, linux/arm64, windows/amd64. |
| `statetrack-server` | Central control plane: gRPC ingest, REST/WS API, integrations, metrics, AI gateway, MCP, embedded console. |
| `statetrack-mcp` | stdio MCP adapter for desktop clients; forwards JSON-RPC to a server. |
| `statetrack-seed` | Idempotent demo seeder (a realistic outage + drift timeline for today). |

### Repository layout

| Path | Purpose |
| --- | --- |
| `agent/` | Host agent: config, baseline, collectors (Linux/Windows/Kubernetes), classifier, shadow cache, debouncer, spool, discovery, transport. |
| `server/` | Backend: gRPC, storage, integrations, ITSM, AI gateway, MCP, metrics, security, REST/WS API. |
| `server/migrations/` | Ordered SQL migrations, embedded in the binary and applied on boot. |
| `server/internal/webui/` | `//go:embed` of the React console — the reason the server is one artifact. |
| `pkg/` | Shared libraries: `pb` (protobuf), `redact` (secret scrubber), `diff` (Myers + zstd). |
| `proto/` | Canonical gRPC contract (`statetrack/v1/change_event.proto`). |
| `web/` | React 19 + TypeScript + Vite console (Tailwind 4, React Query, virtualized timeline, Monaco diff). |
| `integrations/` | Grafana dashboard, Prometheus rules, Checkmk plugin, Zabbix template, each with a README. |
| `deploy/` | `install.sh`/`install.ps1`, `linux/` systemd unit + annotated `agent.yaml.example`, `windows/` example, `docker-compose.quickstart.yml`, `k8s/`, `prometheus/`, `grafana/`, `checkmk/`, `seaweedfs/`. |
| `docs/` | `agent-deployment-guide.md` (per-OS install, every parameter, operations), `enterprise-catalog.md`. |
| `scripts/` | `dev.ps1` (Windows workflow), `release.sh` (release archives), `e2e_smoke.*`, `provision_checkmk.ps1`. |
| `Makefile` | Linux/macOS/CI equivalent of `dev.ps1`. |

The Go workspace (`go.work`) composes three modules — `pkg`, `agent`, `server` —
all on Go 1.26.

### What the agent guarantees

| Property | Target | Why it matters |
| --- | --- | --- |
| Memory (RSS) | **< 25 MB** | `debug.SetMemoryLimit(25 MiB)` at startup; a package burst cannot push a production host into swap. |
| CPU | **< 1%** average | Day-0 walk is paced; steady state is inotify/ReadDirectoryChangesW callbacks, not polling. |
| Disk | **≤ 200 MB** | The offline spool is bounded and evicts oldest-first. |
| Inbound ports | **none** | The agent dials out; it is unreachable from the network. |
| Outbound | **1 × TCP 50051** | Plus DNS, and 443 if the server sits behind a TLS terminator. |

---

## 6. Impact levels & anti-flood defenses

| Level | Name | Behavior |
| --- | --- | --- |
| **0** | Hard blacklist | Dropped at the collector. `/proc`, `/sys`, `/tmp`, `/var/log`, `*.log`, `*.swp`, DB data dirs, `C:\Windows\Temp`. |
| **1** | Critical | Always on, **full scrubbed diff**. `/etc`, `authorized_keys`, `/etc/passwd`, `web.config`, IIS config, service & registry-critical changes, agent self-tamper. Pushed to Grafana instantly. |
| **2** | Grouped | Package/CM runs (`apt`, `dpkg`, `yum`, `dnf`, `msiexec`, `ansible`) collapsed into **one parent event** with `child_count` and an aggregate summary. Only config files get text diffs. |
| **3** | Drift | Non-critical assets: **hash & size only, no diff** (saves ~90% storage). |
| **4** | Forensic | `execve`, sockets, env shifts. **Off by default**; enabled remotely for up to 15 minutes. |

**Anti-flood.** Files > 1 MB or binary (null byte in the first 512 bytes) emit
`BINARY_MODIFIED` with hashes only. Any directory/PID exceeding 50 events in 10 s
trips a token-bucket breaker that pauses diffing for 30 s and emits one
`CHANGE_STORM_THROTTLED` summary; the first event after the storm carries a
single cumulative diff against the pre-storm shadow.

**Sliding-window debouncing.** Mutations whose process ancestry shares the same
outermost tool process join one transaction. It stays open while events keep
arriving within a **3-second sliding inactivity window** (capped at 15 minutes),
then emits one Level 2 parent. Children are released immediately, already linked
to the parent ID, so memory stays bounded regardless of run length.

**Attribution.** Writes are mapped back to the human behind `sudo` using Linux
Audit Netlink/eBPF when available, then fanotify, then a rate-limited `/proc`
scan with `loginuid` inheritance. In an unprivileged container a sub-millisecond
command whose session has already exited may be reported as *"unattributed"* —
it is reported, never guessed.

---

## 7. Secret scrubber

Before a diff leaves the host, every line is scrubbed for credential patterns:
`password|passwd|secret|api_key|token|private_key` assignments, AWS access keys,
`scheme://user:pass@host` URLs, `Authorization: Bearer`, PEM private-key blocks
and high-entropy tokens. Each secret becomes a deterministic salted stub:

```
password = "hunter2"        →  password = "[REDACTED:sha256:1a2b3c4d]"
AWS_SECRET_ACCESS_KEY=…     →  AWS_SECRET_ACCESS_KEY=[REDACTED:sha256:2c9d8e01]
```

The stub is `HMAC-SHA256(secret, per-host-salt)` truncated to 8 hex chars, so the
same secret always maps to the same stub: a reviewer can see **that** a
credential changed — and that it was reused across hosts — without ever seeing
it. Line structure, keys, quotes and line endings are preserved so the diff stays
readable.

Redaction happens **before** hashing, caching, spooling and transmission, so a
secret cannot leak through the spool file, a packet capture or the database. The
`[REDACTED:sha256:…]` shape is a contract every consumer relies on: the AI
gateway, the MCP renderers and the post-mortem generator detect it and declare
that they reasoned over scrubbed content.

---

## 8. Auto-discovery & the enterprise catalog

The agent embeds a **versioned Enterprise Application Knowledge Base** — a YAML
manifest compiled into the binary, so discovery works identically in a connected
datacenter and an air-gapped estate. **No part of discovery makes a network
call.**

- Manifest: [`agent/internal/discovery/catalog.yaml`](agent/internal/discovery/catalog.yaml)
- Engine: [`catalog.go`](agent/internal/discovery/catalog.go), [`probes.go`](agent/internal/discovery/probes.go)
- Reference: [`docs/enterprise-catalog.md`](docs/enterprise-catalog.md)

Discovery runs at startup and every six hours. Probes are strictly read-only and
best-effort — a missing file is *"not found"*, never a scan failure, and every
probe is panic-recovered. Coverage: nginx, Apache, Caddy, HAProxy, PostgreSQL,
MySQL, Redis, RabbitMQ, Kafka, OpenSSH, sudoers, systemd and sysctl (Linux); IIS,
SQL Server, MSMQ, services, scheduled tasks and hosts (Windows); Docker
engine/compose; and Kubernetes ConfigMaps, Secrets, Deployments, StatefulSets and
Ingresses.

Each probe emits a `DiscoveredWorkload` with a `SuggestedLevel`, a
`SuggestedDiff` and a reason — an IIS site on :443 is *Level 1 Critical ("Active
HTTPS site on port 443")*, a staging vhost is *Level 3 Drift*. The server upserts
these into `host_recommendations`; the console shows *"💡 Discovered 3
unconfigured production workloads on prod-web-01"* with a review drawer. Accepting
materialises a `host_policy_rules` row pushed to the agent on its next ingestion
response, where it outranks the built-in heuristics. Every accept/dismiss is
audited.

---

## 9. The web console

React 19 + TypeScript SPA, Google Cloud Console aesthetic (light-mode first,
`#f8fafc` background, white cards, Google blue/red/purple/amber/green semantics),
decomposed into small components with a zero-white-screen guarantee (null-checked
arrays, error boundaries, optional chaining). It is embedded in the server
binary, so there is no second container, no nginx and no CORS to configure.

| Route | Page |
| --- | --- |
| `/` · `/dashboard` | **Dashboard** — fleet pulse, KPI cards, changes-over-time and distribution charts, latest changes, pending recommendations. |
| `/timeline` | **Timeline** — virtualized change feed with window controls, level/category/actor filters, expandable Level 2 parent cards (`📦 N related changes`). |
| `/servers` | **Servers** — fleet inventory, per-host health, discovered workloads, and the **Watched Targets** card (`+ Add Watched Target`). |
| `/drift` | **Drift Matrix** — pairwise comparison of config files, registry keys and packages across hosts. |
| `/integrations` | **Integrations hub** — every external connection. |
| `/reports` | **Reports** — summary, drift, compliance, security and actor reports with exports. |
| `/settings` | **Settings** — general/system info, security & SSO, agent enrollment, audit log. |
| `/events/:id` | Timeline plus the **Inspector drawer** on that event. Grafana deep links use `/?event=:id`. |

### Inspector drawer

Five tabs on any change:

1. **Diff** — side-by-side or inline, syntax-highlighted, with the
   `[REDACTED:sha256:…]` stubs rendered as chips.
2. **Context** — actor, tool, PID, parent process chain, source IP, host.
3. **Compliance** — the covering change ticket and its verdict.
4. **Analyze** — blast radius, rollback command and verification command (AI or
   offline heuristics; see §10).
5. **Post-mortem** — a Markdown incident bundle, copyable or downloadable.

### Empty states are honest

A fresh install shows `0 / 0 agents online` and an onboarding card, never sample
hosts. There is **no fallback demo fleet** in the UI: a `[]` from the API renders
zeroed KPIs and the "No servers enrolled yet — copy the Linux or Windows install
command under Settings → Agents" prompt. Seeded rows only appear in a build with
`VITE_STATETRACK_SAMPLE_DATA=1`, which only the demo tooling sets.

---

## 10. AI provider gateway

The analyzer answers three questions about a change: **how bad is it**, **what
breaks if it is wrong**, and **what is the exact command to undo it**. It runs on
**✦ Analyze & Rollback** in the Inspector, behind the MCP
`statetrack_analyze_and_rollback` tool, and inside the post-mortem bundle.

| Provider | Default endpoint | Default model | Credential |
| --- | --- | --- | --- |
| **Offline heuristics** (`deterministic`) | — | — | none |
| **Ollama** (`ollama`) | `http://localhost:11434/v1` | `llama3.1` | optional |
| **Azure OpenAI** | your resource endpoint | your deployment | `api-key` + `api_version` |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o-mini` | bearer |
| **Anthropic** | `https://api.anthropic.com` | `claude-3-5-sonnet-latest` | `x-api-key` |

Two non-negotiable properties:

- **It always answers.** A model that is down, mis-authenticated or slow degrades
  to the deterministic engine, which derives the same three answers from the event
  itself with no network. The response states which engine answered (`provider`,
  `provider_label`, `model`) and flags `fallback` + `fallback_reason`, so a reader
  can always tell a model's judgement from a rule-based one.
- **Zero-secret guarantee.** The gateway receives the *already-scrubbed* diff.
  There is no field for a raw credential and no code path that could fetch one.

| Method | Endpoint |
| --- | --- |
| `POST` | `/api/v1/events/{id}/analyze` |
| `GET`/`PUT` | `/api/v1/integrations/ai` |
| `POST` | `/api/v1/integrations/ai/test` |

---

## 11. Model Context Protocol (MCP) server

Native MCP over **JSON-RPC 2.0**, so Cursor, Claude Desktop, Windsurf and Copilot
can investigate outages against exactly the data the console shows.

- **HTTP** — `POST /api/v1/mcp`, same identity middleware as the rest of the API,
  requires the `read:mcp` scope, never anonymous.
- **stdio** — the `statetrack-mcp` binary desktop clients launch. It is a
  *transport adapter*, not a second implementation: every request is forwarded
  verbatim to a server, so authorization, org scoping and the data path are the
  same. A client config never holds a database DSN.

Protocol revision `2024-11-05`; implements `initialize`, `ping`, `tools/list`,
`tools/call` and `notifications/*`.

| Tool | Purpose |
| --- | --- |
| `statetrack_list_changes` | Recent changes (host, level, category, search, actor, window, `root_only`). Returns event ids. |
| `statetrack_get_diff` | The scrubbed unified diff plus actor lineage for one event. |
| `statetrack_get_host_summary` | Host/cluster rollup: online, tracked targets, per-level counts, latest critical change. |
| `statetrack_analyze_and_rollback` | Blast radius, rollback command, verification command. |
| `statetrack_export_postmortem` | The Markdown (or structured) incident bundle. |

Every tool result includes a deterministic text block (compact table + summary)
so a model can answer without another round trip.

```json
{
  "mcpServers": {
    "statetrack": {
      "command": "statetrack-mcp",
      "env": { "STATETRACK_URL": "http://localhost:8080", "STATETRACK_API_KEY": "st_live_..." }
    }
  }
}
```

`statetrack-mcp` reads `STATETRACK_URL` (default `http://localhost:8080`) and
`STATETRACK_API_KEY`, fails loudly at startup if the key is missing, writes
diagnostics to stderr only (stdout is the protocol channel), and reports a
forward failure as a JSON-RPC error rather than exiting. `--version` and
`--help` work with no configuration.

---

## 12. Enterprise security

The security surface answers *who can change what, and who changed it?* from the
database alone. Everything is in **Settings**.

**Identity.** Four roles — `admin`, `operator`, `policy_admin`, and `auditor`
(strictly read-only, enforced by middleware rather than hidden in the UI). TOTP
two-factor with setup/verify endpoints. OIDC SSO including a switch-role flow,
with `auth_provider` recorded per user. Login, logout and role changes are all
audited.

**Credentials.** Scoped API keys (`st_live_…`): the secret is shown once, only a
SHA-256 hash is stored, so a database dump yields no working credential. The
closed scope vocabulary is `read:summary`, `read:annotations`, `read:mcp`,
`admin:write`, and a read-only key can never become a write path regardless of
its role. Enrollment tokens (`st_enroll_…`) are time-boxed and capped by
`max_uses` — a token is a fleet-takeover primitive. Passwords are
PBKDF2-HMAC-SHA256.

**Bootstrap.** On a fresh install the first administrator is created with a
generated 144-bit password logged exactly once, or with the credentials you
supply via `STATETRACK_ADMIN_EMAIL` / `STATETRACK_ADMIN_PASSWORD` (which are never
printed). The function only acts while the account still carries the migration
marker, so a restart never resets a working password.

**Control-plane audit.** `control_plane_audit_logs` is append-only: `rule.applied`,
`rule.watch_created`, `integration.updated`, `apikey.created`, `token.created`,
`agent.revoked`, `sso.updated`, `settings.updated`, `host.forensic_enabled`,
`ai.settings_updated`, `itsm.*`, `auth.login`, `auth.2fa_enabled` and more — each
with actor, role, dotted verb, target, source IP and a JSONB `details` blob. The
application can only insert, so a compromised console session cannot rewrite the
record of what it did.

---

## 13. REST, WebSocket & gRPC API

The HTTP tree is wrapped in an identity middleware; authorization is per-route
(`s.readOnly`, `s.apiRead(scope, …)`, `s.mutation(action, …)`, `s.datasource`).
Mutations enforce RBAC **and** write the audit row on success.

### gRPC ingestion

`IngestionService.IngestBatch` over mTLS. The server computes
`clock_offset_ms = server_time_ms - agent_sent_ms` and normalises `occurred_at`,
upserts dictionary rows (`targets`, `actors`, `processes`) via
`ON CONFLICT DO UPDATE`, routes diffs > 2 KB to S3 (deduplicated by content
hash, inline in Postgres when no blob store is configured), updates
`host_current_state` for instant drift, and returns the desired config hash, the
forensic TTL and any policy rules to apply.

### REST

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `/healthz` · `/metrics` · `/api/v1/system` | Liveness, Prometheus exposition, build/runtime info. |
| `GET`/`POST` | `/api/v1/auth/me` · `/login` · `/logout` · `/switch-role` | Session lifecycle. |
| `POST` | `/api/v1/auth/totp/setup` · `/totp/verify` | TOTP enrolment. |
| `GET` | `/api/v1/auth/users` | Console members. |
| `GET`/`PUT` | `/api/v1/security/sso` | SSO configuration. |
| `GET`/`POST`/`DELETE` | `/api/v1/security/api-keys[/{id}]` | Scoped keys. |
| `GET`/`POST`/`DELETE` | `/api/v1/security/enrollment-tokens[/{id}]` | Agent bootstrap. |
| `GET` | `/api/v1/security/audit-logs` | Control-plane trail. |
| `GET` | `/api/v1/hosts` · `/api/v1/hosts/{hostname}/summary` | Fleet inventory; unified poller rollup (`read:summary`). |
| `POST` | `/api/v1/hosts/{id}/forensic` | Enable Level 4 for 15 minutes. |
| `GET` | `/api/v1/events` · `/api/v1/events/{id}` | Change feed; detail with children and transparent diff. |
| `GET` | `/api/v1/events/compliance` · `/api/v1/events/{id}/compliance` | Compliance verdicts. |
| `GET` | `/api/v1/events/{id}/post-mortem` | Markdown incident bundle. |
| `GET` | `/api/v1/drift` | Cross-host drift. |
| `GET`/`POST`/`DELETE` | `/api/v1/rules[/{id}]` | Custom watched targets (console rule builder) + the target catalog. |
| `GET` | `/api/v1/recommendations` · `POST …/{id}/apply` · `/dismiss` · `/apply-all` | Discovery decisions. |
| `GET`/`PUT` | `/api/v1/integrations/grafana` · `/webhooks` · `/ai` · `/itsm` | Integration settings. |
| `POST` | `/api/v1/integrations/*/test` | Connectivity tests. |
| `GET` | `/api/v1/integrations/webhooks/deliveries` | Delivery log. |
| `POST` | `/api/v1/events/{id}/analyze` | AI analysis. |
| `POST` | `/api/v1/mcp` | MCP JSON-RPC 2.0 (`read:mcp`). |
| `GET`/`POST`/`DELETE` | `/api/v1/change-tickets[/{ref}]` · `POST /api/v1/integrations/itsm/sync` | Ticket mirroring. |
| `GET` | `/api/v1/grafana/annotations` · `/api/v1/grafana/events` | Datasource-shaped output. |
| `GET` | `/api/v1/stream` | WebSocket change stream. |

### Host summary example

```bash
curl -s -H "Authorization: Bearer $STATETRACK_TOKEN" \
  "http://localhost:8080/api/v1/hosts/prod-web-01/summary?window=15m" | jq
```

```json
{
  "host": "prod-web-01",
  "os": "linux",
  "online": true,
  "last_seen_seconds": 4,
  "window": "15m",
  "counts": { "total": 9, "l1_critical": 2, "l2_grouped": 1, "l3_drift": 3, "l4_forensic": 0 },
  "drift_targets_count": 14,
  "latest_critical": {
    "id": "00002798-…",
    "occurred_at": "2026-10-17T00:41:12Z",
    "target": "/etc/nginx/nginx.conf",
    "actor": "alice",
    "tool": "vim",
    "summary": "Configuration modified",
    "deep_link": "http://localhost:8080/?event=00002798-…"
  }
}
```

---

## 14. Metrics & alerting

`GET /metrics` is a Prometheus exposition on the main HTTP listener — no second
port to firewall.

| Metric | Type | Labels |
| --- | --- | --- |
| `statetrack_mutations_total` | counter | `host`, `level`, `category`, `action` |
| `statetrack_drift_targets` | gauge | `host` |
| `statetrack_active_agents` | gauge | `host`, `os`, `status` |
| `statetrack_storm_throttles_total` | counter | `host` |
| `statetrack_ingest_batch_duration_seconds` | histogram | — |
| `statetrack_ingest_events_received_total` | counter | — |
| `statetrack_webhook_deliveries_total` | counter | `provider`, `status` |

Every label is a closed enumeration or a bounded fleet dimension — **no label
carries a per-event value** (no path, actor, PID, command line, rule name, event
id or remote IP), so a busy environment cannot mint one time series per event.
Unrecognised values fold into a single `unknown` bucket. The exporter is seeded
from Postgres at startup, so a cold scrape reports real gauges rather than zeros.

---

## 15. Development, build & verification

Prerequisites: Go 1.26+, Node 20+, Docker (for the dependency stack and the
container build).

```bash
# Full local stack (Postgres 17, SeaweedFS, Grafana, Prometheus, Checkmk)
docker compose up -d --wait

# Backend on :8080/:50051 (migrations are applied automatically)
go run ./server/cmd/statetrack-server

# Console dev server on :5173 with /api proxied to :8080
npm run dev --prefix web

# Optional: demo timeline for today, then Grafana import + annotations
make seed
make grafana-seed
```

`make seed` / `.\scripts\dev.ps1 seed` is the **only** path that writes demo
data. It is idempotent, anchored relative to the run, and pairs hosts with live
annotation flags so the dashboard's `now-1h` window is always full.

### Make targets

| Target | Description |
| --- | --- |
| `make build` | Cross-compile the agent (linux amd64/arm64, windows amd64) plus server, `statetrack-mcp`, and the demo tools. |
| `make test` · `make vet` · `make tidy` | Unit tests, vet, module hygiene. |
| `make test-integration` | Tests that need the compose stack. |
| `make test-race` | `go test -race` in a Linux `golang:1.26` container (cgo lives only there). |
| `make test-e2e` | Linux collector end-to-end tests, unprivileged and privileged. |
| `make up` · `down` · `logs` · `psql` | The local dependency stack. |
| `make migrate` | Apply pending SQL migrations, one transaction each. |
| `make seed` · `grafana-seed` · `demo-traffic` | Demo data, dashboard import, live ingest traffic. |
| `make checkmk` | Start and provision the Checkmk Raw demo (`:5000/cmk`). |
| `make check` | gofmt + vet + tests + cross-build + asset-drift check. |

`scripts/dev.ps1` mirrors every target on Windows (`dev.ps1 check` is the one to
run before pushing).

### Building a release locally

```bash
./scripts/release.sh v0.1.0
```

That builds the console, stages it into the server embed, cross-compiles every
binary, and writes `dist/v0.1.0/` with:

```
statetrack-agent-linux-amd64.tar.gz     agent + install.sh + systemd unit + agent.yaml.example
statetrack-agent-linux-arm64.tar.gz
statetrack-agent-windows-amd64.zip      agent.exe + install.ps1 + agent.yaml.example
statetrack-server-linux-amd64.tar.gz    server with console + migrations embedded
statetrack-server-windows-amd64.zip
statetrack-mcp-linux-amd64.tar.gz       stdio MCP adapter + client setup
statetrack-mcp-windows-amd64.zip
statetrack-integrations-bundle.zip      Grafana, Prometheus, Checkmk, Zabbix, K8s, quickstart
SHA256SUMS.txt
```

Tagging pushes both the archives (GitHub Release) and the multi-arch image
(`ghcr.io/premtonx/statetrack:<tag>` + `:latest`, amd64 and arm64):

```bash
git tag -a v0.1.0 -m "StateTrack v0.1.0" && git push origin v0.1.0
```

### Verification

```bash
# Everything a PR must pass
make check                     # gofmt, vet, tests, cross-build, asset drift

# Full-stack smoke test (compose stack → server → Postgres/S3/Grafana → REST)
scripts/e2e_smoke.sh           # Windows: .\scripts\e2e_smoke.ps1

# Component suites
python3 -m unittest discover -s integrations/checkmk -t integrations/checkmk -v
go test ./server/internal/mcp/...
go test ./server/internal/ai/...

# Container build
docker build -t statetrack:v0.1.0 .
```

The smoke test asserts, end to end, that a real agent scrubs
`db_password = "supersecret123"` to `[REDACTED:sha256:...]` in the database, that
a five-file package burst collapses to **one parent event with
`child_count = 5`**, that Grafana receives the annotation POST with the right
tags and deep link, and that the REST API returns the processed events.

---

## License & project

Released under the [Apache License 2.0](LICENSE).

- **Contributing** — [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Security policy** — [`SECURITY.md`](SECURITY.md) (please do not open a public issue for a vulnerability)
- **Code of conduct** — [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- **Architecture spec** — [`spec.md`](spec.md)
- **Agent operator guide** — [`docs/agent-deployment-guide.md`](docs/agent-deployment-guide.md)

StateTrack is under active development. `v0.1.0` is the first public release: the
agent is the stable core (Linux and Windows collectors, classification, edge
scrubbing, spooling), and the server and console carry the enterprise surface
documented above.

---

## Author / Maintainer

StateTrack is designed and maintained by **Premton X.**

| | |
| :--- | :--- |
| **Author** | Premton X. |
| **Website** | [premtonx.cloud](https://premtonx.cloud) |
| **LinkedIn** | [linkedin.com/in/premtonx](https://www.linkedin.com/in/premtonx) |
| **Contact** | [premtonx@gmail.com](mailto:premtonx@gmail.com) |

For **security vulnerabilities and private inquiries**, email
[premtonx@gmail.com](mailto:premtonx@gmail.com) directly rather than opening a
public issue — see the [security policy](SECURITY.md) for what to include and
what to expect.
