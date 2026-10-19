# StateTrack v0.1.0 — Infrastructure Change Intelligence

**Git history for live servers.** StateTrack records every meaningful change to
your Linux and Windows hosts — who changed what, from where, with which tool, and
what the file looked like before — and puts those changes on the same timeline as
your metrics.

This is the first public release. It is a complete, self-hosted
change-intelligence platform: a static agent, a single-binary server with the
React console and the SQL migrations embedded, and turnkey Docker packaging.

---

## Run it in 10 seconds

```bash
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/docker-compose.quickstart.yml \
  -o docker-compose.yml
docker compose up -d
```

Open <http://localhost:8080>. Postgres 17, migrations and the console are all
handled; nothing is compiled.

The first administrator is created on first boot and its password is printed
exactly once:

```bash
docker compose logs statetrack | grep administrator
```

Prefer to choose it yourself:

```bash
STATETRACK_ADMIN_EMAIL=you@example.com \
STATETRACK_ADMIN_PASSWORD='a-long-random-password' \
docker compose up -d
```

**A fresh install is empty by design — 0 hosts, 0 events, no demo data.** The
console shows `0 / 0 agents online` and an enrolment card until you connect a
host. Demo data is opt-in with `make seed`.

### Other ways to run the server

```bash
# Single container against your own Postgres
docker run -d --name statetrack -p 8080:8080 -p 50051:50051 \
  -e DATABASE_URL='postgres://user:pass@db.internal:5432/statetrack?sslmode=disable' \
  -e STATETRACK_SESSION_SECRET='change-me' \
  ghcr.io/premtonx/statetrack:v0.1.0

# From a checkout, building the image locally
git clone https://github.com/premtonx/statetrack.git
cd statetrack && docker compose up -d --build

# ...plus the monitoring stack: Grafana :3000, Prometheus :9090, Checkmk :5000/cmk
docker compose --profile monitoring up -d
```

---

## Install an agent

### Linux (systemd)

```bash
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
  | sudo bash -s -- \
      --server statetrack.internal.example.com:50051 \
      --token  st_enroll_xxxxxxxxxxxxxxxx \
      --org    production
```

The installer resolves `x86_64`/`aarch64`, downloads
`statetrack-agent-linux-<arch>.tar.gz` from this release, **verifies it against
`SHA256SUMS.txt`** and refuses to install on a mismatch, writes
`/etc/statetrack/agent.yaml` (mode `0600`), and installs and starts the hardened
systemd unit.

Manual equivalent:

```bash
curl -fsSLO https://github.com/premtonx/statetrack/releases/latest/download/statetrack-agent-linux-amd64.tar.gz
curl -fsSLO https://github.com/premtonx/statetrack/releases/latest/download/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
tar -xzf statetrack-agent-linux-amd64.tar.gz

sudo install -m 0755 statetrack-agent /usr/local/bin/statetrack-agent
sudo mkdir -p /etc/statetrack
sudo install -m 0600 agent.yaml.example /etc/statetrack/agent.yaml   # then edit it
sudo install -m 0644 statetrack-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now statetrack-agent
systemctl status statetrack-agent
```

### Windows Server (native service)

Elevated PowerShell:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.ps1))) `
    -Server statetrack.internal.example.com:50051 `
    -Token  st_enroll_xxxxxxxxxxxxxxxx `
    -Org    production
```

Manual equivalent — download and extract `statetrack-agent-windows-amd64.zip` to
`C:\ProgramData\StateTrack`, copy `agent.yaml.example` to `agent.yaml` and edit
it, then:

```powershell
& C:\ProgramData\StateTrack\statetrack-agent.exe service install
& C:\ProgramData\StateTrack\statetrack-agent.exe service start
Get-Service StateTrackAgent
```

### Kubernetes

```bash
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset.yaml    # per-node OS-level timeline
kubectl apply -f deploy/k8s/deployment.yaml   # cluster object watcher
```

---

## What's in the box

### Agent

- One static binary, **no inbound ports**, one outbound gRPC stream to `:50051`.
  `< 25 MB` RSS (enforced with `debug.SetMemoryLimit`), `< 1%` CPU, `≤ 200 MB`
  bounded spool.
- **Day-0 baseline** fingerprinting, so only real diffs are reported.
- **Impact classification** L0–L4: blacklist, critical-with-diff, grouped
  transactions, hash-only drift, and a 15-minute forensic window.
- **Edge secret scrubbing** — credentials become `[REDACTED:sha256:…]` *on the
  host*, before hashing, spooling or transmission. The same secret always yields
  the same stub, so reuse is visible and leak is impossible.
- **Sliding-window transaction grouping** collapses a package install or Ansible
  run into one parent event with `child_count`.
- **Collectors** — Linux: filesystem (fanotify/inotify), systemd, packages,
  audit attribution, discovery. Windows: registry, SCM services, MSI, scheduled
  tasks, audit attribution. Plus Docker and Kubernetes.
- **Targeted watchers** — named IIS application pools and sites, read-only
  PostgreSQL/SQL Server tables + schema + server parameters, and pinpointed
  files/directories, each rendered as a canonical document so a *state* change is
  diffable even when no file changed.
- **Enterprise catalog discovery** — a versioned YAML knowledge base compiled
  into the binary, so workload discovery works fully air-gapped and emits
  actionable "add this rule" recommendations.

### Server

- gRPC ingestion, REST + WebSocket API, and the **React console served from the
  same origin as the API** — one binary, no nginx, no CORS, no second TLS
  terminator.
- Postgres with partitioned event storage and dictionary tables; S3/SeaweedFS for
  diffs > 2 KB, with an inline fallback when no blob store is configured.
- **Prometheus exporter** on `/metrics` with a closed label vocabulary, in-alert
  ready rules, and a startup seed so a cold scrape is never zeroed.
- **Grafana** push (point annotations with deep links) and pull (datasource)
  endpoints; bundled 5-zone dashboard.
- **Checkmk** plugin (`--mode local` and `--mode nagios`) and a **Zabbix 7.0**
  template over a unified host-summary endpoint.
- **ChatOps** — Slack, Microsoft Teams, PagerDuty and signed generic SIEM
  webhooks, each with independent L1/storm triggers and a delivery log.
- **ITSM** — Jira and ServiceNow change-ticket correlation with a compliance
  verdict on every critical production change.
- **AI gateway** — offline deterministic engine plus Ollama, OpenAI, Azure OpenAI
  and Anthropic. Always answers; degrades cleanly; receives only scrubbed diffs.
- **MCP server** — JSON-RPC 2.0 over HTTP and a stdio adapter, five tools, for
  Cursor and Claude Desktop.
- **Security surface** — four RBAC roles with a middleware-enforced read-only
  auditor, TOTP 2FA, OIDC SSO, SHA-256-hashed scoped API keys, capped enrollment
  tokens, and an append-only control-plane audit trail.

### Console

Dashboard, virtualized timeline, servers and watched targets, drift matrix,
integrations hub, reports, and settings (system info, security, agents, audit).
Honest empty states: no fabricated fleets, no invented KPIs.

---

## Downloads

| Archive | Contents |
| --- | --- |
| `statetrack-agent-linux-amd64.tar.gz` | `statetrack-agent`, `install.sh`, `statetrack-agent.service`, annotated `agent.yaml.example` |
| `statetrack-agent-linux-arm64.tar.gz` | same, for aarch64 |
| `statetrack-agent-windows-amd64.zip` | `statetrack-agent.exe`, `install.ps1`, annotated `agent.yaml.example` |
| `statetrack-server-linux-amd64.tar.gz` | server binary with the console and SQL migrations embedded |
| `statetrack-server-windows-amd64.zip` | ditto, for Windows |
| `statetrack-mcp-linux-amd64.tar.gz` | stdio MCP adapter + client setup notes |
| `statetrack-mcp-windows-amd64.zip` | ditto, for Windows |
| `statetrack-integrations-bundle.zip` | Grafana dashboard, Prometheus rules, Checkmk plugin, Zabbix template, Kubernetes manifests, quickstart compose |
| `SHA256SUMS.txt` | checksums for every archive above |

Verify before installing:

```bash
sha256sum -c --ignore-missing SHA256SUMS.txt        # Linux
Get-FileHash <archive> -Algorithm SHA256            # Windows
```

### Checksums

```
e167360a3099faf0f8ea7798293871f85ea2c249b5ff25ff7e999ddb91682ff3   statetrack-agent-linux-amd64.tar.gz
83992e378928807aa7b0da20e3dc8edde5d166ed070daf236f23aebb4e2762b5   statetrack-agent-linux-arm64.tar.gz
ff5f92a75b8a94d67dfcfa80c9c6d3c00bab5d1fa97cf74ef79603078ad0a36b   statetrack-mcp-linux-amd64.tar.gz
826fbb328072a5f667b91aaf09e7631b02ac70b2c67fd17f254c55e869dc0177   statetrack-server-linux-amd64.tar.gz
f379714bf4732721503f0acf4abb46099aca9ed0f95263d89819a0501c2630da   statetrack-agent-windows-amd64.zip
74b69a452d8275ae2aa22626a9648c8ee7992c243f9022dd17445b7ac2168a4c   statetrack-integrations-bundle.zip
0785f87c78b6c621d2e1e86fbbcd7cc6f4b3371de272eccdd76fcc3ddec1bdf4   statetrack-mcp-windows-amd64.zip
ce0dabe13e7a2b5f0c3591720a7fc4f793bcf13099f6c8e1b54833b5cc278f51   statetrack-server-windows-amd64.zip
```

---

## Container images

```
ghcr.io/premtonx/statetrack:v0.1.0
ghcr.io/premtonx/statetrack:latest
```

Multi-arch: `linux/amd64` and `linux/arm64`. The image is a three-stage build —
`node:20-alpine` for the console, `golang:1.26-alpine` for a `CGO_ENABLED=0`
server with the console and migrations embedded, `alpine:3.20` for the runtime —
so the final image is one static binary plus a CA bundle, running as a non-root
user, with a `HEALTHCHECK` against `/healthz`.

There is no secret baked into the image, no database in it, and no demo data: a
container started against an empty Postgres migrates itself and serves an empty,
ready console.

---

## Configuration

The console is the primary interface, but everything is file- and
env-configurable:

- **[`docs/agent-deployment-guide.md`](docs/agent-deployment-guide.md)** — per-OS
  install, every `agent.yaml` key and its `STATETRACK_*` override, targeted
  watcher field reference, Kubernetes RBAC rationale, upgrade/rotate/troubleshoot
  runbooks.
- **[`README.md`](README.md)** — server quickstarts, agent install, watcher
  examples, integration setup.
- **[`docs/enterprise-catalog.md`](docs/enterprise-catalog.md)** — the discovered
  application catalog and its recommendation rules.

Server environment variables worth knowing on day one:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | localhost DSN | Postgres connection. |
| `STATETRACK_DEMO_MODE` | `0` | `1` enables the demo heartbeat and auto-login. Keep it `0` in production. |
| `STATETRACK_AUTO_MIGRATE` | `1` | Apply pending migrations on boot. |
| `STATETRACK_SESSION_SECRET` | random per boot | Set it for sessions that survive a restart. |
| `STATETRACK_ADMIN_EMAIL` / `_PASSWORD` | generated | Bootstrap administrator. |
| `S3_ENDPOINT` | `none` | `none` keeps large diffs inline in Postgres. |

---

## Upgrading

```bash
# Containers
docker compose pull && docker compose up -d

# Linux agents (in place, checksum-verified)
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
  | sudo bash -s -- --server <host:50051>          # keeps the existing agent.yaml
```

Migrations are forward-only and run automatically. An agent upgrade does not
reset the Day-0 baseline, so no change storm follows a rollout.

---

## Known limitations in v0.1.0

- `server.token` (enrollment token) is written by the installers and audited, but
  is not yet transmitted over gRPC; mTLS is the enforced transport identity today.
- SSO is configuration-complete but the login handshake is OIDC-generic;
  provider-specific quirks are still being mapped.
- Report exports are client-side; scheduled report delivery is not implemented.
- The Kubernetes watcher is read-only and cluster-scoped only (no
  namespace-scoped watch for a single team's objects beyond the RBAC option).
- Agent auto-update is a toggle in the UI; the fleet-wide rollout endpoint lands
  in the next release.

---

## Thanks

StateTrack is Apache-2.0. Issues, pull requests and integration templates are
welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`SECURITY.md`](SECURITY.md).
