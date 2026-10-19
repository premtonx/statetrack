# StateTrack Agent — Deployment & Parameter Guide

This is the operator-facing guide to installing, configuring and tuning the
StateTrack agent across a fleet: Linux servers, Windows Servers, Kubernetes
nodes and cluster-scoped watchers.

If you only read one section, read [§1 Architecture](#1-how-agent-deployment-works-architecture)
and [§7 The complete parameter reference](#7-complete-agentyaml--environment-variable-reference).

---

## Table of contents

1. [How agent deployment works (architecture)](#1-how-agent-deployment-works-architecture)
2. [Linux server setup](#2-linux-server-setup)
3. [Windows Server setup](#3-windows-server-setup)
4. [Kubernetes & Docker setup](#4-kubernetes--docker-setup)
5. [Targeted watchers: files, directories, IIS pools & databases](#5-targeted-watchers-files-directories-iis-pools--databases)
6. [Checkmk: monitoring StateTrack itself](#6-checkmk-monitoring-statetrack-itself)
7. [Complete `agent.yaml` & environment variable reference](#7-complete-agentyaml--environment-variable-reference)
8. [Operations: upgrade, rotate, troubleshoot](#8-operations-upgrade-rotate-troubleshoot)

---

## 1. How agent deployment works (architecture)

### One static binary per host

`statetrack-agent` is a single statically linked Go binary with no runtime
dependencies — no JVM, no Python, no sidecar container, no shared library set to
match. That is what makes the same artifact deployable to a hardened RHEL host
with no package manager access, an air-gapped Windows Server, and a Kubernetes
node image all at once.

| Property | Target | Why it matters |
| -------- | ------ | -------------- |
| Memory (RSS) | **< 25 MB** | The Go runtime is capped with `debug.SetMemoryLimit(25 MiB)` at startup, so a burst of package installs cannot push the agent into swapping a production host. |
| CPU | **< 1%** average | A Day-0 baseline is paced (`baseline.pace`), and steady state is inotify/ReadDirectoryChangesW callbacks rather than polling. |
| Disk | **≤ 200 MB** | The offline spool is bounded (`spool.max_mb`), oldest-first. |
| Inbound ports | **none** | The agent dials out and keeps one stream open. |
| Outbound | **1 × TCP 50051** (gRPC) | Plus DNS, and 443 if you front the server with a TLS terminator. |

### Pure outbound gRPC with mTLS support

The agent opens a *single* long-lived gRPC stream to `server.address`
(default `:50051`) and pushes change events over it. There is **no listener, no
webhook and no reverse connection** into the monitored host — the agent is
unreachable from the network by design, so a compromised StateTrack server
cannot use the fleet as an ingress path.

```yaml
server:
  address: statetrack.internal.example.com:50051
  token: st_enroll_...          # per-host enrollment token
  org: production               # tenant routing
  # Optional mTLS. When all three are set the stream is mutually authenticated.
  ca_file: /etc/statetrack/pki/ca.pem
  cert_file: /etc/statetrack/pki/agent.pem
  key_file: /etc/statetrack/pki/agent-key.pem
```

> **Note on `server.token`.** The field is written by the installers and
> reserved for server-side authentication; the current release does not yet
> transmit it over gRPC. mTLS (`ca_file`/`cert_file`/`key_file`) is the
> transport identity that is enforced today. Plan for the token to become
> mandatory in a future release and provision it now.

### Day-0 baseline fingerprinting

On first start the agent walks every configured watch root, hashes each file
into a **shadow cache**, and records the result as the host's baseline. Nothing
is reported as a "change" until *after* the baseline exists, which is what stops
a first install from emitting tens of thousands of events and burying the real
ones.

The walk is deliberately paced (`baseline.pace`, default `1ms` between files) so
a host with a million files under `/etc` and `/usr/local/etc` does not saturate
its own page cache during the install window.

### Edge secret scrubbing

Redaction happens **on the monitored host, before the event is hashed, cached,
spooled or transmitted**. A secret therefore cannot leak through the spool file,
a packet capture, or the server's database — it never leaves the machine.

```
password = "hunter2"        →  password = "[REDACTED:sha256:8f1a…]"
AWS_SECRET_ACCESS_KEY=…     →  AWS_SECRET_ACCESS_KEY=[REDACTED:sha256:2c9d…]
```

The stub is a salted SHA-256 prefix, so two files containing the *same* secret
produce the *same* stub: an operator can see that a credential was reused across
hosts without any host ever revealing it. See `pkg/redact` for the pattern set.

### 3-second package-burst debouncing

A single `apt upgrade` rewrites thousands of files under `/etc`. Reporting each
one is noise, and the interesting fact is "package `openssl` moved from 3.0.11 to
3.0.13".

The debouncer groups changes into a transaction with a **3-second sliding
inactivity window** (`debouncer.DefaultWindow`) and a **15-minute maximum group
age** (`DefaultMaxGroupAge`). Each new change extends the window; the group
closes when 3 seconds pass with no further change, or when it hits the maximum
age. The result is one Level 2 "grouped transaction" event carrying the member
changes, rather than thousands of Level 1 events.

### 200 MB local SQLite offline spool

Events are written to a local SQLite database (`<state_dir>/spool.db`) before
transmission. If the server is unreachable — network partition, maintenance
window, a laptop that went to sleep — the agent keeps collecting and buffers.
When the stream reconnects the backlog is flushed in order.

The spool is bounded at **200 MB** (`spool.max_mb`), evicting oldest-first, so a
host that is offline for a month degrades to "we lost the oldest changes"
rather than filling its disk and taking down the workload it was meant to
observe. A full spool is logged loudly and surfaced as a metric.

### What runs where

| Collector | Linux | Windows | Kubernetes (node) | Kubernetes (cluster) |
| --------- | :---: | :-----: | :---------------: | :------------------: |
| Filesystem | `inotify` + `fanotify` | `ReadDirectoryChangesW` | `hostPath` reads | — |
| Actor attribution | Audit netlink, `/proc` | Security 4657 / 4663 | — | — |
| Services | `systemd` unit watcher | SCM (7036) + poll | — | — |
| Packages | `dpkg` / `dnf` / `yum` / `apk` | MSI (1033/1034) | — | — |
| Registry | — | `RegNotifyChangeKeyValue` | — | — |
| IIS pools & sites | — | config + runtime poll | — | — |
| Database tables/schema/params | `SELECT` (read-only) | `SELECT` (read-only) | — | — |
| Kubernetes objects | — | — | — | API server informers |

---

## 2. Linux server setup

### Option A — 1-line automated installer

```bash
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
  | sudo bash -s -- \
      --server statetrack.internal.example.com:50051 \
      --token  st_enroll_xxxxxxxxxxxxxxxx \
      --org    production
```

The script is [`deploy/install.sh`](../deploy/install.sh) in this repository. It:

1. detects `x86_64` / `aarch64`,
2. downloads `statetrack-agent-linux-<arch>.tar.gz` from the latest GitHub release,
3. verifies it against the release's `SHA256SUMS.txt` and **aborts on a mismatch**,
4. installs `/usr/local/bin/statetrack-agent`,
5. writes `/etc/statetrack/agent.yaml` (mode `0600`) from the flags,
6. installs, enables and starts the `statetrack-agent` systemd unit.

It accepts extra flags for environments that cannot reach the public download
endpoint, and `--version` to pin a specific release:

```bash
# Install a binary you already have on disk
sudo bash install.sh --binary ./statetrack-agent-linux-amd64 \
    --server statetrack.internal:50051 --token st_enroll_xxx --org production

# Install from an internal mirror
sudo bash install.sh --url https://mirror.internal/statetrack-agent-linux-amd64.tar.gz \
    --server statetrack.internal:50051 --token st_enroll_xxx --org production

# Pin a release, or overwrite an existing config
sudo bash install.sh --version v0.1.0 --force \
    --server statetrack.internal:50051 --token st_enroll_xxx
```

### Option B — Manual / air-gapped install

**1. Place the binary.**

```bash
sudo install -m 0755 statetrack-agent-linux-amd64 /usr/local/bin/statetrack-agent
/usr/local/bin/statetrack-agent --version
```

**2. Write the configuration.** `/etc/statetrack/agent.yaml`, owned `root:root`
mode `0600` (it can contain the enrollment token):

```yaml
host_id: prod-web-01          # defaults to /etc/machine-id, then the hostname
state_dir: /var/lib/statetrack
log_level: info

server:
  address: statetrack.internal.example.com:50051
  token: st_enroll_xxxxxxxxxxxxxxxx
  org: production

watch:
  paths:
    - /etc
    - /usr/local/etc
    - /etc/systemd/system
    - /var/spool/cron
    - /root/.ssh
    - /home/*/.ssh
  exclude:
    - /etc/ssl/certs/**
  critical:
    - /etc/sudoers
    - /etc/ssh/sshd_config
    - /etc/pam.d/**

systemd:
  enabled: true
  units: ["*.service", "*.timer", "*.socket"]

packages:
  enabled: true

spool:
  max_mb: 200

baseline:
  pace: 1ms

reload_interval: 30s
```

**3. Install the hardened systemd unit.** The unit that ships in
`deploy/linux/statetrack-agent.service`:

```ini
[Unit]
Description=StateTrack Agent (infrastructure change intelligence)
Documentation=https://github.com/premtonx/statetrackWants=network-online.target
After=network-online.target

[Service]
Type=simple
# The agent watches the filesystem and process tree, so it runs as root and
# keeps exactly the privileges its collectors need. Everything else is
# dropped by the sandbox directives below.
ExecStart=/usr/local/bin/statetrack-agent --config /etc/statetrack/agent.yaml
Restart=always
RestartSec=5s

# Make /usr, /boot and /etc read-only for the service.
ProtectSystem=full
# The agent state (salt, shadow index, spool) lives here.
StateDirectory=statetrack
ReadWritePaths=/var/lib/statetrack

# The only capabilities the collectors require:
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_AUDIT_READ CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_ADMIN CAP_AUDIT_READ CAP_DAC_READ_SEARCH

# Network only: gRPC to the central server (plus DNS).
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Defense in depth.
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
SystemCallArchitectures=native
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Why each capability:

| Capability | Used for |
| ---------- | -------- |
| `CAP_SYS_ADMIN` | `fanotify` init — the only way to learn *which PID* wrote a file, rather than just that it changed. Without it the agent falls back to `inotify` + `/proc` attribution. |
| `CAP_AUDIT_READ` | Read the kernel audit log (`AUDIT_EXECVE` / `PATH` / `CWD` records) to attribute a file change to a process, and a process to a tool (`vim`, `sed`, `systemctl`, …). |
| `CAP_DAC_READ_SEARCH` | Read files the agent's own DAC permissions would otherwise hide (e.g. `/etc/shadow`) so their changes are still detected. |

**4. Enable and start.**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now statetrack-agent
```

### Verification

```bash
systemctl status statetrack-agent
journalctl -u statetrack-agent -f
```

A healthy start logs the resolved configuration source and the collectors it
managed to bring up:

```json
{"level":"INFO","msg":"agent starting","version":"1.4.0","host_id":"prod-web-01"}
{"level":"INFO","msg":"collectors","fs":"inotify","fanotify":true,"audit":true,"systemd":true,"packages":true}
{"level":"INFO","msg":"baseline complete","files":41822,"duration":"41s"}
{"level":"INFO","msg":"transport connected","address":"statetrack.internal:50051"}
```

`fanotify:false` while running under systemd almost always means
`CAP_SYS_ADMIN` was dropped — check `systemctl show statetrack-agent -p CapabilityBoundingSet`.

Confirm the host reached the server:

```bash
curl -s -H "Authorization: Bearer st_live_..." \
  "https://statetrack.example.com/api/v1/hosts/prod-web-01/summary?window=1h"
```

### What is collected on Linux

| Collector | Mechanism | Notes |
| --------- | --------- | ----- |
| Filesystem | `inotify` recursive watches + `fanotify` (`FAN_CLOSE_WRITE`) | `fanotify` supplies the writer PID; `inotify` guarantees coverage when `fanotify` is denied. |
| Actor attribution | Kernel audit netlink (`AUDIT_SYSCALL`/`EXECVE`/`PATH`/`CWD`) | Needs `CAP_AUDIT_READ`. Without it, attribution falls back to `/proc` scanning and process lineage is best-effort. |
| Services | `systemd` D-Bus unit watcher | Reports `start`/`stop`/`failed`/`reload` for units matching `systemd.units`. |
| Packages | Tails `dpkg.log`, `dnf.rpm.log`, `yum.log`, `apk.log`, plus the APK installed DB | Version transitions become Level 2 grouped transactions. |

---

## 3. Windows Server setup

### Option A — 1-line PowerShell installer

Run in an **elevated** PowerShell (LocalSystem is required to install the
service and read the Security log):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.ps1))) `
    -Server statetrack.internal.example.com:50051 `
    -Token  st_enroll_xxxxxxxxxxxxxxxx `
    -Org    production
```

The installer downloads `statetrack-agent-windows-amd64.zip` from the latest
GitHub release, verifies it against the release's `SHA256SUMS.txt`, extracts it
to `C:\ProgramData\StateTrack`, writes `agent.yaml` with an ACL limited to
`SYSTEM` and `Administrators`, then registers and starts the `StateTrackAgent`
service.

Useful switches: `-Version v0.1.0` to pin a release, `-Server`/`-Token`/`-Org` to
pre-fill the config, `-Force` to overwrite an existing `agent.yaml`, `-NoStart` to
register without starting, and `-Binary`/`-Url` for an air-gapped or mirrored
install.

> **Note.** The `statetrack-agent service` subcommands below are the mechanism the
> installer uses, and are the supported path for scripted rollouts.

### Option B — Manual / air-gapped service install

**1. Create the directory and place the files.**

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\StateTrack | Out-Null
Copy-Item .\statetrack-agent.exe C:\ProgramData\StateTrack\statetrack-agent.exe
& C:\ProgramData\StateTrack\statetrack-agent.exe --version
```

**2. Write `C:\ProgramData\StateTrack\agent.yaml`.**

```yaml
host_id: win-app-02
state_dir: C:\ProgramData\StateTrack
log_level: info

server:
  address: statetrack.internal.example.com:50051
  token: st_enroll_xxxxxxxxxxxxxxxx
  org: production

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
    source: auto          # eventlog when 7036 is logged, else poll
    poll_interval: 5s
  msi:
    enabled: true
  security_audit:
    enabled: true

spool:
  max_mb: 200

reload_interval: 30s
```

Lock the file down — it holds the enrollment token:

```powershell
icacls C:\ProgramData\StateTrack\agent.yaml /inheritance:r `
  /grant "SYSTEM:(F)" /grant "Administrators:(F)"
```

**3. Install and start the service** using the binary's own service manager:

```powershell
cd C:\ProgramData\StateTrack
.\statetrack-agent.exe service install
.\statetrack-agent.exe service start
```

| Command | Effect |
| ------- | ------ |
| `service install` | Creates the `StateTrackAgent` service pointing at this executable with `-config C:\ProgramData\StateTrack\agent.yaml`, automatic start, and registers the event-log source. |
| `service start` | Starts it. |
| `service stop` | Stops it, waiting up to 20s for the state to reach `Stopped`. |
| `service uninstall` | Stops if running, then deletes the service and its event-log source. |

`install` fails fast if the service already exists (`service "StateTrackAgent"
already exists`); uninstall first when reinstalling.

### Verification

```powershell
Get-Service StateTrackAgent

# Follow the log (the service writes structured JSON to the Windows event log)
Get-EventLog -LogName Application -Source StateTrackAgent -Newest 20 | Format-List
```

`Get-Service` should show `Status: Running`, `StartType: Automatic`. If it is
`Running` but the console never shows the host, the usual cause is a token or
address mismatch — run the binary in the foreground to see the error:

```powershell
cd C:\ProgramData\StateTrack
.\statetrack-agent.exe -config .\agent.yaml
```

### What is collected on Windows

| Collector | Mechanism | Notes |
| --------- | --------- | ----- |
| Filesystem | `ReadDirectoryChangesW`, recursive | Watches IIS config, `drivers\etc`, scheduled tasks and `ProgramData` by default. |
| Registry | `RegNotifyChangeKeyValue` + rescan | `HKLM\SOFTWARE` and `HKLM\SYSTEM\CurrentControlSet\Services` by default; keys are watched recursively. |
| Services | SCM snapshots *and* System log 7036/7040/7045/7031/7034 | `source: auto` uses the event log when the host emits 7036 and falls back to polling (recent Windows 11 builds no longer log it). |
| MSI installs | Application log, `MsiInstaller` 1033/1034 | Product installs/removals become Level 2 grouped transactions. |
| Actor attribution | Security log **4657** (registry value changed) and **4663** (object access) | Only present where *Audit Object Access* and a SACL are configured. Without them the agent still detects changes but cannot name the actor. |
| IIS app pools & sites | `applicationHost.config` parse + runtime state poll (`appcmd`) | One canonical YAML document per watched pool and site; catches a pool that stopped while `W3SVC` stayed up. See [§5.2](#52-iis-application-pool-or-site). |
| Database (read-only) | `SELECT` against the configured tables, `information_schema`, `pg_settings` / `sys.configurations` | PostgreSQL and SQL Server. Catches a flipped config value, an `ALTER TABLE`, or an `ALTER SYSTEM`. See [§5.3](#53-database-table-schema-and-server-parameters-settings_db). |

Enable object-access auditing where you need attribution:

```powershell
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

---

## 4. Kubernetes & Docker setup

The Kubernetes integration is **two workloads with two jobs**. Running only one
of them gives you half a timeline.

| Workload | Scope | Watches |
| -------- | ----- | ------- |
| `DaemonSet` (`deploy/k8s/daemonset.yaml`) | one pod per node | the node's own configuration via read-only `hostPath`: kubelet, CNI, container runtime, mounted secrets. |
| `Deployment` (`deploy/k8s/deployment.yaml`) | one pod per cluster | cluster objects through the API server: ConfigMaps, Secrets, Deployments, StatefulSets, Ingresses. |

The Deployment is deliberately `replicas: 1` with `strategy: Recreate`: two
overlapping watchers would report the same object change twice, and a rolling
update would briefly do exactly that.

### Apply

```bash
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset.yaml
kubectl apply -f deploy/k8s/deployment.yaml
```

`rbac.yaml` grants **only** `get`/`list`/`watch` — there is no `create`,
`update`, `patch` or `delete` in the file, so the agent is structurally incapable
of mutating the cluster. A security reviewer can confirm that by reading one
document.

```yaml
rules:
  - apiGroups: [""]
    resources: ["configmaps"]          # verbs: get, list, watch
  - apiGroups: [""]
    resources: ["secrets"]             # read is what makes edge scrubbing matter
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
```

If a team will not grant a cluster-wide Secret read, `rbac.yaml` also contains a
commented namespace-scoped `Role` + `RoleBinding` alternative. The watcher lists
each configured namespace in its own request, which is what makes a
namespace-scoped Role sufficient — just set `kubernetes.namespaces`.

### Node DaemonSet specifics

```yaml
env:
  # Node identity from the Downward API, not the pod hostname: a re-scheduled
  # pod keeps the same node identity and does not look like a new host.
  - name: STATETRACK_HOST_ID
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

Every host mount is `readOnly: true` and rooted at `/host`, so an agent path is
unambiguous and a stray write is impossible. The pod tolerates all taints
(`operator: Exists`) because a node with a problem is exactly the node whose
configuration is worth reporting.

There is **no privileged escalation and no added capability** — the DaemonSet
detects changes from the informer/watch API plus `hostPath` reads, not from
kernel hooks.

### Cluster watcher specifics

```yaml
env:
  - name: STATETRACK_KUBERNETES_CLUSTER
    value: prod-k8s-01
```

`kubernetes.cluster` is what appears in tracked object paths:

```
/k8s/<cluster>/<namespace>/<resource>/<name>
/k8s/prod-k8s-01/payments/deployments/checkout-api
```

That path is what the diff engine diffs, so changing the cluster name on an
established watcher makes every tracked object look new. Pick it once.

### Secret redaction at the edge

The watcher serializes each object to canonical YAML, then replaces every
`data`, `stringData` and `binaryData` value with a salted
`[REDACTED:sha256:…]` stub **before** the document is hashed, cached, diffed or
sent. Consequences worth internalizing:

- A Secret rotation shows up as a change event, but the diff shows only that
  values changed — never the values.
- The same value in two Secrets produces the same stub, so cross-object reuse is
  visible.
- The server never receives plaintext, so a server-side breach cannot recover
  cluster secrets.

### Docker

For a container on a single Docker host, run the same binary with the host's
config directories mounted read-only:

```yaml
services:
  statetrack-agent:
    image: ghcr.io/premtonx/statetrack-agent:latest
    restart: unless-stopped
    volumes:
      - /etc:/host/etc:ro
      - /var/lib/statetrack:/var/lib/statetrack
    environment:
      STATETRACK_SERVER_ADDRESS: statetrack.internal:50051
      STATETRACK_SERVER_ORG: production
      STATETRACK_HOST_ID: docker-host-01
```

---

## 5. Targeted watchers: files, directories, IIS pools & databases

The filesystem walk reports *everything* under a watch root. A targeted watcher
reports **one** object with a full before/after document, and treats any change
to it as the alert itself. Use it when the operator knows exactly which object
matters: a web tier's `web.config`, a payment gateway's TLS flag, a checkout
app pool.

Three ways to declare one, all equivalent:

| Where | Best for | Survives an agent restart | Needs a config edit |
| ----- | -------- | :-----------------------: | :-----------------: |
| **Console → Servers → Watched targets** | day-to-day operations | ✅ (pushed on heartbeat) | no |
| `agent.yaml` (`watch.paths`, `iis.pools`, `database.connections[].tables`) | image bake, air-gapped install | ✅ | yes |
| `rules[]` in `agent.yaml` | classification only, no new target | ✅ | yes |

> A console rule is a `host_policy_rule`: the same row classifies the event
> *and* tells the collector what to track. Creating one is recorded in
> `control_plane_audit_logs` and pushed to agents on the next heartbeat, so a new
> target starts reporting within one poll interval (30 s for IIS, 60 s for a
> database) with no restart.

### 5.1 Pinpointed file or directory

A file target is one path and is hashed and diffed as a single document. A
directory target is a tree: use `**` for recursive and a trailing `*` for one
level.

```yaml
watch:
  paths:
    - C:\inetpub\wwwroot\checkout\web.config     # one file
    - D:\Apps\Billing\Config\**                  # whole tree, recursive
    - /etc/rabbitmq/**                           # Linux equivalent
    - /opt/app/.env
  exclude:
    - D:\Apps\Billing\Config\logs\**             # never alert on churn
```

The same targets in the console:

| Field | Example value |
| ----- | ------------- |
| Host | `win-app-02` |
| Target Type | `Specific File` |
| Path / Identifier | `C:\inetpub\wwwroot\checkout\web.config` |
| Impact Level | `Level 1 Critical — Full Diff & Instant Alert` |

A file that is deleted and recreated is one change (deleted → created), not two
unrelated rows: the engine keys on the tracked path, which is what makes
"someone replaced `web.config` with an older copy" a single readable event.

**Directory renames are reported as deletions plus creations** — the file
watcher has no inode identity on Windows, so a rename of a watched tree is
indistinguishable from a delete followed by a write.

### 5.2 IIS application pool or site

The IIS watcher polls `applicationHost.config` and the runtime state, then
renders a canonical YAML document per pool and per site at
`iis://apppool/<PoolName>` and `iis://site/<SiteName>`.

```yaml
iis:
  enabled: true
  pools:
    - CheckoutAppPool
    - iis://apppool/BillingAppPool
  sites:
    - iis://site/Checkout
  watch_all: false
```

What the document contains:

| Section | Fields |
| ------- | ------ |
| Pool | `state` (live `Started`/`Stopped`/`Starting`/`Stopping`), `autoStart`, `managedRuntimeVersion`, `managedPipelineMode`, `enable32BitAppOnWin64`, `queueLength`, `startMode` |
| Process model | `identityType`, `userName`, `password` → `[REDACTED:sha256:…]`, `idleTimeout`, `maxProcesses`, `loadUserProfile`, ping/startup/shutdown timeouts |
| Rapid-fail protection | `enabled`, `failureInterval`, `maximumFailures`, `shutdownTimeLimit` |
| Recycling | `schedule`, `periodicRestart`, `privateMemoryLimitKB`, `requestLimit`, `virtualMemoryLimitKB`, `logEventOnRecycle` |
| Site | `state`, `physicalPath`, applications (path → app pool), bindings (`protocol`, `ip`, `port`, `hostHeader`, `sslThumbprint`, `sslStore`, `sslFlags`) |

Why a separate watcher: the `W3SVC` service can be `Running` while a single pool
is `Stopped`. `applicationHost.config` does not change when that happens, so a
file-only deployment would show a green host during a checkout outage. The
runtime poll is what turns it into a Level 1 event, with the transition in the
summary line (`Application pool CheckoutAppPool stopped`).

Actor attribution comes from a recently started management process —
`appcmd.exe`, `InetMgr.exe` (IIS Manager) or `powershell.exe` — sampled within
`DefaultActorWindow`. Without one, the event still fires and names the tool as
unknown rather than inventing a user.

Pool passwords are scrubbed at the edge with `pkg/redact`, so a rotation shows up
as a changed `[REDACTED:sha256:…]` line without the secret ever leaving the host.

### 5.3 Database table, schema and server parameters (`settings_db`)

The database watcher is **strictly read-only**. It issues only `SELECT`
statements, validates each one before execution, and never writes — a watcher
that could write to `settings_db` would be a bigger risk than the drift it
detects. Give it a read-only role:

```sql
-- PostgreSQL
CREATE ROLE statetrack_ro LOGIN PASSWORD '…';
GRANT CONNECT ON DATABASE settings_db TO statetrack_ro;
GRANT USAGE ON SCHEMA public TO statetrack_ro;
GRANT SELECT ON public.app_settings TO statetrack_ro;
GRANT SELECT ON pg_settings TO statetrack_ro;      -- watch_server_params
```

```sql
-- SQL Server
CREATE LOGIN statetrack_ro WITH PASSWORD = '…';
USE settings_db;
CREATE USER statetrack_ro FOR LOGIN statetrack_ro;
GRANT SELECT ON dbo.SystemSettings TO statetrack_ro;
GRANT VIEW SERVER STATE TO statetrack_ro;          -- sys.configurations + sessions
```

```yaml
database:
  enabled: true
  connections:
    - name: settings
      engine: postgres
      dsn: "postgres://statetrack_ro@db.internal:5432/settings_db?sslmode=verify-full"
      database: settings_db
      tables:
        - public.app_settings
      watch_schema: true
      watch_server_params: true
      row_limit: 500
```

Three independently addressable surfaces:

| Surface | Tracked path | Detects |
| ------- | ------------ | ------- |
| Table rows | `db://postgres/settings_db/tables/public.app_settings` | a config value flipped, a secret rotated, a row added or removed |
| Schema & grants | `db://postgres/settings_db/schema` | `ALTER TABLE`, a dropped index, a widened grant |
| Server parameters | `db://postgres/settings_db/server_params` | `ALTER SYSTEM SET` / `sp_configure` |

Rows are ordered by primary key (or every column when there is none) and capped
at `row_limit`, so two polls of an unchanged table are byte-identical and a
mistyped table name cannot pull a million rows. Every document goes through
`pkg/redact` **before hashing**: `password`, `secret`, `api_key`, `token`, `dsn`
and `connection_string` columns become `[REDACTED:sha256:…]`, so a rotation is
visible as a changed line and the value is not.

Attribution is the hardest part of database watching, because the change does not
carry a user. On a detected diff the watcher reads `pg_stat_activity` (Postgres)
or `sys.dm_exec_sessions` (SQL Server) for the active session: database user,
client tool (`psql`, `SSMS`, `DBeaver`, an application name) and client IP. The
event is emitted as **Level 1 Critical** (`application_name=psql`, `client_addr=10.0.14.22`).

A table watch requires a matching `database.connections[]` entry: the agent
cannot reach a database it was never given a DSN for. A console rule whose
`db://` path names an unknown database is skipped with a log line — visible, not
silent, and not fatal.

### 5.4 Adding a watched target in the console

**Servers → Watched targets → + Add Watched Target**:

| Field | Notes |
| ----- | ----- |
| **Host** | `All Hosts` (fleet-wide) or one host. A fleet-wide rule is applied to every agent, so a Windows-only target type is filtered out on Linux hosts. |
| **Target Type** | `File`, `Directory`, `IIS App Pool`, `IIS Site`, `Database Table`, `Database Schema`, `Database Parameters`, `Registry Key`, `Service`, `Kubernetes Object`. Windows-only types are hidden on a Linux host and vice versa. |
| **Path / Identifier** | Placeholder and help text change with the type — `iis://apppool/CheckoutAppPool`, `db://postgres/settings_db/tables/public.app_settings`, `HKLM\Software\Company\App\**`. |
| **Impact Level** | `Level 1 Critical — Full Diff & Instant Alert` (default) or `Level 3 Drift — Hash Only`. Level 1 captures the diff and pages; Level 3 records the change without an alert. |
| **Name** | Derived from the path, editable. |

The table below lists active custom targets with a status badge, the impact
level, the host scope and a delete action. Deletion is audited as
`rule.watch_deleted` (creation as `rule.watch_created`) with the pattern in the
target field, so the audit log reads "stopped watching
`D:\Apps\Billing\Config\**`" rather than "deleted row 41f2…".

Rules are validated server-side before they are stored — a bad glob, a target
type without its scheme, or a `Level` outside the two choices is rejected with a
message the modal shows, so a failed save never looks like a successful one.

### 5.5 How a document becomes a diff

Both surgical watchers go through the same engine path as a file:

```
render canonical YAML → redact → hash → compare with shadow cache
   unchanged  → nothing (no event, no log line)
   changed    → Level 1 event with the previous and current document
   missing    → deletion event (pool removed, table dropped)
```

The first observation of a target is a **seed**, not an event: the baseline is
recorded without an alert, so pointing the watcher at a new table on a busy host
does not immediately report every row as created.

---

## 6. Checkmk: monitoring StateTrack itself

Deploying the agent tells StateTrack what changed. Monitoring StateTrack tells
you when the agent has gone quiet. Both halves are needed, and the Checkmk
integration is covered in depth in
[`integrations/checkmk/README.md`](../integrations/checkmk/README.md).

The short version — a local check on the Checkmk agent:

```bash
sudo install -m 0755 integrations/checkmk/check_statetrack.py \
  /usr/lib/check_mk_agent/local/60/check_statetrack.py
```

...or a Nagios/MRPE active check:

```bash
python3 check_statetrack.py --mode nagios \
  --url https://statetrack.example.com --host prod-web-01 --window 15m
```

A live Docker demo (4 hosts, both modes, real data) is one command:

```powershell
.\scripts\dev.ps1 checkmk
# then open http://localhost:5000/cmk/  (cmkadmin / statetrack)
```

It provisions all four demo hosts with the local check and the Nagios active
check, then forces a check cycle so the GUI is populated immediately:

![Checkmk service detail for StateTrack Changes](images/checkmk-service-detail.png)

---

## 7. Complete `agent.yaml` & environment variable reference

### Fully commented example

```yaml
# ---------------------------------------------------------------------------
# Identity & location
# ---------------------------------------------------------------------------
# Stable host identity. Leave empty to derive it from /etc/machine-id and then
# the hostname; set it explicitly when a host is rebuilt often and you want its
# history to survive the rebuild.
host_id: prod-web-01

# Where the shadow cache, salt and spool live. Must be writable and persistent.
state_dir: /var/lib/statetrack        # Windows: C:\ProgramData\StateTrack

# debug | info | warn | error
log_level: info

# ---------------------------------------------------------------------------
# Server / transport
# ---------------------------------------------------------------------------
server:
  address: statetrack.internal.example.com:50051
  token: st_enroll_xxxxxxxxxxxxxxxx    # per-host enrollment token
  org: production                      # tenant routing
  ca_file: /etc/statetrack/pki/ca.pem  # mTLS (all three or none)
  cert_file: /etc/statetrack/pki/agent.pem
  key_file: /etc/statetrack/pki/agent-key.pem

# ---------------------------------------------------------------------------
# Filesystem watch scope
# ---------------------------------------------------------------------------
watch:
  # Replaces the platform default roots.
  paths:
    - /etc
    - /usr/local/etc
    - /etc/systemd/system
    - /var/spool/cron
    - /root/.ssh
    - /home/*/.ssh                     # globs are expanded at startup
  # Appended to paths (or to the defaults when paths is empty).
  extra_paths: []
  # Level 0: dropped before classification. Use for high-churn caches.
  exclude:
    - /etc/ssl/certs/**
    - /var/cache/**
  # Level 1: forced critical regardless of the default category.
  critical:
    - /etc/sudoers
    - /etc/ssh/sshd_config
    - /etc/pam.d/**
    - /etc/kubernetes/**

# ---------------------------------------------------------------------------
# Offline queue
# ---------------------------------------------------------------------------
spool:
  max_mb: 200                          # bounded, oldest-first eviction

# ---------------------------------------------------------------------------
# Day-0 baseline
# ---------------------------------------------------------------------------
baseline:
  pace: 1ms                            # sleep between files during the walk

# ---------------------------------------------------------------------------
# Linux collectors
# ---------------------------------------------------------------------------
systemd:
  enabled: true
  units: ["*.service", "*.timer", "*.socket"]

packages:
  enabled: true
  dpkg_log: /var/log/dpkg.log
  dnf_log: /var/log/dnf.rpm.log
  yum_log: /var/log/yum.log
  apk_log: /var/log/apk.log
  apk_db: /lib/apk/db/installed

# ---------------------------------------------------------------------------
# Windows collectors
# ---------------------------------------------------------------------------
windows:
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE
      - HKLM\SYSTEM\CurrentControlSet\Services
  services:
    enabled: true
    source: auto                       # auto | eventlog | poll
    poll_interval: 5s
  msi:
    enabled: true                      # MsiInstaller 1033/1034
  security_audit:
    enabled: true                      # Security 4657/4663 attribution

# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------
kubernetes:
  enabled: false                       # true only on the cluster watcher
  cluster: prod-k8s-01
  namespaces: []                       # empty = every namespace the SA can list
  resync_interval: 10m
  # Overrides for watching a cluster you are not running inside. A pod never
  # needs these: the service account is already mounted.
  endpoint: ""
  token_file: ""
  ca_file: ""
  insecure_skip_verify: false

# ---------------------------------------------------------------------------
# IIS application pools & sites (Windows)
# ---------------------------------------------------------------------------
# The file watcher sees applicationHost.config change; this watcher sees a pool
# that stopped while the config file stayed the same. Targets named here are
# merged with the watched targets an operator adds in the console.
iis:
  enabled: true
  application_host: C:\Windows\System32\inetsrv\config\applicationHost.config
  pools:
    - CheckoutAppPool                  # or iis://apppool/CheckoutAppPool
    - BillingAppPool
  sites:
    - iis://site/Checkout
  watch_all: false                     # true turns idle-pool recycling into L1 noise
  interval: 30s                        # runtime-state poll period

# ---------------------------------------------------------------------------
# Read-only database watcher
# ---------------------------------------------------------------------------
# Every query is a SELECT. The DSN is a credential: prefer
# STATETRACK_DATABASE_DSN over writing it into this file.
database:
  enabled: true
  connections:
    - name: settings                    # logs only, never part of a path
      engine: postgres                  # postgres | sqlserver
      dsn: "postgres://statetrack_ro@db.internal:5432/settings_db?sslmode=verify-full"
      database: settings_db             # used in db://<engine>/<db>/…
      tables:
        - public.app_settings
      watch_schema: true                # ALTER TABLE / grant changes
      watch_server_params: true         # ALTER SYSTEM / sp_configure
      row_limit: 500
  interval: 60s

# ---------------------------------------------------------------------------
# Hot-reload window
# ---------------------------------------------------------------------------
# The config file and watch globs are re-evaluated on this interval. Watch
# rules, forensic_until and log_level reload live; see "Restart required" below.
reload_interval: 30s

# ---------------------------------------------------------------------------
# Level 4 forensic capture window
# ---------------------------------------------------------------------------
# Enables full-content capture until this RFC 3339 instant. Capped at 15
# minutes from when it is applied, so a forgotten window cannot run forever.
forensic_until: 2026-10-17T12:30:00Z

# ---------------------------------------------------------------------------
# Custom classification policy
# ---------------------------------------------------------------------------
# Matched against a change's target (path or registry key). Exact matches are
# tried before globs; the first matching rule wins.
rules:
  - name: treasury-key-material
    target_type: file                  # file | registry | service | ...
    pattern: /etc/treasury/keys/**
    level: 1                           # 0 drop, 1-4 impact level
    diff: false                        # capture no text diff for this target
    tags: [pci, key-material]
```

### Parameter reference

Every parameter can be set in `agent.yaml`; the `STATETRACK_*` column is the
equivalent environment override (environment wins over the file).

| YAML key | Environment variable | Default | Description |
| -------- | -------------------- | ------- | ----------- |
| `host_id` | `STATETRACK_HOST_ID` | `/etc/machine-id`, then hostname | Stable host identity. Set explicitly for hosts that are rebuilt but should keep their history. |
| `state_dir` | `STATETRACK_STATE_DIR` | `/var/lib/statetrack` (Linux) · `C:\ProgramData\StateTrack` (Windows) | Shadow cache, salt and spool location. Must be writable and persistent. |
| `log_level` | `STATETRACK_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Hot-reloadable. |
| `reload_interval` | `STATETRACK_RELOAD_INTERVAL` | `30s` | How often the config file and watch globs are re-evaluated. Minimum `1s`. |
| `server.address` | `STATETRACK_SERVER_ADDRESS` | *(empty — spool-only)* | gRPC endpoint of the central server. Empty keeps the agent collecting into the spool without transmitting. |
| `server.token` | `STATETRACK_SERVER_TOKEN` | *(empty)* | Per-host enrollment token written by the installers. Reserved for server-side authentication. |
| `server.org` | `STATETRACK_SERVER_ORG` | *(empty)* | Tenant/org routing identifier. |
| `server.ca_file` | — | *(empty)* | CA bundle for server verification. Enables TLS when set. |
| `server.cert_file` | — | *(empty)* | Client certificate for mTLS. |
| `server.key_file` | — | *(empty)* | Client private key for mTLS. |
| `watch.paths` | `STATETRACK_WATCH_PATHS` | Platform defaults (see below) | Replaces the default watch roots. Comma-separated in the environment. Globs are expanded at startup. |
| `watch.extra_paths` | `STATETRACK_WATCH_EXTRA_PATHS` | *(empty)* | Appended to the watch roots instead of replacing them. |
| `watch.exclude` | `STATETRACK_WATCH_EXCLUDE` | *(empty)* | Level 0 patterns — dropped before classification. For caches and high-churn trees. |
| `watch.critical` | `STATETRACK_WATCH_CRITICAL` | *(empty)* | Level 1 patterns — forced critical regardless of default category. |
| `spool.max_mb` | `STATETRACK_SPOOL_MAX_MB` | `200` | Hard cap on the local SQLite spool. Oldest events are evicted first. Minimum `1`. |
| `baseline.pace` | `STATETRACK_BASELINE_PACE` | `1ms` | Sleep between files during the Day-0 walk. Raise it on hosts with slow storage; lower it to finish the baseline faster. |
| `systemd.enabled` | `STATETRACK_SYSTEMD_ENABLED` | `true` (Linux) | Enable the systemd unit watcher. |
| `systemd.units` | — | `["*.service","*.timer","*.socket"]` | Glob patterns of units to report. |
| `packages.enabled` | `STATETRACK_PACKAGES_ENABLED` | `true` (Linux) | Enable the package-log collectors. |
| `packages.dpkg_log` | `STATETRACK_PACKAGES_DPKG_LOG` | `/var/log/dpkg.log` | Debian/Ubuntu package log. |
| `packages.dnf_log` | — | `/var/log/dnf.rpm.log` | Fedora/RHEL 8+ package log. |
| `packages.yum_log` | — | `/var/log/yum.log` | RHEL/CentOS 7 package log. |
| `packages.apk_log` | `STATETRACK_PACKAGES_APK_LOG` | `/var/log/apk.log` | Alpine package log. |
| `packages.apk_db` | `STATETRACK_PACKAGES_APK_DB` | `/lib/apk/db/installed` | Alpine installed-package database (for version diffs). |
| `windows.registry.enabled` | `STATETRACK_REGISTRY_ENABLED` | `true` (Windows) | Enable registry monitoring. |
| `windows.registry.keys` | `STATETRACK_REGISTRY_KEYS` | `HKLM\SOFTWARE`, `HKLM\SYSTEM\CurrentControlSet\Services` | Keys watched recursively. Must start with `HKLM\` or `HKCU\`. |
| `windows.services.enabled` | `STATETRACK_SERVICES_ENABLED` | `true` (Windows) | Enable SCM service-state monitoring. |
| `windows.services.source` | `STATETRACK_SERVICES_SOURCE` | `auto` | `eventlog` (System 7036), `poll` (SCM snapshots) or `auto`. |
| `windows.services.poll_interval` | — | `5s` | Snapshot interval when `source` is `poll` or `auto` falls back. Minimum `1s`. |
| `windows.msi.enabled` | `STATETRACK_MSI_ENABLED` | `true` (Windows) | Report MsiInstaller 1033/1034 installs and removals. |
| `windows.security_audit.enabled` | `STATETRACK_SECURITY_AUDIT_ENABLED` | `true` (Windows) | Read Security 4657/4663 to attribute changes. Requires object-access auditing and a SACL. |
| `kubernetes.enabled` | `STATETRACK_KUBERNETES_ENABLED` | `false` | Enable the in-cluster configuration watcher. |
| `kubernetes.cluster` | `STATETRACK_KUBERNETES_CLUSTER` | *(derived from API server host)* | Cluster name used in tracked object paths (`/k8s/<cluster>/…`). Pick it once — changing it re-baselines every object. |
| `kubernetes.namespaces` | `STATETRACK_KUBERNETES_NAMESPACES` | *(empty = all)* | Restrict watching to these namespaces (also what makes a namespace-scoped Role sufficient). |
| `kubernetes.resync_interval` | — | `10m` | Safety-net full re-list period, independent of watch events. |
| `kubernetes.endpoint` | `STATETRACK_KUBERNETES_ENDPOINT` | *(in-cluster)* | API server URL for watching a cluster from outside. Requires `token_file`. |
| `kubernetes.token_file` | `STATETRACK_KUBERNETES_TOKEN_FILE` | *(in-cluster)* | Bearer token file for an out-of-cluster watcher. |
| `kubernetes.ca_file` | `STATETRACK_KUBERNETES_CA_FILE` | *(in-cluster)* | CA bundle for API server verification. |
| `kubernetes.insecure_skip_verify` | `STATETRACK_KUBERNETES_INSECURE_SKIP_VERIFY` | `false` | Disable API server certificate verification. Only for a cluster whose certificate is not signed by the mounted CA. |
| `iis.enabled` | `STATETRACK_IIS_ENABLED` | `true` | Start the IIS app-pool/site watcher (Windows; a no-op elsewhere). |
| `iis.application_host` | `STATETRACK_IIS_APPLICATION_HOST` | `%WINDIR%\System32\inetsrv\config\applicationHost.config` | `applicationHost.config` to parse. |
| `iis.pools` | `STATETRACK_IIS_POOLS` | *(empty)* | Application pools to watch, as names, `iis://apppool/…` URIs or globs. Comma-separated in the environment. |
| `iis.sites` | `STATETRACK_IIS_SITES` | *(empty)* | Sites to watch, as names, `iis://site/…` URIs or globs. |
| `iis.watch_all` | `STATETRACK_IIS_WATCH_ALL` | `false` | Track every pool and site. Noisy on a server that recycles idle pools — prefer naming the ones that matter. |
| `iis.interval` | — | `30s` | Runtime-state poll period. |
| `database.enabled` | `STATETRACK_DATABASE_ENABLED` | `true` | Start the read-only database watcher. |
| `database.connections[].engine` | `STATETRACK_DATABASE_ENGINE` | *(required)* | `postgres` or `sqlserver`. The environment variable addresses the first connection. |
| `database.connections[].dsn` | `STATETRACK_DATABASE_DSN` | *(required)* | Connection string. Keep it out of the YAML file when the service manager can inject it. |
| `database.connections[].database` | `STATETRACK_DATABASE_NAME` | *(from the DSN)* | Database name used in tracked paths. |
| `database.connections[].tables` | `STATETRACK_DATABASE_TABLES` | *(empty)* | Tables to snapshot, `schema.table` each. |
| `database.connections[].watch_schema` | — | `false` | Snapshot column and grant DDL as a second document. |
| `database.connections[].watch_server_params` | — | `false` | Snapshot non-default runtime parameters. |
| `database.connections[].row_limit` | — | `500` | Row cap per table snapshot. |
| `database.connections[].interval` | — | *(inherits)* | Per-connection poll period. |
| `database.interval` | — | `60s` | Default poll period for every connection. |
| `forensic_until` | `STATETRACK_FORENSIC_UNTIL` | *(zero)* | RFC 3339 instant until which Level 4 full-content capture is enabled. Capped at 15 minutes from application. |
| `rules[]` | — | *(empty)* | Per-target classification overrides. See below. |

**Default watch roots.**

- Linux: `/etc`, `/usr/local/etc`, `/etc/systemd/system`, `/var/spool/cron`,
  `/root/.ssh`, `/home/*/.ssh`
- Windows: `C:\Windows\System32\inetsrv\config`,
  `C:\Windows\System32\drivers\etc`, `C:\Windows\System32\Tasks`, `C:\ProgramData`

### `iis` fields

The IIS watcher renders one canonical YAML document per watched application pool
(`iis://apppool/<PoolName>`) and per watched site (`iis://site/<SiteName>`).
It answers a question the file watcher cannot: *the config file did not change,
but the pool is not running*.

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `enabled` | bool | `true` | Start the watcher. With no targets it costs one idle goroutine, so a fleet-wide config file is safe. |
| `application_host` | string | `%WINDIR%\System32\inetsrv\config\applicationHost.config` | Config file to parse. Set it for a non-default `WINDIR` or a copied file. |
| `pools` | []string | *(empty)* | Application pools to watch, as `CheckoutAppPool`, `iis://apppool/CheckoutAppPool` or a glob. |
| `sites` | []string | *(empty)* | Sites to watch, as `Default Web Site`, `iis://site/Default Web Site` or a glob. |
| `watch_all` | bool | `false` | Track every pool and site. Off by default: IIS stops an idle pool after 20 minutes, so watching everything turns routine recycling into Level 1 noise. |
| `interval` | duration | `30s` | Runtime-state poll period. Configuration edits are picked up faster by the file watcher, which re-triggers the poll. |

Pools and sites named by a **watched-target rule** in the console are merged
with these lists on every poll, so `+ Add Watched Target → IIS App Pool` needs no
agent restart and no config edit.

### `database` fields

The database watcher is **read-only by construction**: every query it issues is
a `SELECT` (against `pg_settings` / `sys.configurations`, `information_schema`,
`pg_roles` / `sys.database_permissions`, and the configured tables), and a
statement that is not a `SELECT` is rejected before it reaches the driver.

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `enabled` | bool | `true` | Start the watcher. With no connections it is not started at all. |
| `connections[]` | list | *(empty)* | Databases to watch. See the connection fields below. |
| `interval` | duration | `60s` | Default poll period for every connection. |

`connections[]` fields:

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `name` | string | *(derived)* | Label used in logs only — never in a tracked path. |
| `engine` | string | *(required)* | `postgres` or `sqlserver`. |
| `dsn` | string | *(required)* | Connection string. **A credential**: 0600 file or `STATETRACK_DATABASE_DSN`, never a repository. Put `sslmode=verify-full` (Postgres) or `encrypt=true` (SQL Server) in it. |
| `database` | string | *(derived from the DSN)* | Database name used in tracked paths (`db://postgres/settings_db/…`). Pin it when the DSN targets a server, not a database. |
| `tables` | []string | *(empty)* | Tables to snapshot as `schema.table` or `table`, e.g. `public.app_settings`, `dbo.SystemSettings`. |
| `watch_schema` | bool | `false` | Snapshot columns and role/grant DDL at `db://<engine>/<db>/schema` to catch `ALTER TABLE` and privilege changes. |
| `watch_server_params` | bool | `false` | Snapshot non-default runtime settings at `db://<engine>/<db>/server_params` to catch `ALTER SYSTEM` / `sp_configure`. |
| `row_limit` | int | `500` | Caps one table snapshot. A config table is small; a cap stops a mis-typed table name from pulling a million rows. |
| `interval` | duration | *(inherits `database.interval`)* | Per-connection poll period. |

Table rows are ordered deterministically by primary key (or by every column,
when there is no primary key) so an unchanged table produces a byte-identical
document. Every serialized document passes through `pkg/redact` **before**
hashing: a column named `password`, `secret`, `api_key`, `token`, `dsn` or
`connection_string` renders as `[REDACTED:sha256:…]`, and free text is
line-scrubbed for high-entropy values.

Both watchers attribute changes: IIS to a recently started `appcmd.exe`,
`InetMgr.exe` or `powershell.exe`, the database to `pg_stat_activity` /
`sys.dm_exec_sessions` (user, client tool such as `psql` or `SSMS`, client IP).
A change to a watched pool, table, schema or parameter is reported as **Level 1
Critical** with a full before/after YAML diff.

### `rules[]` fields

| Field | Type | Description |
| ----- | ---- | ----------- |
| `name` | string | Rule identifier, attached to matched events as `metadata.rule_name`. Defaults to `pattern`. Must be unique. |
| `target_type` | string | Restrict to a target type (`file`, `registry`, `service`, …). Empty matches any. |
| `pattern` | string | Exact target or glob, matched against the path/key. Empty matches any target. |
| `level` | int | Impact level to apply: `0` drops the event entirely, `1`–`4` set the level. |
| `diff` | bool | Whether a text diff is captured for matched events. |
| `tags` | []string | Surfaced on matched events as `metadata.rule_tags`. |

Matching precedence: the Level 0 hard blacklist is applied first, then exact
target rules, then glob rules in declaration order, then the default
category/path level.

### Hot reload vs. restart

`reload_interval` re-reads the file, and the following take effect live:
`watch.*`, `rules`, `forensic_until`, `log_level`.

Changing any of these requires a restart — the agent logs an explicit warning
naming the field rather than silently ignoring it:

`host_id`, `state_dir`, `server`, `spool`, `systemd`, `packages`, `windows`,
`kubernetes`, `iis`, `database`.

```bash
sudo systemctl restart statetrack-agent        # Linux
Restart-Service StateTrackAgent                # Windows
```

---

## 8. Operations: upgrade, rotate, troubleshoot

### Upgrade a Linux fleet

An upgrade is the same installer run again: it replaces the binary, verifies the
release checksum, keeps the existing configuration (unless `--force`), and
restarts the service. The spool and shadow cache live in `state_dir` and survive
it — and because the Day-0 baseline is not part of a binary upgrade, no change
storm follows a rollout.

```bash
# In place, checksum-verified, config preserved
curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
  | sudo bash -s -- --server statetrack.internal:50051

# Or a pinned release, on every host, without touching config
sudo bash install.sh --version v0.1.0 --server statetrack.internal:50051
```

The equivalent manual step is a file replacement plus a restart:

```bash
sudo install -m 0755 statetrack-agent /usr/local/bin/statetrack-agent
sudo systemctl restart statetrack-agent
```

Rolling restart without losing the spool:

```bash
ansible -i inventory webservers -m shell -a \
  'install -m 0755 /tmp/statetrack-agent /usr/local/bin/ && systemctl restart statetrack-agent' \
  --become
```

### Upgrade a Windows fleet

The installer handles "stop, replace, re-register, start" and preserves
`agent.yaml`:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.ps1))) `
    -Version v0.1.0 -Server statetrack.internal:50051
```

…or, for a scripted rollout that only swaps the binary:

```powershell
Invoke-Command -ComputerName $servers -ScriptBlock {
  Stop-Service StateTrackAgent
  Copy-Item \\fileserver\statetrack\statetrack-agent.exe C:\ProgramData\StateTrack\ -Force
  Start-Service StateTrackAgent
}
```

### Rotate an enrollment token or certificate

1. Mint the new token in the console (**Settings → Security → Enrollment tokens**).
2. Update `server.token` in `agent.yaml` (or `STATETRACK_SERVER_TOKEN`).
3. `systemctl restart statetrack-agent`.

For mTLS, replace `cert_file`/`key_file` and restart — TLS material is read at
startup, not on the reload interval.

### Troubleshooting

| Symptom | Cause and fix |
| ------- | ------------- |
| `fanotify unavailable; using inotify with /proc attribution` | `CAP_SYS_ADMIN` missing. Check `systemctl show statetrack-agent -p CapabilityBoundingSet`. Attribution still works but is less precise. |
| `Agent online` but no events | Watch roots are narrower than you think, or everything is excluded. Run at `log_level: debug` and look for `filesystem collector started` with its resolved `roots`. |
| Host appears twice in the console | `host_id` changed (rebuild without pinning it, or a changed Kubernetes `cluster` name). Keep `host_id` stable. |
| `spool is full; dropping oldest events` | Server unreachable for a long time. Check the network path to `server.address:50051`, then raise `spool.max_mb` if the outage was legitimate. |
| Baseline never finishes | `baseline.pace` too high for the file count, or a watch root covers a huge tree. Raise the pace or narrow `watch.paths`. |
| Windows service `Running` but no data | Security-log auditing not enabled (attribution), or the config path is wrong. Run in the foreground: `statetrack-agent.exe -config agent.yaml`. |
| Kubernetes watcher lists nothing | The ServiceAccount lacks RBAC. `kubectl auth can-i list secrets --as=system:serviceaccount:statetrack:statetrack-agent`. |
| `kubernetes.token_file is required when kubernetes.endpoint is set` | Config validation caught an anonymous watcher. Set `token_file`, or remove `endpoint` to use the in-cluster service account. |

### Health endpoints

The server exposes the fleet rollup the monitoring integrations consume. Poll it
from a jump host to confirm an agent is being heard:

```bash
curl -s -H "Authorization: Bearer st_live_..." \
  "https://statetrack.example.com/api/v1/hosts/prod-web-01/summary?window=1h" | jq
```

```json
{
  "host": "prod-web-01",
  "online": true,
  "last_seen_seconds": 12,
  "window": "1h",
  "counts": { "total": 9, "l1_critical": 2, "l2_grouped": 1, "l3_drift": 3, "l4_forensic": 0 },
  "drift_targets_count": 14,
  "latest_critical": {
    "id": "00002798-...",
    "target": "/etc/nginx/nginx.conf",
    "actor": "alice",
    "tool": "vim",
    "deep_link": "https://statetrack.example.com/events/00002798-...?tab=diff"
  }
}
```

`online: true` with a `last_seen_seconds` that keeps growing means the stream
dropped and the agent has not reconnected — check the outbound firewall rule for
`50051`.
