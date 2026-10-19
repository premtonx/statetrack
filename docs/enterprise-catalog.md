# Enterprise Application Catalog

StateTrack's agent ships with a **built-in Enterprise Application Knowledge Base**
that tells it which workloads to look for on a host or in a cluster. The catalog
is a version-controlled YAML manifest that is embedded into the compiled agent
binary, so discovery works identically in a connected datacenter and in a
strictly air-gapped one: **no part of discovery ever makes a network call**, and
there is no external list to trust, sync, or be tampered with.

- Manifest: [`agent/internal/discovery/catalog.yaml`](../agent/internal/discovery/catalog.yaml)
- Engine: [`agent/internal/discovery/catalog.go`](../agent/internal/discovery/catalog.go),
  [`probes.go`](../agent/internal/discovery/probes.go)
- Embedding: `//go:embed catalog.yaml` in `catalog.go`

The manifest is parsed once at startup and validated strictly (`KnownFields`
plus a version check), so a typo fails fast at build/start time instead of
silently narrowing what the fleet scans.

---

## How the pieces fit together

```
catalog.yaml            profiles + entries (what to look for, how to tier it)
      │  //go:embed
      ▼
Catalog                 parsed, validated, cached
      │  CatalogProbers(RuntimeLinux, RuntimeDocker)
      ▼
Prober[]                one probe per applicable entry
      │  expandTarget()   file globs · dir walks · registry · SCM · tasks · K8s
      ▼
scanDoc[]               concrete documents (file paths, virtual registry paths)
      │  parseDocument()  nginx · apache · iis · systemd · ini · json · yaml · raw
      ▼
docResult[]             instances inside a document (vhosts, sites, units)
      │  Profile.Tier()   smart risk tiering heuristics
      ▼
DiscoveredWorkload[]    recommendations surfaced in the console
```

Probes are strictly read-only and best-effort. A missing config file, an
unreadable registry key, or a permission error is reported as *"not found"*,
never as a scan failure: discovery shares the host with the collection pipeline
and must never delay a heartbeat. Every probe is also wrapped in a panic
recover, so one bad probe cannot take the agent down.

---

## Schema

### `version`

Schema version understood by this build. A manifest declaring a newer version is
rejected rather than half-interpreted.

### `profiles`

Named, reusable risk-tiering heuristics. Keeping the tiering policy in data
rather than Go means a security team can review or amend it in a pull request
against one file.

| Field | Meaning |
| --- | --- |
| `force_level` | Applied unconditionally. Used to express "a live database is always production". |
| `https_ports` | TLS-terminating binds that promote a web workload to Critical. |
| `production_ports` | Plain-TCP binds that promote a web workload to Critical. |
| `production_patterns` | Token patterns matched against the instance name and path; a match promotes. |
| `staging_patterns` | Token patterns matched against the instance name and path; a match downgrades. |
| `critical_level` | Level assigned when a production signal hits (default `1`). |
| `staging_level` | Level assigned when a staging signal hits (default `3`). |
| `default_level` | Level assigned when no signal hits (default `3`). |
| `diff` | `true` captures a full text diff; `false` records metadata and a SHA-256 only. |

#### Tiering order

The order is fixed and deliberate:

1. **`force_level`** always wins. `/etc/shadow` is critical, full stop.
2. **A staging signal downgrades** — checked *before* any port or production
   signal, so a staging site bound to `:443` is still staging.
3. **A production signal promotes**: a TLS bind, a production-looking name, or a
   production port. The reason string names the signal that hit.
4. **Otherwise** `default_level` applies.

#### Pattern matching is token-based, not substring

Patterns match **whole alphanumeric tokens** of the name and path, not arbitrary
substrings. This matters in the direction that is dangerous to get wrong:

- `staging-api` matches `staging` → downgraded to Drift. Correct.
- `/usr/local/nginx/conf/nginx.conf` does **not** match `test`
  (its token is `local`) → not wrongly downgraded.

An over-tiered workload is noisy; an **under**-tiered one is under-watched, so
patterns are deliberately written as complete word forms (`stage`, `staging`,
`dev`, `development`) rather than as prefixes.

A pattern containing a separator (`pre-prod`, `non-prod`) is additionally
matched as a substring, because tokenising would split it apart.

#### Why a plain `:80` bind does not promote

`web_server` deliberately leaves `production_ports` empty. Every default,
placeholder, and parked site in a fleet listens on port 80, so promoting on the
port alone would bury the genuinely interesting findings under hundreds of
default pages. A plain-HTTP site that *matters* still promotes via its name
(`prod`, `www`, `checkout`, `api`, …) or via an explicit policy rule written by
an operator. A load balancer is different — its plain-HTTP frontend *is* the
production edge — which is why `load_balancer` does include port 80.

### `entries`

One per application or resource family.

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier, unique across the catalog. Also the default workload type. |
| `name` / `vendor` | Display metadata for the console. |
| `category` | Grouping: `web_server`, `database`, `message_broker`, `security`, `container`, `orchestration`, `system`. |
| `runtime` | `linux`, `windows`, `docker`, or `kubernetes`. |
| `profile` / `dev_profile` | Production profile, and the fallback profile for non-production environments (Kubernetes only). |
| `staging_namespaces` | Kubernetes namespaces treated as non-production for this entry. |
| `max_results` | Caps how many instances one entry may contribute, so a broad entry cannot drown the review queue. |
| `targets` | One or more discovery mechanisms (below). |

---

## Target kinds

| Kind | Behaviour |
| --- | --- |
| `file_glob` | Expand shell-style globs; one candidate document per match. |
| `dir_walk` | Walk a root to a bounded `depth`, collecting files by `extensions`, capped at `max_files`. |
| `registry` | Windows registry key (build-tagged; a no-op on other platforms). |
| `service` | Windows SCM service by exact name or simple glob (`MSSQL$*`). |
| `scheduled_task` | Windows Task Scheduler task store (extension-less XML). |
| `k8s_resource` | Kubernetes resource kind; consumed by the cluster collector, never by a host scan. |

`dir_walk` file caps are enforced *during* the walk, not after it: a probe must
never stat fifty thousand files on a busy volume just to discard 49,970 of them.

## Parsers

| Parser | Extracts |
| --- | --- |
| `nginx` | `server` blocks — `server_name`, `listen` ports, TLS. |
| `apache` | `<VirtualHost>` blocks — `ServerName`, ports, `SSLEngine`. |
| `iis` | `<site>` elements — bindings, physical roots; prefers each site's own `web.config` as the tracked document. |
| `systemd` | Unit files, named as `systemctl` names them. |
| `ini` | `key = value` files; picks up `port` / `listen` keys. |
| `json` | Extracts listening ports (e.g. Docker's `hosts: ["tcp://0.0.0.0:2376"]`). |
| `yaml` | Treated as an opaque document by the probe engine; canonicalised by the cluster collector. |
| `raw` | An opaque configuration document: still named, pathed, and tiered. |

An unknown parser degrades to `raw` rather than failing the scan, so a catalog
extended in the field still produces a labelled recommendation.

---

## Coverage

### Linux VMs & bare metal (`runtime: linux`)

| Entry ID | Application | Targets |
| --- | --- | --- |
| `nginx` | Nginx | `/etc/nginx/nginx.conf`, `conf.d/*.conf`, `sites-enabled/*`, `/usr/local/nginx/conf/nginx.conf` |
| `apache` | Apache HTTP Server | `/etc/apache2/**`, `/etc/httpd/**`, `/usr/local/apache2/conf/httpd.conf` |
| `caddy` | Caddy | `/etc/caddy/Caddyfile`, `conf.d/*.caddy`, `/etc/caddy/*.conf` |
| `haproxy` | HAProxy | `/etc/haproxy/haproxy.cfg`, `conf.d/*.cfg` |
| `postgresql` | PostgreSQL | `postgresql.conf`, `pg_hba.conf` across Debian/RHEL/Source layouts |
| `mysql` | MySQL / MariaDB | `/etc/mysql/**`, `/etc/my.cnf`, `/etc/my.cnf.d/*.cnf` |
| `redis` | Redis | `/etc/redis/redis.conf`, `/etc/redis.conf`, `/etc/redis/*.conf` |
| `rabbitmq` | RabbitMQ | `/etc/rabbitmq/**` (`rabbitmq.conf`, `advanced.config`, `definitions.json`, erlang cookie) |
| `kafka` | Apache Kafka | `server.properties`, `connect/*.properties`, KRaft configs, ZooKeeper `zoo.cfg` |
| `sshd` | OpenSSH Server | `/etc/ssh/sshd_config`, `sshd_config.d/*.conf` |
| `etc_passwd` | Local Accounts | `/etc/passwd`, `/etc/group`, `/etc/gshadow` |
| `etc_shadow` | Password Hashes | `/etc/shadow` |
| `sudoers` | sudo Policy | `/etc/sudoers`, `/etc/sudoers.d/*` |
| `systemd_units` | systemd Units | `/etc/systemd/system`, `/run/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system` |
| `sysctl` | Kernel Tunables | `/etc/sysctl.conf`, `/etc/sysctl.d/*.conf`, `/usr/lib/sysctl.d/*.conf` |

### Docker (`runtime: docker`)

| Entry ID | Application | Targets |
| --- | --- | --- |
| `docker_daemon` | Docker Engine | `/etc/docker/daemon.json`, `key.json`, `~/.docker/config.json`, `/etc/containers/registries.conf` |
| `docker_compose` | Docker Compose | `/opt/*/docker-compose.yml`, `/srv/*/compose.yaml`, `/etc/docker/compose/*` |
| `docker_volumes` | Docker Volume Mounts | `/var/lib/docker/volumes/**` — fingerprint + SHA-256 only, never diffed |

A Linux host scan registers the `linux` *and* `docker` entries, because the
container runtime it hosts is a Linux detection surface.

### Windows Servers (`runtime: windows`)

| Entry ID | Application | Targets |
| --- | --- | --- |
| `iis` | Internet Information Services | `applicationHost.config`, plus every nested `web.config` under `%SystemDrive%\inetpub\wwwroot` and `%SystemDrive%\sites` |
| `mssql` | Microsoft SQL Server | `HKLM\Software\Microsoft\Microsoft SQL Server`, SCM services (`MSSQLSERVER`, `MSSQL$*`, `SQLAgent$*`) |
| `rabbitmq_windows` | RabbitMQ (Windows) | `%APPDATA%\RabbitMQ\**`, `%RABBITMQ_BASE%\advanced.config` |
| `msmq` | Microsoft Message Queuing | `%WINDIR%\System32\msmq\**`, `HKLM\Software\Microsoft\MSMQ` |
| `hklm_software` | HKLM\Software Configuration | `HKLM\Software` |
| `windows_services` | Service Control Manager | `HKLM\System\CurrentControlSet\Services` |
| `windows_scheduled_tasks` | Windows Scheduled Tasks | `%WINDIR%\System32\Tasks` |
| `windows_sshd` | OpenSSH Server (Windows) | `%PROGRAMDATA%\ssh\sshd_config`, `administrators_authorized_keys` |
| `windows_hosts` | Windows Hosts & Resolver | `%WINDIR%\System32\drivers\etc\hosts` |

Registry keys are rendered in `.reg` syntax — the same convention the Windows
registry collector already emits — so a *discovered* key and a *collected* key
produce byte-identical documents for the same state, and their diffs look the
same to an operator.

### Kubernetes Clusters (`runtime: kubernetes`)

| Entry ID | Resource | Notes |
| --- | --- | --- |
| `k8s_configmap` | ConfigMaps | Canonicalised, scrubbed YAML |
| `k8s_secret` | Secrets | Every `data`/`stringData` value redacted at the edge |
| `k8s_deployment` | Deployments | Images, replicas, probes, limits |
| `k8s_statefulset` | StatefulSets | Stateful production workloads |
| `k8s_ingress` | Ingresses | Routing rules and TLS termination |

Kubernetes entries have no host target, so a host scan skips them; the cluster
collector consumes the same entries, which is what keeps one manifest the single
source of truth for both. Objects in a `staging_namespaces` namespace (or one
matching the production profile's staging patterns) are tiered with
`dev_profile` — metadata and hash only — instead of the production profile.

---

## Windows variable expansion

`%VAR%` (and Go's `$VAR` / `${VAR}`) placeholders are expanded at scan time. An
**unset** variable leaves its placeholder in place, so the pattern matches
nothing rather than collapsing to a relative path: `%RABBITMQ_BASE%\advanced.config`
must not become `\advanced.config`, which could match an unrelated file.

---

## Adding an application

1. Add an `entry` to `catalog.yaml` (and a `profile` if the existing tiering
   heuristics do not fit).
2. Add the entry to the coverage table above and to the `id` map in
   `workload.go` (`entryTypeIDs`) if it needs a workload type the console
   already renders.
3. Run `go test ./agent/internal/discovery/`. A drift test fails the build if an
   entry is missing from this document, so the manifest and the reference cannot
   silently diverge.

No Go change, no configuration, and no network access are required to teach the
agent to scan a new application — which is the entire point in an air-gapped
estate.
