STATETRACK: MASTER ARCHITECTURE & DEVELOPMENT SPECIFICATION1. System Mission & Core Rules for AI Code GenerationYou are building StateTrack, a cross-platform Infrastructure Change Intelligence platform ("Git history for live Linux and Windows servers") with native Grafana integration.   Strict Engineering ConstraintsLanguage Stack:Endpoint Agent (/agent): Go 1.23+ (compiles to a single static binary for Linux amd64/arm64 and Windows amd64).Central Backend (/server): Go 1.23+ modular monolith.   Web Console (/web): React 19, TypeScript, Vite, Tailwind CSS, @tanstack/react-query, @tanstack/react-virtual, @monaco-editor/react.Resource Ceiling (Agent): Hard memory ceiling of < 25 MB RAM (debug.SetMemoryLimit(25 * 1024 * 1024)) and < 1% CPU steady state. No inbound network ports opened on target hosts (outbound TCP 443 gRPC over mTLS only).   Visualization Dual-Strategy ("Trigger in Grafana, Inspect in StateTrack"):Grafana & External Tools: Push Level 1 & Level 2 changes via Grafana Annotations API (POST /api/annotations) and expose a Grafana query endpoint so changes appear as vertical markers directly over CPU/error spikes with a clickable deep link.   StateTrack Web UI: Renders the virtualized chronological timeline, expandable grouped package cards, actor process lineage, side-by-side Monaco code diffs, and cross-server drift matrices.   2. Target Monorepo Directory StructurePlaintextstatetrack/
├── go.work
├── docker-compose.yml              # Postgres 17, SeaweedFS (S3 API), Grafana 11
├── Makefile                        # Proto generation, builds, migrations
├── proto/
│   └── statetrack/v1/
│       └── change_event.proto      # Canonical gRPC & Protobuf contract
├── pkg/
│   ├── pb/                         # Generated Go Protobuf/gRPC code
│   ├── redact/                     # Deterministic SHA-256 secret scrubber
│   └── diff/                       # Myers unified diff + Zstd compression
├── agent/
│   ├── cmd/statetrack-agent/main.go
│   └── internal/
│       ├── config/                 # YAML config + remote hot-reload
│       ├── baseline/               # Day-0 silent shadow-cache walker
│       ├── shadow/                 # Content-addressable Zstd file cache
│       ├── limiter/                # Level 0-4 filter & Token-Bucket storm breaker
│       ├── debouncer/              # 3s sliding window & PPID tree grouper
│       ├── spool/                  # Local SQLite WAL ring buffer (max 200MB, evicts L3 -> L4 -> L2 -> L1)
│       ├── engine/                 # Pipeline orchestrator: classify -> storm breaker -> shadow diff -> debouncer -> spool
│       ├── app/                    # Wires config, baseline, engine and platform collectors (used by main.go)
│       ├── transport/              # mTLS gRPC client + heartbeat clock sync
│       └── collectors/
│           ├── linux/              # inotify/fanotify, audit netlink/eBPF, systemd, dpkg/rpm
│           └── windows/            # ReadDirectoryChangesW, ETW, Registry, SCM, MSI
├── server/
│   ├── cmd/statetrack-server/main.go
│   ├── migrations/                 # SQL migrations (Partitioned Postgres 17)
│   └── internal/
│       ├── grpc/                   # mTLS Agent Ingestion & Heartbeat service
│       ├── storage/                # Postgres repository + S3 blob router
│       ├── integrations/           # Grafana Annotations pusher, Slack, PagerDuty
│       └── api/                    # REST + WebSocket + Grafana Data Source endpoints
└── web/
    ├── package.json
    └── src/
        ├── components/
        │   ├── Timeline/           # Virtualized chronological feed & parent cards
        │   ├── DiffDrawer/         # Monaco side-by-side diff & actor tree
        │   └── DriftMatrix/        # Host-A vs Host-B state comparator
        └── pages/
3. Mutation Impact Levels (0–4) & Anti-Flood DefensesEvery collector must classify events before diffing or spooling:Level 0 (Hard Blacklist — Drop Immediately at Collector):Never hash, diff, or log: /proc/**, /sys/**, /tmp/**, /var/log/**, /var/cache/**, /var/lib/docker/overlay2/**, /var/lib/postgresql/data/**, C:\Windows\Temp\**, *.log, *.etl, *.evtx, *.swp.Level 1 (Critical Mutation — Always On, Full Diff + Instant Alert):Core configuration edits (/etc/**, /usr/local/etc/**, C:\Windows\System32\inetsrv\config\**, web.config).   Service crashes, start/stop/restart events, systemd unit changes.Security/Identity changes (/etc/passwd, /etc/sudoers, ~/.ssh/authorized_keys, Windows Local Administrators group, firewall rules).Agent self-tamper events.Action: Compute unified diff, scrub secrets, store in Postgres/S3, and immediately fire Grafana Annotation + Slack/Webhook.   Level 2 (Grouped System State — Always On, Collapsed Parent Event):Package manager operations (apt, dpkg, yum, dnf, msiexec.exe, WindowsUpdate).   Automated CI/CD runs (Ansible, Puppet, Chef, GitHub Actions runner).Action: Group all child file/service mutations under a single ParentEvent using a 3-second sliding debounce window + PPID ancestry. Compute text diffs only for modified configuration files (never binaries). Push parent summary to Grafana Annotations.   Level 3 (Background Drift — Default: Metadata & Hash Only, No Diff):Non-critical application asset changes (/var/www/**, /opt/**), minor Registry value changes, scheduled cron executions.Action: Record actor, target_path, hash_before, hash_after, and byte_size only. Skip text diff computation to save 90% storage.Level 4 (Forensic / Debug — Default: OFF, Remote TTL Toggle):Short-lived process executions (execve), raw socket binds, environment shifts.Action: Disabled unless activated remotely by the server via heartbeat (forensic_until_ms), which automatically expires after 15 minutes.Mandatory Anti-Flood Circuit Breakers (Agent Side)Binary & Size Cutoff: If target file size > 1 MB or contains null bytes in the first 512 bytes (binary), skip line-by-line diffing; emit BINARY_MODIFIED with old/new SHA-256 hashes and file sizes.Token-Bucket Change Storm Breaker: If any directory or PID generates > 50 events within 10 seconds, pause individual diffing for that scope for 30 seconds and emit a single CHANGE_STORM_THROTTLED summary event containing the total mutation count.Deterministic Secret Scrubbing: Scan all diff lines for credential patterns ((?i)(password|passwd|secret|api_key|token|private_key)\s*[:=], AWS keys, PEM blocks, high-entropy strings). Replace the secret value with [REDACTED:sha256:<first-8-hex-of-salted-hash>] so engineers can see that a secret changed without exposing the secret.   4. Canonical Protobuf Specification (proto/statetrack/v1/change_event.proto)Protocol Bufferssyntax = "proto3";
package statetrack.v1;
option go_package = "github.com/statetrack/statetrack/pkg/pb/statetrackv1";

enum ImpactLevel {
  IMPACT_LEVEL_UNSPECIFIED = 0;
  IMPACT_LEVEL_1_CRITICAL = 1;
  IMPACT_LEVEL_2_GROUPED = 2;
  IMPACT_LEVEL_3_DRIFT = 3;
  IMPACT_LEVEL_4_FORENSIC = 4;
}

enum Category {
  CATEGORY_UNSPECIFIED = 0;
  CATEGORY_CONFIG = 1;
  CATEGORY_PACKAGE = 2;
  CATEGORY_SERVICE = 3;
  CATEGORY_USER = 4;
  CATEGORY_REGISTRY = 5;
  CATEGORY_NETWORK = 6;
  CATEGORY_PROCESS = 7;
  CATEGORY_AGENT_HEALTH = 8;
}

enum Action {
  ACTION_UNSPECIFIED = 0;
  ACTION_CREATED = 1;
  ACTION_MODIFIED = 2;
  ACTION_DELETED = 3;
  ACTION_RESTARTED = 4;
  ACTION_STARTED = 5;
  ACTION_STOPPED = 6;
  ACTION_UPGRADED = 7;
  ACTION_THROTTLED = 8;
}

message ActorContext {
  string username = 1;
  string uid_or_sid = 2;
  string login_uid = 3;         // Original human UID before sudo/su
  uint32 pid = 4;
  uint32 ppid = 5;
  string process_name = 6;
  string cmdline = 7;
  repeated string process_lineage = 8; // e.g., ["sshd", "bash", "sudo", "vim"]
  string remote_ip = 9;         // SSH_CLIENT or RDP session IP
  string login_username = 10;   // Username for login_uid (the human behind sudo/su)
}

message TargetResource {
  string target_type = 1;       // "file", "registry", "service", "package"
  string path_or_key = 2;
  string hash_before = 3;
  string hash_after = 4;
  int64 size_before = 5;
  int64 size_after = 6;
  string version_before = 7;
  string version_after = 8;
}

message MutationEvent {
  string event_id = 1;          // UUIDv7 (time-sortable)
  string parent_event_id = 2;   // Empty if root event
  string host_id = 3;
  int64 agent_timestamp_ms = 4;
  uint64 monotonic_seq = 5;
  ImpactLevel level = 6;
  Category category = 7;
  Action action = 8;
  string summary = 9;
  ActorContext actor = 10;
  TargetResource target = 11;
  bytes unified_diff_zstd = 12; // Zstd-compressed unified diff (scrubbed of secrets)
  uint32 child_count = 13;      // Number of collapsed child events
  map<string, string> metadata = 14;
}

message IngestBatchRequest {
  string host_id = 1;
  int64 agent_sent_ms = 2;
  repeated MutationEvent events = 3;
}

message IngestBatchResponse {
  repeated string ack_event_ids = 1;
  int64 server_time_ms = 2;
  string desired_config_hash = 3;
  int64 forensic_mode_until_ms = 4; // If > current time, enable Level 4
}

service IngestionService {
  rpc IngestBatch(IngestBatchRequest) returns (IngestBatchResponse);
}
5. Central Database Schema (server/migrations/001_init.sql)Use PostgreSQL 17 with dictionary lookup tables for repeated strings (paths, processes, actors) and declarative monthly partitioning on events:   SQLCREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    os_family TEXT NOT NULL, -- 'linux' | 'windows'
    os_version TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    clock_offset_ms BIGINT NOT NULL DEFAULT 0,
    forensic_until TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'online',
    UNIQUE(org_id, hostname)
);

-- Dictionary Table 1: Deduplicated Target Paths / Registry Keys / Package Names
CREATE TABLE targets (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    target_type TEXT NOT NULL,
    path_or_key TEXT NOT NULL,
    UNIQUE(org_id, target_type, path_or_key)
);

-- Dictionary Table 2: Deduplicated Actors
CREATE TABLE actors (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    username TEXT NOT NULL,
    uid_or_sid TEXT NOT NULL,
    login_uid TEXT NOT NULL DEFAULT '',
    UNIQUE(org_id, username, uid_or_sid, login_uid)
);

-- Dictionary Table 3: Deduplicated Processes
CREATE TABLE processes (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    process_name TEXT NOT NULL,
    cmdline_hash TEXT NOT NULL,
    cmdline_sample TEXT NOT NULL,
    UNIQUE(org_id, process_name, cmdline_hash)
);

-- Main Partitioned Events Table (Compact ~90-byte core row)
CREATE TABLE events (
    id UUID NOT NULL,
    org_id UUID NOT NULL,
    host_id UUID NOT NULL,
    parent_event_id UUID,
    occurred_at TIMESTAMPTZ NOT NULL, -- Normalized for clock offset
    impact_level SMALLINT NOT NULL,   -- 1, 2, 3, or 4
    category SMALLINT NOT NULL,
    action SMALLINT NOT NULL,
    target_id BIGINT NOT NULL REFERENCES targets(id),
    actor_id BIGINT REFERENCES actors(id),
    process_id BIGINT REFERENCES processes(id),
    pid INTEGER,
    ppid INTEGER,
    process_lineage TEXT[],
    remote_ip TEXT,
    hash_before TEXT,
    hash_after TEXT,
    version_before TEXT,
    version_after TEXT,
    child_count INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL,
    inline_diff TEXT,                 -- Populated if diff <= 2048 bytes
    s3_blob_key TEXT,                 -- Populated if diff > 2048 bytes (s3://.../sha256.zst)
    metadata JSONB,
    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

-- Create initial monthly partitions
CREATE TABLE events_2026_10 PARTITION OF events
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
CREATE TABLE events_2026_11 PARTITION OF events
    FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');

CREATE INDEX idx_events_host_time ON events (org_id, host_id, occurred_at DESC);
CREATE INDEX idx_events_parent ON events (parent_event_id) WHERE parent_event_id IS NOT NULL;
CREATE INDEX idx_events_level_cat ON events (org_id, impact_level, category, occurred_at DESC);

-- Host State Inventory (For Instant Cross-Node Drift Matrix)
CREATE TABLE host_current_state (
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target_id BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    current_hash TEXT NOT NULL,
    current_version TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    last_event_id UUID NOT NULL,
    PRIMARY KEY (host_id, target_id)
);

-- Integrations Table (Grafana, Slack, PagerDuty, Webhooks)
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, -- 'grafana_annotations' | 'slack' | 'webhook'
    endpoint_url TEXT NOT NULL,
    api_token_encrypted TEXT,
    min_impact_level SMALLINT NOT NULL DEFAULT 2,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);
6. Chronological Implementation Plan for Cursor AIExecute these phases strictly in order. Run tests after every step before proceeding.PHASE 1: Workspace, Protobuf, Core Libraries & DB SetupStep 1.1: Initialize go.work with modules pkg, agent, and server. Set up docker-compose.yml running postgres:17-alpine, chrislusf/seaweedfs (S3 gateway on port 8333; replaces minio/minio, whose community images are no longer published), and grafana/grafana-oss:latest.Step 1.2: Compile proto/statetrack/v1/change_event.proto into pkg/pb.Step 1.3: Implement pkg/redact (Deterministic Secret Scrubber with unit tests verifying passwords/keys turn into [REDACTED:sha256:xxxxxxxx] while preserving line structure) and pkg/diff (Myers unified text diff + klauspost/compress/zstd helper).   Step 1.4: Run 001_init.sql against PostgreSQL and write a partition auto-creator job in server/internal/storage that ensures next month's partition table always exists.PHASE 2: Agent Core Engine (Shadow Cache, Spool, Limiter, Debouncer)Step 2.1 (agent/internal/shadow & baseline): Build the content-addressable Zstd shadow cache (/var/lib/statetrack/shadow/). Implement the Day-0 Baseline Walker: on first boot, scan configured watch paths, compute SHA-256 hashes, store compressed copies in the shadow cache, and mark baseline complete without emitting change events.Step 2.2 (agent/internal/limiter): Implement the Level 0 path blacklist matcher, the 1 MB / binary file detector, and the per-directory/per-PID Token-Bucket storm circuit breaker (50 events / 10s threshold).Step 2.3 (agent/internal/debouncer): Implement the 3-second sliding window transaction correlator. Group events sharing a root package/deploy ancestor PID (apt, dpkg, yum, msiexec, ansible) under a synthesized ParentEvent (ImpactLevel = 2).   Step 2.4 (agent/internal/spool): Build the local SQLite WAL ring buffer (spool.db). Enforce a strict 200 MB size cap by evicting the oldest Level 3 events first if the central server is offline for extended periods (eviction order L3 → L4 → L2 → L1).   Step 2.5 (agent/internal/engine): Pipeline orchestrator wiring classifier → storm breaker → shadow diff + redaction → debouncer → spool. After a storm trips, the first event once the breaker closes carries one cumulative diff against the pre-storm shadow. The Level 0 blacklist names specific spools (postfix, mail, exim4, cups, rsyslog) instead of all of /var/spool so /var/spool/cron stays Level 1, and ignores editor/shadow-utils scratch files (*.tmp, /etc/*+, /etc/*.lock, /etc/.pwd.lock, /etc/{passwd,shadow,group,gshadow,subuid,subgid}-).   PHASE 3: Linux Collectors (agent/internal/collectors/linux)Step 3.1 (Actor Attribution Cache): Listen to Linux Audit Netlink (AUDIT_SYSCALL / AUDIT_PATH) or eBPF tracepoints (sched_process_exec, sys_enter_openat). Maintain a thread-safe TTL cache (30s) mapping PID -> ActorContext (including /proc/$PID/loginuid and SSH_CONNECTION from /proc/$PID/environ so sudo vim still attributes back to the human SSH user and IP).   Step 3.2 (Filesystem Collector): Use fsnotify / fanotify on watched directories (/etc, /usr/local/etc, /etc/systemd/system). Handle vim/sed atomic renames (RENAME / CHMOD / WRITE) by reading the new file, looking up the previous hash in shadow, generating the scrubbed unified diff, and updating shadow.   Step 3.3 (systemd & Package Collectors): Subscribe to systemd D-Bus PropertiesChanged and JobRemoved signals for service state transitions. Parse /var/log/dpkg.log and /var/log/rpm hooks for package version diffs. Add self-monitoring on /etc/statetrack/ and the agent service.   Phase 3 implementation notes: Step 3.0 adds agent/internal/config (YAML at /etc/statetrack/agent.yaml or C:\ProgramData\StateTrack\agent.yaml, STATETRACK_* env overrides, hot reload of watch rules and forensic_until). Attribution sources, in order of precedence: audit SYSCALL/PATH records and fanotify (FAN_MODIFY | FAN_CLOSE_WRITE, needs CAP_SYS_ADMIN) give the exact writer PID; the proc connector keeps the cache warm; without them inotify + a rate-limited /proc scan (cmdline references, known writer tools, newest descendant) is used. loginuid is inherited from session ancestors when the writer has already exited. Inside unprivileged containers sub-millisecond commands whose whole session already exited may be "unattributed" — this is reported, never guessed. Proto mappings (no dedicated enum values exist): package install → CREATED, remove/purge → DELETED, upgrade/downgrade → UPGRADED, reinstall → MODIFIED (metadata.package_action); service reload → RESTARTED with event_type SERVICE_RELOADED; crash → STOPPED with SERVICE_CRASHED; daemon-reload → SYSTEMD_DAEMON_RELOAD. Package-log events correlate with file mutations under one debouncer "pkg" transaction. Race-detector and e2e tests run in golang:1.26 with CGO_ENABLED=1 (make test-race / test-e2e); release binaries stay CGO_ENABLED=0 static.   PHASE 4: Windows Collectors (agent/internal/collectors/windows)Step 4.1 (Windows Service & File Watcher): Wrap agent lifecycle with golang.org/x/sys/windows/svc. Watch C:\Windows\System32\inetsrv\config (IIS), C:\ProgramData, and configured app roots via ReadDirectoryChangesW, feeding into the exact same shadow diff and redact pipeline.   Step 4.2 (Registry, SCM & MSI Collectors): Watch HKLM\Software and HKLM\System\CurrentControlSet\Services via RegNotifyChangeKeyValue + Security Event ID 4657. Subscribe to Windows Event Log channels System (Event IDs 7036, 7040, 7045 for Services) and Application (MsiInstaller IDs 1033, 1034). Map Windows SID to DOMAIN\Username.   PHASE 5: Central Backend, Storage Router & Grafana Bridge (server/)Step 5.1 (gRPC Ingestion & Clock Sync): Implement IngestionService.IngestBatch over mTLS. Calculate clock_offset_ms = server_time_ms - req.agent_sent_ms and adjust occurred_at. Upsert targets, actors, and processes dictionary IDs using in-memory LRU caches backed by Postgres ON CONFLICT DO UPDATE.   Step 5.2 (Hybrid Postgres + S3 Storage Router): Within the ingestion batch:If decompressed diff <= 2048 bytes, save directly in events.inline_diff.If > 2048 bytes, upload the Zstd-compressed payload via the standard S3 API (SeaweedFS S3 gateway in development; any S3-compatible store such as AWS S3 in production, selected purely by endpoint/credentials configuration) to bucket statetrack-diffs at diffs/{org_id}/{sha256_of_diff}.zst (deduplicated by content hash) and save the key in events.s3_blob_key.   Update host_current_state table for every modified config/package to power instant drift comparison.Step 5.3 (Grafana Annotations Pusher & Data Source API):Push Worker: Whenever a root event with impact_level <= integrations.min_impact_level is ingested, asynchronously POST to the configured Grafana /api/annotations endpoint with tags ["statetrack", "host:<hostname>", "level:<level>", "category:<cat>"] and an HTML link <a href="https://<statetrack-ui>/events/<id>" target="_blank">Inspect Diff & Actor ↗</a>.   Pull API: Expose GET /api/v1/grafana/annotations?host=...&from=...&to=... and GET /api/v1/grafana/events so Grafana's Infinity Data Source or State Timeline panels can query StateTrack directly.   Step 5.4 (REST & WebSocket API for Web UI):GET /api/v1/hosts (list hosts, status, last change timestamp)GET /api/v1/events (cursor-paginated timeline filterable by host_id, level, category, actor, search, from, to)GET /api/v1/events/:id (returns event details, child events if parent, and transparently fetches/decompresses s3_blob_key if diff is in S3)GET /api/v1/drift?host_a=...&host_b=... (SQL FULL OUTER JOIN on host_current_state returning only targets where hash_a != hash_b)POST /api/v1/hosts/:id/forensic (enables Level 4 mode on the target host for 15 minutes)PHASE 6: Frontend Web Console (web/)Step 6.1 (Timeline Feed): Build the main layout in React + Tailwind. Implement a virtualized event list (@tanstack/react-virtual) with time-window jump controls (15m prior to incident, 1h, 24h, custom range), impact level badges (L1 Critical, L2 Grouped, L3 Drift), and expandable parent event cards (📦 134 related changes).   Step 6.2 (Forensic Inspector Drawer): Clicking any event opens a slide-over drawer featuring:Actor & Process Lineage Bar: Visual chain (SSH 192.168.1.50 → sshd [1022] → bash [4412] → sudo [8819] → vim [28411]).Monaco Side-by-Side Diff Viewer: Renders inline_diff or S3 diff with syntax highlighting and clear badges on [REDACTED:sha256:...] lines.   Step 6.3 (Cross-Node Drift Matrix UI): Build a two-column host selector (Compare prod-web-01 vs prod-web-02) that highlights mismatched config files, package versions, and services side by side.PHASE 7: Packaging & End-to-End VerificationStep 7.1: Add .goreleaser.yaml to build Linux .deb/.rpm packages (with statetrack-agent.service systemd unit) and Windows .msi/service binaries.Step 7.2: Create an end-to-end integration test script (scripts/e2e_test.sh) that starts the stack, runs the agent, modifies a sample /etc config containing a fake password, runs a package install burst, and verifies:Password is scrubbed into a salted SHA-256 stub.Package burst is collapsed into 1 parent event.Event appears in PostgreSQL and S3 (SeaweedFS).Annotation marker is live inside the local Grafana instance with a working deep link to the React UI.