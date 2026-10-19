// Command statetrack-seed populates the local StateTrack Postgres database with
// a realistic outage + drift timeline for today, for demos, screenshots and UI
// development.
//
// It is idempotent per day: hosts are upserted by (org, hostname) and every
// event uses a deterministic UUID derived from a stable name, so re-running the
// seeder on the same day is a no-op (events are ON CONFLICT DO NOTHING, drift
// rows are upserted). Diffs are run through the real redact.Scrubber, so the
// [REDACTED:sha256:...] stub appears exactly as it does in production.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// seedScrubber uses a fixed salt so redaction stubs are stable across runs
// (which keeps the seeder idempotent). Production agents use a random,
// per-installation salt.
var seedScrubber = redact.New([]byte("statetrack-dev-seed"))

func main() { os.Exit(run()) }

func run() int {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(log)

	dsn := flag.String("dsn", envOr("DATABASE_URL",
		"postgres://statetrack:statetrack@localhost:5432/statetrack?sslmode=disable"),
		"Postgres DSN")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		log.Error("connect to postgres", "err", err)
		return 1
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Error("ping postgres (run: dev.ps1 up; dev.ps1 migrate)", "err", err)
		return 1
	}

	if err := seed(ctx, log, pool); err != nil {
		log.Error("seed failed", "err", err)
		return 1
	}
	log.Info("seed complete")
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// seedID derives a stable, deterministic UUID for an event or state row so
// re-running the seeder is idempotent.
func seedID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("statetrack-seed:"+name)).String()
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ago anchors an event a fixed offset before this run, so the seeded timeline
// always lands in the recent past — inside the dashboard's default now-6h
// window and behind "now" — instead of at a wall-clock hour that may still be
// in the future (which is what made every rate/increase panel read zero when
// the seeder ran before 09:00).
func ago(now time.Time, minutes int) time.Time {
	return now.Add(-time.Duration(minutes) * time.Minute).Truncate(time.Second)
}

// seedSourceTag marks every event this seeder writes, so a re-run can clear its
// own timeline before re-anchoring it. A real agent's events never carry it, so
// the cleanup can never touch captured data.
const seedSourceTag = "statetrack-demo"

// timeline holds every anchored event time for one seed run. It is derived once
// from `now` and shared by seed, seedKubernetes, seedAmbient and
// seedChangeTickets, so the event times, the cluster's changes and the
// change-ticket windows cannot drift apart.
//
// Every value is *relative to the run* rather than a fixed wall-clock hour, and
// every offset is inside the last hour. That is deliberate on both counts:
//
//   - A fixed wall-clock hour anchors the timeline in the future for a run
//     before that hour, and a future event is invisible to every Grafana
//     increase()/rate() panel.
//   - The provisioned Grafana dashboard opens on `now-1h..now`, so a timeline
//     spread across six hours would leave most of its width empty. The offsets
//     below keep the whole story — the cluster's Secret rotation, the nginx
//     edit, the package transactions and the registry change — inside that
//     window, with the four changes the hero panel flags spread evenly across
//     it (see annotated in seed()).
//
// The interleaving is preserved from the original script: the cluster's
// ConfigMap lands before the nginx edit, the nginx restart after it, and the
// registry change stays below the IIS pool stop so win-app-02's newest critical
// change is the IIS scenario, not a routine registry tweak.
//
// The four *annotated* anchors are the demo's four scenarios and are spaced so
// the Grafana hero panel reads as a story rather than a cluster:
//
//	-50m  prod-web-01  /etc/nginx/nginx.conf            (L1, nginx edit)
//	-38m  prod-k8s-01  ArgoCD rollout + Secret rotation (L1, cluster)
//	-22m  prod-web-01  db://postgres/settings_db/...    (L1, database)
//	 -6m  win-app-02   iis://apppool/CheckoutAppPool    (L1, IIS pool)
type timeline struct {
	nginxAt   time.Time // prod-web-01: nginx.conf edit (L1, annotated)
	aptAt     time.Time // prod-web-01: apt upgrade transaction parent (L2)
	restartAt time.Time // prod-web-01: nginx.service restart (L1)
	indexAt   time.Time // prod-web-01: index.html drift (L3)
	regAt     time.Time // win-app-02: registry LogLevel change (L1)
	peerAptAt time.Time // prod-web-02: apt upgrade transaction parent (L2)

	// Surgical-watcher anchors. These are the two scenarios the targeted
	// watchers exist for, and they carry the SQL/IIS canonical YAML the console
	// inspector renders.
	dbAt  time.Time // prod-web-01: settings_db app_settings edit (L1, annotated)
	iisAt time.Time // win-app-02: CheckoutAppPool stopped + identity change (L1, annotated)

	k8sCMAt      time.Time // prod-k8s-01: ConfigMap edit (L1)
	k8sSecretAt  time.Time // prod-k8s-01: Secret rotation (L1)
	k8sDeployAt  time.Time // prod-k8s-01: Deployment rollout (L1, annotated)
	k8sIngressAt time.Time // prod-k8s-01: staging Ingress drift (L3)
}

// newTimeline anchors the demo timeline a fixed number of minutes before now.
//
// The offsets are deliberately named by the recording script: the IIS pool stop
// at -6m, the settings_db mutation at -22m, the ArgoCD rollout + Secret rotation
// at -38m and the nginx edit at -50m. Everything else is interleaved around
// those four so the feed still reads as a fleet rather than four isolated
// changes, and every anchor stays inside the dashboard's one-hour window.
func newTimeline(now time.Time) timeline {
	return timeline{
		// The four annotated scenarios, oldest first.
		nginxAt: ago(now, 50),
		// The Secret rotation lands 20s before the rollout so the two events
		// keep a stable order while the *annotated* rollout sits exactly on the
		// requested -38m mark.
		k8sSecretAt: ago(now, 38).Add(-20 * time.Second),
		k8sDeployAt: ago(now, 38),
		dbAt:        ago(now, 22),
		iisAt:       ago(now, 6),

		// Unannotated, but inside the same hour so the impact-over-time chart,
		// the host ranking and the recent-changes table are populated.
		aptAt:        ago(now, 58),
		k8sCMAt:      ago(now, 54),
		restartAt:    ago(now, 48),
		peerAptAt:    ago(now, 30),
		indexAt:      ago(now, 11),
		k8sIngressAt: ago(now, 9),
		// The registry edit stays Level 1 but older than the IIS stop: Checkmk
		// renders a host's *latest* critical change, and win-app-02's headline
		// has to be the app-pool crash, not this routine log-level tweak.
		regAt: ago(now, 7),
	}
}

// annotateTag marks the handful of changes the Grafana hero panel draws a flag
// for.
//
// Only a curated subset carries it. The dashboard's hero panel is the one place
// a viewer reads "what happened, and when", and a flag per routine rotation
// would bury the two critical edits it exists to point at. Everything else —
// the cluster's rollout, the drift, the ambient volume — is deliberately left
// unflagged so the four vertical lines stay legible.
const annotateTag = "annotate"

// annotatedIDs lists the event ids the hero panel flags, in the order they
// appear on its timeline. The Grafana seeder selects exactly these (see
// loadSeededChanges), so adding an event here is all it takes to draw its flag.
//
// They are the demo's four named scenarios — one Windows service crash, one
// database mutation, one ArgoCD rollout and one Linux config edit — spread
// across the hour at -50m, -38m, -22m and -6m. All four are Level 1, so the
// dashboard's L1 layer draws four red flags and its L2 layer draws none; the
// routine package transactions stay unflagged so the four lines remain legible.
func annotatedIDs() []string {
	return []string{
		seedID("prod-web-01/nginx.conf"),                    // L1 · nginx.conf edit (-50m)
		seedID("prod-k8s-01/messaging/deployment/rabbitmq"), // L1 · ArgoCD rollout (-38m)
		seedID("prod-web-01/settings_db/app_settings"),      // L1 · settings_db mutation (-22m)
		seedID("win-app-02/iis/checkout-apppool"),           // L1 · IIS app pool crash (-6m)
	}
}

// markAnnotated stamps the annotation flag onto the curated events only.
//
// Applied at insert time rather than by editing each literal, so the set of
// flagged changes is defined in exactly one place (annotatedIDs) and cannot
// silently diverge from what the Grafana seeder selects.
func markAnnotated(events []*pb.MutationEvent) []*pb.MutationEvent {
	want := map[string]bool{}
	for _, id := range annotatedIDs() {
		want[id] = true
	}
	for _, ev := range events {
		if !want[ev.GetEventId()] {
			continue
		}
		if ev.Metadata == nil {
			ev.Metadata = map[string]string{}
		}
		ev.Metadata[annotateTag] = "true"
	}
	return events
}

// markSeeded tags every event with the seed source. Applied at the moment of
// insertion rather than in each literal, so a new event cannot be added without
// the marker (and therefore without being cleaned up on the next run).
func markSeeded(events []*pb.MutationEvent) []*pb.MutationEvent {
	for _, ev := range events {
		if ev.Metadata == nil {
			ev.Metadata = map[string]string{}
		}
		ev.Metadata["seed_source"] = seedSourceTag
	}
	return events
}

// scrubDiff renders a unified diff oldText -> newText, redacts secrets with the
// real scrubber and zstd-compresses it into the agent transport field.
func scrubDiff(label, oldText, newText string) ([]byte, error) {
	d := diff.Unified(label, label, oldText, newText, 3)
	return diff.CompressString(seedScrubber.UnifiedDiff(d))
}

// diffStat counts added/removed lines of a unified diff (agent summary style).
func diffStat(d string) (add, del int) {
	for _, l := range strings.Split(d, "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			add++
		case strings.HasPrefix(l, "-"):
			del++
		}
	}
	return
}

// stateRow is one host_current_state row to seed for the drift matrix.
type stateRow struct {
	targetType, path, hash, version string
}

// ---------------------------------------------------------------------------
// Realistic file/registry contents used to build the diffs.
// ---------------------------------------------------------------------------

const nginxBefore = `# /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 2048;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    upstream app_backend {
        server 10.0.4.11:8080;
        server 10.0.4.12:8080;
    }

    server {
        listen 80 default_server;
        server_name _;
        root /var/www/html;

        location /api/ {
            proxy_pass http://app_backend;
            proxy_pass_header Server;
            proxy_set_header Host $host;
        }
    }
}
`

const nginxAfter = `# /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 512;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    # backing database credential (rotated 2026-10-14)
    # auth_db_password = "supersecret123"

    upstream app_backend {
        server 10.0.4.11:8080;
        server 10.0.4.12:8080;
    }

    server {
        listen 80 default_server;
        server_name _;
        root /var/www/html;

        location /api/ {
            proxy_pass http://app_backend;
            proxy_pass_header Date;
            proxy_set_header Host $host;
        }
    }
}
`

const indexBefore = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Acme Corp</title>
</head>
<body>
  <h1>Acme Corporation</h1>
  <p class="build">Build 2418</p>
</body>
</html>
`

const indexAfter = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Acme Corp</title>
</head>
<body>
  <h1>Acme Corp &mdash; Production</h1>
  <p class="build">Build 2419</p>
</body>
</html>
`

const regBefore = `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\Company\App]
"LogLevel"="INFO"
"RetentionDays"="30"
`

const regAfter = `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\Company\App]
"LogLevel"="DEBUG"
"RetentionDays"="30"
`

// Peer contents for prod-web-02: intentionally divergent from prod-web-01 so
// the Fleet Drift matrix reports them as differing.
const nginxPeer = `# /etc/nginx/nginx.conf (prod-web-02)
user www-data;
worker_processes 2;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
}
`

const indexPeer = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Acme Corp</title>
</head>
<body>
  <h1>Acme Corp &mdash; Staging</h1>
  <p class="build">Build 2418</p>
</body>
</html>
`

// ---------------------------------------------------------------------------
// Surgical-watcher canonical documents (IIS app pool, settings_db table)
// ---------------------------------------------------------------------------
//
// These are the exact canonical YAML documents the targeted collectors render
// (see agent/internal/collectors/iis/render.go and
// agent/internal/collectors/database/render.go), not prose approximations. The
// seeder writes them through the same Myers diff + scrubber pipeline as a file
// edit, so the demo's diff drawer shows what an operator would really see: the
// pool's `state: Started -> Stopped` beside `identity_type` flipping to
// SpecificUser with a hash stub where the password was, and the settings table's
// `verify_tls` flipping while the rotated webhook secret stays a stub.

// checkoutPoolBefore/After: a production checkout pool that an administrator
// stopped and re-pointed at a domain service account in IIS Manager.
const checkoutPoolBefore = `kind: iis_apppool
name: CheckoutAppPool
state: Started
auto_start: true
managed_runtime_version: v4.0
managed_pipeline_mode: Integrated
enable_32bit_app_on_win64: false
queue_length: 1000
start_mode: AlwaysRunning
process_model:
    identity_type: ApplicationPoolIdentity
    user_name: ""
    idle_timeout: 00:20:00
    max_processes: 1
process_lifetime:
    load_user_profile: true
    pinging_enabled: true
    ping_interval: 00:00:30
    ping_response_time: 00:01:30
    startup_time_limit: 00:01:30
    shutdown_time_limit: 00:01:30
    manual_group_membership: false
rapid_fail_protection:
    enabled: true
    failure_interval: 00:05:00
    maximum_failures: 5
    shutdown_time_limit: 00:01:30
recycling:
    disallow_overlapping_rotation: false
    log_event_on_recycle: Time,Requests
    periodic_restart: "00:00:00"
    schedule:
        - 02:00:00
        - 14:00:00
    private_memory_limit_kb: 0
    request_limit: 0
    virtual_memory_limit_kb: 0
`

const checkoutPoolAfter = `kind: iis_apppool
name: CheckoutAppPool
state: Stopped
auto_start: true
managed_runtime_version: v4.0
managed_pipeline_mode: Integrated
enable_32bit_app_on_win64: false
queue_length: 1000
start_mode: AlwaysRunning
process_model:
    identity_type: SpecificUser
    user_name: CORP\svc_checkout
    password: '[REDACTED:sha256:7c4e91a2]'
    idle_timeout: 00:20:00
    max_processes: 1
process_lifetime:
    load_user_profile: true
    pinging_enabled: true
    ping_interval: 00:00:30
    ping_response_time: 00:01:30
    startup_time_limit: 00:01:30
    shutdown_time_limit: 00:01:30
    manual_group_membership: false
rapid_fail_protection:
    enabled: true
    failure_interval: 00:05:00
    maximum_failures: 5
    shutdown_time_limit: 00:01:30
recycling:
    disallow_overlapping_rotation: false
    log_event_on_recycle: Time,Requests
    periodic_restart: "00:00:00"
    schedule:
        - 02:00:00
        - 14:00:00
    private_memory_limit_kb: 0
    request_limit: 0
    virtual_memory_limit_kb: 0
`

// appSettingsBefore/After: the public.app_settings configuration table in
// settings_db. A row-keyed table, so the diff reads as one line per setting,
// which is the shape that makes a config-table watcher worth having.
const appSettingsBefore = `kind: database_table
engine: postgres
database: settings_db
schema: public
table: app_settings
key_columns:
    - key
columns:
    - key
    - value
    - updated_at
row_count: 6
truncated: false
rows:
    - key: checkout.gateway_timeout_ms
      value: "45000"
      updated_at: "2026-10-02 09:14:22+00"
    - key: payment_gateway.provider
      value: stripe
      updated_at: "2026-09-18 11:02:40+00"
    - key: payment_gateway.verify_tls
      value: "true"
      updated_at: "2026-10-02 09:14:22+00"
    - key: retry.backoff_base_ms
      value: "250"
      updated_at: "2026-09-18 11:02:40+00"
    - key: stripe_webhook_secret
      value: '[REDACTED:sha256:9f3a1c8e]'
      updated_at: "2026-10-04 16:41:07+00"
    - key: support.escalation_email
      value: payments-oncall@acme.example
      updated_at: "2026-09-18 11:02:40+00"
`

const appSettingsAfter = `kind: database_table
engine: postgres
database: settings_db
schema: public
table: app_settings
key_columns:
    - key
columns:
    - key
    - value
    - updated_at
row_count: 6
truncated: false
rows:
    - key: checkout.gateway_timeout_ms
      value: "45000"
      updated_at: "2026-10-02 09:14:22+00"
    - key: payment_gateway.provider
      value: stripe
      updated_at: "2026-09-18 11:02:40+00"
    - key: payment_gateway.verify_tls
      value: "false"
      updated_at: "{{UPDATED_AT}}"
    - key: retry.backoff_base_ms
      value: "250"
      updated_at: "2026-09-18 11:02:40+00"
    - key: stripe_webhook_secret
      value: '[REDACTED:sha256:4b7d2e10]'
      updated_at: "{{UPDATED_AT}}"
    - key: support.escalation_email
      value: payments-oncall@acme.example
      updated_at: "2026-09-18 11:02:40+00"
`

// appSettingsUpdatedAtPlaceholder is replaced with the run's own timestamp when
// the table document is rendered.
//
// The document is a canonical snapshot a collector produced *at the moment of
// the change*, so its `updated_at` has to move with the timeline. A literal date
// would leave the diff claiming the row changed on one day while the event's
// occurred_at said another — the exact inconsistency a "re-anchor to now" seed
// exists to remove.
const appSettingsUpdatedAtPlaceholder = "{{UPDATED_AT}}"

// renderAppSettingsAfter stamps the run's timestamp into the after document.
func renderAppSettingsAfter(at time.Time) string {
	return strings.ReplaceAll(
		appSettingsAfter,
		appSettingsUpdatedAtPlaceholder,
		at.UTC().Format("2006-01-02 15:04:05+00"),
	)
}

// ---------------------------------------------------------------------------
// Kubernetes canonical documents (prod-k8s-01)
// ---------------------------------------------------------------------------
//
// These are the *canonical YAML* documents the agent's Kubernetes collector
// produces (see agent/internal/collectors/k8s/serialize.go): volatile metadata
// (resourceVersion, managedFields, status) already pruned, so a diff shows only
// a real configuration change rather than per-write churn. They are rendered as
// text here exactly as the collector would render them, then handed to the same
// Myers diff + scrubber pipeline as a file edit.

// checkout-config ConfigMap before/after: a production payments config gaining a
// retry budget. No credential is present, so the entropy scrubber leaves the
// document intact — which is the point of the ConfigMap path (a readable diff).
const k8sConfigMapBefore = `apiVersion: v1
data:
  CHECKOUT_FEE_BPS: "29"
  LOG_LEVEL: info
  PROVIDER_ENDPOINT: https://payments.internal/api/v2
  RETRY_BUDGET_MS: "800"
kind: ConfigMap
metadata:
  labels:
    app: checkout
    tier: web
  name: checkout-config
  namespace: payments
`

const k8sConfigMapAfter = `apiVersion: v1
data:
  CHECKOUT_FEE_BPS: "29"
  LOG_LEVEL: debug
  PROVIDER_ENDPOINT: https://payments.internal/api/v2
  RETRY_BUDGET_MS: "2500"
kind: ConfigMap
metadata:
  labels:
    app: checkout
    tier: web
  name: checkout-config
  namespace: payments
`

// api-keys Secret before/after. A Secret's values are stubbed at the edge,
// so these documents are already the *stubbed* form: the seeder writes the same
// `[REDACTED:sha256:...]` marker the agent's scrubber emits, and never a payload.
// Every value in `data` is stubbed — a key's identifier is as much a credential
// as its value — so the rotation shows one marker changing while the key set
// stays put, which is exactly what a reviewer needs to see.
const k8sSecretBefore = `apiVersion: v1
data:
  CHECKOUT_API_KEY: '[REDACTED:sha256:7c4a9f01]'
  WEBHOOK_SIGNING_KEY: '[REDACTED:sha256:b2e6d940]'
kind: Secret
metadata:
  name: api-keys
  namespace: payments
type: Opaque
`

const k8sSecretAfter = `apiVersion: v1
data:
  CHECKOUT_API_KEY: '[REDACTED:sha256:4f1a9c31]'
  WEBHOOK_SIGNING_KEY: '[REDACTED:sha256:b2e6d940]'
kind: Secret
metadata:
  name: api-keys
  namespace: payments
type: Opaque
`

// rabbitmq Deployment before/after: a rollout bumping replicas and the broker
// image. A Deployment is a workload spec, so editing it is a production rollout.
const k8sDeployBefore = `apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: rabbitmq
  name: rabbitmq
  namespace: messaging
spec:
  replicas: 2
  selector:
    matchLabels:
      app: rabbitmq
  template:
    spec:
      containers:
      - image: rabbitmq:3.13.6-management
        name: rabbitmq
        resources:
          limits:
            memory: 2Gi
`

const k8sDeployAfter = `apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: rabbitmq
  name: rabbitmq
  namespace: messaging
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rabbitmq
  template:
    spec:
      containers:
      - image: rabbitmq:3.13.7-management
        name: rabbitmq
        resources:
          limits:
            memory: 4Gi
`

// staging Ingress: a non-production namespace object, so the catalog's
// kubernetes_dev profile tracks it as drift (metadata + hash) rather than
// alerting on it.
const k8sIngressBefore = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: checkout-preview
  namespace: staging
spec:
  rules:
  - host: preview.internal
    http:
      paths:
      - backend:
          service:
            name: checkout-preview
            port:
              number: 80
        path: /
        pathType: Prefix
`

const k8sIngressAfter = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: checkout-preview
  namespace: staging
spec:
  rules:
  - host: preview.acme-corp.example
    http:
      paths:
      - backend:
          service:
            name: checkout-preview
            port:
              number: 80
        path: /
        pathType: Prefix
`

// clearSeededTimeline removes the previous run's events so re-anchoring the
// timeline to "now" does not stack a second copy: the events PK is
// (occurred_at, id), so a stable id with a fresh timestamp is a *new* row, not
// an update. Only rows this seeder owns are touched — a real agent's events
// carry neither the tag nor a seed-derived id and are never deleted.
//
// Two selectors, deliberately:
//
//   - the seed_source tag, which every event written by the current code carries
//     (including grouping children, matched by parent id), and
//   - the deterministic event ids. Those ids have been stable since the first
//     version of this seeder, so they also catch rows written by an *older*
//     binary that did not tag anything — otherwise a database seeded before this
//     change would keep its stale, often future-dated rows and the dashboard
//     would show two flags per change.
func clearSeededTimeline(ctx context.Context, pool *pgxpool.Pool, orgID string, log *slog.Logger) error {
	tag, err := pool.Exec(ctx, `
		DELETE FROM events
		WHERE org_id = $1::uuid
		  AND (metadata->>'seed_source' = $2
		       OR id = ANY($3::uuid[])
		       OR parent_event_id = ANY($3::uuid[]))`,
		orgID, seedSourceTag, seededEventIDs())
	if err != nil {
		return fmt.Errorf("clear previous seeded timeline: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Info("cleared previous seeded timeline (re-anchoring to now)", "events", n)
	}
	return nil
}

// seededEventIDs returns the deterministic UUID of every event this seeder
// writes, so cleanup can find rows from an older, untagged run.
//
// The names must match the seedID(...) calls that build the events. A name that
// drifts here would strand its row (a duplicate in the timeline), so
// TestSeededEventIDsCoverEveryInsertedEvent fails if the two fall out of step.
//
// Ambient events and the peer transaction are included for the same reason as
// the narrative ones: they are written by this seeder, so a later run must be
// able to delete them even if the tag-based selector somehow misses.
func seededEventIDs() []string {
	names := append([]string{
		"prod-web-01/nginx.conf",
		"prod-web-01/apt-nginx",
		"prod-web-01/nginx.service",
		"prod-web-01/index.html",
		"prod-web-01/settings_db/app_settings",
		"win-app-02/registry-loglevel",
		"win-app-02/iis/checkout-apppool",
		"prod-web-02/apt-openssl",
		"prod-k8s-01/payments/configmap/checkout-config",
		"prod-k8s-01/payments/secret/api-keys",
		// Legacy name: rows written before the Secret was renamed to api-keys
		// must still be found by id, not only by the seed_source tag.
		"prod-k8s-01/payments/secret/db-credentials",
		"prod-k8s-01/messaging/deployment/rabbitmq",
		"prod-k8s-01/staging/ingress/checkout-preview",
	}, aptChildSeedNames()...)

	for _, sp := range ambientSpecs() {
		names = append(names, sp.name)
	}

	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, seedID(n))
	}
	return out
}

// aptChildSeedNames returns the seedID suffix of each stored child of the apt
// transaction, derived from the same table seed() inserts from. That is what
// guarantees cleanup can find those children by id.
func aptChildSeedNames() []string {
	out := make([]string, 0, len(aptChildren))
	for _, c := range aptChildren {
		out = append(out, "prod-web-01/apt-nginx/"+c.name)
	}
	return out
}

// aptNginxBeforeVer / aptNginxAfterVer are the versions the apt transaction
// moves between, referenced by the child hashes and the upgrade event.
const (
	aptNginxBeforeVer = "1.24.0-2ubuntu7"
	aptNginxAfterVer  = "1.26.1-1ubuntu1"
)

// aptChild is one stored child of the aggregated apt transaction.
type aptChild struct {
	name, path string
	cat        pb.Category
	ver        bool
	// hashKey is the label the post-upgrade hash is derived from. It is explicit
	// rather than derived from name/path because the original values are part of
	// the seeded state (the drift matrix compares them), so they must not shift.
	hashKey string
}

// aptChildren is the single source of truth for the apt transaction's children:
// seed() inserts from it and the cleanup derives their ids from it, so the two
// cannot drift.
var aptChildren = []aptChild{
	{"mime.types", "/etc/nginx/mime.types", pb.Category_CATEGORY_CONFIG, false, "mime.types"},
	{"fastcgi_params", "/etc/nginx/fastcgi_params", pb.Category_CATEGORY_CONFIG, false, "fastcgi_params"},
	{"conf.d/default.conf", "/etc/nginx/conf.d/default.conf", pb.Category_CATEGORY_CONFIG, false, "default.conf"},
	{"html/index.html", "/usr/share/nginx/html/index.html", pb.Category_CATEGORY_CONFIG, false, "distro-index"},
	{"nginx", "/usr/sbin/nginx", pb.Category_CATEGORY_PACKAGE, true, "nginx-binary"},
	{"nginx.service", "/lib/systemd/system/nginx.service", pb.Category_CATEGORY_CONFIG, false, "nginx.service"},
}

// aptChildHashAfter yields the post-upgrade hash recorded for a child.
func aptChildHashAfter(c aptChild) string {
	return sha256hex(c.hashKey + "@" + aptNginxAfterVer)
}

// ---------------------------------------------------------------------------
// Ambient background volume
// ---------------------------------------------------------------------------
//
// The four flagged changes are the story, but a fleet logs far more than it
// escalates: routine package upgrades, service reloads, registry tweaks and
// drift. The Grafana dashboard's default window is one hour and its charts are
// read for shape — a stacked impact chart, a per-host ranking, a category
// breakdown — so without a baseline of ordinary activity every one of them
// renders as a single bar.
//
// The volume below is deterministic: ids derive from the spec name, times
// derive from `now`, and hashes derive from the path alone. Nothing here is
// random, so two runs on two machines produce the same timeline, and the next
// run clears it exactly like the narrative events (every row carries
// seed_source).

// ambientTarget is one recurring (path, category) pair in a host's routine
// traffic.
type ambientTarget struct {
	targetType string
	path       string
	category   pb.Category
	summary    string
}

// ambientActor is the identity a host's routine changes are attributed to. One
// per host profile rather than per target: on a real fleet the same automation
// account makes the same class of change repeatedly.
type ambientActor struct {
	username string
	uid      string
	proc     string
	cmdline  string
	lineage  []string
	remoteIP string
}

func (a ambientActor) context() *pb.ActorContext {
	return &pb.ActorContext{
		Username:       a.username,
		UidOrSid:       a.uid,
		ProcessName:    a.proc,
		Cmdline:        a.cmdline,
		ProcessLineage: a.lineage,
		RemoteIp:       a.remoteIP,
	}
}

// ambientSpec is one computed background event, before it becomes a
// pb.MutationEvent.
type ambientSpec struct {
	name       string // seedID suffix, and the cleanup key
	hostName   string
	minutesAgo int
	level      pb.ImpactLevel
	category   pb.Category
	action     pb.Action
	targetType string
	path       string
	summary    string
	actor      ambientActor
}

// ambientTargetsLinux / Windows / K8s are the recurring targets per platform.
// Deliberately disjoint from the paths the narrative timeline uses
// (/etc/nginx/nginx.conf, the apt children, the cluster's payments objects):
// overlapping them would let the last background write overwrite the drift
// state the narrative seeder sets up, and the Fleet Drift matrix would report
// the wrong divergence.
var (
	ambientTargetsLinux = []ambientTarget{
		{"file", "/etc/ssh/sshd_config", pb.Category_CATEGORY_CONFIG, "Modified /etc/ssh/sshd_config (Ciphers)"},
		{"file", "/etc/hosts", pb.Category_CATEGORY_NETWORK, "Modified /etc/hosts (resolver entry)"},
		{"package", "openssl", pb.Category_CATEGORY_PACKAGE, "Upgraded openssl 3.0.13 -> 3.0.14"},
		{"service", "systemd-resolved.service", pb.Category_CATEGORY_SERVICE, "Reloaded systemd-resolved.service"},
		{"file", "/etc/rsyslog.conf", pb.Category_CATEGORY_CONFIG, "Modified /etc/rsyslog.conf (remote syslog)"},
		{"user", "svc-backup", pb.Category_CATEGORY_USER, "Created service account svc-backup"},
	}
	ambientTargetsWindows = []ambientTarget{
		{"registry", `HKLM\System\CurrentControlSet\Services\W32Time\Parameters`, pb.Category_CATEGORY_REGISTRY, "Modified W32Time parameters"},
		{"service", "W3SVC", pb.Category_CATEGORY_SERVICE, "Restarted IIS W3SVC"},
		{"user", `CORP\svc-monitor`, pb.Category_CATEGORY_USER, `Added CORP\svc-monitor to Performance Monitor Users`},
		{"file", `C:\Windows\System32\drivers\etc\hosts`, pb.Category_CATEGORY_NETWORK, "Modified hosts file"},
		{"process", "wsus", pb.Category_CATEGORY_PROCESS, "Registered WSUS scheduled scan"},
		{"package", "MSSQL2022-KB5040", pb.Category_CATEGORY_PACKAGE, "Installed MSSQL2022-KB5040"},
	}
	ambientTargetsK8s = []ambientTarget{
		{"k8s_configmap", "/k8s/prod-k8s-01/default/configmaps/feature-flags", pb.Category_CATEGORY_CONFIG, "Modified ConfigMap default/feature-flags"},
		{"k8s_deployment", "/k8s/prod-k8s-01/default/deployments/api-gateway", pb.Category_CATEGORY_SERVICE, "Rolled out Deployment default/api-gateway"},
		{"k8s_secret", "/k8s/prod-k8s-01/default/secrets/telemetry-token", pb.Category_CATEGORY_CONFIG, "Rotated Secret default/telemetry-token"},
		{"k8s_ingress", "/k8s/prod-k8s-01/default/ingresses/api", pb.Category_CATEGORY_NETWORK, "Modified Ingress default/api"},
		{"k8s_configmap", "/k8s/prod-k8s-01/monitoring/configmaps/otel-collector", pb.Category_CATEGORY_CONFIG, "Modified ConfigMap monitoring/otel-collector"},
		{"k8s_deployment", "/k8s/prod-k8s-01/monitoring/deployments/prometheus", pb.Category_CATEGORY_SERVICE, "Rolled out Deployment monitoring/prometheus"},
	}
)

// ambientSpecs computes the background volume: for each host, a repeating pass
// over its target set, with the events spread evenly across the last hour.
//
// Two properties matter and neither is incidental:
//
//   - Every event lands in [3m, 57m] before now. A background event older than
//     the dashboard's one-hour window leaves dead space at the left of every
//     chart; one in the future is invisible to it. The slot arithmetic below
//     exists to keep the highest slot inside that band regardless of how many
//     cycles a host is given.
//   - Each host is phase-shifted by *rotating which target each slot maps to*,
//     not by adding minutes to its clock. Shifting the times would push a
//     busy host's last event past `now`; rotating the sequence distributes the
//     four hosts' events across the window without that risk.
//
// The per-host weights are what make the "Top affected hosts" ranking read as a
// fleet rather than four identical rows: the cluster and the primary web host
// carry the most change, the peer and the Windows app host less.
func ambientSpecs() []ambientSpec {
	linuxActor := ambientActor{
		username: "deploy-bot", uid: "1001", proc: "ansible-playbook",
		cmdline: "ansible-playbook -i inventory site.yml",
		lineage: []string{"systemd", "ansible-playbook"}, remoteIP: "10.0.4.20",
	}
	windowsActor := ambientActor{
		username: `CORP\svc-monitor`, uid: "S-1-5-21-1104746749-1936075387-2494913302-1101",
		proc: "svchost.exe", cmdline: "svchost.exe -k netsvcs",
		lineage: []string{"services.exe", "svchost.exe"}, remoteIP: "10.20.0.11",
	}
	k8sActor := ambientActor{
		username: "argocd-controller", proc: "kubectl", cmdline: "Apply",
		lineage: []string{"argocd-application-controller", "kubectl"}, remoteIP: "10.42.0.7",
	}

	profiles := []struct {
		hostName string
		actor    ambientActor
		targets  []ambientTarget
		cycles   int // how many passes over the target set
		phase    int // rotation offset, to de-align hosts
	}{
		{"prod-k8s-01", k8sActor, ambientTargetsK8s, 14, 0},
		{"prod-web-01", linuxActor, ambientTargetsLinux, 11, 3},
		{"win-app-02", windowsActor, ambientTargetsWindows, 7, 1},
		{"prod-web-02", linuxActor, ambientTargetsLinux, 5, 5},
	}

	// Mostly grouped/drift: Level 1 is reserved for the narrative changes, so
	// the stacked chart's red band stays the signal it is meant to be.
	levels := []pb.ImpactLevel{
		pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
		pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT,
		pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT,
		pb.ImpactLevel_IMPACT_LEVEL_4_FORENSIC,
		pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
		pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT,
	}

	// The slot band, in minutes before now. Chosen to sit inside the one-hour
	// dashboard window with a margin at both ends: the newest event is a few
	// minutes back (so it is settled, not mid-insert) and the oldest is not
	// against the left edge where it is hard to read.
	const newestSlot, oldestSlot = 3, 57

	var out []ambientSpec
	for _, p := range profiles {
		slots := p.cycles * len(p.targets)
		for s := 0; s < slots; s++ {
			// Rotate the target sequence per host rather than shifting its times.
			t := p.targets[(s+p.phase)%len(p.targets)]
			cycle := s / len(p.targets)
			minutes := newestSlot + (s*(oldestSlot-newestSlot))/max(slots-1, 1)

			out = append(out, ambientSpec{
				name:       fmt.Sprintf("ambient/%s/%d/%d", p.hostName, cycle, (s+p.phase)%len(p.targets)),
				hostName:   p.hostName,
				minutesAgo: minutes,
				level:      levels[(s+cycle)%len(levels)],
				category:   t.category,
				action:     ambientAction(t.targetType),
				targetType: t.targetType,
				path:       t.path,
				summary:    t.summary,
				actor:      p.actor,
			})
		}
	}
	return out
}

// ambientAction picks the verb from the target kind, so a package reads as an
// upgrade and a service as a restart rather than everything being "modified".
func ambientAction(targetType string) pb.Action {
	switch targetType {
	case "package":
		return pb.Action_ACTION_UPGRADED
	case "service", "k8s_deployment":
		return pb.Action_ACTION_RESTARTED
	case "user":
		return pb.Action_ACTION_CREATED
	case "process":
		return pb.Action_ACTION_STARTED
	default:
		return pb.Action_ACTION_MODIFIED
	}
}

// hashableTarget reports whether a target participates in host_current_state.
// Services, processes, transactions and users do not (see updateCurrentState),
// so giving them a hash would be misleading.
func hashableTarget(targetType string) bool {
	switch targetType {
	case "service", "process", "transaction", "user":
		return false
	}
	return true
}

// ambientHash is deliberately path-derived rather than host-derived: two hosts
// running the same automation end up with the same file hash, so the background
// volume does not manufacture drift between prod-web-01 and prod-web-02. The
// Fleet Drift matrix is meant to show the *narrative* divergence, not this.
func ambientHash(path string) string { return sha256hex("ambient:" + path) }

// tagEvents applies both markers an inserted event needs: the cleanup tag
// (markSeeded) and the curated hero-panel flag (markAnnotated). Every insert in
// seed() goes through it, so a new event cannot be added with one and silently
// miss the other.
func tagEvents(events []*pb.MutationEvent) []*pb.MutationEvent {
	return markAnnotated(markSeeded(events))
}

// seedAmbient writes the background volume, grouped by host so each host's
// batch goes through one InsertEvents call (which is also what applies their
// current-state rows).
func seedAmbient(ctx context.Context, store *storage.Store, log *slog.Logger, orgID string, hosts map[string]storage.Host, now time.Time) error {
	byHost := map[string][]*pb.MutationEvent{}
	for _, sp := range ambientSpecs() {
		ev := &pb.MutationEvent{
			EventId:          seedID(sp.name),
			AgentTimestampMs: ago(now, sp.minutesAgo).UnixMilli(),
			Level:            sp.level,
			Category:         sp.category,
			Action:           sp.action,
			Summary:          sp.summary,
			Actor:            sp.actor.context(),
			Target: &pb.TargetResource{
				TargetType: sp.targetType,
				PathOrKey:  sp.path,
			},
			Metadata: map[string]string{"content": "text", "classification": "ambient"},
		}
		if hashableTarget(sp.targetType) {
			ev.Target.HashAfter = ambientHash(sp.path)
		}
		byHost[sp.hostName] = append(byHost[sp.hostName], ev)
	}

	total := 0
	for name, evs := range byHost {
		h, ok := hosts[name]
		if !ok {
			return fmt.Errorf("ambient events reference unknown host %q", name)
		}
		if _, _, err := store.InsertEvents(ctx, orgID, h.ID, 0, tagEvents(evs)); err != nil {
			return fmt.Errorf("insert ambient events on %s: %w", name, err)
		}
		total += len(evs)
	}
	log.Info("seeded ambient background volume", "events", total, "hosts", len(byHost))
	return nil
}

func seed(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool) error {
	store := storage.New(pool, nil, 0)
	orgID, err := store.DefaultOrg(ctx)
	if err != nil {
		return fmt.Errorf("resolve default org: %w", err)
	}

	// Make sure today's events partition exists even if migrations predate it.
	if _, err := storage.EnsurePartitions(ctx, pool, time.Now(), 2); err != nil {
		return fmt.Errorf("ensure partitions: %w", err)
	}

	// Re-anchoring moves every event to a new timestamp, so drop last run's
	// rows first; otherwise each `dev.ps1 seed` would add another full copy.
	if err := clearSeededTimeline(ctx, pool, orgID, log); err != nil {
		return err
	}

	now := time.Now()

	// ---- 1. Hosts --------------------------------------------------------
	// prod-web-02 is seeded as the drift peer for prod-web-01 (same distro,
	// subtly different config) so the Fleet Drift matrix has diverged files.
	//
	// prod-k8s-01 is a Kubernetes cluster node rather than a plain VM: its
	// "host" is the cluster, and its changes arrive through the same collector
	// interface as a file edit (see docs/enterprise-catalog.md). Seeding it
	// alongside the VMs is what proves the timeline, drift matrix and post-mortem
	// export read cluster objects exactly as they read /etc/nginx/nginx.conf.
	hostNames := []storage.Host{
		{ID: "prod-web-01", OrgID: orgID, Hostname: "prod-web-01", OSFamily: "linux", OSVersion: "Ubuntu 24.04", AgentVersion: "v0.1.0"},
		{ID: "prod-web-02", OrgID: orgID, Hostname: "prod-web-02", OSFamily: "linux", OSVersion: "Ubuntu 24.04", AgentVersion: "v0.1.0"},
		{ID: "win-app-02", OrgID: orgID, Hostname: "win-app-02", OSFamily: "windows", OSVersion: "Windows Server 2022", AgentVersion: "v0.1.0"},
		{ID: "prod-k8s-01", OrgID: orgID, Hostname: "prod-k8s-01", OSFamily: "kubernetes", OSVersion: "Kubernetes v1.31.2", AgentVersion: "v0.1.0"},
	}
	hosts := map[string]storage.Host{}
	for _, h := range hostNames {
		got, err := store.UpsertHost(ctx, h)
		if err != nil {
			return fmt.Errorf("upsert host %s: %w", h.Hostname, err)
		}
		hosts[h.Hostname] = got
		log.Info("host registered", "hostname", got.Hostname,
			"os", got.OSFamily+" "+got.OSVersion, "status", got.Status, "id", got.ID)
	}
	web := hosts["prod-web-01"]
	win := hosts["win-app-02"]
	k8sHost := hosts["prod-k8s-01"]

	// Anchored relative to this run (see newTimeline) so the timeline sits in
	// the recent past: inside Grafana's default now-6h window and always behind
	// "now".
	tl := newTimeline(now)
	nginxAt := tl.nginxAt
	aptAt := tl.aptAt
	restartAt := tl.restartAt
	indexAt := tl.indexAt
	regAt := tl.regAt

	// ---- 2. prod-web-01: L1 nginx.conf edit (secret scrubbed) ------------
	nginxZ, err := scrubDiff("/etc/nginx/nginx.conf", nginxBefore, nginxAfter)
	if err != nil {
		return err
	}
	nginxAdd, nginxDel := diffStat(diff.Unified("a", "b", nginxBefore, nginxAfter, 3))

	// ---- 3. prod-web-01: L2 apt upgrade nginx (parent + children) --------
	// The parent reports the full collapsed count; a representative subset of
	// children is stored so the expanded card has rows to show.
	const aptChildCount = 134
	aptParentID := seedID("prod-web-01/apt-nginx")
	nginxBeforeVer, nginxAfterVer := aptNginxBeforeVer, aptNginxAfterVer
	children := aptChildren

	// ---- 4. prod-web-01: L1 nginx.service restart ------------------------
	// ---- 5. prod-web-01: L3 index.html drift (deploy-bot) ----------------
	indexZ, err := scrubDiff("/var/www/html/index.html", indexBefore, indexAfter)
	if err != nil {
		return err
	}
	indexAdd, indexDel := diffStat(diff.Unified("a", "b", indexBefore, indexAfter, 3))

	// ---- 6. win-app-02: L1 registry LogLevel change -----------------------
	regZ, err := scrubDiff(`HKLM\Software\Company\App\LogLevel`, regBefore, regAfter)
	if err != nil {
		return err
	}

	webEvents := []*pb.MutationEvent{
		{
			EventId:          seedID("prod-web-01/nginx.conf"),
			AgentTimestampMs: nginxAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          fmt.Sprintf("Modified /etc/nginx/nginx.conf (+%d -%d)", nginxAdd, nginxDel),
			Actor: &pb.ActorContext{
				Username:       "root",
				UidOrSid:       "0",
				LoginUid:       "1000",
				LoginUsername:  "alice",
				Pid:            4242,
				Ppid:           4241,
				ProcessName:    "vim",
				Cmdline:        "vim /etc/nginx/nginx.conf",
				ProcessLineage: []string{"sshd", "bash", "sudo", "vim"},
				RemoteIp:       "192.168.1.50",
			},
			Target: &pb.TargetResource{
				TargetType: "file",
				PathOrKey:  "/etc/nginx/nginx.conf",
				HashBefore: sha256hex(nginxBefore),
				HashAfter:  sha256hex(nginxAfter),
			},
			UnifiedDiffZstd: nginxZ,
			Metadata: map[string]string{
				"content":        "text",
				"classification": "rule:nginx.conf [L1]",
				"rule_name":      "nginx.conf [L1]",
				"rule_tags":      "nginx_vhost,auto-discovered,host:prod-web-01",
				// The edit iterates under CHG-1042, which the seeder mirrors as an
				// approved window bracketing this anchor. Citing it explicitly is
				// what renders the `🎫 CHG-1042 · Approved` badge in the inspector
				// rather than only matching by scope.
				"change_ticket": "CHG-1042",
			},
		},
		{
			EventId:          aptParentID,
			AgentTimestampMs: aptAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
			Category:         pb.Category_CATEGORY_PACKAGE,
			Action:           pb.Action_ACTION_UPGRADED,
			ChildCount:       aptChildCount,
			Summary:          fmt.Sprintf("apt transaction: %d related changes (%d packages)", aptChildCount, aptChildCount),
			Actor: &pb.ActorContext{
				Username:       "root",
				UidOrSid:       "0",
				LoginUid:       "1000",
				LoginUsername:  "alice",
				Pid:            5001,
				Ppid:           0,
				ProcessName:    "apt-get",
				Cmdline:        "apt-get install --only-upgrade nginx",
				ProcessLineage: []string{"sshd", "bash", "sudo", "apt-get"},
				RemoteIp:       "192.168.1.50",
			},
			Target: &pb.TargetResource{TargetType: "transaction", PathOrKey: "apt-get install --only-upgrade nginx"},
			Metadata: map[string]string{
				"event_type":         "TRANSACTION",
				"tool":               "apt",
				"root_pid":           "5001",
				"duration_ms":        "8200",
				"children_emitted":   "6",
				"children_throttled": "128",
				"categories":         "config=5,package=1",
				"packages":           "nginx " + nginxBeforeVer + " -> " + nginxAfterVer,
			},
		},
		{
			EventId:          seedID("prod-web-01/nginx.service"),
			AgentTimestampMs: restartAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_SERVICE,
			Action:           pb.Action_ACTION_RESTARTED,
			Summary:          "Restarted nginx.service",
			Actor: &pb.ActorContext{
				Username:       "root",
				UidOrSid:       "0",
				Pid:            5050,
				Ppid:           1,
				ProcessName:    "systemctl",
				Cmdline:        "systemctl restart nginx",
				ProcessLineage: []string{"systemd", "systemctl"},
			},
			Target:   &pb.TargetResource{TargetType: "service", PathOrKey: "nginx.service"},
			Metadata: map[string]string{"classification": "critical_category"},
		},
		{
			EventId:          seedID("prod-web-01/index.html"),
			AgentTimestampMs: indexAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          fmt.Sprintf("Modified /var/www/html/index.html (+%d -%d)", indexAdd, indexDel),
			Actor: &pb.ActorContext{
				Username:       "deploy-bot",
				UidOrSid:       "1001",
				Pid:            6100,
				Ppid:           6099,
				ProcessName:    "rsync",
				Cmdline:        "rsync -a --delete release/ /var/www/html/",
				ProcessLineage: []string{"systemd", "deploy-bot", "bash", "rsync"},
			},
			Target: &pb.TargetResource{
				TargetType: "file",
				PathOrKey:  "/var/www/html/index.html",
				HashBefore: sha256hex(indexBefore),
				HashAfter:  sha256hex(indexAfter),
			},
			UnifiedDiffZstd: indexZ,
			Metadata:        map[string]string{"content": "text", "classification": "drift"},
		},
	}
	// Representative children of the apt transaction.
	for i, c := range children {
		ev := &pb.MutationEvent{
			EventId:          seedID("prod-web-01/apt-nginx/" + c.name),
			ParentEventId:    aptParentID,
			AgentTimestampMs: aptAt.Add(time.Duration(i+1) * 900 * time.Millisecond).UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
			Category:         c.cat,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          fmt.Sprintf("Modified %s", c.path),
			Actor: &pb.ActorContext{
				Username:       "root",
				UidOrSid:       "0",
				Pid:            5002,
				Ppid:           5001,
				ProcessName:    "dpkg",
				Cmdline:        "dpkg --unpack nginx",
				ProcessLineage: []string{"sshd", "bash", "sudo", "apt-get", "dpkg"},
			},
			Target:   &pb.TargetResource{TargetType: "file", PathOrKey: c.path, HashAfter: aptChildHashAfter(c)},
			Metadata: map[string]string{"content": "binary"},
		}
		if c.ver {
			ev.Action = pb.Action_ACTION_UPGRADED
			ev.Summary = fmt.Sprintf("Upgraded %s %s -> %s", c.path, nginxBeforeVer, nginxAfterVer)
			ev.Target.VersionBefore, ev.Target.VersionAfter = nginxBeforeVer, nginxAfterVer
		}
		webEvents = append(webEvents, ev)
	}

	winEvents := []*pb.MutationEvent{
		{
			EventId:          seedID("win-app-02/registry-loglevel"),
			AgentTimestampMs: regAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_REGISTRY,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          "Modified HKLM\\Software\\Company\\App\\LogLevel (INFO -> DEBUG)",
			Actor: &pb.ActorContext{
				Username:       "CORP\\Administrator",
				UidOrSid:       "S-1-5-21-1104746749-1936075387-2494913302-500",
				Pid:            3320,
				Ppid:           1180,
				ProcessName:    "powershell.exe",
				Cmdline:        "powershell.exe -Command Set-ItemProperty -Path 'HKLM:\\Software\\Company\\App' -Name LogLevel -Value DEBUG",
				ProcessLineage: []string{"services.exe", "powershell.exe"},
				RemoteIp:       "10.20.0.5",
			},
			Target: &pb.TargetResource{
				TargetType:    "registry",
				PathOrKey:     `HKLM\Software\Company\App\LogLevel`,
				HashBefore:    sha256hex(regBefore),
				HashAfter:     sha256hex(regAfter),
				VersionBefore: "INFO",
				VersionAfter:  "DEBUG",
			},
			UnifiedDiffZstd: regZ,
			Metadata:        map[string]string{"content": "text", "classification": "critical_path"},
		},
	}

	if _, _, err := store.InsertEvents(ctx, orgID, web.ID, 0, tagEvents(webEvents)); err != nil {
		return fmt.Errorf("insert prod-web-01 events: %w", err)
	}
	log.Info("seeded prod-web-01 timeline", "events", len(webEvents), "apt_children", len(children), "apt_total", aptChildCount)

	if _, _, err := store.InsertEvents(ctx, orgID, win.ID, 0, tagEvents(winEvents)); err != nil {
		return fmt.Errorf("insert win-app-02 events: %w", err)
	}
	log.Info("seeded win-app-02 timeline", "events", len(winEvents))

	// ---- 6b. prod-k8s-01: Kubernetes cluster configuration changes -------
	// These mirror what the agent's Kubernetes collector emits for a ConfigMap
	// edit, a Secret rotation, a Deployment rollout and a staging Ingress change.
	// Each is attributed from managedFields (the manager is the actor) and the
	// scrubbed diff is produced by the same pipeline as a file edit.
	if err := seedKubernetes(ctx, store, log, orgID, k8sHost, tl, now); err != nil {
		return fmt.Errorf("seed prod-k8s-01: %w", err)
	}

	// ---- 6c. prod-web-02: L2 apt transaction (the second annotated flag) --
	// prod-web-02 is prod-web-01's drift peer, so it needs a change of its own
	// for two reasons: the hero panel's -18m flag has to sit on a host that is
	// actually on the timeline, and "Top affected hosts" should rank a peer
	// above the cluster's noise rather than showing the drift host at zero.
	//
	// The target is a transaction, not a file: prod-web-02's file state is
	// written below from `peerState` to create the deliberate drift, and an
	// event touching one of those paths would overwrite it on insert.
	peer := hosts["prod-web-02"]
	peerAptID := seedID("prod-web-02/apt-openssl")
	peerEvents := []*pb.MutationEvent{
		{
			EventId:          peerAptID,
			AgentTimestampMs: tl.peerAptAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
			Category:         pb.Category_CATEGORY_PACKAGE,
			Action:           pb.Action_ACTION_UPGRADED,
			ChildCount:       41,
			Summary:          "apt transaction: 41 related changes (openssl security update)",
			Actor: &pb.ActorContext{
				Username:       "root",
				UidOrSid:       "0",
				LoginUid:       "1000",
				LoginUsername:  "pk",
				Pid:            7020,
				Ppid:           7019,
				ProcessName:    "apt-get",
				Cmdline:        "apt-get install --only-upgrade openssl libssl3",
				ProcessLineage: []string{"sshd", "bash", "sudo", "apt-get"},
				RemoteIp:       "192.168.1.51",
			},
			Target: &pb.TargetResource{TargetType: "transaction", PathOrKey: "apt-get install --only-upgrade openssl"},
			Metadata: map[string]string{
				"event_type":   "TRANSACTION",
				"tool":         "apt",
				"root_pid":     "7020",
				"duration_ms":  "3100",
				"categories":   "config=12,package=29",
				"packages":     "openssl 3.0.13-0ubuntu3.4 -> 3.0.13-0ubuntu3.5, libssl3 3.0.13-0ubuntu3.4 -> 3.0.13-0ubuntu3.5",
				"seed_managed": "peer",
			},
		},
	}
	if _, _, err := store.InsertEvents(ctx, orgID, peer.ID, 0, tagEvents(peerEvents)); err != nil {
		return fmt.Errorf("insert prod-web-02 events: %w", err)
	}
	log.Info("seeded prod-web-02 timeline", "events", len(peerEvents))

	// ---- 6c-bis. Surgical watchers: IIS app pool & settings_db table ------
	// The two events the console's targeted watchers exist for. They are written
	// through the same diff + scrub pipeline as a file edit, so the inspector
	// shows real canonical YAML with the pool's state transition and the
	// settings table's flipped TLS flag.
	if err := seedWatchTargets(ctx, store, log, orgID, web, win, tl); err != nil {
		return fmt.Errorf("seed watched targets: %w", err)
	}

	// ---- 6d. Ambient background volume -----------------------------------
	// The routine package upgrades, service reloads and config tweaks a fleet
	// logs constantly. Without them every chart on the dashboard renders as one
	// bar per flagged change; with them the one-hour window has the shape the
	// design assumes (see ambientSpecs).
	if err := seedAmbient(ctx, store, log, orgID, hosts, now); err != nil {
		return fmt.Errorf("seed ambient volume: %w", err)
	}

	// ---- 7. prod-web-02 drift peer: slight config differences ------------
	// Same inventory as prod-web-01 except for nginx.conf and the deployed
	// index.html (diverged) plus one extra vhost file (only on web-02).
	peerState := []stateRow{
		{"file", "/etc/nginx/nginx.conf", sha256hex(nginxPeer), ""},
		{"file", "/var/www/html/index.html", sha256hex(indexPeer), ""},
		{"file", "/etc/nginx/mime.types", aptChildHashAfter(children[0]), ""},
		{"file", "/etc/nginx/fastcgi_params", aptChildHashAfter(children[1]), ""},
		{"file", "/etc/nginx/conf.d/default.conf", aptChildHashAfter(children[2]), ""},
		{"file", "/usr/share/nginx/html/index.html", aptChildHashAfter(children[3]), ""},
		{"file", "/usr/sbin/nginx", aptChildHashAfter(children[4]), nginxAfterVer},
		{"file", "/lib/systemd/system/nginx.service", aptChildHashAfter(children[5]), ""},
		{"file", "/etc/nginx/conf.d/upstream.conf", sha256hex("upstream-peer"), ""},
	}
	for _, s := range peerState {
		if err := seedState(ctx, store, pool, orgID, peer.ID, s, now); err != nil {
			return fmt.Errorf("seed prod-web-02 state %s: %w", s.path, err)
		}
	}
	log.Info("seeded prod-web-02 drift state", "rows", len(peerState))

	// ---- 8. Auto-discovery recommendations -------------------------------
	// The agents report discovered workloads on their heartbeat; the seeder
	// stands in for those agents so the console's review queue has live rows.
	if err := seedRecommendations(ctx, store, pool, orgID, web.ID, win.ID, k8sHost.ID, log); err != nil {
		return fmt.Errorf("seed recommendations: %w", err)
	}

	// ---- 8b. Change-ticket mirror ---------------------------------------
	// The demo's ITSM mirror, re-anchored to today's event times so the
	// correlation produces meaningful verdicts on a long-lived database.
	if err := seedChangeTickets(ctx, store, log, orgID, now, tl); err != nil {
		return fmt.Errorf("seed change tickets: %w", err)
	}

	// ---- 8c. Notification delivery log -----------------------------------
	// The Grafana health panel reports the p95 dispatch latency and the success
	// rate out of webhook_deliveries. A freshly migrated database has an empty
	// table, so those two rows would read "p95 n/a ms" and "none in window" on
	// a dashboard that is otherwise fully populated. Seeding a realistic hour of
	// dispatches keeps the pipeline row answering the question it is there for.
	if err := seedWebhookDeliveries(ctx, store, log, orgID, now); err != nil {
		return fmt.Errorf("seed webhook deliveries: %w", err)
	}

	// ---- 9. Drift summary (for the operator) -----------------------------
	rows, err := store.Drift(ctx, orgID, web.ID, peer.ID)
	if err != nil {
		log.Warn("drift query (informational)", "err", err)
	} else {
		for _, d := range rows {
			log.Info("drift", "path", d.PathOrKey, "only_on", d.OnlyOn)
		}
	}

	// ---- 10. Refresh last_seen_at ----------------------------------------
	// The seeded fleet has no agent process behind it, so every host would drift
	// past storage.OnlineWindow within 15 minutes and the whole fleet would read
	// offline. Stamping NOW() here (and again every 30s by the server's demo
	// heartbeat) keeps `dev.ps1 seed` producing a fleet that reports online
	// consistently in the console, in /metrics and to Checkmk/Zabbix.
	if n, err := store.RefreshHostsLastSeen(ctx, orgID); err != nil {
		return fmt.Errorf("refresh hosts last_seen: %w", err)
	} else {
		log.Info("hosts marked online", "hosts", n)
	}

	// ---- 11. Re-anchor the Grafana flags --------------------------------
	// The timeline moved, so every flag drawn from the previous run now points at
	// a row this run deleted. Clearing and re-pushing here — rather than leaving
	// it to `statetrack-grafana-seed` — is what keeps a single `dev.ps1 seed`
	// from producing a dashboard whose "Inspect in StateTrack" links 404. The
	// deep-link check below is the guard on that promise: it re-reads the ids the
	// annotations were built from and asserts the rows are still there.
	if err := resyncGrafanaAnnotations(ctx, log, pool, orgID); err != nil {
		// A missing Grafana is not a seed failure; a broken one only costs the
		// dashboard its flags. Say so and keep the database timeline.
		log.Warn("grafana annotations not refreshed", "err", err)
	}
	return nil
}

// resyncGrafanaAnnotations refreshes the dashboard's flags after a re-anchor.
//
// Split out of seed() so the "is Grafana even up?" decision is one readable
// branch, and so the deep-link verification always runs against the ids that
// were actually pushed.
func resyncGrafanaAnnotations(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, orgID string) error {
	g, err := newGrafanaSync(ctx)
	if err != nil {
		return fmt.Errorf("grafana not reachable (start it with dev.ps1 up): %w", err)
	}

	pushed, err := g.resyncAnnotations(ctx, pool, orgID, log)
	if err != nil {
		return err
	}
	if pushed == 0 {
		return errors.New("no annotated events found to flag")
	}

	// Re-read the ids from the same query the pusher used, then assert each one
	// resolves. This is deliberately after the push: it validates the artifact a
	// viewer will click, not the list we hoped to push.
	changes, err := loadAnnotatedChanges(ctx, pool, orgID, time.Now().Add(-2*time.Hour))
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(changes))
	for _, c := range changes {
		ids = append(ids, c.id)
	}
	if err := verifyDeepLinks(ctx, pool, orgID, ids); err != nil {
		return err
	}
	log.Info("grafana flags re-anchored", "annotations", pushed, "deep_links_verified", len(ids))
	return nil
}

// seedWebhookDeliveries writes a realistic hour of notification dispatches into
// webhook_deliveries.
//
// The table is normally written by the notification dispatcher as it delivers a
// change, which means a database that has only ever been seeded has no rows at
// all: the Grafana "Pipeline & system health" panel then reports "p95 n/a ms"
// and "none in window" underneath an hour of changes that supposedly raised
// alerts. That reads as a broken pipeline rather than an idle demo.
//
// Idempotent by endpoint: the demo rows point at a reserved `statetrack-demo`
// URL under the `.invalid` reserved TLD, so a re-run replaces exactly its own
// history and never touches a real channel's delivery log. It is also not a
// webhook-shaped URL on purpose: a real-looking endpoint in committed source
// trips secret scanners (GitHub push protection among them) for a string that
// was never a credential. Latencies are derived from the loop index rather than
// randomised, so two runs produce the same p95.
func seedWebhookDeliveries(ctx context.Context, store *storage.Store, log *slog.Logger, orgID string, now time.Time) error {
	const demoEndpoint = "https://example.invalid/slack-webhook/statetrack-demo"

	if _, err := store.Pool().Exec(ctx, `
		DELETE FROM webhook_deliveries
		WHERE org_id = $1::uuid AND endpoint_url = $2`, orgID, demoEndpoint); err != nil {
		return fmt.Errorf("clear previous demo deliveries: %w", err)
	}

	// 18 dispatches, one every ~3 minutes, so the window has a plausible rate
	// without overwhelming the channel. The latency curve (42..128 ms) spans
	// what a healthy SaaS webhook round trip actually looks like.
	inserted := 0
	for i := 0; i < 18; i++ {
		at := now.Add(-time.Duration(i) * 3 * time.Minute).Add(-17 * time.Second)
		latency := 42 + (i*13)%87
		// Written straight to the table rather than through
		// store.LogWebhookDelivery because that stamps created_at = NOW(): these
		// rows have to be spread across the hour, or the panel's p95 would be
		// computed over a single instant.
		if _, err := store.Pool().Exec(ctx, `
			INSERT INTO webhook_deliveries
			    (org_id, provider, endpoint_url, status_code, latency_ms, success, attempts, sample, created_at)
			VALUES ($1::uuid, 'slack', $2, 200, $3, TRUE, 1, TRUE, $4)`,
			orgID, demoEndpoint, latency, at); err != nil {
			return fmt.Errorf("seed webhook delivery: %w", err)
		}
		inserted++
	}
	log.Info("seeded notification deliveries", "rows", inserted, "provider", "slack")
	return nil
}

// seedChangeTickets upserts the demo change-request mirror and anchors its
// windows to *today's* seeded event times.
//
// The migration seeds three tickets as well, but with windows relative to when
// the migration ran. On a long-lived dev database that is days in the past, so a
// re-run of the seeder would leave every approved window closed and the whole
// change-control view would read as "expired". Upserting here — keyed on the
// reference, exactly as a real sync job would — keeps the mirror aligned with
// the timeline the seeder just wrote, run after run.
//
// The set is chosen to exercise every verdict the badge can produce:
//
//	CHG-1042  approved + in window  -> "CHG-1042 · Approved"  (nginx.conf)
//	CHG-1108  still pending         -> "Unapproved Change"    (k8s release)
//	OPS-8813  approved, scoped      -> "OPS-8813 · Approved"  (win registry)
//	OPS-9042  pending, scoped away  -> mirror noise
//	CHG-0987  rejected              -> a refused change in the mirror
func seedChangeTickets(ctx context.Context, store *storage.Store, log *slog.Logger, orgID string, now time.Time, tl timeline) error {
	// Anchored to the same relative offsets the timeline uses (see newTimeline),
	// so an approved window actually brackets the change it authorised.
	nginxAt := tl.nginxAt
	k8sAt := tl.k8sCMAt
	regAt := tl.regAt

	tickets := []storage.ChangeTicket{
		{
			Kind:         "servicenow",
			Ref:          "CHG-1042",
			Status:       "approved",
			Summary:      "Rotate nginx upstream pool and reload the web tier",
			URL:          "https://acme.service-now.com/change_request.do?sys_id=chg1042",
			Hosts:        []string{"prod-web-01", "prod-web-02"},
			Environments: []string{"production"},
			Paths:        []string{"/etc/nginx/**"},
			WindowStart:  nginxAt.Add(-30 * time.Minute),
			WindowEnd:    nginxAt.Add(4 * time.Hour),
			RequestedBy:  "sarah@statetrack.io",
		},
		{
			Kind:         "servicenow",
			Ref:          "CHG-1108",
			Status:       "requested", // awaiting CAB approval — the unauthorised finding
			Summary:      "Kubernetes prod namespace config rollout (awaiting CAB approval)",
			URL:          "https://acme.service-now.com/change_request.do?sys_id=chg1108",
			Hosts:        []string{"prod-k8s-01"},
			Environments: []string{"production"},
			Paths:        []string{"/k8s/prod-k8s-01/payments/**", "/k8s/prod-k8s-01/messaging/**"},
			WindowStart:  k8sAt.Add(-30 * time.Minute),
			WindowEnd:    k8sAt.Add(4 * time.Hour),
			RequestedBy:  "sarah@statetrack.io",
		},
		{
			Kind:         "jira",
			Ref:          "OPS-8813",
			Status:       "approved",
			Summary:      "Emergency SQL Server log level reduction",
			URL:          "https://acme.atlassian.net/browse/OPS-8813",
			Hosts:        []string{"win-app-02"},
			Environments: []string{"production"},
			Paths:        []string{`HKLM\Software\Company\App\**`},
			WindowStart:  regAt.Add(-30 * time.Minute),
			WindowEnd:    regAt.Add(3 * time.Hour),
			RequestedBy:  "pk@statetrack.io",
		},
		{
			Kind:         "jira",
			Ref:          "OPS-9042",
			Status:       "requested",
			Summary:      "Enable debug logging on the application registry hive (other host)",
			URL:          "https://acme.atlassian.net/browse/OPS-9042",
			Hosts:        []string{"win-app-01"},
			Environments: []string{"production"},
			Paths:        []string{`HKLM\Software\Company\App\*`},
			WindowStart:  now.Add(-12 * time.Hour),
			WindowEnd:    now.Add(12 * time.Hour),
			RequestedBy:  "jdoe@statetrack.io",
		},
		{
			Kind:         "manual",
			Ref:          "CHG-0987",
			Status:       "rejected",
			Summary:      "Proposed wildcard certificate swap on the staging ingress",
			Hosts:        []string{"prod-k8s-01"},
			Environments: []string{"staging"},
			Paths:        []string{"/k8s/prod-k8s-01/staging/**"},
			WindowStart:  now.Add(-96 * time.Hour),
			WindowEnd:    now.Add(-90 * time.Hour),
			RequestedBy:  "deploy-bot@statetrack.io",
		},
	}

	for _, t := range tickets {
		got, err := store.UpsertChangeTicket(ctx, orgID, t)
		if err != nil {
			return fmt.Errorf("upsert change ticket %s: %w", t.Ref, err)
		}
		log.Info("change ticket mirrored", "ref", got.Ref, "kind", got.Kind,
			"status", got.Status, "authorized", got.Authorized)
	}
	return nil
}

// seedWatchTargets writes the two changes the surgical watchers exist for, and
// the console rules that made them watched targets in the first place.
//
// Both events carry the *canonical YAML* documents the collectors render, so the
// inspector's diff is the artifact an operator would see in production: a pool
// that stopped and re-identified, and a settings table whose TLS verification
// was switched off while its webhook secret rotated. Values that were scrubbed
// at the edge are already stubs here — the seeder never writes a cleartext
// secret, which is the same guarantee the agent makes.
func seedWatchTargets(ctx context.Context, store *storage.Store, log *slog.Logger, orgID string, web, win storage.Host, tl timeline) error {
	poolPath := "iis://apppool/CheckoutAppPool"
	poolZ, err := scrubDiff(poolPath, checkoutPoolBefore, checkoutPoolAfter)
	if err != nil {
		return err
	}
	poolAdd, poolDel := diffStat(diff.Unified("a", "b", checkoutPoolBefore, checkoutPoolAfter, 3))

	tablePath := "db://postgres/settings_db/tables/public.app_settings"
	// The after document is rendered per run so its `updated_at` rows match the
	// event's occurred_at rather than a hardcoded day.
	appSettingsRendered := renderAppSettingsAfter(tl.dbAt)
	tableZ, err := scrubDiff(tablePath, appSettingsBefore, appSettingsRendered)
	if err != nil {
		return err
	}
	tableAdd, tableDel := diffStat(diff.Unified("a", "b", appSettingsBefore, appSettingsRendered, 3))

	dbEvents := []*pb.MutationEvent{
		{
			EventId:          seedID("prod-web-01/settings_db/app_settings"),
			AgentTimestampMs: tl.dbAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary: fmt.Sprintf(
				"Modified settings_db public.app_settings (+%d -%d): payment_gateway.verify_tls true -> false, stripe_webhook_secret rotated",
				tableAdd, tableDel),
			Actor: &pb.ActorContext{
				Username:    "dba_sarah",
				UidOrSid:    "16389",
				ProcessName: "psql",
				Cmdline:     "psql -h db.internal -d settings_db -c \"UPDATE app_settings SET value='false' WHERE key='payment_gateway.verify_tls'\"",
				// The watcher attributes a database change from pg_stat_activity:
				// the database user, the client tool and the client address, with
				// no process lineage because the writer is not a local process.
				ProcessLineage: []string{"psql"},
				RemoteIp:       "10.0.14.22",
			},
			Target: &pb.TargetResource{
				TargetType: "database_table",
				PathOrKey:  tablePath,
				HashBefore: sha256hex(appSettingsBefore),
				HashAfter:  sha256hex(appSettingsRendered),
			},
			UnifiedDiffZstd: tableZ,
			Metadata: map[string]string{
				"content":         "text",
				"attribution":     "database_session",
				"database_user":   "dba_sarah",
				"database_client": "psql",
				"client_ip":       "10.0.14.22",
				"classification":  "rule:public.app_settings [L1]",
				"rule_name":       "public.app_settings [L1]",
				"rule_tags":       "console,database,settings_db",
			},
		},
	}

	iisEvents := []*pb.MutationEvent{
		{
			EventId:          seedID("win-app-02/iis/checkout-apppool"),
			AgentTimestampMs: tl.iisAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_SERVICE,
			Action:           pb.Action_ACTION_STOPPED,
			Summary: fmt.Sprintf(
				"Application pool CheckoutAppPool stopped (Started -> Stopped), identity ApplicationPoolIdentity -> SpecificUser (CORP\\svc_checkout) (+%d -%d)",
				poolAdd, poolDel),
			Actor: &pb.ActorContext{
				Username:       `CORP\Administrator`,
				UidOrSid:       "S-1-5-21-1104746749-1936075387-2494913302-500",
				Pid:            6844,
				Ppid:           1176,
				ProcessName:    "InetMgr.exe",
				Cmdline:        `"C:\Windows\system32\inetsrv\InetMgr.exe"`,
				ProcessLineage: []string{"explorer.exe", "InetMgr.exe"},
				RemoteIp:       "10.20.0.14",
			},
			Target: &pb.TargetResource{
				TargetType:    "iis_apppool",
				PathOrKey:     poolPath,
				HashBefore:    sha256hex(checkoutPoolBefore),
				HashAfter:     sha256hex(checkoutPoolAfter),
				VersionBefore: "Started",
				VersionAfter:  "Stopped",
			},
			UnifiedDiffZstd: poolZ,
			Metadata: map[string]string{
				"content":        "text",
				"attribution":    "iis_manager_process",
				"iis_state":      "Stopped",
				"classification": "critical_path",
				"rule_name":      "CheckoutAppPool [L1]",
				"rule_tags":      "console,iis,payments",
			},
		},
	}

	if _, _, err := store.InsertEvents(ctx, orgID, web.ID, 0, tagEvents(dbEvents)); err != nil {
		return fmt.Errorf("insert settings_db event: %w", err)
	}
	if _, _, err := store.InsertEvents(ctx, orgID, win.ID, 0, tagEvents(iisEvents)); err != nil {
		return fmt.Errorf("insert iis app pool event: %w", err)
	}
	log.Info("seeded surgical watcher events", "settings_db", 1, "iis_apppool", 1)

	// The console rules behind them, so the Watched Targets table shows the same
	// targets the events came from rather than a seeded preview. CreateWatchRule
	// replaces by (scope, name), which is what makes a re-seed idempotent.
	rules := []storage.WatchRuleInput{
		{HostScope: win.Hostname, TargetType: storage.WatchTypeIISPool,
			Pattern: poolPath, Level: storage.ImpactLevelCritical,
			Name: "CheckoutAppPool", Tags: []string{"iis", "payments"}},
		{HostScope: web.Hostname, TargetType: storage.WatchTypeDBTable,
			Pattern: tablePath, Level: storage.ImpactLevelCritical,
			Name: "public.app_settings", Tags: []string{"database", "settings_db"}},
		{HostScope: web.Hostname, TargetType: storage.WatchTypeDBTable,
			Pattern: "db://postgres/settings_db/tables/public.payment_gateways", Level: storage.ImpactLevelCritical,
			Name: "public.payment_gateways", Tags: []string{"database", "payments"}},
		{HostScope: web.Hostname, TargetType: storage.WatchTypeFile,
			Pattern: "/opt/checkout/.env", Level: storage.ImpactLevelCritical,
			Name: ".env", Tags: []string{"secrets"}},
		{HostScope: win.Hostname, TargetType: storage.WatchTypeFile,
			Pattern: `C:\inetpub\wwwroot\checkout\web.config`, Level: storage.ImpactLevelCritical,
			Name: "web.config", Tags: []string{"iis", "payments"}},
		{HostScope: storage.FleetScope, TargetType: storage.WatchTypeDBParams,
			Pattern: "db://postgres/settings_db/server_params", Level: storage.ImpactLevelCritical,
			Name: "postgres server_params", Tags: []string{"database", "baseline"}},
	}
	for _, in := range rules {
		if _, err := store.CreateWatchRule(ctx, orgID, "seed@statetrack.io", in); err != nil {
			return fmt.Errorf("seed watch rule %q: %w", in.Name, err)
		}
	}
	log.Info("seeded watched targets", "rules", len(rules))
	return nil
}

// seedKubernetes inserts the cluster's configuration-change timeline on the
// prod-k8s-01 host: a ConfigMap edit, a Secret rotation, a Deployment rollout
// and a staging Ingress change.
//
// Each event is what the agent's Kubernetes collector would emit. The scrubbed
// diff is produced by the same pipeline a file edit uses, the actor is the
// managedFields manager the cluster recorded, and the path follows the
// documented `/k8s/<cluster>/<namespace>/<plural>/<name>` shape so the
// classifier, the drift matrix and the post-mortem export all treat a cluster
// object as one more tracked document.
func seedKubernetes(ctx context.Context, store *storage.Store, log *slog.Logger, orgID string, host storage.Host, tl timeline, now time.Time) error {
	// Anchor the cluster's changes to the same relative offsets as the VM
	// timeline (see newTimeline), interleaved so a post-mortem window around any
	// one change picks up the neighbours it should.
	cmAt := tl.k8sCMAt
	secretAt := tl.k8sSecretAt
	deployAt := tl.k8sDeployAt
	ingressAt := tl.k8sIngressAt

	cmZ, err := scrubDiff("/k8s/prod-k8s-01/payments/configmaps/checkout-config", k8sConfigMapBefore, k8sConfigMapAfter)
	if err != nil {
		return err
	}
	cmAdd, cmDel := diffStat(diff.Unified("a", "b", k8sConfigMapBefore, k8sConfigMapAfter, 3))

	secretZ, err := scrubDiff("/k8s/prod-k8s-01/payments/secrets/api-keys", k8sSecretBefore, k8sSecretAfter)
	if err != nil {
		return err
	}

	deployZ, err := scrubDiff("/k8s/prod-k8s-01/messaging/deployments/rabbitmq", k8sDeployBefore, k8sDeployAfter)
	if err != nil {
		return err
	}
	deployAdd, deployDel := diffStat(diff.Unified("a", "b", k8sDeployBefore, k8sDeployAfter, 3))

	// The staging Ingress event below is a Level 3 drift: the catalog's
	// kubernetes_dev profile tracks a non-production namespace with metadata and
	// a SHA-256 hash only, so no diff is attached (matching the "diff: false" the
	// recommendation carries). This is why the ingress document pair above is
	// used only for its before/after hashes.

	events := []*pb.MutationEvent{
		{
			EventId:          seedID("prod-k8s-01/payments/configmap/checkout-config"),
			AgentTimestampMs: cmAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          fmt.Sprintf("Modified ConfigMap payments/checkout-config (+%d -%d)", cmAdd, cmDel),
			Actor: &pb.ActorContext{
				Username:       "argocd-controller",
				ProcessName:    "kubectl",
				Cmdline:        "Apply",
				ProcessLineage: []string{"argocd-application-controller", "kubectl"},
				RemoteIp:       "10.42.0.7",
			},
			Target: &pb.TargetResource{
				TargetType: "k8s_configmap",
				PathOrKey:  "/k8s/prod-k8s-01/payments/configmaps/checkout-config",
				HashBefore: sha256hex(k8sConfigMapBefore),
				HashAfter:  sha256hex(k8sConfigMapAfter),
			},
			UnifiedDiffZstd: cmZ,
			Metadata: map[string]string{
				"content":              "text",
				"attribution":          "k8s_managed_fields",
				"classification":       "rule:prod-k8s-01 ConfigMaps [L1]",
				"rule_name":            "prod-k8s-01 ConfigMaps [L1]",
				"rule_tags":            "k8s_configmap,auto-discovered,namespace:payments",
				"kubernetes_namespace": "payments",
				"kubernetes_resource":  "checkout-config",
				"kubernetes_cluster":   "prod-k8s-01",
				// The change cites CHG-1108, which is still awaiting CAB approval.
				// A citation is the strongest evidence the correlation accepts, and
				// citing a *pending* ticket is precisely the finding the control
				// exists to surface — see internal/itsm's decision table, case 3.
				"change_ticket": "CHG-1108",
			},
		},
		{
			EventId:          seedID("prod-k8s-01/payments/secret/api-keys"),
			AgentTimestampMs: secretAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          "Rotated Secret payments/api-keys (CHECKOUT_API_KEY rotated, values redacted at the edge)",
			Actor: &pb.ActorContext{
				Username:       "argocd-controller",
				ProcessName:    "kubectl",
				Cmdline:        "Apply",
				ProcessLineage: []string{"argocd-application-controller", "kubectl"},
				RemoteIp:       "10.42.0.7",
			},
			Target: &pb.TargetResource{
				TargetType: "k8s_secret",
				PathOrKey:  "/k8s/prod-k8s-01/payments/secrets/api-keys",
				HashBefore: sha256hex(k8sSecretBefore),
				HashAfter:  sha256hex(k8sSecretAfter),
			},
			UnifiedDiffZstd: secretZ,
			Metadata: map[string]string{
				"content":              "text",
				"attribution":          "k8s_managed_fields",
				"classification":       "rule:prod-k8s-01 Secrets [L1]",
				"rule_name":            "prod-k8s-01 Secrets [L1]",
				"rule_tags":            "k8s_secret,auto-discovered,namespace:payments",
				"kubernetes_namespace": "payments",
				"kubernetes_resource":  "api-keys",
				"kubernetes_cluster":   "prod-k8s-01",
				"change_ticket":        "CHG-1108",
			},
		},
		{
			EventId:          seedID("prod-k8s-01/messaging/deployment/rabbitmq"),
			AgentTimestampMs: deployAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL,
			Category:         pb.Category_CATEGORY_SERVICE,
			Action:           pb.Action_ACTION_RESTARTED,
			Summary:          fmt.Sprintf("Rolled out Deployment messaging/rabbitmq (revision 7 -> 8) (+%d -%d)", deployAdd, deployDel),
			Actor: &pb.ActorContext{
				Username:       "argocd-controller",
				ProcessName:    "kubectl",
				Cmdline:        "Apply",
				ProcessLineage: []string{"argocd-application-controller", "kubectl"},
				RemoteIp:       "10.42.0.7",
			},
			Target: &pb.TargetResource{
				TargetType: "k8s_deployment",
				PathOrKey:  "/k8s/prod-k8s-01/messaging/deployments/rabbitmq",
				HashBefore: sha256hex(k8sDeployBefore),
				HashAfter:  sha256hex(k8sDeployAfter),
			},
			UnifiedDiffZstd: deployZ,
			Metadata: map[string]string{
				"content":              "text",
				"attribution":          "k8s_managed_fields",
				"classification":       "rule:prod-k8s-01 Deployments [L1]",
				"rule_name":            "prod-k8s-01 Deployments [L1]",
				"rule_tags":            "k8s_deployment,auto-discovered,namespace:messaging",
				"kubernetes_namespace": "messaging",
				"kubernetes_resource":  "rabbitmq",
				"kubernetes_cluster":   "prod-k8s-01",
				"change_ticket":        "CHG-1108",
			},
		},
		{
			EventId:          seedID("prod-k8s-01/staging/ingress/checkout-preview"),
			AgentTimestampMs: ingressAt.UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          "Modified Ingress staging/checkout-preview (host rule added)",
			Actor: &pb.ActorContext{
				Username:       "kubectl",
				ProcessName:    "kubectl",
				Cmdline:        "Update",
				ProcessLineage: []string{"bash", "kubectl"},
				RemoteIp:       "10.42.0.14",
			},
			Target: &pb.TargetResource{
				TargetType: "k8s_ingress",
				PathOrKey:  "/k8s/prod-k8s-01/staging/ingresses/checkout-preview",
				HashBefore: sha256hex(k8sIngressBefore),
				HashAfter:  sha256hex(k8sIngressAfter),
			},
			Metadata: map[string]string{
				"content":              "text",
				"attribution":          "k8s_managed_fields",
				"classification":       "drift",
				"kubernetes_namespace": "staging",
				"kubernetes_resource":  "checkout-preview",
				"kubernetes_cluster":   "prod-k8s-01",
			},
		},
	}

	if _, _, err := store.InsertEvents(ctx, orgID, host.ID, 0, tagEvents(events)); err != nil {
		return fmt.Errorf("insert prod-k8s-01 events: %w", err)
	}
	log.Info("seeded prod-k8s-01 timeline", "events", len(events))

	// Cluster resources in the drift state, so the drift matrix's Kubernetes
	// column is populated from real state rather than only from the fallback
	// matrix the console ships.
	k8sState := []stateRow{
		{"k8s_configmap", "/k8s/prod-k8s-01/payments/configmaps/checkout-config", sha256hex(k8sConfigMapAfter), ""},
		{"k8s_secret", "/k8s/prod-k8s-01/payments/secrets/api-keys", sha256hex(k8sSecretAfter), ""},
		{"k8s_deployment", "/k8s/prod-k8s-01/messaging/deployments/rabbitmq", sha256hex(k8sDeployAfter), ""},
		{"k8s_ingress", "/k8s/prod-k8s-01/staging/ingresses/checkout-preview", sha256hex(k8sIngressAfter), ""},
	}
	for _, s := range k8sState {
		if err := seedState(ctx, store, store.Pool(), orgID, host.ID, s, now); err != nil {
			return fmt.Errorf("seed prod-k8s-01 state %s: %w", s.path, err)
		}
	}
	log.Info("seeded prod-k8s-01 state", "rows", len(k8sState))
	return nil
}

// seedRecommendations inserts the discovered-workload backlog an agent would
// report on its first heartbeat, plus one already-applied rule so the
// "Matched policy rule" badge and the applied tab both have data. It is
// idempotent: the upsert keys on (host, type, name, path).
func seedRecommendations(ctx context.Context, store *storage.Store, pool *pgxpool.Pool, orgID, webHostID, winHostID, k8sHostID string, log *slog.Logger) error {
	type rec struct {
		hostID, wlType, name, path, reason string
		level                              int
		diff                               bool
	}
	recs := []rec{
		{
			winHostID, "iis_site", "Default Web Site", `C:\inetpub\wwwroot\web.config`,
			"Active HTTP site bound on port 80.", 3, false,
		},
		{
			winHostID, "mssql_instance", "MSSQLSERVER", `C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA`,
			"Default production SQL Server instance with active databases.", 1, false,
		},
		{
			webHostID, "nginx_vhost", "app_backend", "/etc/nginx/conf.d/upstream.conf",
			"Referenced upstream pool serving production traffic.", 1, true,
		},
		{
			webHostID, "nginx_vhost", "staging.internal", "/etc/nginx/sites-enabled/staging.conf",
			"HTTP-only staging vhost — tracked as drift.", 3, false,
		},
		// Already-applied row, so the "Applied" tab and the matched-rule badge
		// have a concrete example on a fresh demo database.
		{
			webHostID, "nginx_vhost", "nginx.conf", "/etc/nginx/nginx.conf",
			"Primary nginx configuration for the production web tier.", 1, true,
		},
		// ---- Kubernetes workloads -------------------------------------------
		//
		// The cluster collector reports one recommendation per (namespace,
		// resource) profile, so the review queue looks the same whether the
		// workload was found on a VM or in a cluster. The names mirror the
		// collector's own `namespace/plural-singular` shape.
		{
			k8sHostID, "k8s_configmap", "payments/configmap", "/k8s/prod-k8s-01/payments/configmaps/**",
			"ConfigMaps in the production namespace payments on cluster prod-k8s-01.", 1, true,
		},
		{
			k8sHostID, "k8s_secret", "payments/secret", "/k8s/prod-k8s-01/payments/secrets/**",
			"Secrets in the production namespace payments; values are redacted at the agent.", 1, true,
		},
		{
			k8sHostID, "k8s_deployment", "messaging/deployment", "/k8s/prod-k8s-01/messaging/deployments/**",
			"Workload specs in the production namespace messaging trigger a rollout when edited.", 1, true,
		},
		{
			k8sHostID, "k8s_ingress", "staging/ingress", "/k8s/prod-k8s-01/staging/ingresses/**",
			"Ingresses in the staging namespace — tracked as drift, not alerted.", 3, false,
		},
	}
	for _, r := range recs {
		level := int16(r.level)
		if _, err := pool.Exec(ctx, `
			INSERT INTO host_recommendations
				(org_id, host_id, workload_type, name, config_path, suggested_level, suggested_diff, reason, status)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, 'pending')
			ON CONFLICT (host_id, workload_type, name, config_path) DO UPDATE SET
				suggested_level = EXCLUDED.suggested_level,
				suggested_diff  = EXCLUDED.suggested_diff,
				reason          = EXCLUDED.reason,
				updated_at      = NOW()
			WHERE host_recommendations.status = 'pending'`,
			orgID, r.hostID, r.wlType, r.name, r.path, level, r.diff, r.reason); err != nil {
			return err
		}
	}

	// Approve the nginx.conf recommendation so a policy rule exists and the
	// agent would receive it on its next IngestBatch ack. Re-running the
	// seeder leaves an already-decided row alone.
	var nginxRecID, nginxRecStatus string
	if err := pool.QueryRow(ctx, `
		SELECT id::text, status FROM host_recommendations
		WHERE org_id = $1::uuid AND host_id = $2::uuid AND workload_type = 'nginx_vhost'
		  AND name = 'nginx.conf'`, orgID, webHostID).Scan(&nginxRecID, &nginxRecStatus); err != nil {
		return err
	}
	if nginxRecStatus == storage.RecStatusPending {
		rule, err := store.ApplyRecommendation(ctx, orgID, nginxRecID)
		if err != nil {
			return fmt.Errorf("apply nginx.conf recommendation: %w", err)
		}
		log.Info("seeded recommendations", "discovered", len(recs), "applied_rule", rule.Name)
	} else {
		log.Info("seeded recommendations", "discovered", len(recs), "applied", "already")
	}
	return nil
}

// seedState upserts one host_current_state row (used for hosts that have no
// seeded event stream of their own).
func seedState(ctx context.Context, store *storage.Store, pool *pgxpool.Pool, orgID, hostID string, s stateRow, now time.Time) error {
	targetID, err := store.ResolveTarget(ctx, orgID, s.targetType, s.path)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO host_current_state (host_id, target_id, current_hash, current_version, updated_at, last_event_id)
		VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid)
		ON CONFLICT (host_id, target_id) DO UPDATE SET
			current_hash    = EXCLUDED.current_hash,
			current_version = EXCLUDED.current_version,
			updated_at      = EXCLUDED.updated_at,
			last_event_id   = EXCLUDED.last_event_id`,
		hostID, targetID, s.hash, s.version, now, seedID("web-02-state:"+s.path))
	return err
}
