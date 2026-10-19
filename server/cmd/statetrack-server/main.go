// Command statetrack-server is the StateTrack central backend: gRPC agent
// ingestion, REST + WebSocket API, S3 blob storage and integration dispatch.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/api"
	"github.com/statetrack/statetrack/server/internal/demo"
	ingestgrpc "github.com/statetrack/statetrack/server/internal/grpc"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/metrics"
	"github.com/statetrack/statetrack/server/internal/storage"
	"github.com/statetrack/statetrack/server/internal/webui"
	"github.com/statetrack/statetrack/server/migrations"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	// `--version` must work with no Postgres, no S3 and no config: it is what a
	// container health job, a package post-install script and the release
	// pipeline use to confirm which build is on the box.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Printf("statetrack-server %s (commit %s, built %s)\n", version, commit, buildDate)
			return
		case "--help", "-h", "help":
			fmt.Print(usage)
			return
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := env("DATABASE_URL", "postgres://statetrack:statetrack@localhost:5432/statetrack?sslmode=disable")
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Error("connect to postgres", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Schema migrations run on boot, from the SQL embedded in the binary.
	//
	// Doing this here rather than in an init container or a `make migrate` step
	// is what makes `docker compose up` a single command against an empty
	// Postgres. The migration runner takes an advisory lock, so starting two
	// replicas at once is safe rather than a race on the same DDL.
	//
	// STATETRACK_AUTO_MIGRATE=0 turns it off for a deployment whose DBA wants
	// migrations applied out of band; the server then still starts, and a
	// missing table surfaces as a clear runtime error instead of a silent
	// half-configured console.
	if migrationsEnabled() {
		migrateCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = migrations.Apply(migrateCtx, pool, logger)
		cancel()
		if err != nil {
			logger.Error("apply database migrations", "err", err)
			os.Exit(1)
		}
	}

	if err := waitForDatabase(ctx, pool, logger); err != nil {
		logger.Error("ping postgres", "err", err)
		os.Exit(1)
	}

	// Blob store (SeaweedFS S3 gateway in dev; any S3-compatible store).
	//
	// Inline is the default. The previous default pointed at
	// http://localhost:8333, which is where the development compose stack's
	// SeaweedFS lives and nowhere at all in a production `docker run` — and
	// because Put happens *before* the event row is written, a diff over 2 KB
	// made the agent's whole batch fail and the change was lost. A deployment
	// that wants S3 offloads must say so.
	var blob *storage.BlobStore
	switch endpoint := strings.TrimSpace(env("S3_ENDPOINT", "none")); endpoint {
	case "", "none", "off", "false", "disabled":
		logger.Info("blob storage disabled; large diffs are stored inline in Postgres",
			"hint", "set S3_ENDPOINT to offload diffs over 2 KB")
	default:
		blob, err = storage.NewBlobStore(ctx, storage.BlobConfig{
			Endpoint:  endpoint,
			Region:    env("S3_REGION", "us-east-1"),
			Bucket:    env("S3_BUCKET", "statetrack-diffs"),
			AccessKey: env("S3_ACCESS_KEY", "statetrack"),
			SecretKey: env("S3_SECRET_KEY", "statetrack-secret"),
			PathStyle: true,
		})
		if err != nil {
			logger.Error("connect to blob store", "err", err)
			os.Exit(1)
		}
		// A fresh SeaweedFS/MinIO has no bucket, and every Put would fail with
		// NoSuchBucket. Creating it at boot keeps "set S3_ENDPOINT and start" a
		// complete instruction; a bucket that already exists is the no-op case.
		bucketCtx, cancelBucket := context.WithTimeout(ctx, 30*time.Second)
		err = blob.EnsureBucket(bucketCtx)
		cancelBucket()
		if err != nil {
			// Not fatal: an endpoint that forbids CreateBucket may still serve a
			// bucket provisioned out of band, so the server starts and the first
			// failed Put degrades to an inline diff with a warning.
			logger.Warn("could not ensure the diff bucket", "err", err,
				"hint", "pre-create the bucket, or grant s3:CreateBucket")
		}
		logger.Info("blob storage configured", "endpoint", endpoint, "bucket", env("S3_BUCKET", "statetrack-diffs"))
	}

	store := storage.New(pool, blob, 0)

	orgID, err := store.DefaultOrg(ctx)
	if err != nil {
		logger.Error("resolve default org", "err", err)
		os.Exit(1)
	}

	// A fresh install has no console account, and every management route needs
	// one. Create the bootstrap administrator and report the credentials once:
	// a generated password is printed to the log and never stored in clear, so
	// this line is the operator's only chance to note it.
	if creds, err := api.EnsureBootstrapAdmin(ctx, store, orgID, logger); err != nil {
		logger.Error("bootstrap administrator", "err", err)
		os.Exit(1)
	} else if creds != nil {
		if creds.Generated {
			logger.Warn("created the first console administrator -- record this password now",
				"email", creds.Email, "password", creds.Password,
				"hint", "set STATETRACK_ADMIN_EMAIL/STATETRACK_ADMIN_PASSWORD to choose your own")
		} else {
			logger.Info("created the first console administrator", "email", creds.Email)
		}
	}

	hub := api.NewHub(logger)

	// Demo mode: keep the seeded fleet reporting online for as long as the
	// process runs.
	//
	// The first stamp is synchronous so /metrics and the first dashboard paint
	// already show a healthy fleet; the ticker then repeats it every 30s. The
	// polling panels count a host online when last_seen_at is inside the last 15
	// minutes, so a single stamp at startup would leave `Agents online` reading
	// "0 / 4" a quarter of an hour later -- which is exactly what a recording
	// started the next morning ran into.
	//
	// Gated behind an explicit opt-in for the same reason it always was: doing
	// this unconditionally would mask a genuine fleet outage for one
	// OnlineWindow after every restart, and would make a clean `docker compose
	// up` look like it had enrolled hosts it never saw. STATETRACK_DEMO_MODE
	// defaults to off; `make seed` + this switch is the demo path.
	if demoModeEnabled() {
		if n, err := store.RefreshHostsLastSeen(ctx, orgID); err != nil {
			logger.Warn("demo mode: refresh hosts last_seen", "err", err)
		} else {
			logger.Info("demo mode: hosts marked online", "hosts", n)
		}
		go demo.RunHeartbeat(ctx, logger, store, orgID, demo.HeartbeatInterval)
	}

	// Prometheus exporter. Seeded from Postgres up front so a scrape that
	// arrives before the first agent batch still reports the fleet's real
	// gauges and counters instead of a wall of zeros.
	metricsRegistry := metrics.New()
	seedMetrics(ctx, store, orgID, metricsRegistry, logger)

	// The dispatcher renders and delivers enterprise notifications (Slack,
	// PagerDuty, Teams, signed generic webhooks) with bounded retries.
	notifier := integrations.NewDispatcher(integrations.DispatcherOptions{
		UIBaseURL: env("STATETRACK_UI_URL", defaultUIURL()),
		Metrics:   metricsRegistry,
	})
	pusher := integrations.New(integrations.Options{
		Store:     store,
		UIBaseURL: env("STATETRACK_UI_URL", defaultUIURL()),
		Logger:    logger,
		Metrics:   metricsRegistry,
		Notifier:  notifier,
	})
	go pusher.Run(ctx)

	ingestion := &ingestgrpc.Server{
		Store:   store,
		OrgID:   orgID,
		Publish: hub.Publish,
		Enqueue: pusher.Enqueue,
		Metrics: metricsRegistry,
		Logger:  logger,
	}

	// gRPC listener.
	grpcAddr := env("GRPC_ADDR", ":50051")
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		logger.Error("grpc listen", "addr", grpcAddr, "err", err)
		os.Exit(1)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterIngestionServiceServer(grpcServer, ingestion)

	// HTTP API.
	apiServer := &api.Server{
		Store:      store,
		Hub:        hub,
		OrgID:      orgID,
		UIBaseURL:  env("STATETRACK_UI_URL", defaultUIURL()),
		Metrics:    metricsRegistry,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Logger:     logger,
		Version:    version,
		Commit:     commit,
		BuildDate:  buildDate,
		EmbeddedUI: webui.Available(),
		StartedAt:  time.Now().Unix(),
	}
	httpAddr := env("HTTP_ADDR", ":8080")
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           consoleHandler(apiServer.Routes(), logger),
		ReadHeaderTimeout: 15 * time.Second,
	}
	// Partition maintainer.
	maintainer := &storage.PartitionMaintainer{DB: pool, Logger: logger}
	go maintainer.Run(ctx)

	logger.Info("statetrack-server starting", "version", version, "grpc", grpcAddr, "http", httpAddr, "org", orgID)

	errCh := make(chan error, 3)
	go func() {
		logger.Info("grpc listening", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			errCh <- fmt.Errorf("grpc: %w", err)
		}
	}()
	go func() {
		logger.Info("http listening", "addr", httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		logger.Error("server failed", "err", err)
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcServer.GracefulStop()
	_ = httpSrv.Shutdown(shutdownCtx)
	logger.Info("statetrack-server stopped")
}

// seedMetrics pre-populates the Prometheus exporter from current database
// state. Failure is logged, never fatal: a running server that cannot read its
// seed data should still serve agents and fill its metrics as batches arrive.
func seedMetrics(ctx context.Context, store *storage.Store, orgID string, reg *metrics.Registry, logger *slog.Logger) {
	snap, err := store.MetricsSnapshot(ctx, orgID)
	if err != nil {
		logger.Warn("seed prometheus metrics", "err", err)
		return
	}
	reg.Populate(metrics.Snapshot{
		Hosts:          toMetricHosts(snap.Hosts),
		Mutations:      toMetricMutations(snap.Mutations),
		StormThrottles: toMetricHostCounts(snap.StormThrottles),
		EventsReceived: snap.EventsReceived,
	})
	logger.Info("prometheus metrics seeded",
		"hosts", len(snap.Hosts),
		"mutations", len(snap.Mutations),
		"events_received", snap.EventsReceived)
}

func toMetricHosts(in []storage.MetricsHost) []metrics.HostState {
	out := make([]metrics.HostState, 0, len(in))
	for _, h := range in {
		out = append(out, metrics.HostState{
			Hostname: h.Hostname, OS: h.OS, Status: h.Status, DriftTargets: h.DriftTargets,
		})
	}
	return out
}

func toMetricMutations(in []storage.MetricsMutation) []metrics.MutationCount {
	out := make([]metrics.MutationCount, 0, len(in))
	for _, m := range in {
		out = append(out, metrics.MutationCount{
			Hostname: m.Hostname, Level: m.Level, Category: m.Category, Action: m.Action, Count: m.Count,
		})
	}
	return out
}

func toMetricHostCounts(in []storage.MetricsHostCount) []metrics.HostCount {
	out := make([]metrics.HostCount, 0, len(in))
	for _, c := range in {
		out = append(out, metrics.HostCount{Hostname: c.Hostname, Count: c.Count})
	}
	return out
}

// usage is the `--help` output. The environment variables are the server's
// whole interface, so they are listed here rather than only in the README.
const usage = `statetrack-server -- StateTrack central backend

Usage:
  statetrack-server [--version|--help]

Environment:
  DATABASE_URL                 Postgres DSN (required)
  HTTP_ADDR                    REST + console listen address    (default :8080)
  GRPC_ADDR                    agent ingestion address          (default :50051)
  S3_ENDPOINT                  S3-compatible blob endpoint; "none" disables
  S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION
  STATETRACK_UI_URL            console base URL used in deep links
  STATETRACK_SESSION_SECRET    HMAC key for console sessions (set in production)
  STATETRACK_DEMO_MODE         1 enables demo heartbeat + auto-login (default 0)
  STATETRACK_AUTO_MIGRATE      apply embedded SQL migrations on boot (default 1)
  STATETRACK_SERVE_UI          serve the embedded console on /         (default 1)
  STATETRACK_ADMIN_EMAIL       first console administrator (default admin@localhost)
  STATETRACK_ADMIN_PASSWORD    its password; generated and logged when unset
  STATETRACK_AUTH_DISABLED     bypass authentication (never in production)
`

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// defaultUIURL is the base for deep links in Grafana annotations and outbound
// notifications.
//
// PORT is honoured because that is the variable a PaaS (Cloud Run, Render,
// Fly) injects; otherwise the embedded console is served on :8080 by the same
// process, so the UI is reachable there rather than on the Vite dev port. Using
// the bundled console by default is what makes a container deployment's
// "Inspect in StateTrack" links work without any configuration.
func defaultUIURL() string {
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		return "http://localhost:" + port
	}
	return "http://localhost" + env("HTTP_ADDR", ":8080")
}

// envBool parses a tri-state boolean: "0"/"false"/"no"/"off" is off,
// "1"/"true"/"yes"/"on" is on, anything else (including unset) is def.
//
// Used for the switches where a non-empty string must not be mistaken for "on":
// demo mode (which enables auto-login) and auto-migration.
func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	default:
		return def
	}
}

// demoModeEnabled gates the seeded-fleet heartbeat and the demo login
// conveniences. Off by default: `docker compose up` on a fresh volume must
// produce 0 hosts and 0 events, not a synthetic fleet.
func demoModeEnabled() bool { return envBool("STATETRACK_DEMO_MODE", false) }

// waitForDatabase blocks until Postgres accepts a connection, up to a bounded
// timeout.
//
// Compose (and Kubernetes) start the server and the database together, so the
// first connect routinely loses that race by a second or two. A bounded retry
// here -- rather than an immediate exit and a restart loop -- is what makes
// `docker compose up -d` succeed on the first attempt on a fresh volume, and it
// keeps the same behaviour for a bare `docker run` with no orchestrator.
func waitForDatabase(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	timeout := 60 * time.Second
	if v := strings.TrimSpace(os.Getenv("STATETRACK_DB_CONNECT_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			timeout = d
		}
	}
	deadline := time.Now().Add(timeout)
	delay := 250 * time.Millisecond
	for attempt := 1; ; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := pool.Ping(pingCtx)
		cancel()
		if err == nil {
			if attempt > 1 {
				logger.Info("connected to postgres", "attempts", attempt)
			}
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		logger.Info("waiting for postgres", "attempt", attempt, "retry_in", delay.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 3*time.Second {
			delay *= 2
		}
	}
}

// migrationsEnabled defaults on, because a container that starts against an
// empty database with no schema would be useless on first boot.
func migrationsEnabled() bool { return envBool("STATETRACK_AUTO_MIGRATE", true) }

// consoleHandler mounts the embedded React console beside the API.
//
// The API owns /api, /metrics and /healthz; everything else is the SPA, which is
// what lets `docker run -p 8080:8080` serve the console and the API from one
// origin (no CORS, no proxy, no second TLS terminator). STATETRACK_SERVE_UI=0
// disables it for a deployment that terminates the console on a CDN instead.
func consoleHandler(apiHandler http.Handler, logger *slog.Logger) http.Handler {
	if !envBool("STATETRACK_SERVE_UI", true) {
		logger.Info("embedded console disabled (STATETRACK_SERVE_UI=0)")
		return apiHandler
	}
	if !webui.Available() {
		logger.Warn("no web console embedded in this binary (placeholder build); serving the API only -- run `make web-build` or use the Docker image")
		return apiHandler
	}
	ui, err := webui.Handler()
	if err != nil {
		logger.Error("mount embedded console", "err", err)
		return apiHandler
	}
	logger.Info("embedded web console mounted", "path", "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/healthz" || p == "/metrics" || strings.HasPrefix(p, "/api/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ui.ServeHTTP(w, r)
	})
}
