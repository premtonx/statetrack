// Command statetrack-smoke validates the full StateTrack distributed loop
// end-to-end: docker stack (Postgres 17, SeaweedFS S3, Grafana) -> a real
// statetrack-server subprocess -> Postgres + SeaweedFS + Grafana annotations
// -> REST API.
//
// The secret-scrubbing phase drives the *real* agent binary against a
// temporary watch directory (real filesystem collection -> redaction ->
// spool -> gRPC -> server). The package-burst phase injects a realistic
// grouped transaction (1 parent + 5 children) over gRPC, mirroring exactly
// what the agent's debouncer emits; the debouncer itself is covered by
// agent/internal/debouncer unit tests and agent/internal/app e2e tests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/storage"
)

func main() { os.Exit(run()) }

type options struct {
	serverBin  string
	agentBin   string
	dsn        string
	s3Endpoint string
	s3Bucket   string
	s3Access   string
	s3Secret   string
	grafanaURL string
	uiURL      string
	skipAgent  bool
	keep       bool
}

func parseFlags() options {
	o := options{}
	flag.StringVar(&o.serverBin, "server-bin", "", "path to the statetrack-server binary (default: bin/statetrack-server(.exe))")
	flag.StringVar(&o.agentBin, "agent-bin", "", "path to the statetrack-agent binary (default: bin/statetrack-agent-<goos>-<arch>(.exe))")
	flag.StringVar(&o.dsn, "dsn", "postgres://statetrack:statetrack@localhost:5432/statetrack?sslmode=disable", "Postgres DSN")
	flag.StringVar(&o.s3Endpoint, "s3-endpoint", "http://localhost:8333", "SeaweedFS S3 gateway URL")
	flag.StringVar(&o.s3Bucket, "s3-bucket", "statetrack-diffs", "S3 diff bucket")
	flag.StringVar(&o.s3Access, "s3-access-key", "statetrack", "S3 access key")
	flag.StringVar(&o.s3Secret, "s3-secret-key", "statetrack-secret", "S3 secret key")
	flag.StringVar(&o.grafanaURL, "grafana-url", "http://localhost:3000", "Grafana URL (health check only)")
	flag.StringVar(&o.uiURL, "ui-url", "http://localhost:5173", "StateTrack UI base URL (annotation deep links)")
	flag.BoolVar(&o.skipAgent, "skip-agent", false, "skip the real-agent secret-scrubbing phase")
	flag.BoolVar(&o.keep, "keep", false, "keep the temporary directory on exit")
	flag.Parse()
	if o.serverBin == "" {
		if b := firstExisting("bin/statetrack-server", "bin/statetrack-server.exe"); b != "" {
			o.serverBin = b
		}
	}
	if o.agentBin == "" {
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		for _, arch := range []string{"amd64", "arm64"} {
			if b := firstExisting(fmt.Sprintf("bin/statetrack-agent-%s-%s%s", runtime.GOOS, arch, suffix)); b != "" {
				o.agentBin = b
				break
			}
		}
	}
	return o
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func run() int {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := smoke(ctx, log, parseFlags()); err != nil {
		log.Error("smoke test FAILED", "err", err)
		return 1
	}
	log.Info("smoke test PASSED: full distributed loop verified")
	return 0
}

// grafanaMock captures annotation POST bodies.
type grafanaMock struct {
	mu   sync.Mutex
	anns []integrations.Annotation
}

func (g *grafanaMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var a integrations.Annotation
	_ = json.Unmarshal(b, &a)
	g.mu.Lock()
	g.anns = append(g.anns, a)
	g.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (g *grafanaMock) annotations() []integrations.Annotation {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]integrations.Annotation(nil), g.anns...)
}

func smoke(ctx context.Context, log *slog.Logger, o options) (err error) {
	// Validate binary paths up front.
	if o.serverBin == "" {
		return errors.New("statetrack-server binary not found; build it (scripts/dev.ps1 build) or pass -server-bin")
	}

	// 1. Docker stack health (poll: containers may still be starting).
	pool, err := pgxpool.New(ctx, o.dsn)
	if err != nil {
		return fmt.Errorf("postgres connect: %w", err)
	}
	defer pool.Close()

	health := func() error {
		if err := ping(ctx, pool); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		if err := httpGetOK(ctx, o.s3Endpoint+"/healthz"); err != nil {
			return fmt.Errorf("seaweedfs: %w", err)
		}
		if err := httpGetOK(ctx, o.grafanaURL+"/api/health"); err != nil {
			return fmt.Errorf("grafana: %w", err)
		}
		return nil
	}
	if err := waitFor(ctx, 60*time.Second, health); err != nil {
		return fmt.Errorf("docker stack unhealthy: %w", err)
	}
	log.Info("docker: postgres, seaweedfs and grafana healthy")

	// 2. Mock Grafana annotation receiver.
	gmock := &grafanaMock{}
	grafanaLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	grafanaSrv := &http.Server{Handler: gmock}
	go func() { _ = grafanaSrv.Serve(grafanaLn) }()
	defer grafanaSrv.Close()
	mockURL := "http://" + grafanaLn.Addr().String() + "/api/annotations"

	// 3. Start the real server on ephemeral ports.
	grpcPort, err := freePort()
	if err != nil {
		return err
	}
	httpPort, err := freePort()
	if err != nil {
		return err
	}
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", grpcPort)
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	serverLog := filepath.Join(os.TempDir(), fmt.Sprintf("statetrack-smoke-server-%d.log", os.Getpid()))
	serverCmd := exec.Command(o.serverBin)
	serverCmd.Env = append(os.Environ(),
		"DATABASE_URL="+o.dsn,
		"S3_ENDPOINT="+o.s3Endpoint,
		"S3_REGION=us-east-1",
		"S3_BUCKET="+o.s3Bucket,
		"S3_ACCESS_KEY="+o.s3Access,
		"S3_SECRET_KEY="+o.s3Secret,
		"GRPC_ADDR="+grpcAddr,
		"HTTP_ADDR="+httpAddr,
		"STATETRACK_UI_URL="+o.uiURL,
		// The smoke run drives every API read unauthenticated, which is exactly
		// the demo posture: auto-login as the bootstrap administrator plus the
		// anonymous datasource reads. A production default would answer 401 here
		// and the test would be asserting the wrong thing.
		"STATETRACK_DEMO_MODE=1",
	)
	slf, err := os.Create(serverLog)
	if err != nil {
		return err
	}
	serverCmd.Stdout, serverCmd.Stderr = slf, slf
	if err := serverCmd.Start(); err != nil {
		slf.Close()
		return fmt.Errorf("start server: %w", err)
	}
	defer func() {
		stopProcess(serverCmd)
		slf.Close()
		_ = os.Remove(serverLog)
	}()
	log.Info("started statetrack-server", "grpc", grpcAddr, "http", httpAddr, "log", serverLog)

	if err := waitHTTP(ctx, "http://"+httpAddr+"/healthz", 20*time.Second); err != nil {
		return fmt.Errorf("server not ready: %w (log: %s)", err, serverLog)
	}

	// 4. Default org + Grafana integration.
	store := storage.New(pool, nil, 0)
	orgID, err := store.DefaultOrg(ctx)
	if err != nil {
		return fmt.Errorf("resolve default org: %w", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO integrations (org_id, provider, endpoint_url, api_token_encrypted, min_impact_level, enabled)
		VALUES ($1::uuid, 'grafana_annotations', $2, 'smoke-token', 2, true)`,
		orgID, mockURL); err != nil {
		return fmt.Errorf("insert grafana integration: %w", err)
	}
	defer pool.Exec(context.WithoutCancel(ctx), `DELETE FROM integrations WHERE org_id = $1::uuid AND endpoint_url = $2`, orgID, mockURL)

	// 5. Phase A: real agent, secret scrubbing.
	var agentHostKey string
	if !o.skipAgent {
		agentHostKey, err = phaseAgent(ctx, log, o, pool, orgID, grpcAddr, httpAddr)
		if err != nil {
			return err
		}
	} else {
		log.Warn("skipping real-agent phase (-skip-agent)")
	}

	// 6. Phase B: package burst (1 parent + 5 children) over gRPC.
	burstHostKey, burstHostname, parentID := phaseBurst(ctx, log, grpcAddr)

	// 7. Assertions.
	if err := assertBurst(ctx, pool, orgID, gmock, o.uiURL, parentID); err != nil {
		return err
	}
	if err := assertRest(ctx, httpAddr, parentID); err != nil {
		return err
	}
	log.Info("assertions: package burst collapsed to 1 parent (child_count=5)", "parent", parentID)

	// 8. Cleanup of test rows.
	cleanupIDs := []string{}
	if agentHostKey != "" {
		cleanupIDs = append(cleanupIDs, storage.NormalizeHostID(agentHostKey))
	}
	cleanupIDs = append(cleanupIDs, storage.NormalizeHostID(burstHostKey))
	if err := cleanupRows(ctx, pool, orgID, cleanupIDs, burstHostname); err != nil {
		log.Warn("cleanup", "err", err)
	}

	return nil
}

func phaseAgent(ctx context.Context, log *slog.Logger, o options, pool *pgxpool.Pool, orgID, grpcAddr, httpAddr string) (string, error) {
	if o.agentBin == "" {
		return "", errors.New("statetrack-agent binary not found; build it or pass -agent-bin (or use -skip-agent)")
	}

	tmp, err := os.MkdirTemp("", "statetrack-smoke-")
	if err != nil {
		return "", err
	}
	if !o.keep {
		defer os.RemoveAll(tmp)
	}
	watchDir := filepath.Join(tmp, "watch")
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(watchDir, 0o755); err != nil {
		return "", err
	}

	hostKey := "smoke-agent-" + uuid.NewString()
	watchPath := filepath.ToSlash(watchDir)
	dbConf := filepath.ToSlash(filepath.Join(watchDir, "db.conf"))
	cfg := fmt.Sprintf(`host_id: %s
log_level: debug
state_dir: %s
reload_interval: 1s
baseline:
  pace: 0s
watch:
  paths: ["%s"]
  critical: ["%s"]
server:
  address: %s
windows:
  registry: {enabled: false}
  services: {enabled: false}
  msi: {enabled: false}
  security_audit: {enabled: false}
`, hostKey, filepath.ToSlash(stateDir), watchPath, dbConf, grpcAddr)

	cfgPath := filepath.Join(tmp, "agent.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return "", err
	}

	agentLog := filepath.Join(tmp, "agent.log")
	lf, err := os.Create(agentLog)
	if err != nil {
		return "", err
	}
	agentCmd := exec.Command(o.agentBin, "-config", cfgPath)
	agentCmd.Stdout, agentCmd.Stderr = lf, lf
	if err := agentCmd.Start(); err != nil {
		lf.Close()
		return "", fmt.Errorf("start agent: %w", err)
	}
	defer stopProcess(agentCmd)
	log.Info("started statetrack-agent", "host", hostKey, "watch", watchDir, "log", agentLog)

	if err := waitFileContains(ctx, agentLog, "agent running", 30*time.Second); err != nil {
		return "", fmt.Errorf("agent not ready: %w", err)
	}

	// Simulated mutation: write a secret, then modify it.
	writeSecret := func(host string) {
		_ = os.WriteFile(filepath.Join(watchDir, "db.conf"),
			[]byte("db_password = \"supersecret123\"\nhost = "+host+"\n"), 0o644)
	}
	writeSecret("db.internal")
	time.Sleep(1200 * time.Millisecond)
	writeSecret("db-new.internal")

	ev, err := waitRestEvent(ctx, httpAddr, "db.conf", 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("agent event: %w (log: %s)", err, agentLog)
	}
	log.Info("agent: detected secret-file mutation", "event", ev.ID, "summary", ev.Summary)

	// The secret must be scrubbed in the database and never stored raw.
	var inline *string
	if err := pool.QueryRow(ctx, `SELECT inline_diff FROM events WHERE id = $1::uuid`, ev.ID).Scan(&inline); err != nil {
		return "", err
	}
	if inline == nil {
		return "", errors.New("agent event has no inline diff")
	}
	if !strings.Contains(*inline, "[REDACTED:sha256:") {
		return "", fmt.Errorf("secret not scrubbed in DB; inline_diff = %q", *inline)
	}
	if strings.Contains(*inline, "supersecret") {
		return "", fmt.Errorf("secret leaked into DB; inline_diff = %q", *inline)
	}
	log.Info("agent: secret scrubbed to [REDACTED:sha256:...] in Postgres")
	return hostKey, nil
}

func phaseBurst(ctx context.Context, log *slog.Logger, grpcAddr string) (hostKey, hostname, parentID string) {
	hostKey = "smoke-burst-" + uuid.NewString()
	hostname = "smoke-burst-host-" + uuid.NewString()
	parentID = uuid.NewString()

	parent := &pb.MutationEvent{
		EventId:          parentID,
		AgentTimestampMs: time.Now().UnixMilli(),
		Level:            pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
		Category:         pb.Category_CATEGORY_PACKAGE,
		Action:           pb.Action_ACTION_UPGRADED,
		Summary:          "apt transaction: 5 related changes",
		Actor:            &pb.ActorContext{ProcessName: "apt", Cmdline: "apt-get install nginx", Pid: 1000},
		Target:           &pb.TargetResource{TargetType: "transaction", PathOrKey: "apt-get"},
		ChildCount:       5,
		Metadata:         map[string]string{"event_type": "TRANSACTION", "tool": "apt"},
	}
	events := []*pb.MutationEvent{parent}
	for i := 0; i < 5; i++ {
		events = append(events, &pb.MutationEvent{
			EventId:          uuid.NewString(),
			AgentTimestampMs: time.Now().UnixMilli(),
			Level:            pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED,
			Category:         pb.Category_CATEGORY_CONFIG,
			Action:           pb.Action_ACTION_MODIFIED,
			Summary:          fmt.Sprintf("Modified /etc/app/conf%d.conf", i),
			ParentEventId:    parentID,
			Actor:            &pb.ActorContext{ProcessName: "dpkg", Pid: 1001},
			Target: &pb.TargetResource{
				TargetType: "file", PathOrKey: fmt.Sprintf("/etc/app/conf%d.conf", i),
				HashAfter: "sha256-" + strings.Repeat("c", 60),
			},
		})
	}

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Error("grpc dial", "err", err)
		return hostKey, hostname, parentID
	}
	defer conn.Close()
	client := pb.NewIngestionServiceClient(conn)

	resp, err := client.IngestBatch(ctx, &pb.IngestBatchRequest{
		HostId:       hostKey,
		AgentSentMs:  time.Now().UnixMilli(),
		Events:       events,
		Hostname:     hostname,
		OsFamily:     "linux",
		OsVersion:    "test",
		AgentVersion: "smoke",
	})
	if err != nil {
		log.Error("ingest burst", "err", err)
		return hostKey, hostname, parentID
	}
	log.Info("burst: ingested parent + 5 children", "acked", len(resp.GetAckEventIds()), "parent", parentID)
	return hostKey, hostname, parentID
}

func assertBurst(ctx context.Context, pool *pgxpool.Pool, orgID string, gmock *grafanaMock, uiURL, parentID string) error {
	var childCount int32
	if err := pool.QueryRow(ctx, `SELECT child_count FROM events WHERE id = $1::uuid`, parentID).Scan(&childCount); err != nil {
		return fmt.Errorf("parent event missing: %w", err)
	}
	if childCount != 5 {
		return fmt.Errorf("parent child_count = %d, want 5", childCount)
	}
	var children int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE parent_event_id = $1::uuid`, parentID).Scan(&children); err != nil {
		return err
	}
	if children != 5 {
		return fmt.Errorf("children stored = %d, want 5", children)
	}

	// Grafana must have received the parent annotation with tags + deep link.
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, a := range gmock.annotations() {
			if !strings.Contains(a.Text, "/events/"+parentID) {
				continue
			}
			if !containsAll(a.Tags, "statetrack", "level:L2", "category:package") {
				continue
			}
			if !hasTagPrefix(a.Tags, "host:") {
				continue
			}
			if !strings.Contains(a.Text, uiURL) {
				return fmt.Errorf("annotation deep link %q lacks UI base %q", a.Text, uiURL)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("grafana annotation for parent %s not received (received %d)", parentID, len(gmock.annotations()))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertRest(ctx context.Context, httpAddr, parentID string) error {
	resp, err := http.Get(fmt.Sprintf("http://%s/api/v1/events?limit=50", httpAddr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /api/v1/events -> %d", resp.StatusCode)
	}
	var body struct {
		Events []storage.Event `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if len(body.Events) == 0 {
		return errors.New("GET /api/v1/events returned no events")
	}
	found := false
	for _, e := range body.Events {
		if e.ID == parentID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("parent event %s not present in /api/v1/events", parentID)
	}

	detail, err := http.Get(fmt.Sprintf("http://%s/api/v1/events/%s", httpAddr, parentID))
	if err != nil {
		return err
	}
	defer detail.Body.Close()
	var de storage.EventDetail
	if err := json.NewDecoder(detail.Body).Decode(&de); err != nil {
		return err
	}
	if len(de.Children) != 5 {
		return fmt.Errorf("REST detail children = %d, want 5", len(de.Children))
	}
	return nil
}

// --- helpers ---

func ping(ctx context.Context, pool *pgxpool.Pool) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return pool.Ping(c)
}

// waitFor polls fn until it returns nil or timeout, returning the last error.
func waitFor(ctx context.Context, timeout time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if lastErr = fn(); lastErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func httpGetOK(ctx context.Context, rawURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s -> %d", rawURL, resp.StatusCode)
	}
	return nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitHTTP(ctx context.Context, rawURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := httpGetOK(ctx, rawURL); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func waitFileContains(ctx context.Context, path, substr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), substr) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %q in %s", substr, path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitRestEvent(ctx context.Context, httpAddr, search string, timeout time.Duration) (storage.Event, error) {
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(fmt.Sprintf("http://%s/api/v1/events?limit=50&search=%s", httpAddr, url.QueryEscape(search)))
		if err == nil && resp.StatusCode == http.StatusOK {
			var body struct {
				Events []storage.Event `json:"events"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			for _, e := range body.Events {
				if strings.Contains(e.PathOrKey, search) || strings.Contains(e.Summary, search) {
					return e, nil
				}
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			return storage.Event{}, fmt.Errorf("timed out waiting for event %q", search)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func cleanupRows(ctx context.Context, pool *pgxpool.Pool, orgID string, hostIDs []string, extraHostname string) error {
	ids := make([]string, 0, len(hostIDs))
	for _, id := range hostIDs {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	_, err := pool.Exec(ctx,
		`DELETE FROM events WHERE host_id = ANY($1::uuid[])`, ids)
	if err == nil {
		_, err = pool.Exec(ctx, `DELETE FROM host_current_state WHERE host_id = ANY($1::uuid[])`, ids)
	}
	if err == nil {
		_, err = pool.Exec(ctx, `DELETE FROM hosts WHERE id = ANY($1::uuid[])`, ids)
	}
	if err == nil && extraHostname != "" {
		_, err = pool.Exec(ctx, `DELETE FROM hosts WHERE hostname = $1`, extraHostname)
	}
	return err
}

func containsAll(tags []string, want ...string) bool {
	for _, w := range want {
		if !contains(tags, w) {
			return false
		}
	}
	return true
}

func hasTagPrefix(tags []string, prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
