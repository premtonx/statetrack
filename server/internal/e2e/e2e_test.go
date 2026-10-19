// Package e2e exercises the full server stack in-process: gRPC ingestion,
// Postgres + S3 storage routing, annotation dispatch, and the REST API.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/api"
	ingestgrpc "github.com/statetrack/statetrack/server/internal/grpc"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/storage"
	"github.com/statetrack/statetrack/server/internal/testdb"
)

// dialIngest registers the ingestion server on a bufconn listener and returns
// a real gRPC client, exercising the generated client/server and the proto
// wire format (including host registration fields).
func dialIngest(t *testing.T, srv *ingestgrpc.Server) pb.IngestionServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pb.RegisterIngestionServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewIngestionServiceClient(conn)
}

// fakeGrafana captures annotation POSTs.
type fakeGrafana struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (f *fakeGrafana) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.mu.Lock()
	f.bodies = append(f.bodies, m)
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (f *fakeGrafana) received() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.bodies...)
}

func setup(t *testing.T) (*pgxpool.Pool, *storage.Store, *storage.BlobStore, string) {
	t.Helper()
	dsn := testdb.DSN()
	if dsn == "" {
		t.Skip(testdb.EnvVar + " not set")
	}
	// These tests exercise ingestion, the storage router and REST shape, not
	// authorization — that is covered by the api package's own auth tests. The
	// routes are authenticated by default (correctly), so an anonymous GET here
	// is a 401 rather than the payload under test. Bypassing auth is the
	// documented way to drive them, and it is scoped to this test binary.
	t.Setenv("STATETRACK_AUTH_DISABLED", "1")
	t.Setenv("STATETRACK_DEV_AUTOLOGIN", "0")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// Applies the schema when the database is bare. Without this the suite only
	// passed on a machine where `make up migrate` had already been run, and
	// failed on an empty CI service container.
	pool := testdb.Pool(t)

	blob, err := storage.NewBlobStore(ctx, storage.BlobConfig{
		Endpoint:  getenv("STATETRACK_TEST_S3_ENDPOINT", "http://localhost:8333"),
		Region:    getenv("STATETRACK_TEST_S3_REGION", "us-east-1"),
		Bucket:    getenv("STATETRACK_TEST_S3_BUCKET", "statetrack-diffs"),
		AccessKey: getenv("STATETRACK_TEST_S3_ACCESS_KEY", "statetrack"),
		SecretKey: getenv("STATETRACK_TEST_S3_SECRET_KEY", "statetrack-secret"),
		PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A fresh SeaweedFS or MinIO service container has no buckets, so the first
	// Put fails with NoSuchBucket and the router correctly degrades to an inline
	// diff — which then fails the s3_blob_key assertion below. The server calls
	// EnsureBucket at boot; the test harness has to do the same or it is not
	// exercising the S3 path at all.
	if err := blob.EnsureBucket(ctx); err != nil {
		t.Fatalf("ensure test bucket: %v", err)
	}

	store := storage.New(pool, blob, 0)
	org, err := store.DefaultOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return pool, store, blob, org
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newEvent(level pb.ImpactLevel, category pb.Category, action pb.Action, summary, targetType, path, diffText string) *pb.MutationEvent {
	ev := &pb.MutationEvent{
		EventId:          uuid.NewString(),
		AgentTimestampMs: time.Now().UnixMilli(),
		Level:            level,
		Category:         category,
		Action:           action,
		Summary:          summary,
		Target:           &pb.TargetResource{TargetType: targetType, PathOrKey: path},
		Actor:            &pb.ActorContext{Username: "alice", UidOrSid: "1000", ProcessName: "vim", Cmdline: "vim /etc/app.conf"},
	}
	if diffText != "" {
		z, _ := diff.CompressString(diffText)
		ev.UnifiedDiffZstd = z
	}
	if targetType == "file" {
		ev.Target.HashAfter = "sha256-" + strings.Repeat("a", 60)
	}
	return ev
}

func TestIngestStorageRouterAndAPI(t *testing.T) {
	pool, store, blob, org := setup(t)
	ctx := context.Background()

	// Fake Grafana capture.
	grafana := &fakeGrafana{}
	grafanaSrv := httptest.NewServer(http.HandlerFunc(grafana.handler))
	t.Cleanup(grafanaSrv.Close)

	hostname := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	hostID := uuid.NewString()
	host, err := store.UpsertHost(ctx, storage.Host{
		ID: hostID, OrgID: org, Hostname: hostname, OSFamily: "linux", OSVersion: "test", AgentVersion: "e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE host_id = $1::uuid`, host.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM hosts WHERE id = $1::uuid`, host.ID)
	})

	// Grafana integration pointing at the capture server, level <= 2.
	if _, err := pool.Exec(ctx, `
		INSERT INTO integrations (org_id, provider, endpoint_url, api_token_encrypted, min_impact_level, enabled)
		VALUES ($1::uuid, 'grafana_annotations', $2, 'test-token', 2, true)`, org, grafanaSrv.URL+"/api/annotations"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM integrations WHERE org_id = $1::uuid AND provider = 'grafana_annotations'`, org)
	})

	// Build 10 events: 1 large diff (>2KB), 1 small diff (<=2KB), 8 metadata.
	largeDiff := strings.Repeat("line with content\n", 200) // ~3600 bytes
	smallDiff := "-old\n+new\n"
	var events []*pb.MutationEvent
	events = append(events, newEvent(pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, pb.Category_CATEGORY_CONFIG,
		pb.Action_ACTION_MODIFIED, "Modified /etc/app.conf", "file", "/etc/app.conf", largeDiff))
	events = append(events, newEvent(pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, pb.Category_CATEGORY_PACKAGE,
		pb.Action_ACTION_UPGRADED, "Upgraded nginx", "package", "nginx", smallDiff))
	for i := 0; i < 8; i++ {
		events = append(events, newEvent(pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, pb.Category_CATEGORY_CONFIG,
			pb.Action_ACTION_MODIFIED, fmt.Sprintf("Drift %d", i), "file", fmt.Sprintf("/var/www/app%d.conf", i), ""))
	}

	// Wire the same components main.go wires.
	hub := api.NewHub(nil)
	pusher := integrations.New(integrations.Options{Store: store, UIBaseURL: "http://localhost:5173", Logger: nil})
	pusherCtx, stopPusher := context.WithCancel(context.Background())
	t.Cleanup(stopPusher)
	go pusher.Run(pusherCtx)

	ingestion := &ingestgrpc.Server{Store: store, OrgID: org, Publish: hub.Publish, Enqueue: pusher.Enqueue}

	req := &pb.IngestBatchRequest{
		HostId:       hostID,
		AgentSentMs:  time.Now().UnixMilli(),
		Events:       events,
		Hostname:     hostname,
		OsFamily:     "linux",
		OsVersion:    "test",
		AgentVersion: "e2e",
	}
	client := dialIngest(t, ingestion)
	resp, err := client.IngestBatch(ctx, req)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(resp.AckEventIds) != 10 {
		t.Fatalf("ack = %d, want 10", len(resp.AckEventIds))
	}

	// 1. Metadata in Postgres.
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE host_id = $1::uuid`, host.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("events in postgres = %d, want 10", count)
	}
	var s3Key string
	if err := pool.QueryRow(ctx,
		`SELECT s3_blob_key FROM events WHERE host_id = $1::uuid AND s3_blob_key IS NOT NULL`, host.ID).Scan(&s3Key); err != nil {
		t.Fatalf("no s3_blob_key row: %v", err)
	}
	var inlineDiff string
	if err := pool.QueryRow(ctx,
		`SELECT inline_diff FROM events WHERE host_id = $1::uuid AND inline_diff IS NOT NULL`, host.ID).Scan(&inlineDiff); err != nil {
		t.Fatalf("no inline_diff row: %v", err)
	}
	if !strings.Contains(inlineDiff, "+new") {
		t.Fatalf("inline diff = %q", inlineDiff)
	}

	// 2. Large diff in SeaweedFS, retrievable and decompressible.
	blobData, err := blob.Get(ctx, s3Key)
	if err != nil {
		t.Fatalf("s3 get: %v", err)
	}
	gotDiff, err := diff.Decompress(blobData)
	if err != nil {
		t.Fatalf("s3 decompress: %v", err)
	}
	if string(gotDiff) != largeDiff {
		t.Fatalf("s3 diff mismatch: got %d bytes, want %d", len(gotDiff), len(largeDiff))
	}

	// 3. Annotation POST to Grafana.
	deadline := time.Now().Add(5 * time.Second)
	for len(grafana.received()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := grafana.received(); len(got) == 0 {
		t.Fatal("no Grafana annotation received")
	} else {
		first := got[0]
		if !strings.Contains(first["text"].(string), "Modified /etc/app.conf") {
			t.Fatalf("annotation text = %q", first["text"])
		}
		tags := first["tags"].([]any)
		if len(tags) < 2 {
			t.Fatalf("annotation tags = %v", tags)
		}
	}

	// 4. REST API: events list + event detail (S3 diff decompressed).
	apiSrv := httptest.NewServer((&api.Server{Store: store, Hub: hub, OrgID: org, UIBaseURL: "http://localhost:5173"}).Routes())
	t.Cleanup(apiSrv.Close)

	// Scoped to this test's host. Asserting a global count would couple the
	// test to whatever else shares the database — the demo seed in a developer
	// environment, or a parallel CI run — and fail on data it did not create.
	eventsPath := "/api/v1/events?host_id=" + hostID + "&limit=50"
	listResp := getJSON(t, apiSrv.URL+eventsPath)
	var listBody struct {
		Events []storage.Event `json:"events"`
	}
	if err := json.Unmarshal(listResp, &listBody); err != nil {
		t.Fatalf("list events: %v (%s)", err, listResp)
	}
	if len(listBody.Events) != 10 {
		t.Fatalf("listed events = %d, want 10", len(listBody.Events))
	}
	for _, e := range listBody.Events {
		if e.HostID != hostID {
			t.Fatalf("host filter leaked an event from %s", e.HostID)
		}
	}

	// Cursor pagination: first page of 6, then the remainder via next_cursor.
	page1Resp := getJSON(t, apiSrv.URL+"/api/v1/events?host_id="+hostID+"&limit=6")
	var page1 struct {
		Events     []storage.Event `json:"events"`
		NextCursor string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(page1Resp, &page1); err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Events) != 6 || page1.NextCursor == "" {
		t.Fatalf("page1 = %d events, cursor=%q", len(page1.Events), page1.NextCursor)
	}
	page2Resp := getJSON(t, apiSrv.URL+"/api/v1/events?host_id="+hostID+"&limit=50&cursor="+page1.NextCursor)
	var page2 struct {
		Events []storage.Event `json:"events"`
	}
	if err := json.Unmarshal(page2Resp, &page2); err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Events) != 4 {
		t.Fatalf("page2 = %d events, want 4", len(page2.Events))
	}
	seen := map[string]bool{}
	for _, e := range append(append([]storage.Event{}, page1.Events...), page2.Events...) {
		if seen[e.ID] {
			t.Fatalf("duplicate event across pages: %s", e.ID)
		}
		seen[e.ID] = true
	}

	// Search filter, scoped to this host for the same reason as the list above.
	searchResp := getJSON(t, apiSrv.URL+"/api/v1/events?host_id="+hostID+"&search=nginx")
	var searchBody struct {
		Events []storage.Event `json:"events"`
	}
	if err := json.Unmarshal(searchResp, &searchBody); err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(searchBody.Events) != 1 || searchBody.Events[0].Summary != "Upgraded nginx" {
		t.Fatalf("search returned %d events, want 1 nginx event", len(searchBody.Events))
	}

	largeID := events[0].EventId
	detailResp := getJSON(t, apiSrv.URL+"/api/v1/events/"+largeID)
	var detail storage.EventDetail
	if err := json.Unmarshal(detailResp, &detail); err != nil {
		t.Fatalf("event detail: %v (%s)", err, detailResp)
	}
	if detail.Diff != largeDiff {
		t.Fatalf("detail diff = %d bytes, want %d", len(detail.Diff), len(largeDiff))
	}
	if detail.DiffSource != "s3" {
		t.Fatalf("detail diff_source = %q, want s3", detail.DiffSource)
	}

	// 5. Drift comparison: second host with a different hash for the same file.
	hostBName := hostname + "-b"
	hostBID := uuid.NewString()
	hostB, err := store.UpsertHost(ctx, storage.Host{ID: hostBID, OrgID: org, Hostname: hostBName, OSFamily: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE host_id = $1::uuid`, hostB.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM hosts WHERE id = $1::uuid`, hostB.ID)
	})
	evB := newEvent(pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, pb.Category_CATEGORY_CONFIG,
		pb.Action_ACTION_MODIFIED, "Modified /etc/app.conf", "file", "/etc/app.conf", "")
	evB.Target.HashAfter = "sha256-" + strings.Repeat("b", 60)
	if _, _, err := store.InsertEvents(ctx, org, hostB.ID, 0, []*pb.MutationEvent{evB}); err != nil {
		t.Fatal(err)
	}

	driftResp := getJSON(t, apiSrv.URL+"/api/v1/drift?host_a="+host.ID+"&host_b="+hostB.ID)
	var driftBody struct {
		Drift []storage.DriftRow `json:"drift"`
	}
	if err := json.Unmarshal(driftResp, &driftBody); err != nil {
		t.Fatalf("drift: %v (%s)", err, driftResp)
	}
	found := false
	for _, d := range driftBody.Drift {
		if d.PathOrKey == "/etc/app.conf" {
			found = true
			if d.HashA == d.HashB {
				t.Fatalf("drift hashes equal: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("/etc/app.conf not in drift result: %+v", driftBody.Drift)
	}
}

// TestHostSummary exercises the unified poller rollup end to end through the
// real HTTP mux, including both identifier forms (hostname and host id) and the
// window option.
func TestHostSummary(t *testing.T) {
	pool, store, _, org := setup(t)
	ctx := context.Background()

	hostname := fmt.Sprintf("itest-summary-%d", time.Now().UnixNano())
	host, err := store.UpsertHost(ctx, storage.Host{
		ID: uuid.NewString(), OrgID: org, Hostname: hostname, OSFamily: "linux",
		OSVersion: "test", AgentVersion: "e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE host_id = $1::uuid`, host.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM host_current_state WHERE host_id = $1::uuid`, host.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM hosts WHERE id = $1::uuid`, host.ID)
	})

	// 1 Level 1 (with a matched rule and a text diff), 1 Level 2, 3 Level 3,
	// plus 1 Level 1 that is a *child* of the Level 2 transaction. The child
	// must not be counted: root-only counting is the contract.
	crit := newEvent(pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, pb.Category_CATEGORY_CONFIG,
		pb.Action_ACTION_MODIFIED, "Modified /etc/nginx/nginx.conf (+4 -2)", "file", "/etc/nginx/nginx.conf", "-old\n+new\n")
	crit.Metadata = map[string]string{"rule_name": "nginx.conf (L1)"}
	grouped := newEvent(pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED, pb.Category_CATEGORY_PACKAGE,
		pb.Action_ACTION_UPGRADED, "apt transaction: 2 related changes", "package", "nginx", "")
	child := newEvent(pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL, pb.Category_CATEGORY_PACKAGE,
		pb.Action_ACTION_UPGRADED, "Upgraded libssl3", "package", "libssl3", "")
	child.ParentEventId = grouped.EventId
	drifts := make([]*pb.MutationEvent, 0, 3)
	for i := 0; i < 3; i++ {
		drifts = append(drifts, newEvent(pb.ImpactLevel_IMPACT_LEVEL_3_DRIFT, pb.Category_CATEGORY_CONFIG,
			pb.Action_ACTION_MODIFIED, fmt.Sprintf("Drift %d", i), "file", fmt.Sprintf("/etc/drift%d.conf", i), ""))
	}
	batch := append([]*pb.MutationEvent{crit, grouped, child}, drifts...)

	// Oldest first so the newest Level 1 is unambiguous, and with staggered
	// timestamps so "latest critical" has exactly one right answer.
	base := time.Now().Add(-10 * time.Minute)
	for i, ev := range batch {
		ev.AgentTimestampMs = base.Add(time.Duration(i) * time.Minute).UnixMilli()
	}
	if _, _, err := store.InsertEvents(ctx, org, host.ID, 0, batch); err != nil {
		t.Fatal(err)
	}

	apiSrv := httptest.NewServer((&api.Server{Store: store, OrgID: org, UIBaseURL: "http://localhost:5173"}).Routes())
	t.Cleanup(apiSrv.Close)

	// Resolve by hostname (the form monitoring inventory uses).
	var byName storage.HostSummary
	if err := json.Unmarshal(getJSON(t, apiSrv.URL+"/api/v1/hosts/"+hostname+"/summary?window=15m"), &byName); err != nil {
		t.Fatal(err)
	}
	if byName.Host != hostname {
		t.Fatalf("host = %q, want %q", byName.Host, hostname)
	}
	if byName.OS != "linux" {
		t.Fatalf("os = %q, want linux", byName.OS)
	}
	if !byName.Online {
		t.Fatalf("online = false; host was just upserted (last_seen_seconds=%d)", byName.LastSeenSeconds)
	}
	if byName.LastSeenSeconds < 0 || byName.LastSeenSeconds > 60 {
		t.Fatalf("last_seen_seconds = %d, want a small non-negative value", byName.LastSeenSeconds)
	}
	if byName.Window != "15m" {
		t.Fatalf("window = %q, want 15m", byName.Window)
	}
	// 4 root events: 1 L1 + 1 L2 + 3 L3 would be 5, but one L1 is a child of
	// the L2, so it must be excluded. The L3 drift events write no
	// host_current_state row, so exactly one tracked target remains.
	wantCounts := storage.HostSummaryCounts{Total: 5, L1Critical: 1, L2Grouped: 1, L3Drift: 3, L4Forensic: 0}
	if byName.Counts != wantCounts {
		t.Fatalf("counts = %+v, want %+v", byName.Counts, wantCounts)
	}
	if byName.Counts.Total != byName.Counts.L1Critical+byName.Counts.L2Grouped+byName.Counts.L3Drift+byName.Counts.L4Forensic {
		t.Fatalf("levels do not partition total: %+v", byName.Counts)
	}

	if byName.LatestCritical == nil {
		t.Fatal("latest_critical is null, want the L1 config change")
	}
	lc := byName.LatestCritical
	if lc.ID != crit.EventId {
		t.Fatalf("latest_critical.id = %q, want the L1 event %q", lc.ID, crit.EventId)
	}
	if lc.Target != "/etc/nginx/nginx.conf" {
		t.Fatalf("latest_critical.target = %q", lc.Target)
	}
	if lc.Actor != "alice" || lc.Tool != "vim" {
		t.Fatalf("latest_critical actor/tool = %q/%q, want alice/vim", lc.Actor, lc.Tool)
	}
	if lc.RuleName != "nginx.conf (L1)" {
		t.Fatalf("latest_critical.rule_name = %q", lc.RuleName)
	}
	// Deep link must point at the diff tab so the alert is immediately actionable.
	wantLink := "http://localhost:5173/events/" + crit.EventId + "?tab=diff"
	if lc.DeepLink != wantLink {
		t.Fatalf("latest_critical.deep_link = %q, want %q", lc.DeepLink, wantLink)
	}

	// Resolve by host id: the same rollup, proving both identifier forms work.
	var byID storage.HostSummary
	if err := json.Unmarshal(getJSON(t, apiSrv.URL+"/api/v1/hosts/"+host.ID+"/summary"), &byID); err != nil {
		t.Fatal(err)
	}
	if byID.Host != hostname || byID.Counts != wantCounts {
		t.Fatalf("by-id summary = %+v (host %q), want host %q counts %+v", byID, byID.Host, hostname, wantCounts)
	}
	// Omitted window falls back to the 15m default.
	if byID.Window != "15m" {
		t.Fatalf("default window = %q, want 15m", byID.Window)
	}

	// A window that predates every event must report an all-zero rollup with a
	// null latest_critical (not an error, not a stale L1).
	var narrow storage.HostSummary
	if err := json.Unmarshal(getJSON(t, apiSrv.URL+"/api/v1/hosts/"+hostname+"/summary?window=60s"), &narrow); err != nil {
		t.Fatal(err)
	}
	if narrow.Counts.Total != 0 || narrow.LatestCritical != nil {
		t.Fatalf("narrow window = %+v, want zero counts and nil latest_critical", narrow)
	}

	// Unknown hosts are a clean 404, not a 500 from a failed ::uuid cast.
	for _, key := range []string{"no-such-host", uuid.NewString(), "not-a-uuid-at-all"} {
		resp, err := http.Get(apiSrv.URL + "/api/v1/hosts/" + key + "/summary")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET summary for %q -> %d, want 404", key, resp.StatusCode)
		}
	}

	// A malformed window is a 400, so a misconfigured poller fails loudly.
	resp, err := http.Get(apiSrv.URL + "/api/v1/hosts/" + hostname + "/summary?window=soon")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed window -> %d, want 400", resp.StatusCode)
	}
}

// TestHostSummaryOffline verifies the online/last_seen contract: a host whose
// last report is older than storage.OnlineWindow reports offline with an
// accurate age, which is what a monitoring check alerts on.
func TestHostSummaryOffline(t *testing.T) {
	pool, store, _, org := setup(t)
	ctx := context.Background()

	hostname := fmt.Sprintf("itest-offline-%d", time.Now().UnixNano())
	host, err := store.UpsertHost(ctx, storage.Host{
		ID: uuid.NewString(), OrgID: org, Hostname: hostname, OSFamily: "windows", OSVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM hosts WHERE id = $1::uuid`, host.ID)
	})

	// Backdate the heartbeat well past the online window.
	const silent = 42 * time.Minute
	if _, err := pool.Exec(ctx,
		`UPDATE hosts SET last_seen_at = NOW() - make_interval(secs => $2) WHERE id = $1::uuid`,
		host.ID, int64(silent.Seconds())); err != nil {
		t.Fatal(err)
	}

	apiSrv := httptest.NewServer((&api.Server{Store: store, OrgID: org, UIBaseURL: "http://localhost:5173"}).Routes())
	t.Cleanup(apiSrv.Close)

	var got storage.HostSummary
	if err := json.Unmarshal(getJSON(t, apiSrv.URL+"/api/v1/hosts/"+hostname+"/summary"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Online {
		t.Fatalf("online = true for a host silent %s (window %s)", silent, storage.OnlineWindow)
	}
	// Allow a couple of seconds of test execution slack.
	if got.LastSeenSeconds < int64(silent.Seconds()) || got.LastSeenSeconds > int64(silent.Seconds())+10 {
		t.Fatalf("last_seen_seconds = %d, want ~%d", got.LastSeenSeconds, int64(silent.Seconds()))
	}
	if got.OS != "windows" {
		t.Fatalf("os = %q, want windows", got.OS)
	}
}

func getJSON(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s -> %d: %s", url, resp.StatusCode, b)
	}
	return b
}
