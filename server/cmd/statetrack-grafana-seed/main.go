// Command statetrack-grafana-seed wires a running Docker Grafana (:3000) to the
// StateTrack demo timeline so the two can be screen-recorded or screenshotted
// side by side on one clock.
//
// It does four things, in order, and each is idempotent so it can be re-run
// before every take:
//
//  1. Waits for Grafana and resolves both provisioned datasources: Prometheus
//     (the server's /metrics counters) and Postgres (the events tables, which
//     back the integer KPIs, the host and recent-changes tables and the
//     one-hour telemetry series). Creates either if the operator is pointing at
//     a bare Grafana.
//  2. Imports integrations/grafana/statetrack-overview-dashboard.json, binding
//     the DS_PROMETHEUS and DS_POSTGRES template variables to the resolved
//     datasource uids. The dashboard is "StateTrack – Change Impact": a KPI
//     grid, a hero panel correlating infrastructure signals with the flagged
//     changes, and the impact / host / category / recent-change breakdowns.
//  3. Reads the *flagged* changes straight out of Postgres and pushes one
//     Grafana annotation per change — carrying the actor, the changed
//     path/registry key and a deep link into the StateTrack diff drawer.
//     Previous annotations are cleared first, so a re-run replaces the flags
//     instead of stacking duplicates on top of them.
//  4. Optionally points StateTrack's own Grafana integration at this instance
//     (with a freshly minted service-account token) so changes the *server*
//     captures from then on are annotated live as well.
//
// Deliberately absent: any replay of the seeded events through the ingest API.
// The server de-skews every batch into server time, so replaying a seeded event
// would file it under "now" as a second row with the same id — a duplicate in
// the timeline, not a re-render of the original. To move the counters during a
// recording, run the sibling traffic generator (`dev.ps1 demo-traffic`,
// server/cmd/statetrack-demo-traffic): it submits new changes through the real
// ingest path, which is what actually advances /metrics.
//
// The flags are pushed as *point* annotations — `time` only, never `timeEnd`
// or isRegion. Grafana renders an annotation with an end time as a translucent
// curtain spanning the range, which obscures the data underneath and is not
// what a "change happened here" marker should look like. The dashboard then
// scopes the statetrack annotation layer to the hero panel alone (see its
// annotations.list `filter.ids`), so the KPI sparklines stay clean.
//
// Usage:
//
//	go run ./server/cmd/statetrack-grafana-seed
//	go run ./server/cmd/statetrack-grafana-seed -grafana http://localhost:3000 -live=false
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// seedTag is the tag every seeded annotation carries. It is the same tag the
// live dispatcher uses, so a Grafana annotation query on `statetrack` shows
// seeded and live changes together on one time series.
const seedTag = integrations.SeedTag

// seedOnlyTag is an extra tag unique to this tool, so a re-run can find and
// remove exactly its own flags without touching annotations a real agent pushed
// (those carry seedTag but not seedOnlyTag).
const seedOnlyTag = "grafana-seed"

// dashboardUID must match the uid in the provisioned dashboard JSON so a
// re-import updates the same dashboard instead of creating a duplicate.
const dashboardUID = "statetrack-overview"

// datasourceUID default matches deploy/grafana/provisioning/datasources/statetrack.yml.
const datasourceUID = "statetrack-prometheus"

// postgresUID is the second provisioned datasource. The dashboard's integer
// KPIs, event tables and one-hour telemetry series read from Postgres rather
// than Prometheus — see deploy/grafana/provisioning/datasources/statetrack.yml
// — so this variable has to be bound at import time too. Without it every one
// of those panels renders "Datasource ${DS_POSTGRES} was not found".
const postgresUID = "statetrack-postgres"

// postgresTypes are the type ids a Postgres datasource reports, depending on
// the Grafana version. Grafana 12 and earlier report the legacy `postgres`; 13
// and later report the plugin's own id, `grafana-postgresql-datasource`. A
// dashboard's datasource ref accepts either spelling, but this check compares
// against what the API returns, so both have to be recognised or a correctly
// provisioned datasource is rejected as "not a postgres datasource".
var postgresTypes = map[string]bool{
	"postgres":                      true,
	"grafana-postgresql-datasource": true,
}

// annotateFlag is the metadata key the seeder stamps on the handful of events
// the hero panel draws a flag for. It is the contract between the two seeder
// commands: statetrack-seed decides *which* changes are worth flagging (see
// its annotatedIDs), and this tool only decides how they are rendered. Reading
// the flag rather than a hardcoded path list here is what keeps the two in
// step — a path list would silently drop a flag the moment the demo timeline
// was re-anchored or a target renamed.
const annotateFlag = "annotate"

func main() { os.Exit(run()) }

type config struct {
	grafanaURL    string
	grafanaUser   string
	grafanaPass   string
	promURL       string
	promUID       string
	pgUID         string
	dashboardPath string
	dsn           string
	uiURL         string
	clean         bool
	cleanDays     int
	live          bool
	timeout       time.Duration
}

func run() int {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(log)

	var cfg config
	flag.StringVar(&cfg.grafanaURL, "grafana", envOr("GRAFANA_URL", "http://localhost:3000"), "Grafana base URL")
	flag.StringVar(&cfg.grafanaUser, "user", envOr("GRAFANA_ADMIN_USER", "admin"), "Grafana admin user")
	flag.StringVar(&cfg.grafanaPass, "password", envOr("GRAFANA_ADMIN_PASSWORD", "admin"), "Grafana admin password")
	flag.StringVar(&cfg.promURL, "prometheus-url", envOr("PROMETHEUS_URL", "http://prometheus:9090"),
		"Prometheus URL as reached *from the Grafana container* (compose service DNS)")
	flag.StringVar(&cfg.promUID, "prometheus-uid", envOr("PROMETHEUS_UID", datasourceUID),
		"uid of the provisioned Prometheus datasource")
	flag.StringVar(&cfg.pgUID, "postgres-uid", envOr("POSTGRES_DS_UID", postgresUID),
		"uid of the provisioned Postgres datasource (the event tables and one-hour SQL telemetry)")
	flag.StringVar(&cfg.dashboardPath, "dashboard", "integrations/grafana/statetrack-overview-dashboard.json",
		"path to the provisioned dashboard JSON")
	flag.StringVar(&cfg.dsn, "dsn", envOr("DATABASE_URL",
		"postgres://statetrack:statetrack@localhost:5432/statetrack?sslmode=disable"), "Postgres DSN")
	flag.StringVar(&cfg.uiURL, "ui", envOr("STATETRACK_UI_URL", "http://localhost:5173"),
		"StateTrack console base URL, baked into each annotation's deep link")
	flag.BoolVar(&cfg.clean, "clean", true,
		"replace this tool's previous annotations (keeps re-runs from stacking duplicate flags)")
	flag.IntVar(&cfg.cleanDays, "clean-days", 7,
		"how far back -clean looks for this tool's own annotations; wider than the push window so a later run cannot leave orphans")
	flag.BoolVar(&cfg.live, "live", true,
		"provision a Grafana service-account token into StateTrack so the running server annotates live changes too")
	flag.DurationVar(&cfg.timeout, "timeout", 20*time.Second, "per-request HTTP timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	gc := newGrafanaClient(cfg.grafanaURL, cfg.grafanaUser, cfg.grafanaPass, cfg.timeout)

	// ---- 1. Grafana reachable + datasource resolved ----------------------
	version, err := gc.waitForHealth(ctx, 60*time.Second)
	if err != nil {
		log.Error("grafana is not reachable",
			"url", cfg.grafanaURL,
			"hint", "run: dev.ps1 up   (or docker compose up -d grafana prometheus node-exporter)",
			"err", err)
		return 1
	}
	log.Info("grafana reachable", "url", cfg.grafanaURL, "version", version)

	dsUID, err := gc.ensurePrometheusDatasource(ctx, cfg.promUID, cfg.promURL)
	if err != nil {
		log.Error("resolve prometheus datasource", "err", err)
		return 1
	}
	log.Info("prometheus datasource ready", "uid", dsUID, "url", cfg.promURL)

	pgDS, err := gc.ensurePostgresDatasource(ctx, cfg.pgUID, cfg.dsn)
	if err != nil {
		log.Error("resolve postgres datasource", "err", err)
		return 1
	}
	log.Info("postgres datasource ready", "uid", pgDS)

	// ---- 2. Import the dashboard ----------------------------------------
	if err := gc.importDashboard(ctx, cfg.dashboardPath, dsUID, pgDS); err != nil {
		log.Error("import dashboard", "path", cfg.dashboardPath, "err", err)
		return 1
	}
	log.Info("dashboard imported", "uid", dashboardUID, "path", cfg.dashboardPath)

	// ---- 3. Push annotations for the seeded Level 1 changes --------------
	pool, err := pgxpool.New(ctx, cfg.dsn)
	if err != nil {
		log.Error("connect to postgres", "err", err)
		return 1
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Error("ping postgres (run: dev.ps1 up; dev.ps1 migrate; dev.ps1 seed)", "err", err)
		return 1
	}

	store := storage.New(pool, nil, 0)
	orgID, err := store.DefaultOrg(ctx)
	if err != nil {
		log.Error("resolve default org", "err", err)
		return 1
	}

	// Scope to a lookback a little wider than the dashboard's default window.
	//
	// The dashboard opens on now-1h..now, and the seeder anchors its whole
	// timeline inside that hour (see its newTimeline). Selecting with exactly
	// the same one-hour bound looks right but loses the oldest flag: `seed` and
	// `grafana-seed` are two commands, so by the time this one runs the -52m
	// anchor is already -52m-plus-a-few-seconds, and a `since = now-1h` cut
	// silently drops it. A 90-minute lookback keeps all four flags; the extra
	// ones sit off the left edge of the panel and are simply not drawn.
	now := time.Now()
	since := now.Add(-90 * time.Minute)

	changes, err := loadSeededChanges(ctx, pool, orgID, since)
	if err != nil {
		log.Error("load annotated changes", "err", err)
		return 1
	}
	if len(changes) == 0 {
		log.Error("no annotated changes found in the last hour",
			"since", since.Format(time.RFC3339),
			"hint", "run: dev.ps1 seed   (it writes the demo timeline relative to now)")
		return 1
	}

	// Bound the delete to a recent window so an operator pointing at a real
	// Grafana never loses historical annotations — but keep it wider than the
	// push window, or a run on a later day would leave that day's flags behind
	// as orphans (only this tool's own marker tag is ever queried).
	cleanFrom := now.AddDate(0, 0, -cfg.cleanDays)
	if cfg.clean {
		// Uses the shared client, so this command and `statetrack-seed` delete by
		// exactly the same selector. Two private copies of "which annotations are
		// ours" is how a stale flag survives a re-run and keeps 404-ing.
		annClient := integrations.NewAnnotationClient(
			cfg.grafanaURL, cfg.grafanaUser, cfg.grafanaPass, "", cfg.timeout)
		if n, err := annClient.Purge(ctx, cleanFrom); err != nil {
			log.Warn("clean previous annotations", "err", err)
		} else if n > 0 {
			log.Info("replaced previous seed annotations", "removed", n, "since", cleanFrom.Format(time.RFC3339))
		}
	}

	pushed, failed := 0, 0
	var earliest, latest time.Time
	for _, c := range changes {
		ann := integrations.FormatAnnotation(cfg.uiURL, c.notification())
		// Mark this flag as seeded so a later run can replace it without
		// touching annotations the live dispatcher pushed.
		ann.Tags = append(append([]string{}, ann.Tags...), seedOnlyTag)
		if _, err := gc.createAnnotation(ctx, ann); err != nil {
			failed++
			log.Warn("push annotation failed", "event", c.id, "target", c.pathOrKey, "err", err)
			_ = store.LogAnnotation(ctx, c.logEntry(orgID, storage.AnnotationFailed, err.Error()))
			continue
		}
		pushed++
		if err := store.LogAnnotation(ctx, c.logEntry(orgID, storage.AnnotationDelivered, "")); err != nil {
			log.Warn("record annotation in the console log", "event", c.id, "err", err)
		}
		if earliest.IsZero() || c.occurredAt.Before(earliest) {
			earliest = c.occurredAt
		}
		if c.occurredAt.After(latest) {
			latest = c.occurredAt
		}
		log.Info("annotation pushed", "host", c.hostname, "actor", c.actor,
			"target", c.pathOrKey, "at", c.occurredAt.Format(time.RFC3339))
	}
	if pushed == 0 {
		log.Error("no annotations were accepted by Grafana")
		return 1
	}
	log.Info("annotations pushed", "delivered", pushed, "failed", failed)

	// ---- 4. Live annotation pushing (optional) --------------------------
	if cfg.live {
		if err := provisionServiceAccount(ctx, gc, store, orgID, cfg.grafanaURL); err != nil {
			log.Warn("could not provision the live Grafana integration; the push-only demo still works",
				"err", err)
		}
	}

	// ---- 5. Where to look -----------------------------------------------
	printHandoff(log, cfg, changes, earliest, latest)
	return 0
}

// ---------------------------------------------------------------------------
// Grafana HTTP API
// ---------------------------------------------------------------------------

type grafanaClient struct {
	base   string
	user   string
	pass   string
	token  string
	client *http.Client
}

func newGrafanaClient(base, user, pass string, timeout time.Duration) *grafanaClient {
	return &grafanaClient{
		base:   strings.TrimRight(base, "/"),
		user:   user,
		pass:   pass,
		client: &http.Client{Timeout: timeout},
	}
}

// do issues one authenticated request. Basic auth is the default (the stack's
// admin:admin); a service-account bearer token is used once one has been minted.
func (g *grafanaClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	} else {
		req.SetBasicAuth(g.user, g.pass)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// waitForHealth polls /api/health until Grafana answers or the deadline passes.
// Grafana's health endpoint is unauthenticated, which makes it the right
// readiness probe: it separates "not up yet" from "credentials wrong".
func (g *grafanaClient) waitForHealth(ctx context.Context, within time.Duration) (string, error) {
	deadline := time.Now().Add(within)
	var lastErr error
	for {
		var health struct {
			Version  string `json:"version"`
			Database string `json:"database"`
		}
		err := g.do(ctx, http.MethodGet, "/api/health", nil, &health)
		if err == nil && health.Version != "" {
			return health.Version, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// ensurePrometheusDatasource returns the uid of the Prometheus datasource,
// creating it when the operator points the tool at a Grafana that was not
// started from this repo's compose file.
func (g *grafanaClient) ensurePrometheusDatasource(ctx context.Context, uid, targetURL string) (string, error) {
	// Prefer the pinned uid so a provisioned stack is used as-is.
	var byUID struct {
		UID  string `json:"uid"`
		Type string `json:"type"`
	}
	if err := g.do(ctx, http.MethodGet, "/api/datasources/uid/"+url.PathEscape(uid), nil, &byUID); err != nil {
		var list []struct {
			UID  string `json:"uid"`
			Type string `json:"type"`
		}
		if listErr := g.do(ctx, http.MethodGet, "/api/datasources", nil, &list); listErr != nil {
			return "", listErr
		}
		for _, ds := range list {
			if ds.Type == "prometheus" {
				return ds.UID, nil
			}
		}
		// Nothing to reuse: create it, pinned to uid so the dashboard's
		// DS_PROMETHEUS variable resolves deterministically on the next run.
		var created struct {
			UID string `json:"uid"`
		}
		if err := g.do(ctx, http.MethodPost, "/api/datasources", map[string]any{
			"uid":       uid,
			"name":      "Prometheus",
			"type":      "prometheus",
			"access":    "proxy",
			"url":       targetURL,
			"isDefault": true,
			"jsonData":  map[string]any{"httpMethod": "POST", "timeInterval": "15s"},
		}, &created); err != nil {
			return "", err
		}
		if created.UID == "" {
			return uid, nil
		}
		return created.UID, nil
	}
	if byUID.Type != "" && byUID.Type != "prometheus" {
		return "", fmt.Errorf("datasource %q is a %s, not a prometheus datasource", uid, byUID.Type)
	}
	return byUID.UID, nil
}

// ensurePostgresDatasource returns the uid of the Postgres datasource, creating
// it when the operator points the tool at a Grafana that was not started from
// this repo's compose file.
//
// The dashboard reads the events tables directly from Postgres for its integer
// KPIs, the host and recent-changes tables, the category breakdown and the
// one-hour telemetry line. That is what makes those panels correct the moment
// the stack boots, instead of correct an hour later once Prometheus has
// accumulated enough scrapes to draw a full-width series.
//
// The DSN is parsed rather than used verbatim: Grafana wants host/port/database
// and credentials as separate fields, and it reaches the database over the
// compose network (postgres:5432) rather than over localhost, which is what the
// Go tooling uses.
func (g *grafanaClient) ensurePostgresDatasource(ctx context.Context, uid, dsn string) (string, error) {
	var byUID datasourceInfo
	if err := g.do(ctx, http.MethodGet, "/api/datasources/uid/"+url.PathEscape(uid), nil, &byUID); err == nil {
		if byUID.Type != "" && !postgresTypes[byUID.Type] {
			return "", fmt.Errorf("datasource %q is a %s, not a postgres datasource", uid, byUID.Type)
		}
		// A datasource provisioned before the `jsonData.database` fix is
		// reachable but cannot answer a single query under Grafana 13's
		// plugin, and the failure surfaces as "No data" on every panel rather
		// than as an error. Repair it in place so an existing Grafana volume
		// heals on the next seed instead of requiring `down -v`.
		if db, _ := byUID.JSONData["database"].(string); db == "" {
			if err := g.patchPostgresDatabase(ctx, uid, byUID, dsn); err != nil {
				return "", err
			}
		}
		return byUID.UID, nil
	}

	// Not provisioned (a bare Grafana): create it from the DSN.
	cfg, err := pgConfigFromDSN(dsn)
	if err != nil {
		return "", err
	}
	var created struct {
		UID string `json:"uid"`
	}
	if err := g.do(ctx, http.MethodPost, "/api/datasources", map[string]any{
		"uid":  uid,
		"name": "StateTrack Postgres",
		// The legacy id is still the portable spelling: Grafana 13 maps it to
		// the plugin internally, and older versions do not know the plugin id.
		"type":     "postgres",
		"access":   "proxy",
		"url":      cfg.url,
		"database": cfg.database,
		"user":     cfg.user,
		"secureJsonData": map[string]any{
			"password": cfg.password,
		},
		"jsonData": map[string]any{
			"sslmode": "disable",
			// Named here as well as at the top level: the legacy `postgres`
			// datasource reads the top-level field, while
			// `grafana-postgresql-datasource` (Grafana 12.3+) reads this one.
			// Without it the newer plugin refuses every query with "You do not
			// currently have a default database configured".
			"database":        cfg.database,
			"postgresVersion": 1700,
			"maxOpenConns":    10,
			"maxIdleConns":    5,
		},
	}, &created); err != nil {
		return "", err
	}
	if created.UID == "" {
		return uid, nil
	}
	return created.UID, nil
}

// datasourceInfo is the subset of Grafana's datasource payload this tool reads
// and rewrites. `database` sits at the top level for the legacy plugin and in
// jsonData for the newer one, so both are kept.
type datasourceInfo struct {
	UID      string         `json:"uid"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	URL      string         `json:"url"`
	Database string         `json:"database"`
	User     string         `json:"user"`
	JSONData map[string]any `json:"jsonData"`
}

// patchPostgresDatabase fills in the one field a provisioned-but-unusable
// Postgres datasource is missing.
//
// Grafana 12.3 moved the Postgres datasource behind a plugin whose
// configuration reads `jsonData.database`; the legacy `postgres` datasource read
// a top-level `database`. A provisioning file written for the legacy shape
// therefore produces a datasource that connects — health check green — but
// refuses every query with "You do not currently have a default database
// configured for this data source". The dashboard then shows "No data" in all
// fourteen panels with no error text anywhere in the UI.
//
// Only the field is patched, and only when it is empty, so an operator's own
// choice is never overwritten.
func (g *grafanaClient) patchPostgresDatabase(ctx context.Context, uid string, ds datasourceInfo, dsn string) error {
	database := ds.Database
	if database == "" {
		cfg, err := pgConfigFromDSN(dsn)
		if err != nil {
			return err
		}
		database = cfg.database
	}
	jsonData := ds.JSONData
	if jsonData == nil {
		jsonData = map[string]any{}
	}
	jsonData["database"] = database
	// Grafana's update endpoint rejects a payload without `name`, and it
	// replaces jsonData wholesale, so the existing keys are carried through.
	updates := map[string]any{
		"uid":      ds.UID,
		"name":     ds.Name,
		"type":     ds.Type,
		"access":   "proxy",
		"url":      ds.URL,
		"database": database,
		"user":     ds.User,
		"jsonData": jsonData,
	}
	if err := g.do(ctx, http.MethodPut, "/api/datasources/uid/"+url.PathEscape(uid), updates, nil); err != nil {
		return fmt.Errorf("patch %s datasource database: %w", uid, err)
	}
	return nil
}

// pgTarget is the subset of a DSN Grafana's datasource API needs.
type pgTarget struct {
	url      string // host:port as reachable *from the Grafana container*
	database string
	user     string
	password string
}

// pgConfigFromDSN converts a postgres:// URL into Grafana's field set.
//
// The host is rewritten to the compose service name when it points at
// localhost: the tooling (this seeder, the server) runs on the developer's
// machine and dials localhost, but Grafana runs in a container, where localhost
// is the container itself. Without the rewrite the datasource would be created
// successfully and then fail every query with "connection refused", which is a
// far more confusing failure than an explicit one.
func pgConfigFromDSN(dsn string) (pgTarget, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return pgTarget{}, fmt.Errorf("parse postgres dsn: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" {
		host = "postgres"
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	database := strings.TrimPrefix(u.Path, "/")
	if database == "" {
		database = "statetrack"
	}
	user := ""
	password := ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
	}
	return pgTarget{
		url:      host + ":" + port,
		database: database,
		user:     user,
		password: password,
	}, nil
}

// importDashboard pushes the provisioned dashboard, resolving the
// DS_PROMETHEUS and DS_POSTGRES placeholders to real datasource uids first.
//
// The JSON ships those refs as *name* placeholders (`${DS_PROMETHEUS}`,
// `${DS_POSTGRES}`) because the file has to be importable by a human through
// Grafana's UI as well as by this tool. Grafana's UI import binds them from a
// picker; the HTTP API does **not** — it stores the dashboard exactly as posted.
// A literal `uid: "${DS_POSTGRES}"` then matches no datasource, and all fourteen
// panels render "No data".
//
// So both places a datasource hides in have to be rewritten: the template
// variables (so the dashboard's own variable substitution is consistent) *and*
// every panel/target `datasource` object, which is what the query engine
// actually reads.
func (g *grafanaClient) importDashboard(ctx context.Context, path, promUID, pgUID string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read dashboard: %w", err)
	}
	var dash map[string]any
	if err := json.Unmarshal(raw, &dash); err != nil {
		return fmt.Errorf("parse dashboard: %w", err)
	}
	if uid, _ := dash["uid"].(string); uid != dashboardUID {
		return fmt.Errorf("dashboard uid %q does not match the expected %q", uid, dashboardUID)
	}

	bindings := map[string]datasourceRef{
		"DS_PROMETHEUS": {label: "Prometheus", uid: promUID, typ: g.datasourceType(ctx, promUID, "prometheus")},
		"DS_POSTGRES":   {label: "StateTrack Postgres", uid: pgUID, typ: g.datasourceType(ctx, pgUID, "postgres")},
	}
	for name, b := range bindings {
		bindDatasourceVariable(dash, name, b.label, b.uid)
	}
	resolveDatasourceRefs(dash, bindings)

	return g.do(ctx, http.MethodPost, "/api/dashboards/db", map[string]any{
		"dashboard": dash,
		"overwrite": true,
		// Keep the message stable so the Grafana version history reads as a
		// provisioning action rather than an edit by a named person.
		"message": "provisioned by statetrack-grafana-seed",
	}, nil)
}

// datasourceRef is one placeholder and the concrete datasource it resolves to.
type datasourceRef struct {
	label string
	uid   string
	// typ is the datasource's own type id, which the dashboard's refs must
	// agree with: Grafana rejects a ref whose type and uid disagree, and
	// Postgres reports two different ids depending on the version.
	typ string
}

// datasourceType asks Grafana what type uid actually is, falling back to def
// when the lookup fails. The fallback keeps a bare-Grafana run working rather
// than failing the whole import over a cosmetic field.
func (g *grafanaClient) datasourceType(ctx context.Context, uid, def string) string {
	var ds struct {
		Type string `json:"type"`
	}
	if err := g.do(ctx, http.MethodGet, "/api/datasources/uid/"+url.PathEscape(uid), nil, &ds); err == nil && ds.Type != "" {
		return ds.Type
	}
	return def
}

// resolveDatasourceRefs rewrites every `{"uid": "${DS_...}"}` object in the
// dashboard — panels, targets and annotations — to the resolved uid and type.
//
// Walking the decoded document generically rather than by path is deliberate:
// a datasource ref can sit on a panel, on each of its targets, and on annotation
// layers, and a new panel shape should not silently reintroduce the "No data"
// bug because this function knew only about the old ones.
func resolveDatasourceRefs(node any, bindings map[string]datasourceRef) {
	switch v := node.(type) {
	case map[string]any:
		if uid, ok := v["uid"].(string); ok {
			// `${DS_POSTGRES}` in a datasource object, and a bare `DS_POSTGRES`
			// in some older exports; strip the wrapping before looking up.
			name := strings.TrimSuffix(strings.TrimPrefix(uid, "${"), "}")
			if b, found := bindings[name]; found {
				v["uid"] = b.uid
				if _, hasType := v["type"]; hasType {
					v["type"] = b.typ
				}
			}
		}
		for _, child := range v {
			resolveDatasourceRefs(child, bindings)
		}
	case []any:
		for _, child := range v {
			resolveDatasourceRefs(child, bindings)
		}
	}
}

// bindDatasourceVariable points the named template variable at uid.
func bindDatasourceVariable(dash map[string]any, name, label, dsUID string) {
	templating, _ := dash["templating"].(map[string]any)
	vars, _ := templating["list"].([]any)
	for _, rawVar := range vars {
		v, ok := rawVar.(map[string]any)
		if !ok || v["name"] != name {
			continue
		}
		v["current"] = map[string]any{
			"selected": true,
			"text":     label,
			"value":    dsUID,
		}
	}
}

// createAnnotation posts one annotation and returns its Grafana id.
func (g *grafanaClient) createAnnotation(ctx context.Context, ann integrations.Annotation) (int64, error) {
	var out struct {
		ID      int64  `json:"id"`
		Message string `json:"message"`
	}
	if err := g.do(ctx, http.MethodPost, "/api/annotations", ann, &out); err != nil {
		return 0, err
	}
	if out.ID == 0 {
		return 0, errors.New("grafana did not return an annotation id")
	}
	return out.ID, nil
}

// deleteSeededAnnotations is retained for the smoke test and for callers that
// still want the tag-pair behaviour explicitly. The seeding path uses
// integrations.AnnotationClient.Purge so both commands share one selector.
func (g *grafanaClient) deleteSeededAnnotations(ctx context.Context, from time.Time) (int, error) {
	removed := 0
	for _, tag := range []string{seedOnlyTag, seedTag} {
		n, err := g.deleteAnnotationsByTag(ctx, tag, from)
		removed += n
		if err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// deleteAnnotationsByTag removes every annotation carrying tag within the
// window. Grafana's tag DELETE is not supported by every version, so this lists
// then deletes by id — which works everywhere and reports per-row failures.
func (g *grafanaClient) deleteAnnotationsByTag(ctx context.Context, tag string, from time.Time) (int, error) {
	path := fmt.Sprintf("/api/annotations?tags=%s&from=%d&to=%d&limit=500",
		url.QueryEscape(tag), from.UnixMilli(), time.Now().Add(48*time.Hour).UnixMilli())

	var rows []struct {
		ID int64 `json:"id"`
	}
	if err := g.do(ctx, http.MethodGet, path, nil, &rows); err != nil {
		return 0, err
	}
	removed := 0
	for _, r := range rows {
		if err := g.do(ctx, http.MethodDelete, fmt.Sprintf("/api/annotations/%d", r.ID), nil, nil); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// provisionServiceAccount mints a Grafana service-account token and saves it
// into StateTrack's Grafana integration settings, so changes the *server* sees
// from now on are annotated live as well. Existing configuration is preserved;
// only endpoint, token and toggles are touched.
func provisionServiceAccount(ctx context.Context, gc *grafanaClient, store *storage.Store, orgID, baseURL string) error {
	// Reuse a previous token if the integration already points at this Grafana:
	// minting a fresh service account on every run would litter the instance.
	current, err := store.GetGrafanaSettings(ctx, orgID)
	if err != nil {
		return err
	}
	if current.URL == baseURL && current.APIToken != "" {
		slog.Info("grafana integration already configured for live pushes", "url", baseURL)
		return nil
	}

	var sa struct {
		ID int64 `json:"id"`
	}
	if err := gc.do(ctx, http.MethodPost, "/api/serviceaccounts", map[string]any{
		"name":       "statetrack-server",
		"role":       "Editor",
		"isDisabled": false,
	}, &sa); err != nil {
		return fmt.Errorf("create service account: %w", err)
	}
	var tok struct {
		Key string `json:"key"`
	}
	if err := gc.do(ctx, http.MethodPost, fmt.Sprintf("/api/serviceaccounts/%d/tokens", sa.ID),
		map[string]any{"name": "statetrack-annotations"}, &tok); err != nil {
		return fmt.Errorf("create service account token: %w", err)
	}
	if tok.Key == "" {
		return errors.New("grafana returned an empty service-account token")
	}

	next := current
	next.URL = baseURL
	next.APIToken = tok.Key
	// L1/L2 always make it onto the timeline; L3 drift stays opt-in so the demo
	// dashboard is not flooded by routine file churn.
	next.PushL1, next.PushL2, next.PushL3 = true, true, false
	next.Enabled = true
	next.LastTestOK = true
	next.LastTestError = ""
	now := time.Now().UTC()
	next.LastTestAt = &now

	if _, err := store.SaveGrafanaSettings(ctx, orgID, next); err != nil {
		return fmt.Errorf("save grafana settings: %w", err)
	}
	slog.Info("live annotation pushing enabled",
		"url", baseURL, "push_l1", true, "push_l2", true, "push_l3", false)
	return nil
}

// ---------------------------------------------------------------------------
// Seeded changes
// ---------------------------------------------------------------------------

// seededChange is one root Level 1 event read back from Postgres.
type seededChange struct {
	id         string
	hostname   string
	actor      string
	pathOrKey  string
	summary    string
	category   pb.Category
	action     pb.Action
	level      pb.ImpactLevel
	occurredAt time.Time
}

func (c seededChange) notification() storage.Notification {
	return storage.Notification{
		ID:          c.id,
		Hostname:    c.hostname,
		OccurredAt:  c.occurredAt,
		ImpactLevel: c.level,
		Category:    c.category,
		Action:      c.action,
		Summary:     c.summary,
		ActorName:   c.actor,
		PathOrKey:   c.pathOrKey,
	}
}

func (c seededChange) logEntry(orgID, status, errText string) storage.AnnotationEntry {
	ann := integrations.FormatAnnotation("", c.notification())
	e := storage.AnnotationEntry{
		OrgID:        orgID,
		EventID:      c.id,
		Hostname:     c.hostname,
		ImpactLevel:  int32(c.level),
		Summary:      c.summary,
		Text:         ann.Text,
		Tags:         ann.Tags,
		Dashboard:    dashboardUID,
		Status:       status,
		DispatchedAt: time.Now(),
	}
	if errText != "" {
		// Keep the row readable; Grafana errors can be long.
		if len(errText) > 400 {
			errText = errText[:400]
		}
		e.Error = errText
	}
	return e
}

// loadSeededChanges reads the demo fleet's *annotated* events inside a window.
//
// The selection is driven by the `annotate` metadata flag the seeder stamps on
// a curated few changes (see its annotatedIDs), not by impact level. Level
// alone used to be the filter, and it stopped being right the moment the demo
// timeline gained background volume: an L1 filter would either flag every
// critical change in the hour or none, and there is no level that means "this
// one is worth a vertical line on the hero panel".
//
// The flag is set by the seeder for exactly the four changes the design names —
// two L2 package transactions and two L1 edits, spread across the hour — so the
// hero panel reads as a story rather than a thicket of flags.
//
// The window is the same one the dashboard opens on (now-1h..now). Ordering
// oldest-first keeps the printed hand-off in reading order and makes the
// "spread across the hour" property visible in the log.
func loadSeededChanges(ctx context.Context, pool *pgxpool.Pool, orgID string, since time.Time) ([]seededChange, error) {
	rows, err := pool.Query(ctx, `
		SELECT e.id::text, h.hostname, COALESCE(a.username, ''), t.path_or_key, e.summary,
		       e.category, e.action, e.impact_level, e.occurred_at
		FROM events e
		JOIN hosts h ON h.id = e.host_id
		JOIN targets t ON t.id = e.target_id
		LEFT JOIN actors a ON a.id = e.actor_id
		WHERE e.org_id = $1::uuid
		  AND e.parent_event_id IS NULL
		  AND e.metadata->>$3 = 'true'
		  AND e.occurred_at >= $2
		ORDER BY e.occurred_at`, orgID, since, annotateFlag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []seededChange
	for rows.Next() {
		var c seededChange
		var category, action, level int32
		if err := rows.Scan(&c.id, &c.hostname, &c.actor, &c.pathOrKey, &c.summary,
			&category, &action, &level, &c.occurredAt); err != nil {
			return nil, err
		}
		c.category = pb.Category(category)
		c.action = pb.Action(action)
		c.level = pb.ImpactLevel(level)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Handoff
// ---------------------------------------------------------------------------

// printHandoff prints the two URLs to open, with an explicit Grafana time range.
//
// The seeder anchors its timeline inside the last hour, which is the same window
// the provisioned dashboard opens on (now-1h..now). The explicit range is still
// printed so a take stays reproducible while the clock advances — the left edge
// is pinned to the earliest flagged change rather than to "now".
func printHandoff(log *slog.Logger, cfg config, changes []seededChange, earliest, latest time.Time) {
	from := earliest.Add(-10 * time.Minute)
	to := time.Now().Add(10 * time.Minute)
	if !latest.IsZero() && latest.Add(10*time.Minute).After(to) {
		to = latest.Add(10 * time.Minute)
	}

	q := url.Values{}
	q.Set("from", fmt.Sprint(from.UnixMilli()))
	q.Set("to", fmt.Sprint(to.UnixMilli()))
	q.Set("refresh", "30s")
	grafanaURL := fmt.Sprintf("%s/d/%s/statetrack-change-impact?%s",
		strings.TrimRight(cfg.grafanaURL, "/"), dashboardUID, q.Encode())

	// The StateTrack console deep links land on the diff drawer; one per change.
	links := make([]string, 0, len(changes))
	for _, c := range changes {
		links = append(links, fmt.Sprintf("%s/events/%s?tab=diff", strings.TrimRight(cfg.uiURL, "/"), c.id))
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 78))
	fmt.Println("  StateTrack  <->  Grafana  demo ready")
	fmt.Println(strings.Repeat("=", 78))
	fmt.Println("  Dashboard  : StateTrack – Change Impact   (Last 1 hour)")
	fmt.Println("  Hero panel : Infrastructure signals + change events")
	fmt.Printf("  Annotations: %d changes flagged (L1 red / L2 amber), %s .. %s\n",
		len(changes), earliest.Format("15:04:05"), latest.Format("15:04:05"))
	fmt.Println(strings.Repeat("-", 78))
	fmt.Printf("  1. Grafana   %s\n", grafanaURL)
	fmt.Printf("  2. Console   %s/integrations\n", strings.TrimRight(cfg.uiURL, "/"))
	fmt.Println()
	fmt.Println("  The Grafana URL above pins the range to the seeded hour. In the")
	fmt.Println("  console, the same changes are under Timeline (range: Last 1 hour).")
	fmt.Println()
	fmt.Println("  The metric panels need live traffic to move; in another shell run:")
	fmt.Println("      .\\scripts\\dev.ps1 demo-traffic")
	fmt.Println()
	fmt.Println("  Diff drawers for the flagged changes:")
	for _, l := range links {
		fmt.Printf("    %s\n", l)
	}
	fmt.Println(strings.Repeat("=", 78))
	fmt.Println()
	log.Info("done", "annotations", len(changes), "grafana", grafanaURL)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
