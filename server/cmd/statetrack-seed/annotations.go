package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/server/internal/integrations"
	"github.com/statetrack/statetrack/server/internal/storage"
)

// grafanaSync holds the resolved Grafana connection for annotation re-seeding.
//
// It is optional by design: `statetrack-seed` must succeed on a machine where
// Grafana is not running (a plain `dev.ps1 up` without the dashboard), because
// the database timeline is the primary artifact. A missing Grafana therefore
// downgrades the run to "events seeded, flags not refreshed" with a warning
// rather than failing the seed.
type grafanaSync struct {
	client *integrations.AnnotationClient
	uiURL  string
}

// grafanaCleanWindow is how far back the purge looks for annotations to remove.
//
// The seeder's whole timeline is inside the last hour, but the purge has to be
// wider than the push: annotations from yesterday's take carry yesterday's event
// ids, and those rows are gone the moment this run re-anchors. Leaving them
// behind is precisely how "Inspect in StateTrack" came to 404 — the flag was
// still on someone's timeline pointing at a deleted row. Seven days is long
// enough to clean up after a demo week and short enough that it can never touch
// a screenshot-era annotation an operator might still want.
const grafanaCleanWindow = 7 * 24 * time.Hour

// newGrafanaSync resolves the demo Grafana from the environment. A nil result
// (and a nil error) means "no Grafana configured"; an error means it *is*
// configured but unreachable, which the caller reports and then continues past.
func newGrafanaSync(ctx context.Context) (*grafanaSync, error) {
	base := envOr("GRAFANA_URL", "http://localhost:3000")
	client := integrations.NewAnnotationClient(
		base,
		envOr("GRAFANA_ADMIN_USER", "admin"),
		envOr("GRAFANA_ADMIN_PASSWORD", "admin"),
		envOr("GRAFANA_TOKEN", ""),
		5*time.Second,
	)
	if err := client.Health(ctx); err != nil {
		return nil, err
	}
	return &grafanaSync{
		client: client,
		uiURL:  envOr("STATETRACK_UI_URL", "http://localhost:5173"),
	}, nil
}

// resyncAnnotations replaces every StateTrack annotation on the dashboard with a
// fresh point annotation for the events this run just wrote.
//
// The ordering is the whole point of the function. Events are inserted first
// (elsewhere in seed), then the flags are derived by *reading those rows back*,
// so the UUID in a deep link is the one PostgreSQL stored rather than the one the
// seeder intended to store. The two are the same today, and this is what keeps
// them the same if the insert ever gains an ON CONFLICT that drops a row, a
// partition that rejects one, or a trigger that rewrites an id: the annotation
// can only reference a row that exists, because it was read from that row.
//
// A failed push is logged and summarised, never fatal. The return value is the
// number of flags successfully posted; an error is returned only when the purge
// itself failed, since in that case the dashboard still shows dead links and the
// operator should hear about it loudly.
func (g *grafanaSync) resyncAnnotations(ctx context.Context, pool *pgxpool.Pool, orgID string, log *slog.Logger) (int, error) {
	removed, err := g.client.Purge(ctx, time.Now().Add(-grafanaCleanWindow))
	if err != nil {
		return 0, fmt.Errorf("clear previous grafana annotations: %w", err)
	}
	if removed > 0 {
		log.Info("cleared previous grafana annotations", "removed", removed)
	}

	changes, err := loadAnnotatedChanges(ctx, pool, orgID, time.Now().Add(-2*time.Hour))
	if err != nil {
		return 0, fmt.Errorf("read annotated changes: %w", err)
	}

	pushed, failed := 0, 0
	for _, c := range changes {
		ann := integrations.FormatAnnotation(g.uiURL, storage.Notification{
			ID:          c.id,
			Hostname:    c.hostname,
			OccurredAt:  c.occurredAt,
			ImpactLevel: c.level,
			Category:    c.category,
			Action:      c.action,
			Summary:     c.summary,
			ActorName:   c.actor,
			PathOrKey:   c.pathOrKey,
		})
		// The marker tag is what lets a later run find exactly its own flags,
		// even if the text-based selector above were ever to miss.
		ann.Tags = append(ann.Tags, "grafana-seed")

		if _, err := g.client.Create(ctx, ann); err != nil {
			failed++
			log.Warn("push grafana annotation", "event", c.id, "target", c.pathOrKey, "err", err)
			continue
		}
		pushed++
		log.Info("grafana annotation pushed",
			"host", c.hostname, "target", c.pathOrKey,
			"at", c.occurredAt.Format(time.RFC3339), "event", c.id)
	}

	if failed > 0 {
		log.Warn("some grafana annotations were rejected", "delivered", pushed, "failed", failed)
	}
	if pushed != len(changes) {
		return pushed, fmt.Errorf("%d of %d annotations were rejected by grafana", failed, len(changes))
	}
	return pushed, nil
}

// annotatedChange is one flagged event, read back from the events table.
//
// Only the fields the annotation text needs are selected: the goal is to prove
// the row exists and to quote it, not to re-read the whole timeline.
type annotatedChange struct {
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

// loadAnnotatedChanges reads the events carrying the `annotate` flag.
//
// The filter is the metadata flag rather than a hardcoded id list on purpose:
// the seeder decides which changes are worth flagging (annotatedIDs), and this
// query simply follows that decision. A path list here would silently stop
// flagging the moment a target was renamed.
func loadAnnotatedChanges(ctx context.Context, pool *pgxpool.Pool, orgID string, since time.Time) ([]annotatedChange, error) {
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
		ORDER BY e.occurred_at`, orgID, since, annotateTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []annotatedChange
	for rows.Next() {
		var c annotatedChange
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

// verifyDeepLinks is a sanity check run at the end of a seed: every event id a
// flag links to must resolve through the same lookup the console uses.
//
// This is a Postgres query rather than an HTTP call to the console API on
// purpose. It has to hold whether or not the backend is running (`dev.ps1 seed`
// runs before `run-server`), and the console's handler is a thin wrapper around
// exactly this `events WHERE id = …` lookup. Checking the row is the honest test.
func verifyDeepLinks(ctx context.Context, pool *pgxpool.Pool, orgID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	var found int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE org_id = $1::uuid AND id = ANY($2::uuid[])`,
		orgID, ids).Scan(&found); err != nil {
		return err
	}
	if found != len(ids) {
		return fmt.Errorf("%d of %d annotation deep links point at a missing event", len(ids)-found, len(ids))
	}
	return nil
}
