// Package storage is the server's persistence layer: Postgres repository
// (dictionary IDs, hosts, partitioned events, current-state drift) plus the
// S3-compatible blob router for large diffs.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// DiffInlineMax is the byte threshold under which a decompressed diff is
// stored inline in events.inline_diff (spec: 2048 bytes).
const DiffInlineMax = 2048

// ErrNotFound reports that a requested row does not exist. Handlers translate it
// into a 404 instead of leaking the driver's "no rows in result set" as a 500.
var ErrNotFound = errors.New("not found")

// Store is the Postgres repository. It is safe for concurrent use.
type Store struct {
	pool      *pgxpool.Pool
	s3        *BlobStore
	targets   *dict
	actors    *dict
	processes *dict
}

// New builds a Store. s3 may be nil when blob storage is disabled.
func New(pool *pgxpool.Pool, s3 *BlobStore, dictCacheSize int) *Store {
	if dictCacheSize <= 0 {
		dictCacheSize = DefaultDictCacheSize
	}
	return &Store{
		pool:      pool,
		s3:        s3,
		targets:   &dict{cache: newLRU(dictCacheSize)},
		actors:    &dict{cache: newLRU(dictCacheSize)},
		processes: &dict{cache: newLRU(dictCacheSize)},
	}
}

// Pool exposes the underlying pool for maintenance jobs.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// HasBlobStore reports whether large diffs are offloaded to S3. The console's
// system card shows "inline" when they are not, which is the honest state of a
// single-container deployment.
func (s *Store) HasBlobStore() bool { return s.s3 != nil }

// DatabaseVersion returns the Postgres server version, for the system card.
func (s *Store) DatabaseVersion(ctx context.Context) (string, error) {
	var v string
	if err := s.pool.QueryRow(ctx, `SELECT current_setting('server_version')`).Scan(&v); err != nil {
		return "", err
	}
	return "PostgreSQL " + v, nil
}

// DefaultOrg returns the default organization's id, creating it if absent.
func (s *Store) DefaultOrg(ctx context.Context) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT id::text FROM organizations WHERE name = 'default' ORDER BY created_at LIMIT 1`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != pgx.ErrNoRows {
		return "", fmt.Errorf("default org: %w", err)
	}
	// Race-tolerant create: use a transaction with advisory lock.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, orgLockKey); err != nil {
		return "", err
	}
	if err := tx.QueryRow(ctx,
		`SELECT id::text FROM organizations WHERE name = 'default' ORDER BY created_at LIMIT 1`).Scan(&id); err != nil {
		if err != pgx.ErrNoRows {
			return "", err
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO organizations (name) VALUES ('default') RETURNING id::text`).Scan(&id); err != nil {
			return "", fmt.Errorf("create default org: %w", err)
		}
	}
	return id, tx.Commit(ctx)
}

const orgLockKey int64 = 0x5354_4f52_47

// Host is a hosts row.
type Host struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"-"`
	Hostname      string     `json:"hostname"`
	OSFamily      string     `json:"os_family"`
	OSVersion     string     `json:"os_version"`
	AgentVersion  string     `json:"agent_version"`
	ClockOffsetMS int64      `json:"clock_offset_ms"`
	ForensicUntil *time.Time `json:"forensic_until,omitempty"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	Status        string     `json:"status"`
}

// RefreshHostsLastSeen stamps every enrolled host's last_seen_at to NOW() and
// clears any explicit offline status, returning how many rows changed.
//
// This exists for the demo and screenshot workflow: the seeded fleet
// (prod-web-01, prod-web-02, win-app-02) has no agent actually running, so
// without this every host drifts past OnlineWindow and the console reports an
// entirely offline fleet minutes after `dev.ps1 seed`.
//
// It is deliberately NOT called on a normal startup. Marking the whole fleet
// online whenever the server restarts would paper over a real outage for a full
// OnlineWindow and is exactly the kind of lie a monitoring product must not
// tell; the caller gates it behind an explicit demo-mode switch.
func (s *Store) RefreshHostsLastSeen(ctx context.Context, orgID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE hosts
		SET last_seen_at = NOW(), status = 'online'
		WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return 0, fmt.Errorf("refresh hosts last_seen: %w", err)
	}
	return tag.RowsAffected(), nil
}

// HeartbeatDemoHosts stamps last_seen_at = NOW() on the named hosts only, and
// returns how many rows it touched.
//
// This is the allow-listed sibling of RefreshHostsLastSeen, used by the demo
// heartbeat ticker. The difference matters: RefreshHostsLastSeen makes the whole
// org look online once, at startup, which is right for a freshly seeded demo
// database and wrong every thirty seconds thereafter. A demo instance can have a
// genuinely dark host enrolled next to the four seeded ones, and a repeating
// "everything is online" would hide exactly the failure the fleet view exists to
// report. Naming the four seeded hosts keeps the heartbeat honest — it asserts
// liveness only about the hosts that are known fiction.
//
// An unknown hostname is silently skipped by the IN clause rather than erroring,
// so a seed that added or renamed a host cannot wedge the ticker.
func (s *Store) HeartbeatDemoHosts(ctx context.Context, orgID string, hostnames []string) (int64, error) {
	if len(hostnames) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE hosts
		SET last_seen_at = NOW(), status = 'online'
		WHERE org_id = $1::uuid
		  AND hostname = ANY($2::text[])`, orgID, hostnames)
	if err != nil {
		return 0, fmt.Errorf("heartbeat demo hosts: %w", err)
	}
	return tag.RowsAffected(), nil
}

// NormalizeHostID maps an agent host identifier to a deterministic UUID. A
// value that is already a valid UUID is returned unchanged; otherwise a v5
// UUID is derived from the string so hosts.id stays a real UUID.
func NormalizeHostID(hostID string) string {
	if id, err := uuid.Parse(hostID); err == nil {
		return id.String()
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(hostID)).String()
}

// UpsertHost inserts or updates a host keyed by (org_id, hostname),
// returning the authoritative row (id, forensic_until, ...). clockOffsetMS
// and agent metadata are refreshed on every batch.
func (s *Store) UpsertHost(ctx context.Context, h Host) (Host, error) {
	if h.Hostname == "" {
		h.Hostname = h.ID
	}
	id := NormalizeHostID(h.ID)
	var out Host
	err := s.pool.QueryRow(ctx, `
		INSERT INTO hosts (id, org_id, hostname, os_family, os_version, agent_version, clock_offset_ms, last_seen_at, status)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, NOW(), 'online')
		ON CONFLICT (org_id, hostname) DO UPDATE SET
			os_family       = EXCLUDED.os_family,
			os_version      = EXCLUDED.os_version,
			agent_version   = EXCLUDED.agent_version,
			clock_offset_ms = EXCLUDED.clock_offset_ms,
			last_seen_at    = NOW(),
			status          = 'online'
		RETURNING id::text, org_id::text, hostname, os_family, os_version, agent_version,
		          clock_offset_ms, forensic_until, last_seen_at, status`,
		id, h.OrgID, h.Hostname, h.OSFamily, h.OSVersion, h.AgentVersion, h.ClockOffsetMS).
		Scan(&out.ID, &out.OrgID, &out.Hostname, &out.OSFamily, &out.OSVersion,
			&out.AgentVersion, &out.ClockOffsetMS, &out.ForensicUntil, &out.LastSeenAt, &out.Status)
	if err != nil {
		return Host{}, fmt.Errorf("upsert host: %w", err)
	}
	return out, nil
}

// GetHost returns a host by id.
func (s *Store) GetHost(ctx context.Context, orgID, id string) (Host, error) {
	var h Host
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, org_id::text, hostname, os_family, os_version, agent_version,
		       clock_offset_ms, forensic_until, last_seen_at, status
		FROM hosts WHERE id = $1::uuid AND org_id = $2::uuid`, id, orgID).
		Scan(&h.ID, &h.OrgID, &h.Hostname, &h.OSFamily, &h.OSVersion, &h.AgentVersion,
			&h.ClockOffsetMS, &h.ForensicUntil, &h.LastSeenAt, &h.Status)
	if err != nil {
		return Host{}, err
	}
	// Report the recency-derived status, matching ListHosts and HostSummary.
	h.ApplyReportingStatus(time.Now())
	return h, nil
}

// ListHosts returns all hosts for org, with `status` rewritten to the
// recency-derived online/offline value (see ReportingStatusAt).
func (s *Store) ListHosts(ctx context.Context, orgID string) ([]Host, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, org_id::text, hostname, os_family, os_version, agent_version,
		       clock_offset_ms, forensic_until, last_seen_at, status
		FROM hosts WHERE org_id = $1::uuid ORDER BY hostname`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Initialized, not nil: an empty fleet must serialize as `"hosts": []`. A
	// `null` makes the console render "no data" instead of the honest empty state
	// and forces every client to null-check before iterating.
	out := []Host{}
	now := time.Now()
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.OrgID, &h.Hostname, &h.OSFamily, &h.OSVersion, &h.AgentVersion,
			&h.ClockOffsetMS, &h.ForensicUntil, &h.LastSeenAt, &h.Status); err != nil {
			return nil, err
		}
		h.ApplyReportingStatus(now)
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetForensicUntil enables Level 4 collection on hostID for d (capped by the
// caller; typically 15 minutes).
func (s *Store) SetForensicUntil(ctx context.Context, orgID, hostID string, d time.Duration) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE hosts SET forensic_until = NOW() + make_interval(secs => $3)
		WHERE id = $1::uuid AND org_id = $2::uuid`, hostID, orgID, int64(d.Seconds()))
	if err != nil {
		return fmt.Errorf("set forensic: %w", err)
	}
	return nil
}

// ResolveTarget returns the targets.id for a target type/path.
func (s *Store) ResolveTarget(ctx context.Context, orgID, targetType, path string) (int64, error) {
	key := orgID + "\x00" + targetType + "\x00" + path
	return s.targets.resolve(ctx, key, func(ctx context.Context) (int64, error) {
		var id int64
		err := s.pool.QueryRow(ctx, `
			INSERT INTO targets (org_id, target_type, path_or_key)
			VALUES ($1::uuid, $2, $3)
			ON CONFLICT (org_id, target_type, path_or_key) DO UPDATE SET path_or_key = EXCLUDED.path_or_key
			RETURNING id`, orgID, targetType, path).Scan(&id)
		return id, err
	})
}

// ResolveActor returns the actors.id for an actor context, or 0 when the
// actor is empty.
func (s *Store) ResolveActor(ctx context.Context, orgID string, a *pb.ActorContext) (int64, error) {
	if a == nil || (a.Username == "" && a.UidOrSid == "") {
		return 0, nil
	}
	key := orgID + "\x00" + a.Username + "\x00" + a.UidOrSid + "\x00" + a.LoginUid
	return s.actors.resolve(ctx, key, func(ctx context.Context) (int64, error) {
		var id int64
		err := s.pool.QueryRow(ctx, `
			INSERT INTO actors (org_id, username, uid_or_sid, login_uid)
			VALUES ($1::uuid, $2, $3, $4)
			ON CONFLICT (org_id, username, uid_or_sid, login_uid) DO UPDATE SET login_uid = EXCLUDED.login_uid
			RETURNING id`, orgID, a.Username, a.UidOrSid, a.LoginUid).Scan(&id)
		return id, err
	})
}

// ResolveProcess returns the processes.id for an actor's process, or 0 when
// there is no process name.
func (s *Store) ResolveProcess(ctx context.Context, orgID, processName, cmdline string) (int64, error) {
	if processName == "" {
		return 0, nil
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(cmdline)))
	key := orgID + "\x00" + processName + "\x00" + hash
	return s.processes.resolve(ctx, key, func(ctx context.Context) (int64, error) {
		var id int64
		err := s.pool.QueryRow(ctx, `
			INSERT INTO processes (org_id, process_name, cmdline_hash, cmdline_sample)
			VALUES ($1::uuid, $2, $3, $4)
			ON CONFLICT (org_id, process_name, cmdline_hash) DO UPDATE SET cmdline_sample = EXCLUDED.cmdline_sample
			RETURNING id`, orgID, processName, hash, truncate(cmdline, 512)).Scan(&id)
		return id, err
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Notification is a normalized event summary produced by InsertEvents for
// the annotation pusher and websocket hub.
type Notification struct {
	ID            string         `json:"id"`
	OrgID         string         `json:"-"`
	HostID        string         `json:"host_id"`
	Hostname      string         `json:"hostname,omitempty"`
	ParentEventID string         `json:"parent_event_id,omitempty"`
	OccurredAt    time.Time      `json:"occurred_at"`
	ImpactLevel   pb.ImpactLevel `json:"impact_level"`
	Category      pb.Category    `json:"category"`
	Action        pb.Action      `json:"action"`
	Summary       string         `json:"summary"`
	ActorName     string         `json:"actor,omitempty"`
	TargetType    string         `json:"target_type,omitempty"`
	PathOrKey     string         `json:"path_or_key,omitempty"`
	// Metadata carries the agent's classification and, when a granular policy
	// rule decided the verdict, metadata["rule_name"] / ["rule_tags"] so the
	// live timeline can render the "Rule: <name>" badge without a refetch.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// eventRow is a fully resolved event ready for insertion.
type eventRow struct {
	ev         *pb.MutationEvent
	targetID   int64
	actorID    *int64
	processID  *int64
	occurredAt time.Time
	inlineDiff *string
	s3Key      *string
}

// InsertEvents normalizes and stores a batch of events, returning the
// acknowledged IDs and notifications for downstream consumers. clockOffsetMS
// is server_time - agent_sent so occurred_at is de-skewed.
func (s *Store) InsertEvents(ctx context.Context, orgID, hostID string, clockOffsetMS int64, events []*pb.MutationEvent) (ack []string, notifs []Notification, err error) {
	host, err := s.GetHost(ctx, orgID, hostID)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup host %s: %w", hostID, err)
	}

	rows := make([]eventRow, 0, len(events))
	ack = make([]string, 0, len(events))
	for _, ev := range events {
		if ev.GetEventId() == "" {
			continue
		}
		targetType := ev.GetTarget().GetTargetType()
		if targetType == "" {
			targetType = "file"
		}
		targetID, err := s.ResolveTarget(ctx, orgID, targetType, ev.GetTarget().GetPathOrKey())
		if err != nil {
			return nil, nil, err
		}
		var actorID, processID *int64
		if ev.Actor != nil {
			if id, err := s.ResolveActor(ctx, orgID, ev.Actor); err != nil {
				return nil, nil, err
			} else if id != 0 {
				actorID = &id
			}
			if id, err := s.ResolveProcess(ctx, orgID, ev.Actor.GetProcessName(), ev.Actor.GetCmdline()); err != nil {
				return nil, nil, err
			} else if id != 0 {
				processID = &id
			}
		}
		var inlineDiff, s3Key *string
		if len(ev.GetUnifiedDiffZstd()) > 0 {
			text, err := diff.Decompress(ev.GetUnifiedDiffZstd())
			if err != nil {
				return nil, nil, fmt.Errorf("event %s: decompress diff: %w", ev.GetEventId(), err)
			}
			if len(text) <= DiffInlineMax {
				v := string(text)
				inlineDiff = &v
			} else if s.s3 == nil {
				// No blob store configured (the single-container quickstart
				// runs without S3). Store the diff inline rather than rejecting
				// the event: an unrecorded change is worse than a wide row, and
				// a deployment that cares about table size configures S3.
				v := string(text)
				inlineDiff = &v
			} else {
				sum := sha256.Sum256(text)
				key := fmt.Sprintf("diffs/%s/%x.zst", orgID, sum)
				if err := s.s3.Put(ctx, key, ev.GetUnifiedDiffZstd()); err != nil {
					// A blob store that is down must not turn into a change that
					// was never recorded. The agent has already been told the
					// batch was accepted at this point in the old code path, so
					// failing here would mean the operator loses the event
					// entirely; storing this one row inline keeps the timeline
					// complete and surfaces the outage as a single wide row
					// instead of a gap.
					slog.Default().Warn("blob store put failed; storing the diff inline",
						"event", ev.GetEventId(), "key", key, "err", err)
					v := string(text)
					inlineDiff = &v
				} else {
					s3Key = &key
				}
			}
		}
		rows = append(rows, eventRow{
			ev:         ev,
			targetID:   targetID,
			actorID:    actorID,
			processID:  processID,
			occurredAt: time.UnixMilli(ev.GetAgentTimestampMs() + clockOffsetMS),
			inlineDiff: inlineDiff,
			s3Key:      s3Key,
		})
		ack = append(ack, ev.GetEventId())
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	const insertSQL = `
		INSERT INTO events (
			id, org_id, host_id, parent_event_id, occurred_at, impact_level, category, action,
			target_id, actor_id, process_id, pid, ppid, process_lineage, remote_ip,
			hash_before, hash_after, version_before, version_after, child_count, summary,
			inline_diff, s3_blob_key, metadata)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24::jsonb)
		ON CONFLICT (occurred_at, id) DO NOTHING`

	for _, r := range rows {
		ev := r.ev
		meta, _ := json.Marshal(ev.GetMetadata())
		if string(meta) == "null" {
			meta = []byte(`{}`)
		}
		var pid, ppid int32
		if ev.Actor != nil {
			pid, ppid = int32(ev.Actor.GetPid()), int32(ev.Actor.GetPpid())
		}
		_, err := tx.Exec(ctx, insertSQL,
			ev.GetEventId(), orgID, hostID, nullableID(ev.GetParentEventId()), r.occurredAt,
			int32(ev.GetLevel()), int32(ev.GetCategory()), int32(ev.GetAction()),
			r.targetID, r.actorID, r.processID, pid, ppid, lineage(ev), ev.Actor.GetRemoteIp(),
			ev.GetTarget().GetHashBefore(), ev.GetTarget().GetHashAfter(),
			ev.GetTarget().GetVersionBefore(), ev.GetTarget().GetVersionAfter(),
			ev.GetChildCount(), ev.GetSummary(), r.inlineDiff, r.s3Key, string(meta))
		if err != nil {
			return nil, nil, fmt.Errorf("insert event %s: %w", ev.GetEventId(), err)
		}
		if err := updateCurrentState(ctx, tx, hostID, r); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit events: %w", err)
	}

	for _, r := range rows {
		name := ""
		if r.ev.Actor != nil {
			name = r.ev.Actor.GetUsername()
		}
		notifs = append(notifs, Notification{
			ID:            r.ev.GetEventId(),
			OrgID:         orgID,
			HostID:        hostID,
			Hostname:      host.Hostname,
			ParentEventID: r.ev.GetParentEventId(),
			OccurredAt:    r.occurredAt,
			ImpactLevel:   r.ev.GetLevel(),
			Category:      r.ev.GetCategory(),
			Action:        r.ev.GetAction(),
			Summary:       r.ev.GetSummary(),
			ActorName:     name,
			TargetType:    r.ev.GetTarget().GetTargetType(),
			PathOrKey:     r.ev.GetTarget().GetPathOrKey(),
			Metadata:      r.ev.GetMetadata(),
		})
	}
	return ack, notifs, nil
}

func nullableID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func lineage(ev *pb.MutationEvent) []string {
	if ev.Actor == nil {
		return nil
	}
	return ev.Actor.GetProcessLineage()
}

// updateCurrentState keeps host_current_state fresh for drift comparison.
func updateCurrentState(ctx context.Context, tx pgx.Tx, hostID string, r eventRow) error {
	tt := r.ev.GetTarget().GetTargetType()
	switch tt {
	case "file", "registry", "package":
	default:
		return nil // services/processes are not part of the state matrix
	}
	if r.ev.GetAction() == pb.Action_ACTION_DELETED {
		_, err := tx.Exec(ctx, `DELETE FROM host_current_state WHERE host_id = $1::uuid AND target_id = $2`, hostID, r.targetID)
		return err
	}
	hash := r.ev.GetTarget().GetHashAfter()
	version := r.ev.GetTarget().GetVersionAfter()
	if hash == "" && version == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO host_current_state (host_id, target_id, current_hash, current_version, updated_at, last_event_id)
		VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid)
		ON CONFLICT (host_id, target_id) DO UPDATE SET
			current_hash    = EXCLUDED.current_hash,
			current_version = EXCLUDED.current_version,
			updated_at      = EXCLUDED.updated_at,
			last_event_id   = EXCLUDED.last_event_id`,
		hostID, r.targetID, hash, version, r.occurredAt, r.ev.GetEventId())
	return err
}

// Event is a flattened events row for API responses.
type Event struct {
	ID             string            `json:"id"`
	HostID         string            `json:"host_id"`
	Hostname       string            `json:"hostname,omitempty"`
	ParentEventID  string            `json:"parent_event_id,omitempty"`
	OccurredAt     time.Time         `json:"occurred_at"`
	ImpactLevel    int32             `json:"impact_level"`
	Category       int32             `json:"category"`
	Action         int32             `json:"action"`
	Summary        string            `json:"summary"`
	TargetType     string            `json:"target_type"`
	PathOrKey      string            `json:"path_or_key"`
	ActorUsername  string            `json:"actor_username,omitempty"`
	ActorSID       string            `json:"actor_sid,omitempty"`
	LoginUID       string            `json:"login_uid,omitempty"`
	ProcessName    string            `json:"process_name,omitempty"`
	ProcessLineage []string          `json:"process_lineage,omitempty"`
	RemoteIP       string            `json:"remote_ip,omitempty"`
	PID            int32             `json:"pid,omitempty"`
	PPID           int32             `json:"ppid,omitempty"`
	Cmdline        string            `json:"cmdline,omitempty"`
	HashBefore     string            `json:"hash_before,omitempty"`
	HashAfter      string            `json:"hash_after,omitempty"`
	VersionBefore  string            `json:"version_before,omitempty"`
	VersionAfter   string            `json:"version_after,omitempty"`
	ChildCount     int32             `json:"child_count"`
	HasDiff        bool              `json:"has_diff"`
	DiffSource     string            `json:"diff_source,omitempty"` // "inline" | "s3"
	Metadata       map[string]string `json:"metadata,omitempty"`
}

const eventSelect = `
	SELECT e.id::text, e.host_id::text, h.hostname, COALESCE(e.parent_event_id::text, ''),
	       e.occurred_at, e.impact_level, e.category, e.action, e.summary,
	       t.target_type, t.path_or_key,
	       COALESCE(a.username, ''), COALESCE(a.uid_or_sid, ''), COALESCE(a.login_uid, ''),
	       COALESCE(p.process_name, ''), e.process_lineage, e.remote_ip,
	       COALESCE(e.pid, 0), COALESCE(e.ppid, 0), COALESCE(p.cmdline_sample, ''),
	       e.hash_before, e.hash_after,
	       e.version_before, e.version_after, e.child_count,
	       (e.inline_diff IS NOT NULL OR e.s3_blob_key IS NOT NULL) AS has_diff,
	       CASE WHEN e.inline_diff IS NOT NULL THEN 'inline' WHEN e.s3_blob_key IS NOT NULL THEN 's3' ELSE '' END AS diff_source,
	       e.metadata
	FROM events e
	JOIN hosts h ON h.id = e.host_id
	JOIN targets t ON t.id = e.target_id
	LEFT JOIN actors a ON a.id = e.actor_id
	LEFT JOIN processes p ON p.id = e.process_id`

func scanEvent(row pgx.Row) (Event, error) {
	var e Event
	var meta []byte
	err := row.Scan(&e.ID, &e.HostID, &e.Hostname, &e.ParentEventID, &e.OccurredAt,
		&e.ImpactLevel, &e.Category, &e.Action, &e.Summary, &e.TargetType, &e.PathOrKey,
		&e.ActorUsername, &e.ActorSID, &e.LoginUID, &e.ProcessName, &e.ProcessLineage, &e.RemoteIP,
		&e.PID, &e.PPID, &e.Cmdline,
		&e.HashBefore, &e.HashAfter, &e.VersionBefore, &e.VersionAfter, &e.ChildCount,
		&e.HasDiff, &e.DiffSource, &meta)
	if err != nil {
		return Event{}, err
	}
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &e.Metadata)
	}
	return e, nil
}

// EventFilter constrains a timeline query.
type EventFilter struct {
	HostID      string
	ImpactLevel int // 0 = any
	Category    int // 0 = any
	Actor       string
	From, To    time.Time
	Search      string
	Limit       int
	Cursor      string // "" = latest page
	// RootOnly drops child events. Aggregated (parent) events carry their
	// children, and those children sort immediately after the parent, so a
	// limited root-level feed (dashboard "latest changes", Grafana annotations)
	// would otherwise spend its whole page on children and omit other roots.
	RootOnly bool
}

// Cursor encodes (occurred_at, id) for keyset pagination.
type Cursor struct {
	OccurredAt time.Time
	ID         string
}

// Encode renders a cursor for the next page.
func (c Cursor) Encode() string {
	return fmt.Sprintf("%d:%s", c.OccurredAt.UnixMilli(), c.ID)
}

// DecodeCursor parses a cursor string.
func DecodeCursor(s string) (Cursor, error) {
	var c Cursor
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return c, fmt.Errorf("invalid cursor")
	}
	ms, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return c, fmt.Errorf("invalid cursor time: %w", err)
	}
	c.OccurredAt = time.UnixMilli(ms)
	c.ID = s[i+1:]
	return c, nil
}

// ListEvents returns a page of events, newest first.
func (s *Store) ListEvents(ctx context.Context, orgID string, f EventFilter) ([]Event, string, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	where := []string{"e.org_id = $1::uuid"}
	args := []any{orgID}
	// add appends vals to args and renders cond's $%d placeholders with the
	// corresponding parameter indexes.
	add := func(cond string, vals ...any) {
		start := len(args) + 1
		args = append(args, vals...)
		ph := make([]any, len(vals))
		for i := range vals {
			ph[i] = start + i
		}
		where = append(where, fmt.Sprintf(cond, ph...))
	}
	if f.HostID != "" {
		add("e.host_id = $%d::uuid", f.HostID)
	}
	if f.ImpactLevel > 0 {
		add("e.impact_level = $%d", f.ImpactLevel)
	}
	if f.Category > 0 {
		add("e.category = $%d", f.Category)
	}
	if f.Actor != "" {
		add("a.username = $%d", f.Actor)
	}
	if !f.From.IsZero() {
		add("e.occurred_at >= $%d", f.From)
	}
	if !f.To.IsZero() {
		add("e.occurred_at < $%d", f.To)
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		add("(e.summary ILIKE $%d OR t.path_or_key ILIKE $%d)", like, like)
	}
	if f.RootOnly {
		where = append(where, "e.parent_event_id IS NULL")
	}
	if f.Cursor != "" {
		c, err := DecodeCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		add("(e.occurred_at, e.id) < ($%d, $%d::uuid)", c.OccurredAt, c.ID)
	}

	q := eventSelect + " WHERE " + strings.Join(where, " AND ") +
		" ORDER BY e.occurred_at DESC, e.id DESC LIMIT " + fmt.Sprint(f.Limit+1)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	// Initialized, not nil: an empty timeline must serialize as `"events": []`,
	// so a clean install's dashboard renders zeroed KPIs rather than a client
	// that has to treat null and [] differently.
	out := []Event{}
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		last := out[len(out)-1]
		next = (Cursor{OccurredAt: last.OccurredAt, ID: last.ID}).Encode()
	}
	return out, next, nil
}

// EventDetail is a single event with its diff and child events.
type EventDetail struct {
	Event
	Diff     string  `json:"diff,omitempty"`
	Children []Event `json:"children,omitempty"`
}

// GetEvent returns an event, transparently fetching and decompressing a blob
// diff, plus its child events when it is a parent.
func (s *Store) GetEvent(ctx context.Context, orgID, id string) (EventDetail, error) {
	// Validate before the ::uuid cast: an unparseable id is a client error, not
	// an internal one. Without this a malformed path segment surfaces as a 500.
	if _, err := uuid.Parse(id); err != nil {
		return EventDetail{}, ErrNotFound
	}
	row := s.pool.QueryRow(ctx, eventSelect+" WHERE e.id = $1::uuid AND e.org_id = $2::uuid", id, orgID)
	ev, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EventDetail{}, ErrNotFound
		}
		return EventDetail{}, err
	}
	out := EventDetail{Event: ev}

	var inline, s3key *string
	if err := s.pool.QueryRow(ctx,
		`SELECT inline_diff, s3_blob_key FROM events WHERE id = $1::uuid AND org_id = $2::uuid`, id, orgID).
		Scan(&inline, &s3key); err == nil {
		switch {
		case inline != nil:
			out.Diff = *inline
		case s3key != nil && s.s3 != nil:
			data, err := s.s3.Get(ctx, *s3key)
			if err != nil {
				return out, err
			}
			text, err := diff.Decompress(data)
			if err != nil {
				return out, err
			}
			out.Diff = string(text)
		}
	}

	// Children, if this is a parent event.
	rows, err := s.pool.Query(ctx, eventSelect+`
		WHERE e.parent_event_id = $1::uuid AND e.org_id = $2::uuid
		ORDER BY e.occurred_at, e.id`, id, orgID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		child, err := scanEvent(rows)
		if err != nil {
			return out, err
		}
		out.Children = append(out.Children, child)
	}
	return out, rows.Err()
}

// DriftRow is one target whose state differs between two hosts.
type DriftRow struct {
	TargetID   int64  `json:"target_id"`
	TargetType string `json:"target_type"`
	PathOrKey  string `json:"path_or_key"`
	HashA      string `json:"hash_a"`
	VersionA   string `json:"version_a"`
	HashB      string `json:"hash_b"`
	VersionB   string `json:"version_b"`
	OnlyOn     string `json:"only_on,omitempty"` // "a" | "b" when present on one side
}

// Drift runs the FULL OUTER JOIN host-current-state comparison.
func (s *Store) Drift(ctx context.Context, orgID, hostA, hostB string) ([]DriftRow, error) {
	rows, err := s.pool.Query(ctx, `
		WITH a AS (SELECT target_id, current_hash, current_version FROM host_current_state WHERE host_id = $1::uuid),
		     b AS (SELECT target_id, current_hash, current_version FROM host_current_state WHERE host_id = $2::uuid)
		SELECT COALESCE(a.target_id, b.target_id), t.target_type, t.path_or_key,
		       COALESCE(a.current_hash, ''), COALESCE(a.current_version, ''),
		       COALESCE(b.current_hash, ''), COALESCE(b.current_version, ''),
		       CASE WHEN a.target_id IS NULL THEN 'b' WHEN b.target_id IS NULL THEN 'a' ELSE '' END
		FROM a
		FULL OUTER JOIN b ON a.target_id = b.target_id
		JOIN targets t ON t.id = COALESCE(a.target_id, b.target_id)
		WHERE a.current_hash IS DISTINCT FROM b.current_hash
		   OR a.target_id IS NULL OR b.target_id IS NULL
		ORDER BY t.path_or_key`, hostA, hostB)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DriftRow
	for rows.Next() {
		var d DriftRow
		if err := rows.Scan(&d.TargetID, &d.TargetType, &d.PathOrKey, &d.HashA, &d.VersionA, &d.HashB, &d.VersionB, &d.OnlyOn); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Integration is an integrations row.
type Integration struct {
	ID             string
	OrgID          string
	Provider       string
	EndpointURL    string
	APIToken       string
	MinImpactLevel int32
	Enabled        bool
	// Label and Severity are provider-specific display/routing fields (Slack
	// channel name, PagerDuty severity override).
	Label    string
	Severity string
	// NotifyL1 / NotifyStorms are the per-channel trigger toggles the hub
	// exposes. MinImpactLevel is derived from NotifyL1 on save, so the two are
	// consistent; they are carried separately because a storm is not a level.
	NotifyL1     bool
	NotifyStorms bool
}

// ListIntegrations returns enabled integrations for an org.
func (s *Store) ListIntegrations(ctx context.Context, orgID string) ([]Integration, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, org_id::text, provider, endpoint_url, COALESCE(api_token_encrypted, ''),
		       min_impact_level, enabled, label, severity, notify_l1, notify_storms
		FROM integrations WHERE org_id = $1::uuid AND enabled ORDER BY provider`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Integration
	for rows.Next() {
		var in Integration
		if err := rows.Scan(&in.ID, &in.OrgID, &in.Provider, &in.EndpointURL, &in.APIToken,
			&in.MinImpactLevel, &in.Enabled, &in.Label, &in.Severity,
			&in.NotifyL1, &in.NotifyStorms); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}
