package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Watched target types the console's rule builder can create.
//
// These are the same strings the agent matches with limiter.ruleTypeMatches, so
// a rule authored here is understood by the collector that owns the surface:
// the IIS watcher reads iis_apppool rules to discover which pools to poll, and
// the database watcher reads database_table rules to discover which tables to
// snapshot. That coupling is the point — a target type is not a label, it is
// the selector the watcher uses.
const (
	WatchTypeFile      = "file"
	WatchTypeDirectory = "directory"
	WatchTypeIISPool   = "iis_apppool"
	WatchTypeIISSite   = "iis_site"
	WatchTypeDBTable   = "database_table"
	WatchTypeDBSchema  = "database_schema"
	WatchTypeDBParams  = "database_params"
	WatchTypeRegistry  = "registry"
	WatchTypeService   = "service"
	WatchTypeK8sObject = "k8s_object"
)

// FleetScope is the host selector meaning "every host in the organisation".
//
// Stored as a NULL host_id rather than a magic host row, because a fleet rule
// must also apply to hosts that enrol after it was written.
const FleetScope = "*"

// WatchRule is a custom watched target authored in the console.
type WatchRule struct {
	ID string `json:"id"`
	// HostID is empty for a fleet-wide rule.
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname,omitempty"`
	// HostScope is the value the console selected: a hostname, a host id, or
	// FleetScope. It lets the UI round-trip its own selector without having to
	// know that "all hosts" is stored as a NULL.
	HostScope  string    `json:"host_scope"`
	Name       string    `json:"name"`
	TargetType string    `json:"target_type"`
	Pattern    string    `json:"pattern"`
	Level      int16     `json:"level"`
	Diff       bool      `json:"diff"`
	Tags       []string  `json:"tags"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// WatchRuleInput is the payload the rule builder submits.
type WatchRuleInput struct {
	// HostScope is a hostname, a host id, or FleetScope ("*"). Empty means
	// fleet-wide, which is what makes the "All Hosts" default work.
	HostScope  string   `json:"host_scope"`
	TargetType string   `json:"target_type"`
	Pattern    string   `json:"pattern"`
	Level      int16    `json:"level"`
	Diff       *bool    `json:"diff"`
	Name       string   `json:"name"`
	Tags       []string `json:"tags"`
}

// Validate checks the input before it reaches the database.
//
// Validation lives here rather than in the handler because the same rules must
// hold for any caller (a future CLI, an import script), and because a rule that
// reaches the agent with a bad pattern becomes a classifier that silently
// matches nothing — the worst failure mode for a watcher, since the console
// would show a watched target that is not actually watched.
func (in *WatchRuleInput) Validate() error {
	in.TargetType = strings.ToLower(strings.TrimSpace(in.TargetType))
	if !validWatchType(in.TargetType) {
		return fmt.Errorf("unsupported target type %q", in.TargetType)
	}
	in.Pattern = strings.TrimSpace(in.Pattern)
	if in.Pattern == "" {
		return errors.New("pattern is required")
	}
	if err := validatePattern(in.TargetType, in.Pattern); err != nil {
		return err
	}
	if in.Level < 1 || in.Level > 4 {
		// Level 0 (drop) is deliberately not offered: a watch rule that records
		// nothing is indistinguishable from a broken watcher in the console.
		return fmt.Errorf("impact level must be 1-4, got %d", in.Level)
	}
	if in.HostScope == "" {
		in.HostScope = FleetScope
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = defaultRuleName(in.TargetType, in.Pattern)
	}
	return nil
}

// ImpactLevelCritical is the level the builder's "Full Diff & Instant Alert"
// option sends, so the UI's two choices are not magic numbers in two languages.
const ImpactLevelCritical int16 = 1

// ImpactLevelDrift is the "hash only" option.
const ImpactLevelDrift int16 = 3

func validWatchType(t string) bool {
	switch t {
	case WatchTypeFile, WatchTypeDirectory, WatchTypeIISPool, WatchTypeIISSite,
		WatchTypeDBTable, WatchTypeDBSchema, WatchTypeDBParams,
		WatchTypeRegistry, WatchTypeService, WatchTypeK8sObject:
		return true
	}
	return false
}

// validatePattern checks the one thing each target type cannot tolerate: a
// shape the owning collector cannot interpret.
func validatePattern(targetType, pattern string) error {
	switch targetType {
	case WatchTypeIISPool, WatchTypeIISSite:
		// The IIS watcher resolves these against applicationHost.config and
		// accepts a name, an iis:// URI or a glob, so there is nothing to
		// reject beyond an empty value.
		return nil
	case WatchTypeDBTable:
		if !strings.HasPrefix(strings.ToLower(pattern), "db://") {
			return errors.New("a database table target must be a db:// path, " +
				"e.g. db://postgres/settings_db/tables/public.app_settings")
		}
		if !strings.Contains(strings.ToLower(pattern), "/tables/") {
			return errors.New("a database table target must name /tables/<schema>.<table>")
		}
		return nil
	case WatchTypeDBSchema, WatchTypeDBParams:
		if !strings.HasPrefix(strings.ToLower(pattern), "db://") {
			return errors.New("a database target must be a db:// path")
		}
		return nil
	case WatchTypeRegistry:
		if !strings.HasPrefix(strings.ToUpper(pattern), "HK") {
			return errors.New("a registry target must start with a hive, e.g. HKLM\\Software\\Company\\App")
		}
		return nil
	case WatchTypeK8sObject:
		if !strings.HasPrefix(pattern, "/") {
			return errors.New("a Kubernetes target must be an absolute object path, " +
				"e.g. /k8s/prod-k8s-01/production/configmaps/checkout-config")
		}
		return nil
	}
	return nil
}

// defaultRuleName builds the readable label the list view shows when the
// operator did not type one.
func defaultRuleName(targetType, pattern string) string {
	short := pattern
	if i := strings.LastIndexAny(short, `/\`); i >= 0 && i+1 < len(short) {
		short = short[i+1:]
	}
	if short == "" {
		short = targetType
	}
	return short
}

// CreateWatchRule stores a custom watched target.
//
// The host scope is resolved from either an id or a hostname so the console can
// send whichever it has: the server list renders hostnames, while the timeline
// filters by id, and asking the UI to normalise would put a lookup on the
// critical path of every rule creation.
func (s *Store) CreateWatchRule(ctx context.Context, orgID, createdBy string, in WatchRuleInput) (WatchRule, error) {
	if err := in.Validate(); err != nil {
		return WatchRule{}, err
	}
	var hostID *string
	if in.HostScope != FleetScope {
		id, err := s.resolveHostScope(ctx, orgID, in.HostScope)
		if err != nil {
			return WatchRule{}, err
		}
		hostID = &id
	}
	diff := true
	if in.Diff != nil {
		diff = *in.Diff
	}
	tags := in.Tags
	if tags == nil {
		tags = []string{}
	}
	tags = append(tags, "console")

	var r WatchRule
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Replace-by-name rather than ON CONFLICT: the unique constraint is
		// partial (per-host rows have a host_id, fleet rows have NULL), so a
		// single conflict target cannot cover both scopes. Deleting first also
		// makes "re-create a rule with the same name" an update in both scopes
		// instead of only the per-host one.
		if _, err := tx.Exec(ctx, `
			DELETE FROM host_policy_rules
			WHERE org_id = $1::uuid AND host_id IS NOT DISTINCT FROM $2::uuid AND name = $3`,
			orgID, hostID, in.Name); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO host_policy_rules
				(org_id, host_id, name, target_type, pattern, level, diff, tags, created_by)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id::text, COALESCE(host_id::text, ''), name, target_type, pattern,
			          level, diff, tags, created_by, created_at`,
			orgID, hostID, in.Name, in.TargetType, in.Pattern, in.Level, diff, tags, createdBy).
			Scan(&r.ID, &r.HostID, &r.Name, &r.TargetType, &r.Pattern, &r.Level, &r.Diff,
				&r.Tags, &r.CreatedBy, &r.CreatedAt)
	})
	if err != nil {
		return WatchRule{}, fmt.Errorf("create watch rule: %w", err)
	}
	r.HostScope = in.HostScope
	if r.HostID != "" {
		// Best-effort label: the rule exists, and a hostname lookup failure must
		// not turn a successful creation into an error the operator retries.
		_ = s.pool.QueryRow(ctx, `SELECT hostname FROM hosts WHERE id = $1::uuid`, r.HostID).Scan(&r.Hostname)
	}
	return r, nil
}

// resolveHostScope turns a hostname or id into a host id within the org.
//
// Matching on either is what stops a rule from being created against another
// organisation's host id supplied by hand.
func (s *Store) resolveHostScope(ctx context.Context, orgID, scope string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text FROM hosts
		WHERE org_id = $1::uuid
		  AND (id::text = $2 OR hostname = $2)
		LIMIT 1`, orgID, scope).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("host %q not found", scope)
	}
	if err != nil {
		return "", fmt.Errorf("resolve host %q: %w", scope, err)
	}
	return id, nil
}

// ListWatchRules returns the custom watched targets for the console.
//
// It returns every rule regardless of scope: a fleet-wide rule is as much a
// watched target as a per-host one, and hiding it would make an operator's own
// rule invisible after they created it. targetType and hostScope filter the
// list; empty means no filter.
func (s *Store) ListWatchRules(ctx context.Context, orgID, targetType, hostScope string) ([]WatchRule, error) {
	where := []string{"r.org_id = $1::uuid"}
	args := []any{orgID}
	if targetType != "" {
		args = append(args, targetType)
		where = append(where, fmt.Sprintf("r.target_type = $%d", len(args)))
	}
	if hostScope != "" && hostScope != FleetScope {
		args = append(args, hostScope)
		where = append(where, fmt.Sprintf("(h.hostname = $%d OR r.host_id::text = $%d)", len(args), len(args)))
	}
	if hostScope == FleetScope {
		where = append(where, "r.host_id IS NULL")
	}
	q := `
		SELECT r.id::text, COALESCE(r.host_id::text, ''), COALESCE(h.hostname, ''),
		       r.name, r.target_type, r.pattern, r.level, r.diff, r.tags,
		       r.created_by, r.created_at
		FROM host_policy_rules r
		LEFT JOIN hosts h ON h.id = r.host_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY (r.host_id IS NULL) DESC, h.hostname NULLS FIRST, r.created_at DESC, r.name`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list watch rules: %w", err)
	}
	defer rows.Close()

	out := []WatchRule{}
	for rows.Next() {
		var r WatchRule
		if err := rows.Scan(&r.ID, &r.HostID, &r.Hostname, &r.Name, &r.TargetType,
			&r.Pattern, &r.Level, &r.Diff, &r.Tags, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.HostScope = FleetScope
		if r.HostID != "" {
			r.HostScope = r.Hostname
			if r.HostScope == "" {
				r.HostScope = r.HostID
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteWatchRule removes a rule, returning the deleted row so the audit trail
// can name what was removed rather than only its id.
func (s *Store) DeleteWatchRule(ctx context.Context, orgID, id string) (WatchRule, error) {
	if _, err := uuid.Parse(id); err != nil {
		return WatchRule{}, ErrNotFound
	}
	var r WatchRule
	err := s.pool.QueryRow(ctx, `
		DELETE FROM host_policy_rules
		WHERE id = $1::uuid AND org_id = $2::uuid
		RETURNING id::text, COALESCE(host_id::text, ''), name, target_type, pattern,
		          level, diff, tags, created_by, created_at`, id, orgID).
		Scan(&r.ID, &r.HostID, &r.Name, &r.TargetType, &r.Pattern, &r.Level, &r.Diff,
			&r.Tags, &r.CreatedBy, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WatchRule{}, ErrNotFound
	}
	if err != nil {
		return WatchRule{}, fmt.Errorf("delete watch rule: %w", err)
	}
	r.HostScope = FleetScope
	if r.HostID != "" {
		r.HostScope = r.HostID
		if err := s.pool.QueryRow(ctx, `SELECT hostname FROM hosts WHERE id = $1::uuid`, r.HostID).
			Scan(&r.Hostname); err != nil {
			r.Hostname = ""
		}
		r.HostScope = r.Hostname
		if r.HostScope == "" {
			r.HostScope = r.HostID
		}
	}
	return r, nil
}

// FleetPolicyRules returns the org's fleet-wide rules in wire form, for the
// hosts that have no per-host rule of their own.
func (s *Store) FleetPolicyRules(ctx context.Context, orgID string) ([]PolicyRuleRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, target_type, pattern, level, diff, tags, created_at
		FROM host_policy_rules
		WHERE org_id = $1::uuid AND host_id IS NULL
		ORDER BY created_at, name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list fleet policy rules: %w", err)
	}
	defer rows.Close()
	return scanPolicyRules(rows)
}
