package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// Recommendation statuses.
const (
	RecStatusPending   = "pending"
	RecStatusApplied   = "applied"
	RecStatusDismissed = "dismissed"
)

// Recommendation is a discovered workload awaiting operator review.
type Recommendation struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"-"`
	HostID         string    `json:"host_id"`
	Hostname       string    `json:"hostname,omitempty"`
	WorkloadType   string    `json:"workload_type"`
	Name           string    `json:"name"`
	ConfigPath     string    `json:"config_path"`
	SuggestedLevel int16     `json:"suggested_level"`
	SuggestedDiff  bool      `json:"suggested_diff"`
	Reason         string    `json:"reason"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PolicyRuleRow is one row of a host's active granular policy set.
type PolicyRuleRow struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	TargetType string    `json:"target_type"`
	Pattern    string    `json:"pattern"`
	Level      int16     `json:"level"`
	Diff       bool      `json:"diff"`
	Tags       []string  `json:"tags"`
	CreatedAt  time.Time `json:"created_at"`
}

// UpsertRecommendations records the workloads an agent reported on a
// heartbeat. Rows already decided (applied/dismissed) are left alone so a
// re-discovery never resurrects a recommendation the operator resolved.
// It returns nothing interesting: discovery is fire-and-forget.
func (s *Store) UpsertRecommendations(ctx context.Context, orgID, hostID string, workloads []*pb.DiscoveredWorkload) error {
	if len(workloads) == 0 {
		return nil
	}
	for _, w := range workloads {
		if w == nil || w.GetType() == "" || w.GetName() == "" {
			continue
		}
		level := int16(w.GetSuggestedLevel())
		if level < 1 || level > 4 {
			level = 3
		}
		_, err := s.pool.Exec(ctx, `
			INSERT INTO host_recommendations
				(org_id, host_id, workload_type, name, config_path, suggested_level, suggested_diff, reason, status)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, 'pending')
			ON CONFLICT (host_id, workload_type, name, config_path) DO UPDATE SET
				suggested_level = EXCLUDED.suggested_level,
				suggested_diff  = EXCLUDED.suggested_diff,
				reason          = EXCLUDED.reason,
				updated_at      = NOW()
			WHERE host_recommendations.status = 'pending'`,
			orgID, hostID, w.GetType(), w.GetName(), w.GetConfigPath(),
			level, w.GetSuggestedDiff(), w.GetReason())
		if err != nil {
			return fmt.Errorf("upsert recommendation %s/%s: %w", w.GetType(), w.GetName(), err)
		}
	}
	return nil
}

// ListRecommendations returns recommendations for org, newest first. status
// filters by status ("" = any); hostID filters by host ("" = any).
func (s *Store) ListRecommendations(ctx context.Context, orgID, status, hostID string) ([]Recommendation, error) {
	where := []string{"r.org_id = $1::uuid"}
	args := []any{orgID}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("r.status = $%d", len(args)))
	}
	if hostID != "" {
		args = append(args, hostID)
		where = append(where, fmt.Sprintf("r.host_id = $%d::uuid", len(args)))
	}
	q := `
		SELECT r.id::text, r.org_id::text, r.host_id::text, h.hostname,
		       r.workload_type, r.name, r.config_path, r.suggested_level,
		       r.suggested_diff, r.reason, r.status, r.created_at, r.updated_at
		FROM host_recommendations r
		JOIN hosts h ON h.id = r.host_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY r.updated_at DESC, r.name`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Recommendation
	for rows.Next() {
		var r Recommendation
		if err := rows.Scan(&r.ID, &r.OrgID, &r.HostID, &r.Hostname, &r.WorkloadType,
			&r.Name, &r.ConfigPath, &r.SuggestedLevel, &r.SuggestedDiff, &r.Reason,
			&r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRecommendation returns one recommendation by id.
func (s *Store) GetRecommendation(ctx context.Context, orgID, id string) (Recommendation, error) {
	var r Recommendation
	err := s.pool.QueryRow(ctx, `
		SELECT r.id::text, r.org_id::text, r.host_id::text, h.hostname,
		       r.workload_type, r.name, r.config_path, r.suggested_level,
		       r.suggested_diff, r.reason, r.status, r.created_at, r.updated_at
		FROM host_recommendations r
		JOIN hosts h ON h.id = r.host_id
		WHERE r.id = $1::uuid AND r.org_id = $2::uuid`, id, orgID).
		Scan(&r.ID, &r.OrgID, &r.HostID, &r.Hostname, &r.WorkloadType, &r.Name,
			&r.ConfigPath, &r.SuggestedLevel, &r.SuggestedDiff, &r.Reason,
			&r.Status, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// ApplyRecommendation approves a recommendation: it materializes the
// recommendation into a host_policy_rules row and marks the recommendation
// applied, in one transaction. It returns the created rule.
func (s *Store) ApplyRecommendation(ctx context.Context, orgID, id string) (PolicyRuleRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PolicyRuleRow{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rec, err := getRecommendationTx(ctx, tx, orgID, id)
	if err != nil {
		return PolicyRuleRow{}, err
	}
	if rec.Status != RecStatusPending {
		return PolicyRuleRow{}, fmt.Errorf("recommendation %s is already %s", id, rec.Status)
	}

	rule, err := upsertRuleTx(ctx, tx, orgID, rec)
	if err != nil {
		return PolicyRuleRow{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE host_recommendations SET status = 'applied', decided_at = NOW(), updated_at = NOW()
		WHERE id = $1::uuid AND org_id = $2::uuid`, id, orgID); err != nil {
		return PolicyRuleRow{}, err
	}
	return rule, tx.Commit(ctx)
}

// DismissRecommendation marks a pending recommendation dismissed.
func (s *Store) DismissRecommendation(ctx context.Context, orgID, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE host_recommendations SET status = 'dismissed', decided_at = NOW(), updated_at = NOW()
		WHERE id = $1::uuid AND org_id = $2::uuid AND status = 'pending'`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("recommendation %s not found or already decided", id)
	}
	return nil
}

// ApplyAllRecommendations approves every pending recommendation for org
// (optionally scoped to one host), returning the rules created.
func (s *Store) ApplyAllRecommendations(ctx context.Context, orgID, hostID string) ([]PolicyRuleRow, error) {
	where := []string{"org_id = $1::uuid", "status = 'pending'"}
	args := []any{orgID}
	if hostID != "" {
		args = append(args, hostID)
		where = append(where, fmt.Sprintf("host_id = $%d::uuid", len(args)))
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text FROM host_recommendations WHERE `+strings.Join(where, " AND ")+`
		ORDER BY updated_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rules := make([]PolicyRuleRow, 0, len(ids))
	for _, id := range ids {
		rule, err := s.ApplyRecommendation(ctx, orgID, id)
		if err != nil {
			return rules, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ListPolicyRules returns a host's active policy rules, oldest first.
func (s *Store) ListPolicyRules(ctx context.Context, orgID, hostID string) ([]PolicyRuleRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, target_type, pattern, level, diff, tags, created_at
		FROM host_policy_rules WHERE org_id = $1::uuid AND host_id = $2::uuid
		ORDER BY created_at, name`, orgID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicyRules(rows)
}

// ListPolicyRulesByHost returns every host's rules keyed by host id. Used to
// build the per-host rule sets pushed to agents.
func (s *Store) ListPolicyRulesByHost(ctx context.Context, orgID string) (map[string][]PolicyRuleRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host_id::text, id::text, name, target_type, pattern, level, diff, tags, created_at
		FROM host_policy_rules WHERE org_id = $1::uuid
		ORDER BY host_id, created_at, name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]PolicyRuleRow{}
	for rows.Next() {
		var hostID string
		var r PolicyRuleRow
		if err := rows.Scan(&hostID, &r.ID, &r.Name, &r.TargetType, &r.Pattern,
			&r.Level, &r.Diff, &r.Tags, &r.CreatedAt); err != nil {
			return nil, err
		}
		out[hostID] = append(out[hostID], r)
	}
	return out, rows.Err()
}

// PolicyRulesForHost returns the pb wire form of a host's rules, ready to be
// attached to an IngestBatchResponse.
//
// Fleet-wide rules are merged in here rather than at creation time. A rule
// authored as "All Hosts" lives once, with a NULL host_id, so it also applies to
// hosts that enrol after it was written; fanning it out to the hosts that
// existed at creation time would silently skip every new one. Per-host rules
// come first so a host-specific override is evaluated before the fleet default
// when both match — the classifier takes the first match.
func (s *Store) PolicyRulesForHost(ctx context.Context, orgID, hostID string) ([]*pb.PolicyRule, error) {
	rules, err := s.ListPolicyRules(ctx, orgID, hostID)
	if err != nil {
		return nil, err
	}
	fleet, err := s.FleetPolicyRules(ctx, orgID)
	if err != nil {
		return nil, err
	}
	rules = append(rules, fleet...)
	out := make([]*pb.PolicyRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, &pb.PolicyRule{
			Name:       r.Name,
			TargetType: r.TargetType,
			Pattern:    r.Pattern,
			Level:      int32(r.Level),
			Diff:       r.Diff,
			Tags:       r.Tags,
		})
	}
	return out, nil
}

func getRecommendationTx(ctx context.Context, tx pgx.Tx, orgID, id string) (Recommendation, error) {
	var r Recommendation
	err := tx.QueryRow(ctx, `
		SELECT r.id::text, r.org_id::text, r.host_id::text, h.hostname,
		       r.workload_type, r.name, r.config_path, r.suggested_level,
		       r.suggested_diff, r.reason, r.status, r.created_at, r.updated_at
		FROM host_recommendations r
		JOIN hosts h ON h.id = r.host_id
		WHERE r.id = $1::uuid AND r.org_id = $2::uuid
		FOR UPDATE OF r`, id, orgID).
		Scan(&r.ID, &r.OrgID, &r.HostID, &r.Hostname, &r.WorkloadType, &r.Name,
			&r.ConfigPath, &r.SuggestedLevel, &r.SuggestedDiff, &r.Reason,
			&r.Status, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return Recommendation{}, err
	}
	return r, nil
}

// upsertRuleTx inserts (or replaces) the policy rule derived from a
// recommendation. The rule name is derived from the workload so it is stable
// and human-readable in the console ("CheckoutApp [L1]").
func upsertRuleTx(ctx context.Context, tx pgx.Tx, orgID string, rec Recommendation) (PolicyRuleRow, error) {
	name := ruleNameFor(rec)
	tags := []string{rec.WorkloadType, "auto-discovered"}
	if rec.Hostname != "" {
		tags = append(tags, "host:"+rec.Hostname)
	}
	var r PolicyRuleRow
	err := tx.QueryRow(ctx, `
		INSERT INTO host_policy_rules
			(org_id, host_id, name, target_type, pattern, level, diff, tags, source_recommendation_id)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::uuid)
		ON CONFLICT (host_id, name) DO UPDATE SET
			target_type = EXCLUDED.target_type,
			pattern     = EXCLUDED.pattern,
			level       = EXCLUDED.level,
			diff        = EXCLUDED.diff,
			tags        = EXCLUDED.tags,
			source_recommendation_id = EXCLUDED.source_recommendation_id
		RETURNING id::text, name, target_type, pattern, level, diff, tags, created_at`,
		orgID, rec.HostID, name, ruleTargetType(rec.WorkloadType), rec.ConfigPath,
		rec.SuggestedLevel, rec.SuggestedDiff, tags, rec.ID).
		Scan(&r.ID, &r.Name, &r.TargetType, &r.Pattern, &r.Level, &r.Diff, &r.Tags, &r.CreatedAt)
	if err != nil {
		return PolicyRuleRow{}, err
	}
	return r, nil
}

// ruleNameFor builds a stable, readable rule name from a recommendation.
func ruleNameFor(rec Recommendation) string {
	base := rec.Name
	if base == "" {
		base = rec.WorkloadType
	}
	base = strings.NewReplacer(`\`, "-", "/", "-", ":", "-", " ", "-").Replace(strings.TrimSpace(base))
	if base == "" {
		base = uuid.NewString()[:8]
	}
	return fmt.Sprintf("%s [L%d]", base, rec.SuggestedLevel)
}

// ruleTargetType maps a discovered workload type to the policy rule target
// type the agent matches against. Every workload the discovery engine reports
// is ultimately a configuration file on disk, so they all map to "file"
// (the pattern is the file's path).
func ruleTargetType(string) string { return "file" }

func scanPolicyRules(rows pgx.Rows) ([]PolicyRuleRow, error) {
	var out []PolicyRuleRow
	for rows.Next() {
		var r PolicyRuleRow
		if err := rows.Scan(&r.ID, &r.Name, &r.TargetType, &r.Pattern, &r.Level,
			&r.Diff, &r.Tags, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
