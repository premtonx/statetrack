package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// DefaultMonthsAhead is how many future monthly partitions are kept
	// ready in addition to the current month.
	DefaultMonthsAhead = 2
	// DefaultPartitionCheckInterval is how often the maintainer re-checks.
	DefaultPartitionCheckInterval = 6 * time.Hour

	// Arbitrary constant identifying the partition-maintenance advisory lock,
	// so concurrent server replicas do not race on CREATE TABLE.
	partitionLockKey int64 = 0x5354_5041_5254 // "STPART"
)

// TxBeginner is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// MonthlyPartition describes one monthly range partition of the events table.
type MonthlyPartition struct {
	Name     string
	From, To time.Time // [From, To) in UTC
}

// CreateSQL returns an idempotent statement creating the partition.
func (p MonthlyPartition) CreateSQL() string {
	const layout = "2006-01-02 15:04:05-07"
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')",
		pgx.Identifier{p.Name}.Sanitize(), p.From.Format(layout), p.To.Format(layout))
}

// MonthlyPartitions returns the partitions covering the UTC month containing
// now and the following monthsAhead months.
func MonthlyPartitions(now time.Time, monthsAhead int) []MonthlyPartition {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	parts := make([]MonthlyPartition, 0, monthsAhead+1)
	for i := 0; i <= monthsAhead; i++ {
		from := start.AddDate(0, i, 0)
		parts = append(parts, MonthlyPartition{
			Name: fmt.Sprintf("events_%04d_%02d", from.Year(), int(from.Month())),
			From: from,
			To:   from.AddDate(0, 1, 0),
		})
	}
	return parts
}

// EnsurePartitions creates any missing partitions for the current month and
// the next monthsAhead months, returning the names of the partitions it
// created. It is safe to call concurrently from multiple servers.
func EnsurePartitions(ctx context.Context, db TxBeginner, now time.Time, monthsAhead int) ([]string, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", partitionLockKey); err != nil {
		return nil, fmt.Errorf("acquire partition lock: %w", err)
	}

	var created []string
	for _, p := range MonthlyPartitions(now, monthsAhead) {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", p.Name).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check partition %s: %w", p.Name, err)
		}
		if exists {
			continue
		}
		if _, err := tx.Exec(ctx, p.CreateSQL()); err != nil {
			return nil, fmt.Errorf("create partition %s: %w", p.Name, err)
		}
		created = append(created, p.Name)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return created, nil
}

// PartitionMaintainer periodically ensures upcoming events partitions exist.
type PartitionMaintainer struct {
	DB          TxBeginner
	MonthsAhead int
	Interval    time.Duration
	Logger      *slog.Logger
	Now         func() time.Time
}

// RunOnce performs a single maintenance pass.
func (m *PartitionMaintainer) RunOnce(ctx context.Context) error {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	ahead := m.MonthsAhead
	if ahead <= 0 {
		ahead = DefaultMonthsAhead
	}
	created, err := EnsurePartitions(ctx, m.DB, now(), ahead)
	if err != nil {
		return err
	}
	for _, name := range created {
		m.logger().Info("created events partition", "partition", name)
	}
	return nil
}

// Run performs a pass immediately and then every Interval until ctx is
// cancelled. Failures are logged and retried on the next tick.
func (m *PartitionMaintainer) Run(ctx context.Context) {
	interval := m.Interval
	if interval <= 0 {
		interval = DefaultPartitionCheckInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := m.RunOnce(ctx); err != nil && ctx.Err() == nil {
			m.logger().Error("events partition maintenance failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *PartitionMaintainer) logger() *slog.Logger {
	if m.Logger != nil {
		return m.Logger
	}
	return slog.Default()
}
