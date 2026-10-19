package storage

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/statetrack/statetrack/server/internal/testdb"
)

func TestMonthlyPartitions(t *testing.T) {
	got := MonthlyPartitions(time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC), 2)
	want := []MonthlyPartition{
		{"events_2026_11", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
		{"events_2026_12", time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"events_2027_01", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d partitions, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name || !got[i].From.Equal(want[i].From) || !got[i].To.Equal(want[i].To) {
			t.Errorf("partition %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMonthlyPartitionsUsesUTC(t *testing.T) {
	// 2026-11-01 05:00 in UTC+14 is still October in UTC.
	kiribati := time.FixedZone("UTC+14", 14*3600)
	got := MonthlyPartitions(time.Date(2026, 11, 1, 5, 0, 0, 0, kiribati), 0)
	if len(got) != 1 || got[0].Name != "events_2026_10" {
		t.Fatalf("got %+v, want events_2026_10", got)
	}
}

func TestMonthlyPartitionsEndOfMonth(t *testing.T) {
	// AddDate on the 31st must not skip February.
	got := MonthlyPartitions(time.Date(2027, 1, 31, 23, 59, 0, 0, time.UTC), 1)
	if got[1].Name != "events_2027_02" {
		t.Fatalf("got %s, want events_2027_02", got[1].Name)
	}
}

func TestCreateSQL(t *testing.T) {
	p := MonthlyPartitions(time.Date(2026, 12, 3, 0, 0, 0, 0, time.UTC), 0)[0]
	want := `CREATE TABLE IF NOT EXISTS "events_2026_12" PARTITION OF events FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00')`
	if got := p.CreateSQL(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// Integration test: needs a Postgres, which the helper migrates if it is bare,
// so `make test-integration` and a CI service container both work.
func TestEnsurePartitionsIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := testdb.Pool(t)
	// Cleanups run LIFO after the test body (and after deferred calls), so
	// the pool is closed only once the partitions below have been dropped.
	t.Cleanup(pool.Close)

	// Use a far-future window so the test never touches real partitions.
	now := time.Date(2099, 11, 20, 0, 0, 0, 0, time.UTC)
	names := []string{"events_2099_11", "events_2099_12", "events_2100_01"}
	cleanup := func() {
		for _, n := range names {
			if _, err := pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+n); err != nil {
				t.Errorf("cleanup %s: %v", n, err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	// Concurrent callers must not fail and must create each partition once.
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created []string
		errs    []error
	)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := EnsurePartitions(ctx, pool, now, 2)
			mu.Lock()
			defer mu.Unlock()
			created = append(created, c...)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("EnsurePartitions errors: %v", errs)
	}
	if len(created) != len(names) {
		t.Fatalf("created %v, want each of %v exactly once", created, names)
	}

	again, err := EnsurePartitions(ctx, pool, now, 2)
	if err != nil || len(again) != 0 {
		t.Fatalf("second call: created=%v err=%v, want nothing", again, err)
	}

	var bound string
	err = pool.QueryRow(ctx, `
		SELECT pg_get_expr(c.relpartbound, c.oid)
		FROM pg_class c JOIN pg_inherits i ON i.inhrelid = c.oid
		WHERE i.inhparent = 'events'::regclass AND c.relname = 'events_2099_12'`).Scan(&bound)
	if err != nil {
		t.Fatalf("partition not attached to events: %v", err)
	}
	if !strings.Contains(bound, "2099-12-01") || !strings.Contains(bound, "2100-01-01") {
		t.Fatalf("unexpected bounds: %s", bound)
	}
}
