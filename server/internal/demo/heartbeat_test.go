package demo

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"
)

// fakeFleet records every heartbeat call so a test can assert the ticker's
// cadence and, more importantly, *which* hosts it claims are alive.
type fakeFleet struct {
	mu       sync.Mutex
	calls    int
	hosts    [][]string
	errs     []error
	updated  int64
	interval time.Duration
	done     chan struct{}
}

func (f *fakeFleet) HeartbeatDemoHosts(_ context.Context, _ string, hostnames []string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++
	f.hosts = append(f.hosts, append([]string{}, hostnames...))
	var err error
	if len(f.errs) > 0 {
		err = f.errs[0]
		f.errs = f.errs[1:]
	}
	if f.done != nil {
		select {
		case <-f.done:
		default:
			close(f.done)
		}
	}
	return f.updated, err
}

func (f *fakeFleet) snapshot() (calls int, hosts [][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, append([][]string{}, f.hosts...)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&strings.Builder{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// TestHeartbeatNamesOnlyTheSeededHosts is the invariant that keeps the demo
// honest. The ticker runs for the life of the process, so a query that updated
// the whole table would continuously mark a genuinely dark host online — the one
// thing a fleet-health panel must never do. Only the four seeded hostnames may
// be asserted alive.
func TestHeartbeatNamesOnlyTheSeededHosts(t *testing.T) {
	fleet := &fakeFleet{updated: 4, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go RunHeartbeat(ctx, quietLogger(), fleet, "org", 10*time.Millisecond)
	waitFor(t, fleet.done)

	_, hosts := fleet.snapshot()
	if len(hosts) == 0 {
		t.Fatal("heartbeat never ran")
	}
	for _, call := range hosts {
		if len(call) != 4 {
			t.Fatalf("heartbeat named %d hosts, want the 4 seeded ones: %v", len(call), call)
		}
		for _, want := range DemoHostnames {
			if !contains(call, want) {
				t.Errorf("heartbeat call %v is missing %q", call, want)
			}
		}
	}
}

// TestHeartbeatTicksBeforeWaiting pins the immediate first tick. A browser
// opened one second after `dev.ps1 run-server` must already see a healthy fleet;
// waiting out the first interval leaves the KPI card stale for half a minute,
// which is precisely the window a screenshot is taken in.
func TestHeartbeatTicksBeforeWaiting(t *testing.T) {
	fleet := &fakeFleet{updated: 4, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go RunHeartbeat(ctx, quietLogger(), fleet, "org", time.Hour)
	waitFor(t, fleet.done)

	if calls, _ := fleet.snapshot(); calls != 1 {
		t.Fatalf("heartbeat ran %d times before the first interval; want exactly 1", calls)
	}
}

// TestHeartbeatRepeatsOnInterval guards the "stays fresh for days" requirement:
// one stamp is not enough, since the panels only look back 15 minutes.
func TestHeartbeatRepeatsOnInterval(t *testing.T) {
	fleet := &fakeFleet{updated: 4, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go RunHeartbeat(ctx, quietLogger(), fleet, "org", 5*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls, _ := fleet.snapshot(); calls >= 3 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	calls, _ := fleet.snapshot()
	t.Fatalf("heartbeat ran %d times; want it to repeat every interval", calls)
}

// TestHeartbeatSurvivesAFailingTick ensures a transient database error does not
// kill the loop. A demo database that is restarted mid-recording should resume
// stamping once it is back, not leave the fleet offline until the server is
// restarted too.
func TestHeartbeatSurvivesAFailingTick(t *testing.T) {
	fleet := &fakeFleet{
		updated: 4,
		done:    make(chan struct{}),
		errs:    []error{errors.New("connection refused")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go RunHeartbeat(ctx, quietLogger(), fleet, "org", 5*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls, _ := fleet.snapshot(); calls >= 3 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	calls, _ := fleet.snapshot()
	t.Fatalf("heartbeat stopped after a failed tick (%d calls); it must keep retrying", calls)
}

// TestHeartbeatStopsWithContext pins that the goroutine is bound to the server's
// lifetime. A leaked ticker keeps writing to Postgres after shutdown, which
// makes `go test -race` and a clean container stop both noisy.
func TestHeartbeatStopsWithContext(t *testing.T) {
	fleet := &fakeFleet{updated: 4, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())

	stopped := make(chan struct{})
	go func() {
		RunHeartbeat(ctx, quietLogger(), fleet, "org", 2*time.Millisecond)
		close(stopped)
	}()
	waitFor(t, fleet.done)
	cancel()
	waitFor(t, stopped)

	before, _ := fleet.snapshot()
	time.Sleep(30 * time.Millisecond)
	after, _ := fleet.snapshot()
	if after != before {
		t.Fatalf("heartbeat kept running after cancel: %d -> %d calls", before, after)
	}
}

// TestHeartbeatLogsOnceInSteadyState keeps a 30-second ticker from writing a log
// line every 30 seconds for days. The demo asserts a fleet is alive; it must not
// drown the events a recording is trying to show in heartbeat noise.
func TestHeartbeatLogsOnceInSteadyState(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	fleet := &fakeFleet{updated: 4, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go RunHeartbeat(ctx, log, fleet, "org", 3*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls, _ := fleet.snapshot(); calls >= 5 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if calls, _ := fleet.snapshot(); calls < 5 {
		t.Fatalf("heartbeat ran only %d times; cannot judge logging", calls)
	}
	if n := strings.Count(buf.String(), "fleet heartbeat"); n != 1 {
		t.Fatalf("logged the steady-state heartbeat %d times; want exactly 1\n%s", n, buf.String())
	}
}

func waitFor(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the heartbeat")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
