// Package demo holds the demo-only background behaviour that keeps a seeded
// fleet looking alive.
package demo

import (
	"context"
	"log/slog"
	"time"
)

// HeartbeatInterval is how often the demo fleet's last_seen_at is refreshed.
//
// Thirty seconds is chosen against the dashboard's own arithmetic, not for
// liveliness: the Agents-online KPI counts a host as online when
// `last_seen_at > now() - interval '15 minutes'`, so the ticker only has to win
// that race with a wide margin. Thirty seconds means a refresh is missed sixteen
// times over before a host would read offline, which keeps the card green across
// a laptop sleep or a slow `go build` while staying cheap enough to be
// irrelevant (one indexed UPDATE every thirty seconds).
const HeartbeatInterval = 30 * time.Second

// DemoHostnames are the four hosts statetrack-seed enrolls. The heartbeat is
// deliberately allow-listed to them rather than updating the whole table: in a
// demo database that has had a real agent enrolled alongside the seeded fleet,
// stamping every row would mark the real one online while it is genuinely dark,
// which is the one lie a monitoring product must not tell.
var DemoHostnames = []string{"prod-web-01", "win-app-02", "prod-k8s-01", "prod-web-02"}

// FleetRefresher is the slice of storage the heartbeat needs. Keeping it an
// interface (rather than taking *storage.Store) is what lets the ticker be
// tested with a fake and without a database.
type FleetRefresher interface {
	HeartbeatDemoHosts(ctx context.Context, orgID string, hostnames []string) (int64, error)
}

// RunHeartbeat refreshes the demo fleet's last_seen_at every interval until ctx
// is cancelled.
//
// It ticks once immediately, so a server that just started reports a healthy
// fleet without waiting out the first interval. Only the first success and any
// change of outcome are logged: a line every thirty seconds would bury the
// events a demo is being recorded to show.
func RunHeartbeat(ctx context.Context, log *slog.Logger, fleet FleetRefresher, orgID string, interval time.Duration) {
	if interval <= 0 {
		interval = HeartbeatInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// `announced` is what keeps a 30-second ticker from writing a log line every
	// 30 seconds: the first success is worth reporting (it proves the demo fleet
	// is being kept alive), every later one is not. A recovered failure and a
	// fleet that suddenly matches no hosts still speak up, because those are
	// changes in outcome rather than the steady state.
	announced := false
	beat := func() {
		updated, err := fleet.HeartbeatDemoHosts(ctx, orgID, DemoHostnames)
		switch {
		case err != nil:
			// A demo database that is briefly unreachable must not spam a line
			// per tick; only report the transition into failure, and re-arm so
			// the recovery is reported too.
			log.Warn("demo mode: heartbeat failed", "err", err)
			announced = false
		case updated == 0:
			// The UPDATE matched nothing: the seeded hosts are missing (a fresh
			// database, or a rename). Worth saying once, then staying quiet.
			if announced {
				log.Warn("demo mode: heartbeat found no seeded hosts", "hosts", DemoHostnames)
				announced = false
			}
		case !announced:
			log.Info("demo mode: fleet heartbeat", "hosts", updated, "every", interval.String())
			announced = true
		}
	}

	beat()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			beat()
		}
	}
}
