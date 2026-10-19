package app

import (
	"context"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/collectors/database"
	"github.com/statetrack/statetrack/agent/internal/collectors/iis"
	"github.com/statetrack/statetrack/agent/internal/engine"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// startIIS starts the application pool and site watcher.
//
// It is started even with no configured target, because the console is the
// primary place an operator names a pool: the collector re-reads the pushed
// rules on every poll, so the first heartbeat after a rule is created is enough
// to start tracking it. On a host without IIS the config file simply does not
// exist and the poll is skipped, which is why an unconditional start is safe.
func startIIS(ctx context.Context, wg *sync.WaitGroup, a *Agent) (*iis.Collector, error) {
	kcfg := a.Config.IIS
	if !kcfg.Enabled {
		return nil, nil
	}
	col := iis.New(iis.Options{
		ConfigPath: kcfg.ApplicationHost,
		Pools:      kcfg.Pools,
		Sites:      kcfg.Sites,
		WatchAll:   kcfg.WatchAll,
		Interval:   kcfg.Interval.D(),
		Classifier: a.Classifier,
		// Pools pushed by the console are discovered through the same
		// classifier the rules are compiled into, so there is no second copy of
		// the target list to keep in sync.
		DynamicTargets: func() (pools, sites []string) {
			return splitIISPatterns(a.Classifier.RulePatterns(iis.TargetPool)),
				splitIISPatterns(a.Classifier.RulePatterns(iis.TargetSite))
		},
		Scrub: a.scrubber.Stub,
		Handle: func(ctx context.Context, de engine.DocEvent) error {
			return a.Engine.HandleDoc(ctx, de)
		},
		Seed: a.Engine.SeedDocOfType,
		Known: func(ctx context.Context, path string) bool {
			_, ok, err := a.Store.Get(ctx, path)
			return err == nil && ok
		},
		Attribute: func(now time.Time) (*pb.ActorContext, string) {
			return iis.AttributeRecentManager(now, iis.DefaultActorWindow)
		},
		Logger: a.Logger,
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := col.Run(ctx); err != nil && ctx.Err() == nil {
			a.Logger.Error("iis collector stopped", "err", err)
		}
	}()
	a.Logger.Info("iis watcher started",
		"pools", len(kcfg.Pools), "sites", len(kcfg.Sites), "watch_all", kcfg.WatchAll)
	return col, nil
}

// splitIISPatterns keeps only the rules that address a pool or a site, so a
// console rule for an ordinary file never becomes an app pool named after it.
func splitIISPatterns(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// startDatabase starts the read-only database watcher.
//
// With no connection the collector would have nothing to poll, so it is not
// started at all: an empty watcher costs a goroutine and logs an error on every
// boot for a host that simply has no database to watch.
func startDatabase(ctx context.Context, wg *sync.WaitGroup, a *Agent) (*database.Collector, error) {
	dcfg := a.Config.Database
	if !dcfg.Enabled {
		return nil, nil
	}
	conns := make([]database.Connection, 0, len(dcfg.Connections))
	for _, c := range dcfg.Connections {
		conns = append(conns, database.Connection{
			Name:              c.Name,
			Engine:            c.Engine,
			DSN:               c.DSN,
			Database:          c.Database,
			Tables:            c.Tables,
			WatchSchema:       c.WatchSchema,
			WatchServerParams: c.WatchServerParams,
			RowLimit:          c.RowLimit,
			Interval:          c.Interval.D(),
		})
	}
	if len(conns) == 0 {
		return nil, nil
	}

	col := database.New(database.Options{
		Connections: conns,
		// Console rules for db:// paths are the same list the classifier
		// matches against, so a table added in the UI is polled from the next
		// cycle without an agent restart.
		Targets: append([]string(nil), a.Classifier.RulePatterns(database.TargetFamily)...),
		// Re-read each poll: a target added in the console is pushed as a rule
		// on the next heartbeat, and the collector is already running.
		DynamicTargets: func() []string {
			return a.Classifier.RulePatterns(database.TargetFamily)
		},
		Interval:   dcfg.Interval.D(),
		Classifier: a.Classifier,
		Scrub: &database.Scrubber{
			Stub: a.scrubber.Stub,
			Line: a.scrubber.Line,
		},
		Handle: func(ctx context.Context, de engine.DocEvent) error {
			return a.Engine.HandleDoc(ctx, de)
		},
		Seed: a.Engine.SeedDocOfType,
		Known: func(ctx context.Context, path string) bool {
			_, ok, err := a.Store.Get(ctx, path)
			return err == nil && ok
		},
		Logger: a.Logger,
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := col.Run(ctx); err != nil && ctx.Err() == nil {
			a.Logger.Error("database collector stopped", "err", err)
		}
	}()
	a.Logger.Info("database watcher started", "connections", len(conns))
	return col, nil
}
