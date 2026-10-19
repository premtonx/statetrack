package iis

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// DefaultInterval is how often the runtime state is polled.
//
// Thirty seconds, not one: the poll shells out to appcmd, and a stopped pool is
// an operational fact with a human response time, not a packet that needs
// sub-second detection. Configuration edits arrive faster than that through the
// file watcher anyway, which re-triggers the poll.
const DefaultInterval = 30 * time.Second

// Options configures the collector.
type Options struct {
	// ConfigPath is applicationHost.config. Empty uses the WINDIR default.
	ConfigPath string
	// Pools and Sites are the watched targets, as names or iis:// URIs. They
	// come from the config file and from the policy rules the console pushes,
	// so a target added in the UI starts being tracked without an agent edit.
	Pools []string
	Sites []string
	// DynamicTargets returns pools and sites discovered at poll time. It is
	// how a rule pushed by the console after the agent started takes effect:
	// the classifier is reconfigured on every heartbeat, and re-reading the
	// rules each poll means a newly watched pool does not need a restart.
	DynamicTargets func() (pools, sites []string)
	// WatchAll tracks every pool and site in applicationHost.config. It is off
	// by default on purpose: IIS stops an idle pool after 20 minutes, so
	// watching every pool turns routine idle recycling into a stream of Level 1
	// events. An operator who wants the whole server opts in explicitly.
	WatchAll bool

	Interval   time.Duration
	Classifier *limiter.Classifier
	// Scrub replaces a credential with a stable stub. Required for password
	// scrubbing; a nil scrubber leaves the fixed [REDACTED] marker.
	Scrub func(string) string
	// Handle receives a rendered pool/site document (engine.HandleDoc).
	Handle func(context.Context, engine.DocEvent) error
	// Seed records a baseline without emitting an event (engine.SeedDocOfType).
	Seed func(ctx context.Context, path, targetType string, content []byte, modTime time.Time) error
	// Known reports whether a path already has a baseline in the shadow store,
	// so a restart does not re-report the whole server as created.
	Known func(ctx context.Context, path string) bool
	// Attribute resolves the actor behind a detected change. On Windows it is
	// wired to the audit notes and to a recently-started management process.
	Attribute func(now time.Time) (*pb.ActorContext, string)
	// States queries live pool and site state. Empty uses the platform query
	// (appcmd on Windows); a test supplies a fixture.
	States func(ctx context.Context) (map[string]string, error)
	// ReadConfig reads applicationHost.config. Empty uses the filesystem.
	ReadConfig func(path string) ([]byte, time.Time, error)

	Logger *slog.Logger
}

// Collector polls applicationHost.config and the IIS runtime, rendering one
// canonical YAML document per watched pool and site.
type Collector struct {
	o   Options
	log *slog.Logger

	mu   sync.Mutex
	last map[string]snapshot // rendered-document state, for change summaries
}

// snapshot is the minimum needed to describe what changed since the last poll.
type snapshot struct {
	pool    *Pool
	site    *Site
	summary string
}

// New builds a collector, applying defaults.
func New(o Options) *Collector {
	if o.ConfigPath == "" {
		o.ConfigPath = DefaultApplicationHost
	}
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.ReadConfig == nil {
		o.ReadConfig = readFile
	}
	return &Collector{o: o, log: o.Logger.With("collector", "iis"), last: map[string]snapshot{}}
}

// ConfigPath returns the resolved applicationHost.config path.
func (c *Collector) ConfigPath() string { return c.o.ConfigPath }

// Watched returns the concrete pool and site names this collector tracks,
// resolved from the configured names and globs against the parsed config.
func (c *Collector) Watched(cfg Config) (pools []Pool, sites []Site) {
	poolPatterns, sitePatterns := c.targets()
	poolMatch, err := limiter.NewMatcher(uriPatterns(poolPatterns, PoolScheme)...)
	if err != nil {
		c.log.Warn("invalid app pool watch pattern", "err", err)
	}
	siteMatch, err := limiter.NewMatcher(uriPatterns(sitePatterns, SiteScheme)...)
	if err != nil {
		c.log.Warn("invalid site watch pattern", "err", err)
	}
	for _, p := range cfg.Pools {
		if c.o.WatchAll || (poolMatch != nil && poolMatch.Match(PoolPath(p.Name))) {
			pools = append(pools, p)
		}
	}
	for _, s := range cfg.Sites {
		if c.o.WatchAll || (siteMatch != nil && siteMatch.Match(SitePath(s.Name))) {
			sites = append(sites, s)
		}
	}
	return pools, sites
}

// targets returns the static and console-pushed pool and site patterns.
//
// Merging here rather than at construction is what makes a rule created in the
// console take effect on the next poll: the collector is already running, and
// the classifier it reads from is reconfigured on every server ack.
func (c *Collector) targets() (pools, sites []string) {
	pools = append(pools, c.o.Pools...)
	sites = append(sites, c.o.Sites...)
	if c.o.DynamicTargets != nil {
		dp, ds := c.o.DynamicTargets()
		pools = append(pools, dp...)
		sites = append(sites, ds...)
	}
	return pools, sites
}

// hasTargets reports whether any pool or site is watched.
func (c *Collector) hasTargets() bool {
	if c.o.WatchAll {
		return true
	}
	pools, sites := c.targets()
	for _, p := range pools {
		if strings.TrimSpace(p) != "" {
			return true
		}
	}
	for _, s := range sites {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// uriPatterns normalises operator input into document-path patterns. A bare
// name becomes the full URI so the matcher stays one code path for names,
// URIs and globs.
func uriPatterns(vals []string, scheme string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(v), "iis://") {
			v = scheme + strings.TrimPrefix(v, "/")
		}
		out = append(out, v)
	}
	return out
}

// Run polls until ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	if c.o.Handle == nil {
		return errors.New("iis: Handle is required")
	}
	if len(c.o.Pools) == 0 && len(c.o.Sites) == 0 && !c.o.WatchAll && c.o.DynamicTargets == nil {
		c.log.Info("iis watcher has no targets; add a watched target in the console to enable it")
		return nil
	}
	if !c.hasTargets() {
		c.log.Info("iis watcher has no targets yet; waiting for a console rule")
	}
	c.log.Info("iis collector started", "config", c.o.ConfigPath,
		"pools", len(c.o.Pools), "sites", len(c.o.Sites), "all", c.o.WatchAll,
		"interval", c.o.Interval)

	// One immediate poll so a restart reconciles promptly instead of waiting a
	// full interval for the first observation.
	c.poll(ctx)
	t := time.NewTicker(c.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			c.poll(ctx)
		}
	}
}

// Poll runs one observation cycle now (used by Run and by tests).
func (c *Collector) Poll(ctx context.Context) { c.poll(ctx) }

func (c *Collector) poll(ctx context.Context) {
	raw, _, err := c.o.ReadConfig(c.o.ConfigPath)
	if err != nil {
		// A missing file means IIS is not installed; a parse error means the
		// operator is mid-edit. Either way, reporting every pool as deleted
		// would be a false alarm, so the cycle is skipped.
		if !errors.Is(err, os.ErrNotExist) {
			c.log.Warn("read applicationHost.config", "path", c.o.ConfigPath, "err", err)
		}
		return
	}
	cfg, err := ParseConfig(raw)
	if err != nil {
		c.log.Warn("parse applicationHost.config", "path", c.o.ConfigPath, "err", err)
		return
	}

	states := map[string]string{}
	if c.o.States != nil {
		if got, err := c.o.States(ctx); err != nil {
			// Unknown state is reported as such rather than as Stopped: a
			// failed query must not be indistinguishable from an outage.
			c.log.Debug("query iis runtime state", "err", err)
		} else {
			states = got
		}
	}

	now := time.Now()
	pools, sites := c.Watched(cfg)
	seen := make(map[string]bool, len(pools)+len(sites))

	for _, p := range pools {
		if s, ok := states[p.Name]; ok && s != "" {
			p.State = s
		}
		path := PoolPath(p.Name)
		seen[path] = true
		c.observePool(ctx, path, p, now)
	}
	for _, s := range sites {
		if v, ok := states[s.Name]; ok && v != "" {
			s.State = v
		}
		path := SitePath(s.Name)
		seen[path] = true
		c.observeSite(ctx, path, s, now)
	}
	c.prune(ctx, seen)
}

func (c *Collector) observePool(ctx context.Context, path string, p Pool, now time.Time) {
	if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
		return
	}
	content := renderPool(p, c.o.Scrub)
	if content == nil {
		return
	}
	c.mu.Lock()
	prev, had := c.last[path]
	c.last[path] = snapshot{pool: &p}
	c.mu.Unlock()

	if !c.known(ctx, path) {
		if c.o.Seed != nil {
			if err := c.o.Seed(ctx, path, TargetPool, content, now); err != nil {
				c.log.Error("iis seed", "pool", p.Name, "err", err)
			}
		}
		return
	}
	if had && prev.pool != nil && !poolDiffers(*prev.pool, p) {
		return
	}
	summary := "Modified " + path
	if had && prev.pool != nil {
		summary = PoolSummary(path, *prev.pool, p)
	}
	c.emit(ctx, engine.DocEvent{
		Path:        path,
		TargetType:  TargetPool,
		Content:     content,
		ModTime:     now,
		Actor:       c.actor(now),
		Attribution: c.attribution(now),
	}, summary, p.Name, "pool")
}

func (c *Collector) observeSite(ctx context.Context, path string, s Site, now time.Time) {
	if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
		return
	}
	content := renderSite(s)
	if content == nil {
		return
	}
	c.mu.Lock()
	prev, had := c.last[path]
	c.last[path] = snapshot{site: &s}
	c.mu.Unlock()

	if !c.known(ctx, path) {
		if c.o.Seed != nil {
			if err := c.o.Seed(ctx, path, TargetSite, content, now); err != nil {
				c.log.Error("iis seed", "site", s.Name, "err", err)
			}
		}
		return
	}
	if had && prev.site != nil && prev.site.State == s.State &&
		renderEqual(renderSite(*prev.site), content) {
		return
	}
	summary := "Modified " + path
	if had && prev.site != nil {
		summary = SiteSummary(path, prev.site.State, s.State)
	}
	c.emit(ctx, engine.DocEvent{
		Path:        path,
		TargetType:  TargetSite,
		Content:     content,
		ModTime:     now,
		Actor:       c.actor(now),
		Attribution: c.attribution(now),
	}, summary, s.Name, "site")
}

// emit hands one document to the engine and logs a readable line. The summary
// is attached to the event metadata so the timeline reads
// "Application pool CheckoutAppPool stopped" instead of "Modified iis://…",
// which is the difference between an alert an operator can act on and one they
// have to open to understand.
func (c *Collector) emit(ctx context.Context, de engine.DocEvent, summary, name, kind string) {
	if err := c.o.Handle(ctx, de); err != nil {
		c.log.Error("iis change", kind, name, "err", err)
		return
	}
	c.log.Info("iis change observed", kind, name, "summary", summary)
}

// prune reports watched documents that no longer exist as deletions, so
// removing a pool or site from applicationHost.config is itself a change rather
// than a row that silently stops updating.
func (c *Collector) prune(ctx context.Context, seen map[string]bool) {
	c.mu.Lock()
	var gone []string
	for path := range c.last {
		if !seen[path] {
			gone = append(gone, path)
		}
	}
	for _, path := range gone {
		delete(c.last, path)
	}
	c.mu.Unlock()
	sort.Strings(gone)
	for _, path := range gone {
		if c.o.Classifier != nil && c.o.Classifier.Blacklisted(path) {
			continue
		}
		targetType := TargetPool
		if IsSitePath(path) {
			targetType = TargetSite
		}
		if err := c.o.Handle(ctx, engine.DocEvent{
			Path:        path,
			TargetType:  targetType,
			Content:     nil, // deletion
			ModTime:     time.Now(),
			Actor:       c.actor(time.Now()),
			Attribution: c.attribution(time.Now()),
		}); err != nil {
			c.log.Error("iis delete", "path", path, "err", err)
		}
	}
}

func (c *Collector) known(ctx context.Context, path string) bool {
	return c.o.Known != nil && c.o.Known(ctx, path)
}

func (c *Collector) actor(now time.Time) *pb.ActorContext {
	if c.o.Attribute == nil {
		return nil
	}
	a, _ := c.o.Attribute(now)
	return a
}

func (c *Collector) attribution(now time.Time) string {
	if c.o.Attribute == nil {
		return ""
	}
	_, method := c.o.Attribute(now)
	return method
}

// poolDiffers compares the fields the rendered document carries. It exists so a
// poll that observes no change does not re-render and re-dispatch: the shadow
// tracker would return no change anyway, but the comparison keeps the summary
// logic honest and the log quiet.
func poolDiffers(a, b Pool) bool {
	return a.State != b.State ||
		a.AutoStart != b.AutoStart ||
		a.ManagedRuntimeVersion != b.ManagedRuntimeVersion ||
		a.ManagedPipelineMode != b.ManagedPipelineMode ||
		a.Enable32BitAppOnWin64 != b.Enable32BitAppOnWin64 ||
		a.ProcessModel != b.ProcessModel ||
		a.RapidFailProtection != b.RapidFailProtection ||
		!strings.EqualFold(strings.Join(a.Recycling.Schedule, ","), strings.Join(b.Recycling.Schedule, ","))
}

func renderEqual(a, b []byte) bool { return string(a) == string(b) }

func readFile(path string) ([]byte, time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	var mod time.Time
	if fi, err := os.Stat(path); err == nil {
		mod = fi.ModTime()
	}
	return b, mod, nil
}
