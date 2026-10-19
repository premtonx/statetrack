// Package app wires the agent together: config -> state (salt, shadow
// cache, spool) -> classifier/engine -> Day-0 baseline -> platform
// collectors, plus the periodic engine tick and config hot-reload.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/baseline"
	"github.com/statetrack/statetrack/agent/internal/config"
	"github.com/statetrack/statetrack/agent/internal/debouncer"
	"github.com/statetrack/statetrack/agent/internal/discovery"
	"github.com/statetrack/statetrack/agent/internal/engine"
	"github.com/statetrack/statetrack/agent/internal/limiter"
	"github.com/statetrack/statetrack/agent/internal/shadow"
	"github.com/statetrack/statetrack/agent/internal/spool"
	"github.com/statetrack/statetrack/agent/internal/transport"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
	"github.com/statetrack/statetrack/pkg/redact"
)

// Options configures Run. Zero values mean production defaults.
type Options struct {
	ConfigPath string
	GOOS       string
	Env        func(string) (string, bool)
	Logger     *slog.Logger
	LogLevel   *slog.LevelVar
	// SelfFiles are watched as agent self-tamper targets (default: the
	// agent executable and the config file).
	SelfFiles []string
	// TickInterval drives engine.Tick (default 1s).
	TickInterval time.Duration
	// Ready is called once all collectors are running.
	Ready func(*Agent)
	// Hostname, OSVersion and AgentVersion are sent to the server on every
	// batch for host registration (transport). Empty values are derived.
	Hostname     string
	OSVersion    string
	AgentVersion string
	// Transport configures the spool flusher; Server.Address from the config
	// is used when not set here.
	Transport *transport.Options
	// Linux overrides (tests).
	ProcRoot   string
	PasswdPath string
}

// Agent is the running agent's state, exposed for tests and diagnostics.
type Agent struct {
	Config     config.Config
	ConfigPath string
	HostID     string
	Classifier *limiter.Classifier
	Store      *shadow.Store
	Spool      *spool.Spool
	Engine     *engine.Engine
	Logger     *slog.Logger
	// Platform describes the active collectors (e.g. fanotify on/off).
	Platform map[string]string

	o         Options
	scrubber  *redact.Scrubber
	selfFiles []string
	walker    *baseline.Walker
	flusher   *transport.Flusher
	discovery *discovery.Scanner
	// extraWorkloads contributes workload recommendations from collectors that
	// are not host scanners (the Kubernetes watcher). It is set before the
	// transport starts and is not mutated afterwards.
	extraWorkloads func() []discovery.DiscoveredWorkload
	// serverRules are the policy rules pushed by the server; they are merged
	// with the config's rules when (re)configuring the classifier.
	serverRules []limiter.PolicyRule
	mu          sync.Mutex
	roots       []string
	plat        platform
}

// platform is implemented per OS by the collectors.
type platform interface {
	// SetRoots applies new watch roots (hot reload, glob re-expansion).
	SetRoots(roots []string)
	// Tick is called with every engine tick.
	Tick()
}

// Run starts the agent and blocks until ctx is done, then shuts down
// cleanly (flushing open transactions into the spool).
func Run(ctx context.Context, o Options) error {
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.Env == nil {
		o.Env = os.LookupEnv
	}
	if o.LogLevel == nil {
		o.LogLevel = new(slog.LevelVar)
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: o.LogLevel}))
	}
	if o.TickInterval <= 0 {
		o.TickInterval = time.Second
	}
	log := o.Logger

	cfg, src, err := config.LoadFor(o.GOOS, o.ConfigPath, o.Env)
	if err != nil {
		return err
	}
	setLevel(o.LogLevel, cfg.LogLevel)
	log.Info("configuration loaded", "path", src.Path, "file", src.FileLoaded, "env_overrides", src.EnvApplied)

	a, err := open(ctx, o, cfg, src.Path)
	if err != nil {
		return err
	}
	defer a.close()

	roots := cfg.WatchRoots()
	if err := a.baseline(ctx, append(slices.Clone(roots), a.selfFiles...)); err != nil {
		return err
	}
	a.roots = roots

	var wg sync.WaitGroup
	collectCtx, stopCollectors := context.WithCancel(ctx)
	plat, info, err := startPlatform(collectCtx, &wg, a, roots)
	if err != nil {
		stopCollectors()
		return err
	}
	a.plat, a.Platform = plat, info

	// The cluster watcher is a collector in its own right, not a host scanner,
	// but its recommendations belong in the same heartbeat as the host's so a
	// cluster and its nodes are offered to the console as one fleet. It is
	// started before the transport so the first heartbeat already carries them.
	k8sCol, err := startKubernetes(collectCtx, &wg, a)
	if err != nil {
		stopCollectors()
		return err
	}
	if k8sCol != nil {
		a.extraWorkloads = func() []discovery.DiscoveredWorkload {
			return kubernetesWorkloads(k8sCol)
		}
	}

	// Surgical watchers: IIS application pools/sites and read-only database
	// surfaces. Both read the targets an operator authored in the console
	// through the classifier's rule set, so a watched target added in the UI
	// takes effect on the next poll without an agent restart. A failure to
	// start one never stops the agent: the file pipeline is the product, and a
	// host with no IIS or no database is the common case.
	if _, err := startIIS(collectCtx, &wg, a); err != nil {
		log.Warn("iis watcher unavailable", "err", err)
	}
	if _, err := startDatabase(collectCtx, &wg, a); err != nil {
		log.Warn("database watcher unavailable", "err", err)
	}

	// Workload auto-discovery runs independently of the collection pipeline:
	// it scans at startup and every six hours, and never blocks ingest.
	if a.discovery != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.discovery.Run(collectCtx)
		}()
	}

	flusher, err := a.startTransport(ctx)
	if err != nil {
		stopCollectors()
		return err
	}
	if flusher != nil {
		wg.Add(1)
		go func() { defer wg.Done(); flusher.Run(ctx) }()
	}

	reloader := &config.Reloader{Path: o.ConfigPath, GOOS: o.GOOS, Env: o.Env, Logger: log,
		OnChange: a.reconfigure, OnTick: a.refreshRoots}
	wg.Add(1)
	go func() { defer wg.Done(); reloader.Run(collectCtx, cfg) }()

	log.Info("agent running", "host_id", a.HostID, "roots", roots, "collectors", info)
	if o.Ready != nil {
		o.Ready(a)
	}

	tick := time.NewTicker(o.TickInterval)
	defer tick.Stop()
	gc := time.NewTicker(time.Hour)
	defer gc.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
			if err := a.Engine.Tick(ctx); err != nil && ctx.Err() == nil {
				log.Error("engine tick", "err", err)
			}
			plat.Tick()
		case <-gc.C:
			if n, err := a.Store.GC(ctx); err != nil {
				log.Warn("shadow gc", "err", err)
			} else if n > 0 {
				log.Debug("shadow gc", "removed", n)
			}
		}
	}

	log.Info("shutting down")
	stopCollectors()
	wg.Wait()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := a.Engine.Tick(shutdownCtx); err != nil {
		log.Error("final tick", "err", err)
	}
	if err := a.Engine.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("flush transactions: %w", err)
	}
	if a.flusher != nil {
		if err := a.flusher.Flush(shutdownCtx); err != nil {
			log.Warn("final spool flush failed", "err", err)
		}
	}
	st, _ := a.Spool.Stats(shutdownCtx)
	log.Info("agent stopped", "spooled_events", st.Events, "spool_bytes", st.Bytes)
	return nil
}

func open(ctx context.Context, o Options, cfg config.Config, cfgPath string) (*Agent, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	salt, err := loadSalt(filepath.Join(cfg.StateDir, "salt"))
	if err != nil {
		return nil, err
	}

	self := o.SelfFiles
	if self == nil {
		if exe, err := os.Executable(); err == nil {
			if real, err := filepath.EvalSymlinks(exe); err == nil {
				exe = real
			}
			self = append(self, exe)
		}
		self = append(self, cfgPath)
	}
	a := &Agent{Config: cfg, ConfigPath: cfgPath, HostID: cfg.ResolveHostID(), Logger: o.Logger, o: o}
	for _, p := range self {
		if p != "" {
			a.selfFiles = append(a.selfFiles, filepath.Clean(p))
		}
	}

	if a.Classifier, err = limiter.NewClassifier(a.classifierConfig(cfg)); err != nil {
		return nil, fmt.Errorf("classifier: %w", err)
	}
	a.Classifier.SetForensicUntil(time.Now(), cfg.ForensicUntil)

	if a.Store, err = shadow.Open(ctx, filepath.Join(cfg.StateDir, "shadow")); err != nil {
		return nil, err
	}
	a.scrubber = redact.New(salt)
	tracker := shadow.NewTracker(a.Store, a.scrubber, shadow.TrackerOptions{})
	if a.Spool, err = spool.Open(ctx, filepath.Join(cfg.StateDir, "spool.db"),
		spool.Options{MaxBytes: int64(cfg.Spool.MaxMB) << 20}); err != nil {
		a.Store.Close()
		return nil, err
	}
	a.Engine = &engine.Engine{
		HostID:     a.HostID,
		Classifier: a.Classifier,
		Breaker:    limiter.NewBreaker(limiter.DefaultBreakerConfig()),
		Tracker:    tracker,
		Debouncer:  debouncer.New(debouncer.Config{HostID: a.HostID}),
		Spool:      a.Spool,
	}
	a.walker = &baseline.Walker{Tracker: tracker, Policy: a.Engine.Policy(), Pace: cfg.Baseline.Pace.D(), Logger: o.Logger}
	a.discovery = discovery.New(discovery.Options{Logger: o.Logger})
	return a, nil
}

// startTransport builds the spool flusher. It returns nil when no server is
// configured (spool-only operation).
func (a *Agent) startTransport(ctx context.Context) (*transport.Flusher, error) {
	opts := transport.Options{}
	if a.o.Transport != nil {
		opts = *a.o.Transport
	}
	cfg := a.Config
	if opts.Address == "" {
		opts.Address = cfg.Server.Address
	}
	if opts.Address == "" {
		return nil, nil
	}
	opts.Spool = a.Spool
	opts.HostID = a.HostID
	opts.Hostname = a.o.Hostname
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}
	opts.OSFamily = a.o.GOOS
	opts.OSVersion = a.o.OSVersion
	if opts.OSVersion == "" {
		opts.OSVersion = config.OSVersion(a.o.GOOS)
	}
	opts.AgentVersion = a.o.AgentVersion
	if opts.CAFile == "" {
		opts.CAFile = cfg.Server.CAFile
	}
	if opts.CertFile == "" {
		opts.CertFile = cfg.Server.CertFile
	}
	if opts.KeyFile == "" {
		opts.KeyFile = cfg.Server.KeyFile
	}
	if opts.Logger == nil {
		opts.Logger = a.Logger
	}
	if opts.OnForensic == nil {
		opts.OnForensic = func(until time.Time) {
			a.Classifier.SetForensicUntil(time.Now(), until)
			a.Logger.Info("forensic mode toggled by server", "until", until,
				"active", a.Classifier.ForensicActive(time.Now()))
		}
	}
	if opts.Workloads == nil && a.discovery != nil {
		opts.Workloads = func() []*pb.DiscoveredWorkload {
			ws, _ := a.discovery.Last()
			// Host discoveries come first: a cluster recommendation is
			// additive, and the console should not list it above the
			// workloads found on the node itself.
			if a.extraWorkloads != nil {
				ws = append(ws, a.extraWorkloads()...)
			}
			return discovery.ToPB(discovery.Dedupe(ws))
		}
	}
	if opts.OnPolicyRules == nil {
		opts.OnPolicyRules = a.applyPolicyRules
	}
	f, err := transport.New(opts)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	a.flusher = f
	a.Logger.Info("transport started", "server", opts.Address)
	return f, nil
}

func (a *Agent) close() {
	if a.flusher != nil {
		_ = a.flusher.Close()
	}
	a.Spool.Close()
	a.Store.Close()
}

func (a *Agent) classifierConfig(cfg config.Config) limiter.ClassifierConfig {
	sep := "/"
	if a.o.GOOS == "windows" {
		sep = `\`
	}
	a.mu.Lock()
	serverRules := append([]limiter.PolicyRule(nil), a.serverRules...)
	a.mu.Unlock()
	// Server-pushed rules come first so an operator's accepted recommendation
	// wins over a stale config-file rule with the same target.
	rules := append(serverRules, cfg.Rules...)
	return limiter.ClassifierConfig{
		ExtraBlacklist: append([]string{strings.TrimSuffix(filepath.Clean(cfg.StateDir), sep) + sep + "**"}, cfg.Watch.Exclude...),
		ExtraCritical:  cfg.Watch.Critical,
		ExtraSelf:      a.selfFiles,
		Rules:          rules,
	}
}

// baseline seeds roots that were never baselined, and reports changes made
// while the agent was not running for roots that were.
func (a *Agent) baseline(ctx context.Context, roots []string) error {
	var fresh, known []string
	for _, r := range roots {
		done, err := a.walker.Done(ctx, r)
		if err != nil {
			return err
		}
		if done {
			known = append(known, r)
		} else {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) > 0 {
		st, err := a.walker.Run(ctx, fresh)
		if err != nil {
			return fmt.Errorf("baseline: %w", err)
		}
		a.Logger.Info("day-0 baseline", "roots", st.RootsWalked, "files", st.Files, "skipped", st.Skipped,
			"errors", st.Errors, "duration", st.Duration.Round(time.Millisecond))
	}
	if len(known) > 0 {
		n, err := a.catchUp(ctx, known)
		if err != nil {
			return err
		}
		a.Logger.Info("offline change reconciliation", "roots", len(known), "changed", n)
	}
	return nil
}

// catchUp re-observes files whose size, mtime or mode differ from the
// shadow index, and indexed files that no longer exist.
func (a *Agent) catchUp(ctx context.Context, roots []string) (int, error) {
	n := 0
	observe := func(p string) error {
		n++
		return a.Engine.HandleFile(ctx, engine.FileEvent{Path: p, Attribution: "offline"})
	}
	sep := byte(filepath.Separator)
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if a.Classifier.Blacklisted(p) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			e, ok, err := a.Store.Get(ctx, p)
			if err != nil {
				return err
			}
			if !ok || e.Size != fi.Size() || !e.ModTime.Equal(fi.ModTime()) || e.Mode != fi.Mode() {
				return observe(p)
			}
			return nil
		})
		if err != nil {
			return n, err
		}
		known, err := a.Store.PathsUnder(ctx, root, sep)
		if err != nil {
			return n, err
		}
		for _, p := range known {
			if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
				if err := observe(p); err != nil {
					return n, err
				}
			}
		}
	}
	return n, nil
}

// applyPolicyRules installs the server's active policy rules and rebuilds the
// classifier so they take effect immediately. It is safe to call from the
// transport goroutine.
func (a *Agent) applyPolicyRules(rules []*pb.PolicyRule) {
	converted := make([]limiter.PolicyRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		converted = append(converted, limiter.PolicyRule{
			Name:       r.GetName(),
			TargetType: r.GetTargetType(),
			Pattern:    r.GetPattern(),
			Level:      int(r.GetLevel()),
			Diff:       r.GetDiff(),
			Tags:       r.GetTags(),
		})
	}
	a.mu.Lock()
	a.serverRules = converted
	cfg := a.Config
	a.mu.Unlock()
	if err := a.Classifier.Reconfigure(a.classifierConfig(cfg)); err != nil {
		a.Logger.Error("failed to apply server policy rules; keeping previous", "err", err)
		return
	}
	a.Logger.Info("policy rules updated by server", "rules", len(converted))
}

// reconfigure applies a reloaded configuration.
func (a *Agent) reconfigure(old, cur config.Config) {
	setLevel(a.o.LogLevel, cur.LogLevel)
	if err := a.Classifier.Reconfigure(a.classifierConfig(cur)); err != nil {
		a.Logger.Error("reload: invalid watch rules; keeping previous", "err", err)
	}
	if !old.ForensicUntil.Equal(cur.ForensicUntil) {
		a.Classifier.SetForensicUntil(time.Now(), cur.ForensicUntil)
		a.Logger.Info("forensic mode updated", "until", cur.ForensicUntil, "active", a.Classifier.ForensicActive(time.Now()))
	}
	a.mu.Lock()
	a.Config = cur
	a.mu.Unlock()
	// New configured roots are baselined silently before being watched.
	var fresh []string
	for _, r := range cur.WatchRoots() {
		if !slices.Contains(old.WatchRoots(), r) {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) > 0 {
		if _, err := a.walker.Run(context.Background(), fresh); err != nil {
			a.Logger.Error("reload: baseline of new roots failed", "roots", fresh, "err", err)
		}
	}
	a.Logger.Info("configuration reloaded")
	a.refreshRoots(cur)
}

// refreshRoots re-expands watch globs (e.g. a new /home/*/.ssh).
func (a *Agent) refreshRoots(cur config.Config) {
	roots := cur.WatchRoots()
	a.mu.Lock()
	changed := !slices.Equal(roots, a.roots)
	a.roots = roots
	plat := a.plat
	a.mu.Unlock()
	if changed && plat != nil {
		a.Logger.Info("watch roots changed", "roots", roots)
		plat.SetRoots(roots)
	}
}

func setLevel(v *slog.LevelVar, level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err == nil {
		v.Set(l)
	}
}

// loadSalt returns the per-host redaction salt, creating it on first start.
func loadSalt(p string) ([]byte, error) {
	if b, err := os.ReadFile(p); err == nil && len(b) >= 16 {
		return b, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, salt, 0o600); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	return salt, nil
}
