package discovery

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultInterval is how often the scanner re-probes after the startup scan.
const DefaultInterval = 6 * time.Hour

// prober inspects one workload family and returns everything it found. A
// prober must be non-blocking (bounded reads) and must never return an error:
// a missing config file simply yields no workloads.
type prober func() []DiscoveredWorkload

// Options configures a Scanner. Zero values mean production defaults.
type Options struct {
	// Probers are the discovery probes to run. When nil, the platform default
	// set is used (iis/sql-server on Windows, nginx/apache/postgres/mysql/
	// redis/docker on Linux). Tests inject deterministic probes.
	Probers []Prober
	// Interval between rescans (default DefaultInterval).
	Interval time.Duration
	// Report receives the full workload set after every successful scan. It is
	// called synchronously from Scan and must not block; a nil Report disables
	// delivery.
	Report func([]DiscoveredWorkload)
	Logger *slog.Logger
}

// Prober is one named discovery probe. Exported so tests and platform files
// can register probes without depending on unexported scanner internals.
type Prober struct {
	Name  string
	Probe func() []DiscoveredWorkload
}

// Scanner runs the discovery probes and reports the aggregate result. It is
// safe for concurrent use; the scan itself is serialised so a slow probe can
// never stack up behind the timer.
type Scanner struct {
	o      Options
	log    *slog.Logger
	mu     sync.Mutex
	last   []DiscoveredWorkload
	lastAt time.Time
}

// New builds a Scanner from opts.
func New(opts Options) *Scanner {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Scanner{o: opts, log: log}
}

// Last returns a copy of the most recent scan result and when it ran.
func (s *Scanner) Last() ([]DiscoveredWorkload, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]DiscoveredWorkload(nil), s.last...), s.lastAt
}

// Scan runs every configured probe and returns the de-duplicated, sorted
// workload set. Probe panics are contained so one bad probe cannot take down
// the heartbeat. Scan never returns an error: discovery is best-effort.
func (s *Scanner) Scan() []DiscoveredWorkload {
	probers := s.o.Probers
	if probers == nil {
		probers = platformProbers()
	}
	var out []DiscoveredWorkload
	for _, p := range probers {
		if p.Probe == nil {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Warn("discovery probe panicked", "probe", p.Name, "panic", r)
				}
			}()
			got := p.Probe()
			out = append(out, got...)
		}()
	}
	out = Dedupe(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ConfigPath < out[j].ConfigPath
	})

	s.mu.Lock()
	s.last, s.lastAt = append([]DiscoveredWorkload(nil), out...), time.Now()
	s.mu.Unlock()

	if s.o.Report != nil {
		s.o.Report(out)
	}
	return out
}

// Run scans immediately, then every Interval until ctx is done. It blocks, so
// callers should start it in its own goroutine; it is deliberately independent
// of the collection pipeline so a stalled probe can never delay events.
func (s *Scanner) Run(ctx context.Context) {
	s.Scan()
	t := time.NewTicker(s.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Scan()
		}
	}
}

// normPath lower-cases Windows paths for comparisons and trims trailing
// separators so "/etc/nginx/" and "/etc/nginx" compare equal.
func normPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `\`, `/`)
	p = strings.TrimRight(p, "/")
	if len(p) >= 2 && p[1] == ':' {
		p = strings.ToLower(p)
	}
	return p
}
